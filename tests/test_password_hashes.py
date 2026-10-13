"""Synthetic key material and isolated workers; no test contacts a domain."""

from copy import deepcopy
import json
import logging
import time
from types import SimpleNamespace
import zipfile

import pytest

import AtilKurt
from core import password_hashes as hashes
from core.assessment_scope import AssessmentScope
from core.directory_redaction import redact_assessment_secrets
from reporting.client_report import client_document, export_client_report
from reporting.report_sections.password_hash_section import password_hash_section
from tests.test_audit_roundtrip_regressions import snapshot_data, run_offline

NTLM, LM, KEY = 'a' * 32, 'b' * 32, 'c' * 64


def record():
    return {'account': 'alice', 'sid': 'S-1-5-21-1-2-3-1100', 'status': 'not_attempted',
            'ntlm': None, 'lm': None, 'kerberos_keys': [], 'errors': []}


def fill_record(row):
    hashes.accept_secret(row, 0, f"example.com\\{row['account']}:{row['sid'].rsplit('-', 1)[-1]}:{LM}:{NTLM}:::")
    hashes.accept_secret(row, 2, f"example.com\\{row['account']}:aes256-cts-hmac-sha1-96:{KEY}")
    row['status'] = 'collected'
    return row


def successful_worker(pipe, config):
    while True:
        pipe.send({'event': 'ready'})
        row = pipe.recv()
        if row is None:
            break
        pipe.send({'event': 'record', 'record': fill_record(row)})
    pipe.send({'event': 'done'})
    pipe.close()


def hanging_worker(pipe, config):
    pipe.send({'event': 'ready'})
    row = pipe.recv()
    pipe.send({'event': 'record', 'record': fill_record(row)})
    time.sleep(20)


def denied_worker(pipe, config):
    pipe.send({'event': 'ready'})
    row = pipe.recv()
    row['status'] = 'failed'
    row['errors'] = [{'reason': 'access_denied', 'code': 8453}]
    pipe.send({'event': 'record', 'record': row})
    pipe.send({'event': 'error', 'error': {'reason': 'access_denied'}})
    pipe.send({'event': 'done'})


def collect(monkeypatch, worker=successful_worker, data=None, **options):
    monkeypatch.setattr(hashes, '_worker', worker)
    return hashes.collect_password_hashes(data or snapshot_data(), host='dc.example.com', domain='example.com',
                                          username='auditor', password='<test-password>', **options)


def test_typed_callbacks_preserve_exact_keys_and_ignore_cleartext():
    row = fill_record(record())
    hashes.accept_secret(row, 1, '<unrequested-test-value>')
    assert row['ntlm'] == NTLM and row['lm'] == LM
    assert row['kerberos_keys'] == [{'algorithm': 'aes256-cts-hmac-sha1-96', 'kerberos_key': KEY}]
    assert '<unrequested-test-value>' not in json.dumps(row)


@pytest.mark.parametrize('value', [f'other:1100:{LM}:{NTLM}:::', f'alice:1101:{LM}:{NTLM}:::',
                                 'alice:1100:bad:bad:::', 'incomplete'])
def test_reject_mismatched_identity_or_invalid_hash(value):
    with pytest.raises(ValueError):
        hashes.accept_secret(record(), 0, value)


def test_reject_invalid_key_or_unknown_callback():
    for kind, value in [(2, f'alice:aes256-cts-hmac-sha1-96:{NTLM}'), (2, f'alice:unknown:{KEY}'), (3, KEY)]:
        with pytest.raises(ValueError):
            hashes.accept_secret(record(), kind, value)


def test_success_worker_inventory_dedup_and_counts(monkeypatch):
    data = snapshot_data()
    data['computers'] = deepcopy(data['users'])
    result = collect(monkeypatch, data=data)
    assert result['status'] == 'completed'
    assert result['summary'] == {'requested': 1, 'collected': 1, 'attempted': 1, 'failed': 0,
                                 'not_attempted': 0, 'kerberos_keys': 1, 'password_history': 0}
    assert result['records'][0]['ntlm'] == NTLM


def test_incomplete_inventory_cannot_claim_all_hashes(monkeypatch):
    data = snapshot_data()
    data['collection_health']['status'] = 'partial'
    assert collect(monkeypatch, data=data)['status'] == 'partial'


def test_denied_retains_failure_and_unattempted_accounts(monkeypatch):
    data = snapshot_data()
    data['users'].append({'sAMAccountName': 'bob', 'objectSid': 'S-1-5-21-1-2-3-1101'})
    result = collect(monkeypatch, denied_worker, data)
    assert result['status'] == 'failed'
    assert result['summary']['failed'] == 1 and result['summary']['not_attempted'] == 1
    assert AtilKurt.scan_exit_code({'password_hashes': result}, {}) == 2
    assert 'successfully' not in AtilKurt.scan_completion_message({'collection_health': {'status': 'completed'}, 'password_hashes': result}, {})


def test_timeout_preserves_completed_results(monkeypatch):
    started = time.monotonic()
    result = collect(monkeypatch, hanging_worker, max_seconds=1)
    assert time.monotonic() - started < 6
    assert result['status'] == 'partial' and result['records'][0]['ntlm'] == NTLM
    assert {'reason': 'time_budget_exceeded'} in result['errors']


def test_scope_denies_drs_before_worker(monkeypatch):
    scope = AssessmentScope('example.com', {'schema_version': 1, 'services': ['ldap', 'smb']})
    result = collect(monkeypatch, scope=scope)
    assert result['summary']['not_attempted'] == 1
    assert result['errors'] == [{'reason': 'scope_or_request_budget_exceeded'}]


def test_scope_request_budget_stops_worker(monkeypatch):
    scope = AssessmentScope('example.com', max_queries=1)
    result = collect(monkeypatch, scope=scope)
    assert result['status'] == 'failed'
    assert result['summary']['not_attempted'] == 1


def test_missing_inventory_is_failure_without_network(monkeypatch):
    data = snapshot_data()
    data['users'] = [{'sAMAccountName': 'missing-sid'}]
    result = collect(monkeypatch, data=data)
    assert result['status'] == 'failed' and result['summary']['requested'] == 0


def test_upstream_worker_does_not_log_secrets_and_notices_swallowed_error(monkeypatch, capsys):
    from impacket.examples import secretsdump
    from impacket import smbconnection

    class SMB:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args):
            pass

        def setTimeout(self, timeout):
            pass

        def close(self):
            pass

    class Remote:
        def __init__(self, *args):
            pass

        def finish(self):
            pass

        def getMachineNameAndDomain(self):
            return 'DC', 'EXAMPLE'

        def connectSamr(self, domain):
            pass

    class Dumper:
        def __init__(self, *args, **kwargs):
            assert kwargs['outputFileName'] is None and kwargs['history'] is True and not kwargs.get('useVSSMethod')
            self.callback = kwargs['perSecretCallback']

        def dump(self):
            self.callback(0, f'alice:1100:{LM}:{NTLM}:::')
            logging.getLogger('impacket').error('Sensitive upstream error: %s', KEY)

        def finish(self):
            pass

    class Pipe:
        sent = []
        inputs = iter([record(), None])

        def send(self, value):
            self.sent.append(deepcopy(value))

        def recv(self):
            return next(self.inputs)

        def close(self):
            pass

    monkeypatch.setattr(secretsdump, 'NTDSHashes', Dumper)
    monkeypatch.setattr(secretsdump, 'RemoteOperations', Remote)
    monkeypatch.setattr(smbconnection, 'SMBConnection', SMB)
    # Exercise the process-local handler without replacing pytest's handlers.
    def configure(**kwargs):
        monkeypatch.setattr(logging.getLogger(), 'handlers', kwargs['handlers'])
    monkeypatch.setattr(logging, 'basicConfig', configure)
    pipe = Pipe()
    hashes._worker(pipe, {'host': 'dc.example.com', 'timeout': 1, 'username': 'auditor', 'password': '<test-password>', 'domain': 'example.com'})
    result = next(event['record'] for event in pipe.sent if event['event'] == 'record')
    assert result['status'] == 'partial'
    assert result['errors'] == [{'reason': 'upstream_processing_error', 'count': 1}]
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err


@pytest.mark.parametrize('redacted', [False, True])
def test_offline_report_and_checkpoint_preserve_policy(tmp_path, monkeypatch, redacted):
    snapshot = snapshot_data()
    snapshot['users'][0]['description'] = 'password = "<synthetic-directory-value>"'
    snapshot['password_hashes'] = {'status': 'completed', 'records': [fill_record(record())], 'summary': {'collected': 1}}
    code, exported = run_offline(tmp_path, monkeypatch, snapshot, extra_args=['--redact-secrets'] if redacted else [])
    assert code == 0
    assert exported['secrets_redacted'] == redacted
    assert exported['password_hashes']['records'][0]['ntlm'] == ('[REDACTED]' if redacted else NTLM)
    report = (tmp_path / 'report.html').read_text()
    assert (NTLM in report) is not redacted
    checkpoint = AtilKurt.build_checkpoint_payload(SimpleNamespace(domain='example.com', redact_secrets=redacted),
                                                   deepcopy(exported), {}, {}, {})
    assert (NTLM in json.dumps(checkpoint)) is not redacted
    assert ('<synthetic-directory-value>' in json.dumps(exported)) is not redacted


@pytest.mark.parametrize('redacted', [False, True])
def test_client_documents_preserve_hash_visibility(tmp_path, redacted):
    data = {'password_hashes': {'status': 'completed', 'records': [fill_record(record())]}}
    document = client_document('example.com', data, [], {}, redact_secrets=redacted)
    assert (KEY in json.dumps(document)) is not redacted
    for extension in ('docx', 'pdf'):
        path = tmp_path / ('client.' + extension)
        export_client_report(path, document)
        assert path.stat().st_mode & 0o777 == 0o600
    with zipfile.ZipFile(tmp_path / 'client.docx') as archive:
        assert (KEY in archive.read('word/document.xml').decode()) is not redacted


def test_html_unmasked_values_are_escaped():
    row = fill_record(record())
    row['account'] = '<script>alert(1)</script>'
    html = password_hash_section({'status': 'completed', 'records': [row]})
    assert '<script>alert(1)</script>' not in html
    assert '&lt;script&gt;' in html and NTLM in html


def test_hash_redaction_and_error_text_policy():
    row = fill_record(record())
    hashes.accept_secret(row, 0, f"example.com\\alice_history0:{row['sid'].rsplit('-', 1)[-1]}:{LM}:{'d' * 32}:::")
    data = {'password_hashes': {'records': [row]}}
    redact_assessment_secrets(data)
    dumped = json.dumps(data)
    assert NTLM not in dumped and KEY not in dumped and 'd' * 32 not in dumped
    assert '<secret-in-exception>' not in json.dumps(hashes._error(RuntimeError('<secret-in-exception>')))


def test_password_history_is_retained_and_rendered():
    row = record()
    rid = row['sid'].rsplit('-', 1)[-1]
    hashes.accept_secret(row, 0, f'example.com\\alice:{rid}:{LM}:{NTLM}:::')
    hashes.accept_secret(row, 0, f'example.com\\alice_history0:{rid}:{LM}:{"d" * 32}:::')
    hashes.accept_secret(row, 0, f'example.com\\alice_history1:{rid}::{hashes.EMPTY_NT}:::')
    assert row['ntlm'] == NTLM
    assert row['nt_history'] == [{'index': 0, 'lm': LM, 'ntlm': 'd' * 32, 'empty_lm_placeholder': False}]
    html = password_hash_section({'status': 'completed', 'records': [row], 'summary': {'password_history': 1}})
    assert 'd' * 32 in html and hashes.EMPTY_NT not in html
    assert NTLM in html and 'NT history' in html
    assert html.find('>NTLM<') < html.find('>LM<')
    assert f'{LM}:{NTLM}' in html
    assert 'id="passwordHashesTable"' in html and 'table-layout:fixed' in html
    assert 'exportPasswordHashes' in html and 'Export to Excel' in html
    turkish = password_hash_section({'status': 'completed', 'records': [row], 'summary': {}}, language='tr')
    assert 'Excel&#39;e Aktar' not in turkish and "Excel'e Aktar" in turkish


def test_missing_replication_rights_do_not_start_collection(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError('worker started')

    monkeypatch.setattr(hashes, '_worker', boom)
    result = hashes.collect_password_hashes(
        snapshot_data(), host='dc.example.com', domain='example.com', username='auditor',
        password='<test-password>', authorization={'status': 'not_authorized',
                                                   'rights': {'get_changes': False, 'get_changes_all': False}})
    assert result['status'] == 'failed'
    assert result['summary']['not_attempted'] == 1 and result['summary']['attempted'] == 0
    assert {'reason': 'replication_not_authorized'} in result['errors']
    assert 'not granted both' in password_hash_section(result)


def test_replication_rights_require_both_controls():
    sid = 'S-1-5-21-1-2-3-1100'

    def ace(guid, trustee=sid):
        return {'sid': trustee, 'ace_flags': 0, 'type': 'ACCESS_ALLOWED_OBJECT',
                'object_type': guid, 'access_mask': 0x100}

    only_changes = hashes.replication_authorization({'dacl': [ace(hashes.GET_CHANGES)]}, sid, set())
    assert only_changes['status'] == 'not_authorized'
    both = hashes.replication_authorization(
        {'dacl': [ace(hashes.GET_CHANGES), ace(hashes.GET_CHANGES_ALL)]}, sid, set())
    assert both['status'] == 'authorized' and both['rights'] == {'get_changes': True, 'get_changes_all': True}
    via_group = hashes.replication_authorization(
        {'dacl': [ace(hashes.GET_CHANGES, 'S-1-5-32-544'), ace(hashes.GET_CHANGES_ALL, 'S-1-5-32-544')]},
        sid, {'S-1-5-32-544'})
    assert via_group['status'] == 'authorized'


def test_unreadable_token_does_not_claim_missing_rights():
    verdict = hashes.domain_replication_authorization(
        SimpleNamespace(base_search=lambda *_args, **_kwargs: [], base_dn='DC=example,DC=com'),
        {'sid': 'S-1-5-21-1-2-3-1100', 'token_groups': {'status': 'unreadable', 'sids': []}})
    assert verdict['status'] == 'unknown' and verdict['reason'] == 'identity_unresolved'


@pytest.mark.parametrize(('label', 'expected', 'length'), [('dec-cbc-crc', 'des-cbc-crc', 16), ('rc4_hmac', 'rc4-hmac', 32)])
def test_upstream_kerberos_algorithm_labels(label, expected, length):
    row = record()
    hashes.accept_secret(row, 2, f'alice:{label}:' + 'a' * length)
    assert row['kerberos_keys'][0]['algorithm'] == expected


def test_identity_masking_does_not_corrupt_visible_hashes():
    data = {'users': [{'sAMAccountName': 'a'}], 'password_hashes': {'records': [fill_record(record())]}}
    doc = client_document('example.com', data, [], {}, masked=True, redact_secrets=False)
    assert doc['password_hashes']['records'][0]['ntlm'] == NTLM


@pytest.mark.parametrize('redacted', [False, True])
def test_sysvol_visibility_policy(redacted):
    from analysis.sysvol_analyzer import _inspect
    risks = _inspect(b'<Groups cpassword="synthetic-ciphertext-only"/>', 'Groups.xml', redact_secrets=redacted)
    assert ('synthetic-ciphertext-only' in json.dumps(risks)) is not redacted


def test_client_report_uses_real_collection_health_fields():
    from reporting.client_report import _paragraphs
    health = {'status': 'completed', 'query_count': 100, 'failed_queries': 0}
    doc = client_document('example.com', {'collection_health': health}, [], {})
    assert doc['collection_health'] == health
    assert json.dumps(health) in [value for _, value in _paragraphs(doc, 'en')]


def test_cli_default_visibility_and_invalid_collection_modes():
    parser = AtilKurt.build_parser()
    assert not parser.parse_args(['-d', 'example.com']).redact_secrets
    for flags in (['--auth-method', 'kerberos'], ['--resume', 'example']):
        args = parser.parse_args(['-d', 'example.com', '--collect-password-hashes', *flags])
        with pytest.raises(SystemExit):
            AtilKurt.validate_cli_arguments(parser, args)
