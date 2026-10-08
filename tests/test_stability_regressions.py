"""Regression coverage for publication, resume, partial LDAP and worker lifetime."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from threading import Barrier, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import AtilKurt
from analysis import registry
from analysis.remediation_verifier import verify_remediation
from analysis.scan_coverage import build_scan_coverage
from core.assessment_history import AssessmentHistory
from core.diagnostics import collection_health
from core.effective_access import collect_effective_tokens
from core.exceptions import LDAPSearchError, ValidationError
from core.finding_review import FindingReviewManager
from core.ldap_connection import LDAPConnection
from core.parallel_ldap import ParallelCollector, ParallelLDAPExecutor
from core.product_workflow import prepare_product_workspace
from core.progress_persistence import IncrementalScanner, ProgressPersistence
from core.utility_cli import utility_main
from core.validators import validate_distinct_paths
from reporting.export_formats import ExportFormats

DOMAIN = 'example.com'


def report_state(tmp_path):
    args = AtilKurt.build_parser().parse_args([
        '-d', DOMAIN, '-u', 'auditor', '--output', str(tmp_path / 'report.html'),
        '--history-db', str(tmp_path / 'history.db'),
    ])
    data = {name: [] for name in ('users', 'computers', 'groups', 'gpos')}
    data['scan_context'] = {'fresh_ldap': True}
    risk = {'type': 'dcsync_rights', 'severity': 'critical', 'title': 'DCSync rights',
            'affected_object': DOMAIN, 'object_type': 'domain', 'evidence': {'trustee_sid': 'S-1-5-21-1-2-3-1001'}}
    analysis = {'misconfig_findings': [], 'legacy_os_results': {}, 'acl_security_results': {},
                'kerberoasting_targets': [], 'asrep_targets': []}
    scoring = AtilKurt.score_and_consolidate(analysis, data, domain=DOMAIN, input_risks=[risk])
    compliance = {'compliance_data': {}, 'risk_management_data': {}}
    return args, data, analysis, scoring, compliance


@pytest.mark.parametrize('failure_stage', ['html', 'export'])
def test_failed_publication_rolls_back_history_and_preserves_alert_on_retry(tmp_path, monkeypatch, failure_stage):
    args, data, analysis, scoring, compliance = report_state(tmp_path)
    if failure_stage == 'html':
        def fail(*_args, **_kwargs):
            raise OSError('Synthetic report publication failure')
        monkeypatch.setattr(AtilKurt.HTMLReportGenerator, 'generate', fail)
    else:
        args.siem_export = str(tmp_path / 'missing' / 'events.jsonl')
    with pytest.raises(OSError):
        AtilKurt.generate_reports(args, data, analysis, scoring, compliance, None)
    with AssessmentHistory(args.history_db) as history:
        assert history.runs(DOMAIN) == []
        assert history.tasks(DOMAIN) == []
        assert history.audit_document()['entries'] == []
    monkeypatch.undo()
    args.siem_export = None
    AtilKurt.generate_reports(args, data, analysis, scoring, compliance, None)
    assert len(scoring['product_workspace']['history']['notifications']) == 1
    with AssessmentHistory(args.history_db) as history:
        assert len(history.runs(DOMAIN)) == 1
        assert len(history.tasks(DOMAIN)) == 1


def test_bad_task_import_cannot_commit_a_new_scan(tmp_path):
    args, data, analysis, scoring, _ = report_state(tmp_path)
    task_file = tmp_path / 'tasks.json'
    task_file.write_text(json.dumps({'schema_version': 1, 'domain': DOMAIN, 'tickets': [
        {'finding_id': 'unknown', 'owner': 'operator'}]}), encoding='utf-8')
    args.ticket_file = str(task_file)
    with pytest.raises(ValidationError):
        prepare_product_workspace(args, data, analysis, scoring)
    with AssessmentHistory(args.history_db) as history:
        assert history.runs(DOMAIN) == []
        assert history.tasks(DOMAIN) == []


def checkpoint_payload():
    return {'domain': DOMAIN, 'data': {key: [] for key in ('users', 'computers', 'groups', 'gpos')},
            'analysis': {'misconfig_findings': [], 'kerberoasting_targets': [], 'asrep_targets': [],
                         'legacy_os_results': {}, 'acl_security_results': {}}, 'scoring': {}, 'compliance': {}}


def test_resume_restores_binary_identity_and_accepts_optional_review_lists(tmp_path):
    persistence = ProgressPersistence(str(tmp_path / 'checkpoints'))
    payload = checkpoint_payload()
    payload['data']['users'] = [{'objectSid': b'\x01\x05sid', 'objectGUID': b'guid'}]
    payload['scoring']['review_center'] = {'document': {'schema_version': 1, 'domain': DOMAIN}}
    persistence.save_checkpoint('resume', payload)
    loaded = AtilKurt.load_resume_checkpoint(persistence, 'resume', DOMAIN.upper())
    assert loaded['data']['users'] == payload['data']['users']


@pytest.mark.parametrize('problem', ['missing', 'domain', 'section', 'collection', 'findings', 'review', 'analysis', 'execution'])
def test_invalid_resume_state_is_rejected(tmp_path, problem):
    persistence = ProgressPersistence(str(tmp_path / 'checkpoints'))
    payload = checkpoint_payload()
    if problem == 'domain':
        payload['domain'] = 'different.example'
    elif problem == 'section':
        payload['analysis'] = []
    elif problem == 'collection':
        payload['data']['users'] = [None]
    elif problem == 'findings':
        payload['analysis']['user_risks'] = [None]
    elif problem == 'review':
        payload['scoring']['review_center'] = {'document': {'schema_version': 1, 'domain': 'other.example'}}
    elif problem == 'analysis':
        payload['analysis'].pop('misconfig_findings')
    elif problem == 'execution':
        payload['analysis']['analysis_execution'] = {'completed_steps': [None]}
    if problem != 'missing':
        persistence.save_checkpoint('resume', payload)
    with pytest.raises(ValidationError):
        AtilKurt.load_resume_checkpoint(persistence, 'resume', DOMAIN)


def test_missing_resume_fails_before_password_or_ldap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('sys.argv', ['Atilkurt', '-d', DOMAIN, '-u', 'auditor', '--resume', 'missing'])
    credentials = Mock(side_effect=AssertionError('Credentials must not be requested'))
    connection = Mock(side_effect=AssertionError('LDAP must not be opened'))
    monkeypatch.setattr(AtilKurt, 'resolve_password', credentials)
    monkeypatch.setattr(AtilKurt, 'LDAPConnection', connection)
    with pytest.raises(SystemExit) as caught:
        AtilKurt.main()
    assert caught.value.code == 1
    credentials.assert_not_called()
    connection.assert_not_called()


def test_serialized_ldap_values_do_not_create_incremental_false_changes(tmp_path):
    persistence = ProgressPersistence(str(tmp_path / 'checkpoints'))
    current = [{'sAMAccountName': 'user1', 'objectSid': b'\x01sid',
                'lastLogon': datetime(2026, 10, 8, tzinfo=timezone.utc)}]
    persistence.save_checkpoint('previous', {'users': current})
    previous = persistence.load_checkpoint('previous')['users']
    scanner = IncrementalScanner(persistence)
    assert scanner.find_changed_items(current, previous, ['sAMAccountName']) == []
    changed = deepcopy(current)
    changed[0]['objectSid'] = b'\x01changed'
    assert len(scanner.find_changed_items(changed, previous, ['sAMAccountName'])) == 1


def test_checkpoint_writer_works_without_posix_fchmod(tmp_path, monkeypatch):
    monkeypatch.delattr(os, 'fchmod', raising=False)
    persistence = ProgressPersistence(str(tmp_path / 'checkpoints'))
    persistence.save_checkpoint('portable', {'domain': DOMAIN})
    assert persistence.load_checkpoint('portable') == {'domain': DOMAIN}
    handler = AtilKurt._PrivateFileHandler(str(tmp_path / 'private.log'))
    handler.close()


def test_swallowed_ldap_failure_marks_step_partial_and_blocks_remediation(monkeypatch):
    ldap = LDAPConnection(DOMAIN, 'auditor', 'test-only-secret', DOMAIN, max_retries=1)
    ldap.connection = SimpleNamespace(result={'result': 50})

    def failing_query():
        raise LDAPSearchError('Read denied')

    def runner(connection, _data):
        try:
            connection._audited_query(failing_query, DOMAIN, '(objectClass=*)', [], 0, 'BASE')
        except LDAPSearchError:
            return {'password_policy_risks': []}

    selected = [('password_policy', 'Password policy', runner)]
    monkeypatch.setattr(registry, 'ANALYSIS_STEP_REGISTRY', selected)
    monkeypatch.setattr('analysis.scan_coverage.ANALYSIS_STEP_REGISTRY', selected)
    analysis = registry.run_all_analyses(ldap, {})
    assert analysis['analysis_execution']['partial_steps']['password_policy']['failed_queries'] == 1
    coverage = build_scan_coverage(analysis, [], {})
    assert coverage['analysis_steps'][0]['status'] == 'partial'
    assert coverage['summary']['execution_percent'] == 0
    data = {'scan_context': {'fresh_ldap': True, 'collected_at': datetime.now(timezone.utc).isoformat()},
            'collection_health': {'status': 'completed'}}
    risk = {'type': 'password_policy_weak', 'severity': 'critical', 'affected_object': DOMAIN}
    FindingReviewManager().apply([risk], {}, DOMAIN)
    result = verify_remediation({'domain': DOMAIN, 'risks': [risk]}, [], data, coverage, DOMAIN)
    assert result['findings'][0]['status'] == 'insufficient_evidence'


def test_failures_after_ledger_limit_remain_counted():
    ldap = LDAPConnection(DOMAIN, 'auditor', 'test-only-secret', DOMAIN)
    ldap.merge_query_audit([{'status': 'completed'}] * 10000)
    ldap.merge_query_audit([{'status': 'failed'}])
    health = collection_health(ldap)
    assert health['record_limit_exceeded'] and health['failed_queries'] == 1
    assert health['status'] == 'partial'


class PagedConnection:
    """Fake paged server exposing a different result and cookie each call."""

    def __init__(self, pages):
        self.pages = iter(pages)
        self.calls = 0
        self.result = {}
        self.entries = []

    def search(self, **_kwargs):
        self.calls += 1
        self.entries, cookie = next(self.pages)
        self.result = {'result': 0, 'controls': {
            '1.2.840.113556.1.4.319': {'value': {'cookie': cookie}}}}
        return True


def paged_wrapper(pages):
    ldap = LDAPConnection(DOMAIN, 'auditor', 'test-only-secret', DOMAIN, page_size=1,
                          max_retries=1, enable_cache=True)
    ldap.connection = PagedConnection(pages)
    ldap._entry_to_dict = lambda entry: dict(entry)
    return ldap


@pytest.mark.parametrize('pages', [
    [([{'dn': 'one'}], b'first'), ([], b'second')],
    [([{'dn': 'one'}], b'repeated'), ([{'dn': 'two'}], b'repeated')],
])
def test_paging_without_progress_fails_and_does_not_cache_partial_data(pages):
    ldap = paged_wrapper(pages)
    with pytest.raises(LDAPSearchError, match='partial results discarded'):
        ldap.search()
    assert ldap.connection.calls == 2
    assert ldap.query_audit[-1]['status'] == 'failed'
    ldap.connection = PagedConnection([([{'dn': 'complete'}], b'')])
    assert ldap.search() == [{'dn': 'complete'}]
    assert ldap.connection.calls == 1


def test_paging_applies_network_delay_to_every_page_and_skips_cache_hits():
    ldap = paged_wrapper([([{'dn': 'one'}], b'next'), ([{'dn': 'two'}], b'')])
    hook = Mock()
    ldap.pre_search_hook = hook
    assert len(ldap.search()) == 2
    assert hook.call_count == 2
    assert len(ldap.search()) == 2
    assert hook.call_count == 2


def test_paging_final_cookie_does_not_reuse_stale_response_controls():
    ldap = paged_wrapper([([{'dn': 'complete'}], b'')])
    ldap.connection.response = {'controls': {
        '1.2.840.113556.1.4.319': {'value': {'cookie': b'stale'}}}}
    assert ldap.search() == [{'dn': 'complete'}]
    assert ldap.connection.calls == 1


@pytest.mark.parametrize('cookie', [None, 'invalid', 1000000])
def test_malformed_paging_cookie_cannot_be_treated_as_a_complete_result(cookie):
    ldap = paged_wrapper([([{'dn': 'one'}], cookie)])
    with pytest.raises(LDAPSearchError, match='Invalid LDAP paging cookie'):
        ldap.search()
    assert ldap.query_failure_count == 1


def test_paging_last_page_cannot_exceed_overall_deadline(monkeypatch):
    ldap = paged_wrapper([([{'dn': 'one'}], b'')])
    clock = iter([0, 0, 31])
    monkeypatch.setattr('core.ldap_connection.time.monotonic', lambda: next(clock))
    with pytest.raises(LDAPSearchError, match='timed out'):
        ldap._paged_search(ldap.base_dn, '(objectClass=*)', [], 0, timeout=30)


def test_parallel_workers_preserve_tls_settings_and_close_after_success_and_failure(monkeypatch):
    base = LDAPConnection(DOMAIN, 'auditor', 'test-only-secret', DOMAIN, validate_certificate=False)
    connections, lock = [], Lock()
    barrier = Barrier(2)

    class Worker:
        def __init__(self, **config):
            self.config, self.closed = config, False
            with lock:
                connections.append(self)

        def connect(self):
            pass

        def search(self, **kwargs):
            barrier.wait(timeout=5)
            if kwargs['search_filter'] == '(fail=1)':
                raise LDAPSearchError('Denied')
            return [{'result': 'ok'}]

        def disconnect(self):
            self.closed = True

    monkeypatch.setattr('core.ldap_connection.LDAPConnection', Worker)
    executor = ParallelLDAPExecutor(base, max_workers=2, rate_limit=0)
    assert len(executor.execute_parallel([{'id': 'one'}, {'id': 'two'}])) == 2
    progress = []
    with pytest.raises(LDAPSearchError, match='partial results discarded'):
        executor.execute_parallel([{'id': 'one'}, {'id': 'two', 'filter': '(fail=1)'}],
                                  lambda count, total: progress.append((count, total)))
    assert len(connections) == 4 and all(connection.closed for connection in connections)
    assert all(connection.config['validate_certificate'] is False for connection in connections)
    assert progress == [(1, 2), (2, 2)]


def test_parallel_collector_progress_uses_supported_callback():
    executor = Mock()

    def execute(_queries, callback):
        callback(1, 1)
        return {'one': []}

    executor.execute_parallel.side_effect = execute
    assert ParallelCollector(executor, show_progress=True).collect_parallel([{'id': 'one'}]) == {'one': []}


@pytest.mark.parametrize('alias', ['same', 'relative', 'symlink', 'hardlink'])
def test_output_aliases_cannot_overwrite_inputs(tmp_path, alias):
    source = tmp_path / 'evidence.json'
    source.write_text('{}', encoding='utf-8')
    target = source
    if alias == 'relative':
        target = tmp_path / '.' / 'evidence.json'
    elif alias == 'symlink':
        target = tmp_path / 'alias.json'
        target.symlink_to(source)
    elif alias == 'hardlink':
        target = tmp_path / 'alias.json'
        os.link(source, target)
    with pytest.raises(ValidationError, match='separate file paths'):
        validate_distinct_paths({'output': str(target)}, {'input': str(source)})
    assert source.read_text(encoding='utf-8') == '{}'


def test_duplicate_output_paths_and_history_database_are_rejected(tmp_path):
    args = AtilKurt.build_parser().parse_args(['-d', DOMAIN, '-u', 'auditor',
        '--output', str(tmp_path / 'history.db'), '--history-db', str(tmp_path / 'history.db')])
    with pytest.raises(SystemExit):
        AtilKurt.validate_output_paths(args)


@pytest.mark.parametrize('flag', ['--pass=synthetic', '--off=evidence.json', '--res=checkpoint'])
def test_watch_rejects_abbreviated_credentials_and_reused_evidence(flag):
    with pytest.raises(SystemExit):
        utility_main(['watch', '-d', DOMAIN, '-u', 'auditor', flag],
                     lambda _: pytest.fail('Credentials must not be requested'))


def test_utility_output_cannot_replace_input_or_signing_key(tmp_path):
    path = tmp_path / 'input.json'
    path.write_text('{}', encoding='utf-8')
    assert utility_main(['sign', '--input', str(path), '--output', str(path), '--signing-key', str(path)],
                        lambda _: pytest.fail('Credentials must not be requested')) == 1
    assert path.read_text(encoding='utf-8') == '{}'


def test_token_groups_cannot_be_verified_without_principal_sid():
    ldap = Mock()
    ldap.base_search.return_value = [{'tokenGroups': ['S-1-5-32-544']}]
    account = {'sAMAccountName': 'user1', 'distinguishedName': 'CN=user1,DC=example,DC=com'}
    result = collect_effective_tokens(ldap, {'users': [account]},
                                      [{'severity': 'critical', 'affected_object': 'user1'}], delay=0)
    assert result['collected'] == 0
    ldap.base_search.assert_not_called()


def test_nullable_legacy_risk_fields_do_not_abort_integration_exports(tmp_path):
    risk = {'type': 'legacy', 'severity': 'high', 'title': None, 'description': None}
    ExportFormats.export_siem_json([risk], str(tmp_path / 'events.jsonl'))
    ExportFormats.export_cef([risk], str(tmp_path / 'events.cef'))
    assert json.loads((tmp_path / 'events.jsonl').read_text(encoding='utf-8'))['description'] == ''
    assert (tmp_path / 'events.cef').read_text(encoding='utf-8').startswith('CEF:0|')


@pytest.mark.parametrize('basis', ['invalid', {}, {'evidence': {}}])
def test_malformed_review_basis_is_a_validation_error(basis):
    risk = {'type': 'example', 'affected_object': 'user1', 'review_basis': basis}
    with pytest.raises(ValidationError, match='review_basis'):
        FindingReviewManager().apply([risk], {}, DOMAIN)


def test_generated_report_name_is_checked_against_other_outputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(AtilKurt, '_report_output_path', lambda _: 'generated.html')
    args = AtilKurt.build_parser().parse_args(['-d', DOMAIN, '-u', 'auditor', '--json-export', 'generated.html'])
    with pytest.raises(SystemExit):
        AtilKurt.validate_output_paths(args)


def test_internal_checkpoint_symlink_cannot_delete_or_replace_original(tmp_path):
    persistence = ProgressPersistence(str(tmp_path / 'checkpoints'))
    original = persistence.save_checkpoint('original', {'domain': DOMAIN})
    (persistence.checkpoint_dir / 'alias.json').symlink_to(original)
    for operation in (lambda: persistence.delete_checkpoint('alias'),
                      lambda: persistence.save_checkpoint('alias', {'domain': 'different.example'}),
                      lambda: persistence.load_checkpoint('alias')):
        with pytest.raises(ValueError, match='symbolic link'):
            operation()
    assert persistence.load_checkpoint('original') == {'domain': DOMAIN}


def test_checkpoint_directory_symlink_is_rejected_without_changing_target_permissions(tmp_path):
    target = tmp_path / 'original'
    target.mkdir(mode=0o755)
    mode = target.stat().st_mode
    link = tmp_path / 'checkpoints'
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match='symbolic link'):
        ProgressPersistence(str(link))
    assert target.stat().st_mode == mode


@pytest.mark.parametrize('flag,value', [('--checkpoint', 'scan'), ('--resume', 'scan'), ('--checkpoint', '../invalid')])
def test_checkpoint_destinations_are_protected_before_logging_or_network(tmp_path, monkeypatch, flag, value):
    monkeypatch.chdir(tmp_path)
    args = AtilKurt.build_parser().parse_args(['-d', DOMAIN, '-u', 'auditor', flag, value,
                                             '--log-file', '.atilkurt_checkpoints/scan.json'])
    with pytest.raises(SystemExit):
        AtilKurt.validate_output_paths(args)
