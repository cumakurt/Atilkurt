"""Behavioral coverage for provenance, protection, recovery and transport controls."""

from datetime import datetime, timedelta, timezone
import json
import struct
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from AtilKurt import build_parser, validate_cli_arguments
from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer
from analysis.security_controls_analyzer import analyze_security_controls, reconcile_hybrid_findings
from analysis.tier_analyzer import TierAnalyzer
from core.control_evidence import observation_document
from core.endpoint_graph import attach_endpoint_graph
from core.evidence_signing import generate_keys, sign_document
from core.exceptions import LDAPConnectionError, ValidationError
from core.gpo_policy_content import attach_policy_content, parse_registry_pol, read_policy_file
from core.ldap_connection import LDAPConnection

NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
DOMAIN = 'example.com'
HOST = 'dc.example.com'
SID = 'S-1-5-21-1-2-3-1100'


def test_required_phs_permissions_do_not_hide_observed_excess_rights():
    payload = document('hybrid_replication_permissions', {
        'account': 'MSOL_account', 'password_hash_sync': True,
        'required_replication_only': True, 'excessive_permissions': True,
    })
    result = analyze_security_controls([payload], DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == 'insecure'
    risk = {'type': 'hybrid_entra_connect_excessive_rights', 'affected_object': 'MSOL_account'}
    reconcile_hybrid_findings([risk], result['observations'])
    assert risk['type'] == 'hybrid_entra_connect_excessive_rights'


def document(name, value, **changes):
    row = {'name': name, 'value': value, 'target': HOST, 'source': 'registry/runtime export',
           'collected_at': NOW.isoformat(), **changes}
    return {'schema_version': 1, 'domain': DOMAIN, 'observations': [row]}


@pytest.mark.parametrize('changes', [
    {'collected_at': (NOW - timedelta(days=31)).isoformat()},
    {'collected_at': (NOW + timedelta(minutes=6)).isoformat()},
    {'collected_at': '2026-10-12'}, {'target': ''}, {'source': ''},
    {'domain': 'other.example'}, {'status': 'failed'},
])
def test_unusable_provenance_never_verifies_a_control(changes):
    rows = observation_document(document('wdigest', 0, **changes), DOMAIN, now=NOW)
    assert rows[0]['status'] == 'unknown'
    result = analyze_security_controls([document('wdigest', 0, **changes)], DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == 'unknown'
    assert result['risks'] == []


def test_cross_domain_document_rejected():
    payload = document('wdigest', 0)
    payload['domain'] = 'other.example'
    with pytest.raises(ValidationError, match='different domain'):
        analyze_security_controls([payload], DOMAIN)


@pytest.mark.parametrize('policy,value,state', [
    ('LDAPServerIntegrity', 99, 'unknown'), ('RequireSecuritySignature', 99, 'unknown'),
    ('RestrictReceivingNTLMTraffic', 1, 'secure'), ('RestrictSendingNTLMTraffic', 1, 'insecure'),
    ('RestrictNTLMInDomain', 2, 'insecure'), ('RestrictNTLMInDomain', 7, 'secure'),
    ('LdapEnforceChannelBinding', 1, 'insecure'), ('LdapEnforceChannelBinding', 2, 'secure'),
])
def test_policy_specific_values(policy, value, state, tmp_path):
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps(document(policy, value)))
    result = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == state
    if state == 'unknown':
        assert result['summary']['covered_controls'] == []


def test_legacy_flat_export_is_not_verification(tmp_path):
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps({'LDAPServerIntegrity': 2, 'domain': DOMAIN,
                                'target': 'other.example', 'collected_at': '2000-01-01T00:00:00Z'}))
    result = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, now=NOW)
    assert result['summary']['covered_controls'] == []


def test_opposite_sources_are_conflicting_and_unscored(tmp_path):
    payload = document('LDAPServerIntegrity', 2)
    payload['observations'].append({**payload['observations'][0], 'value': 0, 'source': 'second source'})
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps(payload))
    result = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == 'conflicting'
    assert not any(r['type'] == 'posture_ldap_signing_weak' for r in result['risks'])


def test_unsigned_posture_rejected_under_signature_policy(tmp_path):
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps(document('LDAPServerIntegrity', 2)))
    with pytest.raises(ValidationError, match='Unsigned'):
        PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, require_signed=True)


def test_signed_posture_keeps_target_and_time(tmp_path):
    private, public = str(tmp_path / 'private.pem'), str(tmp_path / 'public.pem')
    generate_keys(private, public)
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps(sign_document(document('LDAPServerIntegrity', 2), private)))
    result = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, require_signed=True, trusted_keys=[public], now=NOW)
    row = result['evidence']['ldap_signing'][0]
    assert row['target'] == HOST and row['collected_at'] == NOW.isoformat()
    assert row['signature_status'] == 'verified'


def test_domain_admins_and_renamed_nested_groups_are_tier0():
    dn = 'CN=Renamed,CN=Users,DC=example,DC=com'
    groups = [{'name': 'Renamed', 'objectSid': 'S-1-5-21-1-2-3-512', 'distinguishedName': dn,
               'member': ['CN=Nested,DC=example,DC=com']},
              {'name': 'Nested', 'objectSid': 'S-1-5-21-1-2-3-1200', 'distinguishedName': 'CN=Nested,DC=example,DC=com',
               'member': ['CN=user,DC=example,DC=com']}]
    users = [{'sAMAccountName': 'user', 'distinguishedName': 'CN=user,DC=example,DC=com', 'objectSid': SID},
             {'sAMAccountName': 'direct', 'memberOf': ['CN=Domain Admins,DC=example,DC=com']}]
    result = TierAnalyzer().analyze_tiers(users, [], groups)
    assert set(result['tier_0']['users']) == {'direct', 'user'}


def test_management_server_promoted_only_with_explicit_control_evidence():
    computers = [{'name': 'dc', 'dNSHostName': HOST, 'userAccountControl': 8192},
                 {'name': 'backup', 'dNSHostName': 'backup.example.com', 'operatingSystem': 'Windows Server'}]
    row = {'name': 'controls_identity_asset', 'target': 'backup.example.com', 'status': 'available',
           'value': {'controlled_target': HOST}}
    assert 'backup' in TierAnalyzer().analyze_tiers([], computers, [], [row])['tier_0']['computers']
    row['status'] = 'unknown'
    assert 'backup' not in TierAnalyzer().analyze_tiers([], computers, [], [row])['tier_0']['computers']


@pytest.mark.parametrize('name,value,state', [
    ('credential_guard', {'configured': True}, 'unknown'),
    ('credential_guard', {'running': False}, 'insecure'),
    ('lsa_protection', {'running': True}, 'secure'),
    ('wdigest', 1, 'insecure'), ('wdigest', '0', 'unknown'),
    ('entra_privileged_mfa', {'complete': True, 'total': 10, 'covered': 10, 'basis': 'registration'}, 'unknown'),
    ('entra_privileged_mfa', {'complete': True, 'total': 10, 'covered': 9, 'basis': 'effective_enforcement'}, 'insecure'),
    ('recovery_backup', {'last_success': (NOW-timedelta(days=8)).isoformat(), 'max_age_days': 7, 'system_state': True}, 'insecure'),
    ('recovery_restore_test', {'successful': True, 'isolated': True, 'tested_at': NOW.isoformat()}, 'secure'),
    ('recovery_restore_test', {'successful': True, 'isolated': False, 'tested_at': NOW.isoformat()}, 'unknown'),
    ('recovery_dsrm_access', {'vaulted': True, 'access_reviewed': False}, 'insecure'),
    ('adcs_ca_permissions', {'complete': True, 'dacl_present': True, 'approved_trustees': ['S-1-5-18'], 'grants': [{'sid': SID, 'mask': 1}]}, 'insecure'),
    ('adcs_ca_permissions', {'complete': True, 'dacl_present': True, 'approved_trustees': ['S-1-5-18'], 'grants': [{'sid': SID, 'mask': 1, 'denied': True}]}, 'unknown'),
])
def test_control_semantics(name, value, state):
    result = analyze_security_controls([document(name, value)], DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == state
    assert bool(result['risks']) == (state == 'insecure')


def test_missing_dc_controls_remain_visible():
    result = analyze_security_controls([], DOMAIN, expected_targets=[HOST], now=NOW)
    assert result['summary']['unknown'] == 9
    assert result['risks'] == []


def test_explicit_not_applicable_cannot_hide_observed_weakness():
    payload = document('wdigest', 1)
    payload['targets'] = [{'target': HOST, 'controls': ['wdigest'], 'not_applicable': {'wdigest': 'Owner exclusion'}}]
    assert analyze_security_controls([payload], DOMAIN, now=NOW)['checks'][0]['status'] == 'conflicting'


def test_required_phs_rights_are_not_reported_as_excess():
    risk = {'type': 'hybrid_entra_connect_excessive_rights', 'affected_object': 'MSOL_account'}
    payload = document('hybrid_replication_permissions', {'account': 'MSOL_account', 'password_hash_sync': True, 'required_replication_only': True})
    observations = observation_document(payload, DOMAIN, now=NOW)
    reconcile_hybrid_findings([risk], observations)
    assert risk['type'] == 'hybrid_entra_connect_required_replication'
    assert risk['requires_validation'] is True


def pol(value):
    def encode(text):
        return (text + '\0').encode('utf-16-le')
    return b'PReg\x01\0\0\0' + b'[\0' + encode('SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters') + b';\0' + encode('LDAPServerIntegrity') + b';\0' + struct.pack('<I', 4) + b';\0' + struct.pack('<I', 4) + b';\0' + struct.pack('<I', value) + b']\0'


def test_registry_pol_content_and_digest_binding(tmp_path):
    path = tmp_path / 'Registry.pol'
    path.write_bytes(pol(2))
    content = read_policy_file(path)
    assert content['settings'] == {'LDAPServerIntegrity': 2}
    context = {'gpos': [{'id': 'policy', 'settings': {}}]}
    with pytest.raises(ValidationError, match='digest'):
        attach_policy_content(context, [f'policy={path}'], require_signed=True)
    context['gpos'][0]['policy_sha256'] = [content['sha256']]
    assert attach_policy_content(context, [f'policy={path}'], require_signed=True)['gpos'][0]['settings'] == content['settings']


@pytest.mark.parametrize('raw', [b'', b'PReg\x02\0\0\0', pol(2)[:-2], pol(2) + b'bad'])
def test_malformed_policy_binary_rejected(raw):
    with pytest.raises(ValidationError):
        parse_registry_pol(raw)


def test_session_evidence_is_conditional_and_unresolved_identity_is_excluded():
    graph = {'nodes': [{'id': 'u', 'label': 'user', 'sid': SID}, {'id': 'c', 'label': HOST}], 'edges': []}
    rows = observation_document(document('privileged_session', {'principal_sid': SID}), DOMAIN, now=NOW)
    result = attach_endpoint_graph(graph, {}, rows)
    assert result['edges'][0]['source'] == 'c'
    assert result['edges'][0]['properties']['status'] == 'conditional'
    rows[0]['value']['principal_sid'] = 'unknown'
    assert attach_endpoint_graph(graph, {}, rows)['edges'] == []


def test_insecure_ldap_default_and_explicit_tls_cli():
    parser = build_parser()
    assert parser.parse_args(['-d', DOMAIN, '-u', 'auditor']).ssl is False
    assert parser.parse_args(['-d', DOMAIN, '-u', 'auditor', '--ssl']).ssl is True
    starttls = parser.parse_args(['-d', DOMAIN, '-u', 'auditor', '--starttls'])
    validate_cli_arguments(parser, starttls)
    assert starttls.starttls is True and starttls.ssl is False
    assert parser.parse_args(['-d', DOMAIN, '-u', 'auditor', '--insecure-ldap']).ssl is False
    args = parser.parse_args(['-d', DOMAIN, '-u', 'auditor', '--insecure-ldap', '--auth-method', 'simple'])
    with pytest.raises(SystemExit):
        validate_cli_arguments(parser, args)


def test_starttls_failure_never_binds():
    with patch('core.ldap_connection.Server'), patch('core.ldap_connection.Connection') as connection:
        connection.return_value.start_tls.return_value = False
        ldap = LDAPConnection(DOMAIN, 'auditor', 'placeholder', HOST, use_ssl=False, start_tls=True)
        with pytest.raises(LDAPConnectionError):
            ldap.connect()
        connection.return_value.bind.assert_not_called()


def test_kerberos_does_not_use_password_or_fallback():
    with patch('core.ldap_connection.Server'), patch('core.ldap_connection.Connection') as connection:
        connection.return_value.bound = True
        ldap = LDAPConnection(DOMAIN, 'auditor@example.com', '', HOST, auth_method='kerberos')
        assert ldap.connect()
        assert connection.call_args.kwargs['sasl_mechanism'] == 'GSSAPI'
        assert connection.call_args.kwargs['password'] is None


def test_security_evidence_integrates_with_existing_offline_workflow(tmp_path):
    from core.engagement_workflow import prepare_engagement_inputs, apply_engagement
    path = tmp_path / 'security.json'
    payload = document('wdigest', 1, collected_at=datetime.now(timezone.utc).isoformat())
    path.write_text(json.dumps(payload))
    args = SimpleNamespace(domain=DOMAIN, security_evidence=[str(path)], offline_snapshot='snapshot.json')
    prepare_engagement_inputs(args)
    analysis = {}
    apply_engagement(args, {'users': [], 'computers': [], 'groups': []}, analysis)
    assert analysis['security_control_risks'][0]['type'] == 'security_control_wdigest'
    assert analysis['engagement']['security_controls']['checks'][0]['status'] == 'insecure'


def test_server2025_signing_precedence_requires_os_evidence(tmp_path):
    payload = document('LDAPServerIntegrity', 0)
    payload['observations'].append({**payload['observations'][0], 'name': 'LDAPServerEnforceIntegrity', 'value': 1})
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps(payload))
    result = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, now=NOW)
    assert any(r['type'] == 'posture_ldap_signing_weak' for r in result['risks'])
    payload['observations'].append({**payload['observations'][0], 'name': 'operating_system',
                                    'value': {'caption': 'Windows Server 2025', 'build': '26100'}})
    path.write_text(json.dumps(payload))
    result = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, now=NOW)
    assert not any(r['type'] == 'posture_ldap_signing_weak' for r in result['risks'])


def test_posture_matrix_keeps_unmeasured_dc_controls():
    result = PostureEvidenceAnalyzer().analyze([], domain=DOMAIN, now=NOW, expected_targets=[HOST])
    assert len(result['checks']) == 6
    assert all(row['status'] == 'unknown' for row in result['checks'])


def test_telemetry_retirement_inventory_is_target_bound_and_fresh(tmp_path):
    from analysis.event_correlation_analyzer import EventCorrelationAnalyzer
    event = {'EventID': 4776, 'Computer': HOST, 'timestamp': NOW.isoformat(),
             'Provider': 'Microsoft-Windows-Security-Auditing',
             'EventData': {'Status': '0x0', 'Workstation': 'client.example.com', 'TargetUserName': 'service'}}
    path = tmp_path / 'events.json'
    path.write_text(json.dumps([event]))
    result = EventCorrelationAnalyzer().analyze([str(path)], domain=DOMAIN, expected_targets=[HOST], now=NOW)
    dependency = result['summary']['transition_readiness']['dependencies'][0]
    assert dependency['protocol'] == 'NTLM' and dependency['count'] == 1
    result = EventCorrelationAnalyzer().analyze([str(path)], domain=DOMAIN, expected_targets=['other.example.com'], now=NOW)
    assert result['summary']['transition_readiness']['dependencies'] == []


def test_offline_cli_exports_security_controls_and_rendered_coverage(tmp_path):
    from AtilKurt import generate_offline_report, load_workflow_inputs
    snapshot = tmp_path / 'snapshot.json'
    snapshot.write_text(json.dumps({'domain': DOMAIN, 'users': [], 'groups': [], 'gpos': [], 'risks': [],
                                    'computers': [{'name': 'dc', 'dNSHostName': HOST, 'userAccountControl': 8192}]}))
    evidence = tmp_path / 'controls.json'
    evidence.write_text(json.dumps(document('wdigest', 1, collected_at=datetime.now(timezone.utc).isoformat())))
    report, export = tmp_path / 'report.html', tmp_path / 'result.json'
    parser = build_parser()
    args = parser.parse_args(['-d', DOMAIN, '--offline-snapshot', str(snapshot), '--security-evidence', str(evidence),
                              '--output', str(report), '--json-export', str(export)])
    validate_cli_arguments(parser, args)
    reviews, removed = load_workflow_inputs(args)
    generate_offline_report(args, reviews, removed)
    saved = json.loads(export.read_text())
    assert any(r['type'] == 'security_control_wdigest' for r in saved['risks'])
    assert saved['scan_coverage']['summary']['target_control_states']['insecure'] >= 1
    assert 'wdigest' in report.read_text() and HOST in report.read_text()
