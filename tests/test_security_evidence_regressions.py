"""Regression coverage for evidence replay and malformed external inputs."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from analysis.security_controls_analyzer import analyze_security_controls, refresh_security_findings
from analysis.tier_analyzer import TierAnalyzer
from core.control_evidence import observation_document
from core.exceptions import LDAPConnectionError, ValidationError
from core.finding_review import FindingReviewManager
from core.gpo_policy_content import attach_policy_content, read_policy_file
from core.ldap_connection import LDAPConnection

NOW = datetime.now(timezone.utc)
DOMAIN = 'example.com'
HOST = 'dc.example.com'


def evidence(name='wdigest', value=1, **extra):
    return {'schema_version': 1, 'domain': DOMAIN, 'observations': [
        {'name': name, 'value': value, 'target': HOST, 'source': 'Host collection',
         'collected_at': NOW.isoformat(), **extra},
    ]}


@pytest.mark.parametrize('name', [None, '', [], {}, 12])
def test_invalid_observation_names_fail_preflight(name):
    with pytest.raises(ValidationError):
        observation_document(evidence(name), DOMAIN, now=NOW)


def test_stale_reviewed_security_finding_retains_identity_and_needs_validation():
    result = analyze_security_controls([evidence()], DOMAIN, now=NOW)
    previous = result['risks']
    FindingReviewManager().apply(previous, {}, DOMAIN, now=NOW)
    future = NOW + timedelta(days=31)
    refreshed = analyze_security_controls([evidence()], DOMAIN, now=future)
    risks = refresh_security_findings(previous, refreshed)
    assert risks[0]['type'] == 'security_control_wdigest'
    assert risks[0]['affected_object'] == HOST
    FindingReviewManager().apply(risks, {}, DOMAIN, now=future)
    assert risks[0]['finding_status'] == 'needs_validation'
    assert risks[0]['evidence']['control_state'] == 'unknown'


def test_target_manifest_survives_security_evidence_replay():
    from core.engagement_workflow import apply_engagement, prepare_engagement_inputs
    args = SimpleNamespace(domain=DOMAIN, offline_snapshot='unused.json')
    prepare_engagement_inputs(args)
    payload = {'schema_version': 1, 'domain': DOMAIN, 'observations': [], 'targets': [
        {'target': HOST, 'controls': ['wdigest'], 'not_applicable': {'wdigest': 'Documented platform exclusion'}},
        {'target': 'tenant.example.com', 'controls': ['entra_privileged_mfa']},
    ]}
    args._engagement_documents['security_evidence'] = [payload]
    analysis = {}
    apply_engagement(args, {}, analysis)
    original = deepcopy(analysis['engagement']['security_controls']['checks'])
    args._engagement_documents['security_evidence'] = []
    analysis['engagement'] = {}
    apply_engagement(args, {}, analysis)
    assert analysis['engagement']['security_controls']['checks'] == original


def test_local_administrator_with_invalid_sid_is_not_a_tier_relationship():
    rows = observation_document(evidence('local_administrator', {'principal_sid': []}), DOMAIN, now=NOW)
    computer = {'name': 'dc', 'dNSHostName': HOST, 'userAccountControl': 8192}
    result = TierAnalyzer().analyze_tiers([], [computer], [], rows)
    assert result['tier_0']['computers'] == ['dc']


def test_tier_control_relations_resolve_inventory_host_aliases():
    computers = [
        {'name': 'dc', 'dNSHostName': HOST, 'userAccountControl': 8192},
        {'name': 'manager', 'dNSHostName': 'manager.example.com'},
    ]
    rows = observation_document(evidence('controls_identity_asset', {'controlled_target': 'dc'}, target='MANAGER'), DOMAIN, now=NOW)
    result = TierAnalyzer().analyze_tiers([], computers, [], rows)
    assert set(result['tier_0']['computers']) == {'dc', 'manager'}


@pytest.mark.parametrize('name,content', [
    ('GptTmpl.inf', b'[Registry Values]\ninvalid line\n'),
    ('GptTmpl.inf', b'[Registry Values]\nMACHINE\\SYSTEM\\Setting=4,not-an-integer\n'),
    ('GptTmpl.inf', b'\xffbroken encoding'),
])
def test_malformed_text_policy_files_raise_validation_errors(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)
    with pytest.raises(ValidationError):
        read_policy_file(path)


@pytest.mark.parametrize('context', [{'gpos': [None]}, {'gpos': 'invalid'}, {'gpos': [{'id': 'p', 'settings': []}]}])
def test_malformed_gpo_context_cannot_crash_content_attachment(tmp_path, context):
    path = tmp_path / 'GptTmpl.inf'
    path.write_text('[Registry Values]\nMACHINE\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity=4,2\n')
    with pytest.raises(ValidationError):
        attach_policy_content(context, [f'p={path}'])


def test_unbound_ldap_connection_is_closed():
    with patch('core.ldap_connection.Server'), patch('core.ldap_connection.Connection') as factory:
        factory.return_value.bound = False
        ldap = LDAPConnection(DOMAIN, 'auditor', 'placeholder', HOST)
        with pytest.raises(LDAPConnectionError):
            ldap.connect()
        factory.return_value.unbind.assert_called_once()
        assert ldap.connection is None


@pytest.mark.parametrize('include_security_observations', [False, True])
def test_offline_stale_posture_finding_is_not_silently_resolved(tmp_path, include_security_observations):
    from AtilKurt import build_parser, generate_offline_report, load_workflow_inputs, validate_cli_arguments
    from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer
    path = tmp_path / 'posture.json'
    payload = evidence('LDAPServerIntegrity', 0)
    path.write_text(json.dumps(payload))
    original = PostureEvidenceAnalyzer().analyze([str(path)], domain=DOMAIN, now=NOW)
    rows = deepcopy(payload['observations'])
    rows[0]['collected_at'] = (NOW - timedelta(days=31)).isoformat()
    for values in original['evidence'].values():
        for row in values:
            row['collected_at'] = rows[0]['collected_at']
    for row in original['observations']:
        row['collected_at'] = rows[0]['collected_at']
    snapshot = tmp_path / 'snapshot.json'
    snapshot.write_text(json.dumps({'domain': DOMAIN, 'users': [], 'groups': [], 'gpos': [],
        'computers': [{'name': 'dc', 'dNSHostName': HOST, 'userAccountControl': 8192}],
        'risks': original['risks'], 'posture_evidence_risks': original['risks'],
        'posture_evidence': original,
        'security_control_observations': rows if include_security_observations else []}))
    export = tmp_path / 'result.json'
    parser = build_parser()
    args = parser.parse_args(['-d', DOMAIN, '--offline-snapshot', str(snapshot),
        '--output', str(tmp_path / 'report.html'), '--json-export', str(export)])
    validate_cli_arguments(parser, args)
    reviews, removed = load_workflow_inputs(args)
    generate_offline_report(args, reviews, removed)
    saved = json.loads(export.read_text())
    findings = [risk for risk in saved['risks'] if risk['type'] == 'posture_ldap_signing_weak']
    assert len(findings) == 1
    assert findings[0]['finding_status'] == 'needs_validation'


def test_live_gpo_targets_cannot_silently_override_imported_context(tmp_path):
    from AtilKurt import build_parser, validate_cli_arguments
    path = tmp_path / 'gpo.json'
    path.write_text('{}')
    parser = build_parser()
    args = parser.parse_args(['-d', DOMAIN, '-u', 'auditor', '--gpo-context', str(path),
                             '--gpo-target', 'CN=dc,DC=example,DC=com'])
    with pytest.raises(SystemExit):
        validate_cli_arguments(parser, args)


def test_replaced_endpoint_evidence_does_not_reappear_from_saved_federation():
    from core.engagement_workflow import apply_engagement, prepare_engagement_inputs
    args = SimpleNamespace(domain=DOMAIN, offline_snapshot='unused.json')
    prepare_engagement_inputs(args)
    graph = {'nodes': [{'id': 'u'}, {'id': 'c'}], 'edges': [{
        'source': 'u', 'target': 'c', 'type': 'AdminTo',
        'snapshot_provenance': {'source': 'validated_endpoint_evidence', 'fresh': True},
    }]}
    args._saved_federated_graph = graph
    args._engagement_documents['security_evidence'] = [evidence()]
    analysis = {'attack_graph_v2': {'nodes': graph['nodes'], 'edges': []}}
    apply_engagement(args, {}, analysis)
    assert analysis['federated_graph']['edges'] == []


@pytest.mark.parametrize('value', [
    {'last_success': 'invalid', 'max_age_days': 7, 'system_state': True},
    {'last_success': NOW.isoformat(), 'max_age_days': 7},
])
def test_incomplete_backup_evidence_remains_unknown(value):
    result = analyze_security_controls([evidence('recovery_backup', value)], DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == 'unknown'
    assert result['risks'] == []


def test_audit_display_names_do_not_replace_required_guids():
    value = {'required_subcategories': ['Directory Service Changes'],
             'subcategories': {'Directory Service Changes': 3}}
    result = analyze_security_controls([evidence('advanced_audit_policy', value)], DOMAIN, now=NOW)
    assert result['checks'][0]['status'] == 'unknown'


def test_new_posture_evidence_can_resolve_previous_weakness():
    from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer, refresh_posture_findings
    old = PostureEvidenceAnalyzer().analyze([], observations=evidence('LDAPServerIntegrity', 0)['observations'], domain=DOMAIN, now=NOW)
    new = PostureEvidenceAnalyzer().analyze([], observations=evidence('LDAPServerIntegrity', 2)['observations'], domain=DOMAIN, now=NOW)
    assert not any(r['type'] == 'posture_ldap_signing_weak' for r in refresh_posture_findings(old['risks'], new))


def test_server2025_os_provenance_survives_posture_report_round_trip(tmp_path):
    from AtilKurt import build_parser, generate_offline_report, load_workflow_inputs, validate_cli_arguments
    snapshot = tmp_path / 'snapshot.json'
    snapshot.write_text(json.dumps({'domain': DOMAIN, 'users': [], 'groups': [], 'gpos': [], 'risks': [],
        'computers': [{'name': 'dc', 'dNSHostName': HOST, 'userAccountControl': 8192}]}))
    payload = evidence('LDAPServerIntegrity', 0)
    payload['observations'] += evidence('LDAPServerEnforceIntegrity', 1)['observations']
    payload['observations'] += evidence('operating_system', {'caption': 'Windows Server 2025', 'build': '26100'})['observations']
    posture = tmp_path / 'posture.json'
    posture.write_text(json.dumps(payload))
    for index in range(2):
        export = tmp_path / f'result-{index}.json'
        parser = build_parser()
        options = ['-d', DOMAIN, '--offline-snapshot', str(snapshot),
                   '--output', str(tmp_path / f'report-{index}.html'), '--json-export', str(export)]
        if index == 0:
            options += ['--posture-file', str(posture)]
        args = parser.parse_args(options)
        validate_cli_arguments(parser, args)
        reviews, removed = load_workflow_inputs(args)
        generate_offline_report(args, reviews, removed)
        saved = json.loads(export.read_text())
        assert not any(r['type'] == 'posture_ldap_signing_weak' for r in saved['risks'])
        snapshot = export


@pytest.mark.skipif(shutil.which('pwsh') is None, reason='PowerShell is not installed')
def test_generated_collector_runs_with_simulated_windows_read_commands(tmp_path):
    from core.validation_collector import build_validation_script
    collector = tmp_path / 'collector.ps1'
    collector.write_text(build_validation_script({'domain': DOMAIN, 'rule_version': 'test', 'findings': []}))
    output = tmp_path / 'evidence.json'
    harness = tmp_path / 'harness.ps1'
    harness.write_text(r"""
param([string]$Collector, [string]$Output)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($Collector, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) { throw 'Generated collector has syntax errors' }
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace)
    switch ($ClassName) {
        'Win32_ComputerSystem' { [pscustomobject]@{Domain='example.com'; DNSHostName='dc'} }
        'Win32_OperatingSystem' { [pscustomobject]@{LastBootUpTime=[DateTime]::Now.AddHours(-1); Caption='Windows Server 2025'; Version='10.0'; BuildNumber='26100'} }
        'Win32_DeviceGuard' { [pscustomobject]@{SecurityServicesRunning=@(1); SecurityServicesConfigured=@(1)} }
        'Win32_LogonSession' { @() }
    }
}
function Get-ItemPropertyValue {
    param([string]$LiteralPath, [string]$Name)
    if ($LiteralPath -like '*CertSvc*') { throw 'CA not installed' }
    if ($Name -eq 'UseLogonCredential') { return 0 }
    return 2
}
function Get-WinEvent { [pscustomobject]@{Id=12} }
function Get-LocalGroup { [pscustomobject]@{Name='Administrators'} }
function Get-LocalGroupMember { [pscustomobject]@{SID='S-1-5-21-1-2-3-1100'} }
function Get-Service { param([string]$Name) [pscustomobject]@{Name=$Name; Status='Stopped'} }
function Get-HotFix { @() }
function Import-Module { throw 'IIS not installed' }
function auditpol.exe {
    $global:LASTEXITCODE = 0
    'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
    foreach ($id in @('923b','923c','9237','9240','9242')) {
        'dc,System,Localized name,{0cce' + $id + '-69ae-11d9-bed3-505054503030},Localized flags,,3'
    }
}
function gpresult.exe { $global:LASTEXITCODE = 1 }
& $Collector -OutputPath $Output
""")
    result = subprocess.run([shutil.which('pwsh'), '-NoProfile', '-NonInteractive', '-File', str(harness),
                             str(collector), str(output)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    document = json.loads(output.read_text(encoding='utf-8-sig'))
    assert document['collection_errors']
    assert all(row['target'] == HOST and row['domain'] == DOMAIN for row in document['observations'])
    checked = analyze_security_controls([document], DOMAIN)
    states = {row['control']: row['status'] for row in checked['checks']}
    assert states['credential_guard'] == states['lsa_protection'] == states['wdigest'] == 'secure'
    assert states['advanced_audit_policy'] == 'secure'
