"""Regression cases for evidence boundaries and AD access semantics."""

import json
import struct
from uuid import UUID

import pytest

from analysis.acl_security_analyzer import ACLSecurityAnalyzer
from analysis.certificate_analyzer import CertificateAnalyzer
from analysis.confidence_scorer import ConfidenceScorer
from analysis.dcsync_analyzer import DCSyncAnalyzer
from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer
from analysis.event_correlation_analyzer import EventCorrelationAnalyzer
from analysis.identity_protection_analyzer import IdentityProtectionAnalyzer
from analysis.laps_v2_analyzer import WindowsLAPSV2Analyzer
from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
from analysis.password_spray_risk_analyzer import PasswordSprayRiskAnalyzer
from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer
from analysis.vulnerability_scanner import VulnerabilityScanner
from core.ad_security import dacl_fingerprint, dangerous_broad_aces, guid_text
from core.security_descriptor_parser import directory_right_granted, effective_allow_aces, parse_security_descriptor
from scoring.risk_scorer import RiskScorer
from analysis.baseline_comparator import BaselineComparator
from analysis.gmsa_reader_graph_analyzer import GMSAReaderGraphAnalyzer
from analysis.trust_analyzer import TrustAnalyzer
from analysis.trust_security_v2_analyzer import TrustSecurityV2Analyzer
from core.ad_identity import group_is_role, is_privileged_group_record
from core.ad_security import principal_group_tokens
from reporting.compliance_reporter import ComplianceReporter
from reporting.localization import localize_html_document, localize_report_structure
from reporting.report_sections.domain_admin_section import DomainAdminSectionMixin
from risk.risk_manager import RiskManager


SID = 'S-1-5-21-100-200-300-1100'
CHANGES = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
RESET = '00299570-246d-11d0-a768-00aa006e0529'


def ace(mask, sid=SID, guid=None, denied=False, flags=0):
    parts = [int(part) for part in sid.split('-')[1:]]
    binary_sid = bytes([parts[0], len(parts) - 2]) + parts[1].to_bytes(6, 'big')
    binary_sid += b''.join(part.to_bytes(4, 'little') for part in parts[2:])
    kind = (6 if denied else 5) if guid else (1 if denied else 0)
    payload = struct.pack('<I', mask)
    if guid:
        payload += struct.pack('<I', 1) + UUID(guid).bytes_le
    payload += binary_sid
    return struct.pack('<BBH', kind, flags, len(payload) + 4) + payload


def descriptor(*entries):
    body = b''.join(entries)
    acl = struct.pack('<BBHHH', 4, 0, 8 + len(body), len(entries), 0) + body
    return struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 20) + acl


class LDAP:
    base_dn = 'DC=example,DC=com'

    def __init__(self, rows=None):
        self.rows = rows or []

    def search(self, **kwargs):
        return self.rows


def dcsync(*entries, groups=None):
    return DCSyncAnalyzer(LDAP([{'nTSecurityDescriptor': descriptor(*entries)}])).analyze_dcsync_rights(
        [{'sAMAccountName': 'delegate', 'objectSid': SID, 'userAccountControl': 512}], groups or [],
    )


def test_scoped_extended_right_is_not_all_extended_rights():
    parsed = parse_security_descriptor(descriptor(ace(0x100, guid=RESET)))
    assert set(parsed['dacl'][0]['permissions']) == {'UserForceChangePassword'}
    assert dcsync(ace(0x100, guid=RESET)) == []
    unknown = '11111111-2222-3333-4444-555555555555'
    parsed = parse_security_descriptor(descriptor(ace(0x100, sid='S-1-1-0', guid=unknown)))
    assert 'AllExtendedRights' not in parsed['dacl'][0]['permissions']
    assert dangerous_broad_aces(parsed) == []


def test_property_write_requires_the_correct_guid_and_access_bit():
    member = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    parser = parse_security_descriptor(descriptor(ace(0x20, guid=member)))
    assert set(parser['dacl'][0]['permissions']) == {'WriteMember'}
    parser = parse_security_descriptor(descriptor(ace(0x100, guid=member)))
    assert 'WriteMember' not in parser['dacl'][0]['permissions']


@pytest.mark.parametrize('mask', [0x40000000, 0x20028, 0x10000000, 0xF01FF])
def test_scoped_generic_masks_do_not_claim_unrestricted_property_access(mask):
    member = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    parsed = parse_security_descriptor(descriptor(ace(mask, guid=member)))
    permissions = effective_allow_aces(parsed)[0]['permissions']
    assert 'GenericWrite' not in permissions
    assert 'GenericAll' not in permissions
    assert 'WriteProperty' not in permissions
    assert 'WriteMember' in permissions
    # Standard object rights remain valid even when directory rights are scoped.
    if mask in (0x10000000, 0xF01FF):
        assert 'WriteDACL' in permissions
    unrestricted = parse_security_descriptor(descriptor(ace(mask)))
    assert 'GenericWrite' in effective_allow_aces(unrestricted)[0]['permissions']


def test_dcsync_needs_both_rights_for_the_same_principal():
    assert dcsync(ace(0x100, guid=CHANGES)) == []
    assert dcsync(ace(0x100, guid=CHANGES_ALL)) == []
    assert dcsync(ace(0x100, guid=CHANGES), ace(0x100, sid=SID + '1', guid=CHANGES_ALL)) == []
    risks = dcsync(ace(0x100, guid=CHANGES), ace(0x100, guid=CHANGES_ALL))
    assert len(risks) == 1
    assert len(risks[0]['dcsync_rights']) == 2


@pytest.mark.parametrize('mask', [0x100, 0x10000000, 0xF01FF])
def test_full_replication_grants_remain_detected(mask):
    assert len(dcsync(ace(mask))) == 1


def test_deny_order_and_inherit_only_are_respected():
    assert dcsync(ace(0x100, guid=CHANGES_ALL, denied=True), ace(0x100)) == []
    assert dcsync(ace(0x100, flags=0x08)) == []
    assert len(dcsync(ace(0x100), ace(0x100, denied=True))) == 1
    # An unrelated deny must not terminate parsing of the remaining ACL.
    assert len(dcsync(ace(0x100, sid=SID + '1', denied=True), ace(0x100))) == 1


def test_audit_ace_does_not_hide_subsequent_grants():
    audit = bytearray(ace(0x100))
    audit[0] = 2
    assert len(dcsync(bytes(audit), ace(0x100))) == 1
    assert dcsync(bytes(audit)) == []


def test_expected_admin_permissions_do_not_create_acl_alerts():
    admin_sid = 'S-1-5-21-100-200-300-512'
    groups = [{'name': 'Domain Admins', 'objectSid': admin_sid}]
    assert dcsync(ace(0x100, sid=admin_sid), groups=groups) == []
    ldap = LDAP([{'nTSecurityDescriptor': descriptor(ace(0xF01FF, sid='S-1-5-18')),
                  'objectClass': ['domainDNS']}])
    assert ACLSecurityAnalyzer(ldap).analyze([], [], [], ldap.base_dn)['acl_risks'] == []


def test_inherited_or_denied_grants_do_not_create_broad_control_findings():
    for entries in ((ace(0x40000000, sid='S-1-1-0', flags=0x08),),
                    (ace(0x40000000, sid='S-1-1-0', denied=True), ace(0x40000000, sid='S-1-1-0'))):
        assert dangerous_broad_aces(parse_security_descriptor(descriptor(*entries))) == []
    assert dangerous_broad_aces(parse_security_descriptor(descriptor(ace(0x40000000, sid='S-1-1-0'))))


def test_truncated_descriptor_does_not_return_partial_grants():
    raw = descriptor(ace(0x100), ace(0x100, denied=True))[:-1]
    parsed = parse_security_descriptor(raw)
    assert parsed['parse_valid'] is False
    assert effective_allow_aces(parsed) == []
    assert not directory_right_granted(parsed, SID, 0x100)


def test_dacl_fingerprint_preserves_guid_identity():
    assert guid_text(UUID(CHANGES).bytes_le) == CHANGES
    first = parse_security_descriptor(descriptor(ace(0x100, guid=CHANGES)))
    second = parse_security_descriptor(descriptor(ace(0x100, guid=CHANGES_ALL)))
    assert dacl_fingerprint(first) != dacl_fingerprint(second)


@pytest.mark.parametrize('value', [None, [], 'unavailable', {}])
def test_unknown_lockout_is_not_disabled(value):
    risks = PasswordSprayRiskAnalyzer(LDAP([{'lockoutThreshold': value}]))._analyze_lockout_policy(LDAP.base_dn)
    assert not any(risk['type'] == 'password_spray_no_lockout' for risk in risks)


def test_explicit_disabled_lockout_is_still_reported():
    risks = PasswordSprayRiskAnalyzer(LDAP([{'lockoutThreshold': 0}]))._analyze_lockout_policy(LDAP.base_dn)
    assert any(risk['type'] == 'password_spray_no_lockout' for risk in risks)


def test_missing_or_list_password_policy_values_do_not_become_zero():
    assert PasswordPolicyAnalyzer(LDAP([{'distinguishedName': LDAP.base_dn}])).analyze_password_policy() == []
    row = {'minPwdLength': [16], 'pwdHistoryLength': [24], 'pwdProperties': [1],
           'lockoutThreshold': [5], 'maxPwdAge': ['not-readable']}
    assert PasswordPolicyAnalyzer(LDAP([row])).analyze_password_policy() == []


def test_unknown_account_control_does_not_prove_smartcard_absence():
    assert IdentityProtectionAnalyzer().analyze([{'sAMAccountName': 'admin', 'adminCount': 1}]) == []


def test_unknown_posture_values_remain_coverage_gaps(tmp_path):
    path = tmp_path / 'posture.json'
    path.write_text(json.dumps({'LDAPServerIntegrity': 'not collected', 'RequireSecuritySignature': None}))
    result = PostureEvidenceAnalyzer().analyze([str(path)])
    assert {risk['type'] for risk in result['risks']} == {'posture_evidence_incomplete'}
    assert 'ldap_signing' in result['summary']['missing_controls']
    from datetime import datetime, timezone
    path.write_text(json.dumps({'schema_version': 1, 'domain': 'example.com', 'observations': [
        {'target': 'dc.example.com', 'name': 'LDAPServerIntegrity', 'value': 0, 'source': 'registry export',
         'collected_at': datetime.now(timezone.utc).isoformat()}]}))
    assert any(risk['type'] == 'posture_ldap_signing_weak'
               for risk in PostureEvidenceAnalyzer().analyze([str(path)])['risks'])


def test_laps_read_failure_is_not_an_encryption_or_backup_gap():
    class RestrictedLDAP(LDAP):
        def search(self, **kwargs):
            if 'msLAPS-PasswordExpirationTime' in kwargs['search_filter']:
                return [{'distinguishedName': 'CN=DC1,' + self.base_dn}]
            raise PermissionError('Insufficient access')

    risks = WindowsLAPSV2Analyzer(RestrictedLDAP()).analyze([
        {'distinguishedName': 'CN=DC1,' + LDAP.base_dn, 'userAccountControl': 8192},
    ])
    assert risks == []


@pytest.mark.parametrize('extra', [{'msPKI-Enrollment-Flag': 2}, {'msPKI-RA-Signature': 1},
                                  {'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.20']}])
def test_certificate_prerequisites_and_exact_eku_matching(extra):
    template = {'msPKI-Certificate-Name-Flag': 1, 'msPKI-Enrollment-Flag': 0,
                'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2'], **extra}
    assert CertificateAnalyzer(LDAP())._analyze_template_vulnerabilities(template, 'Template') == []


def event(event_id, **fields):
    return {'EventID': event_id, 'timestamp': '2026-10-08T09:00:00Z', 'EventData': fields}


@pytest.mark.parametrize('status', ['0x20', 'invalid', None])
def test_failed_or_unverified_tickets_are_not_successful_issuance(tmp_path, status):
    path = tmp_path / 'events.json'
    path.write_text(json.dumps([event(4769, Status=status, TicketEncryptionType='0x17'),
                                event(4768, Status=status, PreAuthType='0')]))
    assert EventCorrelationAnalyzer().analyze([str(path)])['risks'] == []


def test_missing_timestamps_and_wrong_providers_do_not_create_attacks(tmp_path):
    events = [event(4769, Status=0, TargetUserName='user', ServiceName=f'svc{i}') for i in range(20)]
    for row in events:
        row.pop('timestamp')
    events += [{'EventID': 41, 'Provider': 'Microsoft-Windows-Kernel-Power'},
               event(4768, Status=0, PreAuthType='-'), event(4662, Description=CHANGES, AccessMask='0x100'),
               event(4662, Properties=CHANGES, AccessMask='0x10')]
    path = tmp_path / 'events.json'
    path.write_text(json.dumps(events))
    assert EventCorrelationAnalyzer().analyze([str(path)])['risks'] == []


def test_unverified_findings_do_not_inflate_confirmed_risk_scores():
    real = {'type': 'password_not_required', 'severity': 'critical', 'affected_object': 'user'}
    score = RiskScorer().score_risks([dict(real)])[0]['final_score']
    candidate = {'type': 'nopac_vulnerable', 'severity': 'critical', 'affected_object': 'user'}
    risks = RiskScorer().score_risks([dict(real), candidate])
    assert risks[0]['final_score'] == score
    assert candidate['final_score'] == 0
    assert candidate['potential_severity'] == 'critical'
    assert candidate['finding_status'] == 'needs_validation'
    assert RiskScorer().calculate_domain_score([candidate]) == 100
    assert DomainAdminTakeoverAnalyzer().analyze([candidate])['open_paths'] == []
    assert DomainAdminTakeoverAnalyzer().analyze([candidate])['pending_paths']


def test_type_names_alone_do_not_manufacture_evidence():
    for risk_type in ('event_dcsync_activity', 'acl_write_dacl'):
        risk = ConfidenceScorer().enrich({'type': risk_type})
        assert risk['confidence_level'] != 'high'


def test_print_in_hostname_is_not_print_spooler_evidence():
    assert VulnerabilityScanner(LDAP()).scan_printnightmare([
        {'name': 'print-server', 'servicePrincipalName': ['HOST/print-server', 'HTTP/sprint.example.com']},
    ]) == []


def test_nested_group_deny_blocks_dcsync_and_split_group_grants_are_preserved():
    group_sid = SID.rsplit('-', 1)[0] + '-1200'
    parent_sid = SID.rsplit('-', 1)[0] + '-1300'
    user = {'objectSid': SID, 'sAMAccountName': 'delegate', 'distinguishedName': 'CN=delegate,' + LDAP.base_dn}
    groups = [
        {'objectSid': group_sid, 'name': 'Helpdesk', 'distinguishedName': 'CN=Helpdesk,' + LDAP.base_dn,
         'member': [user['distinguishedName']], 'memberOf': ['CN=Parent,' + LDAP.base_dn]},
        {'objectSid': parent_sid, 'name': 'Parent', 'distinguishedName': 'CN=Parent,' + LDAP.base_dn},
    ]
    tokens = principal_group_tokens([user], groups)
    assert tokens[SID] == {group_sid, parent_sid}
    raw = descriptor(ace(0x100, sid=parent_sid, guid=CHANGES_ALL, denied=True), ace(0x100))
    analyzer = DCSyncAnalyzer(LDAP([{'nTSecurityDescriptor': raw}]))
    assert analyzer.analyze_dcsync_rights([user], groups) == []
    raw = descriptor(ace(0x100, sid=group_sid, guid=CHANGES), ace(0x100, sid=parent_sid, guid=CHANGES_ALL))
    analyzer = DCSyncAnalyzer(LDAP([{'nTSecurityDescriptor': raw}]))
    assert any(risk['affected_object'] == 'delegate' for risk in analyzer.analyze_dcsync_rights([user], groups))


def test_privileged_names_do_not_override_a_contradictory_sid():
    counterfeit = {'name': 'Domain Admins', 'objectSid': SID}
    assert not group_is_role(counterfeit, 'Domain Admins')
    assert not is_privileged_group_record(counterfeit)
    assert not group_is_role({'objectSid': 'S-1-5-32-512'}, 'Domain Admins')


def test_gmsa_write_permission_does_not_grant_password_retrieval():
    for mask, expected in ((0x40000000, 0), (0x10, 1), (0x10000000, 1)):
        rows = [{'sAMAccountName': 'service$', 'msDS-GroupMSAMembership': descriptor(ace(mask, sid='S-1-1-0'))}]
        result = GMSAReaderGraphAnalyzer(LDAP(rows)).analyze([], [], [])
        assert len(result['graph']['edges']) == expected


@pytest.mark.parametrize('attributes', [0x20, 0x8 | 0x10, 0x4 | 0x10])
def test_secure_trust_boundaries_do_not_become_sid_filtering_alerts(attributes):
    row = {'name': 'other.example', 'trustDirection': 3, 'trustType': 2,
           'trustAttributes': attributes, 'distinguishedName': 'CN=other,' + LDAP.base_dn}
    assert TrustAnalyzer(LDAP([row])).analyze_trusts() == []
    assert TrustSecurityV2Analyzer(LDAP([row])).analyze()['risks'] == []


def test_unknown_trust_settings_are_not_disabled_controls():
    row = {'name': 'other.example', 'trustDirection': 3, 'trustType': 2,
           'distinguishedName': 'CN=other,' + LDAP.base_dn}
    assert TrustAnalyzer(LDAP([row])).analyze_trusts() == []
    assert TrustSecurityV2Analyzer(LDAP([row])).analyze()['risks'] == []
    assert TrustAnalyzer(LDAP()).analyze_trusts() == []


def test_trust_direction_matches_local_authentication_exposure():
    row = {'name': 'other.example', 'trustType': 2, 'trustAttributes': 0}
    inbound = TrustSecurityV2Analyzer(LDAP([{**row, 'trustDirection': 1}])).analyze()
    outbound = TrustSecurityV2Analyzer(LDAP([{**row, 'trustDirection': 2}])).analyze()
    assert inbound['risks'] == []
    assert any(risk['type'] == 'trust_sid_filtering_weak' for risk in outbound['risks'])
    assert inbound['graph']['edges'][0]['source'] == 'domain:' + LDAP.base_dn.casefold()
    assert outbound['graph']['edges'][0]['target'] == 'domain:' + LDAP.base_dn.casefold()


def test_validation_candidates_do_not_create_compliance_or_cost_failures():
    risk = {'type': 'gpo_modification_rights', 'severity': 'high'}
    assert ComplianceReporter._risk_type_counts([risk])['gpo_modification_rights'] == 0
    manager = RiskManager()
    assert manager.prioritize_risks([risk]) == []
    assert manager.generate_risk_heat_map([risk])['total_risks'] == 0


def test_new_heuristic_is_not_a_new_critical_baseline_alert(tmp_path):
    path = tmp_path / 'baseline.json'
    path.write_text(json.dumps({'risks': []}))
    result = BaselineComparator().compare_snapshot({}, {}, [
        {'type': 'nopac_vulnerable', 'severity': 'critical', 'affected_object': 'DC1'},
    ], str(path))
    assert not any(risk['type'] == 'snapshot_new_critical_risk' for risk in result['risks'])


def test_pending_paths_remain_visible_in_both_report_languages():
    result = DomainAdminTakeoverAnalyzer().analyze([
        {'type': 'certificate_esc1', 'severity': 'critical', 'affected_object': 'ReviewTemplate'},
    ])
    english = DomainAdminSectionMixin()._generate_domain_admin_takeover_section(result)
    translated = localize_report_structure(result, 'tr', structure_kind='domain_admin_takeover')
    turkish = localize_html_document(DomainAdminSectionMixin()._generate_domain_admin_takeover_section(translated), 'tr')
    assert 'Paths requiring validation' in english
    assert 'Requires validation' in english
    assert 'Doğrulama gerektiren yollar' in turkish
    assert 'Doğrulama gerekli' in turkish
    assert 'ReviewTemplate' in english and 'ReviewTemplate' in turkish
    assert result['summary']['open_path_count'] == 0


def test_pipeline_keeps_true_dcsync_and_unverified_cve_separate():
    from AtilKurt import score_and_consolidate

    result = score_and_consolidate(
        {'dcsync_risks': dcsync(ace(0x100)),
         'nopac_risks': [{'type': 'nopac_vulnerable', 'severity': 'critical', 'affected_object': 'DC1'}]},
        {'users': [], 'groups': [], 'computers': []},
    )
    risks = {risk['type']: risk for risk in result['scored_risks']}
    assert risks['dcsync_rights']['severity'] == 'critical'
    assert risks['nopac_vulnerable']['final_score'] == 0
    assert result['executive_summary']['validation_required_count'] == 1
    assert result['domain_admin_takeover']['summary']['pending_path_count'] == 1
