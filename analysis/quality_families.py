"""Labelled scenarios exercising AD CS, delegation, GPO, trust and LAPS rules."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from core.ad_security import as_int
from core.exceptions import ValidationError

FAMILIES = {'adcs', 'delegation', 'gpo', 'trust', 'laps'}
BASE = 'DC=example,DC=com'
HOST_DN = 'CN=host,OU=Lab,' + BASE
CONFIG = 'CN=Configuration,' + BASE


def family_cases():
    cases = []

    def add(rule, name, expected, inputs):
        cases.append({'id': rule + '_' + name, 'rule': rule, 'expected': expected, 'input': inputs})

    for name, grants, expected in (
        ('broad_write', [{'mask': 0x40000000, 'sid': 'S-1-1-0'}], 'positive'),
        ('deny_write', [{'mask': 0x40000000, 'sid': 'S-1-1-0', 'denied': True}, {'mask': 0x40000000, 'sid': 'S-1-1-0'}], 'negative'),
        ('privileged_writer', [{'mask': 0x40000000, 'sid': 'S-1-5-18'}], 'negative'),
    ):
        add('adcs', name, expected, {'grants': grants})
    add('adcs', 'unreadable_acl', 'unknown', {'descriptor_unreadable': True})
    add('adcs', 'old_acl', 'unknown', {'grants': [{'mask': 0x40000000, 'sid': 'S-1-1-0'}], 'collected_at': '2000-01-01T00:00:00Z'})
    add('adcs', 'conflicting_acl', 'unknown', {'conflicting_evidence': True})
    for name, value, expected in (('unconstrained', 0x80200, 'positive'), ('normal', 512, 'negative'),
                                   ('missing_flags', None, 'unknown'), ('malformed_flags', 'unreadable', 'unknown')):
        add('delegation', name, expected, {'users': [{'sAMAccountName': 'service', 'userAccountControl': value}]})
    add('delegation', 'old_flags', 'unknown', {'users': [{'userAccountControl': 0x80200}], 'collected_at': '2000-01-01T00:00:00Z'})
    add('delegation', 'conflicting_flags', 'unknown', {'conflicting_evidence': True})
    for name, flags, expected in (('external_unfiltered', 0, 'positive'), ('external_hardened', 0x14, 'negative'),
                                  ('missing_flags', None, 'unknown')):
        add('trust', name, expected, {'rows': [{'trustPartner': 'other.example', 'trustDirection': 2, 'trustType': 2,
                                               'trustAttributes': flags, 'msDS-SupportedEncryptionTypes': 0x18}]})
    add('trust', 'unreadable_query', 'unknown', {'query_error': True})
    add('trust', 'old_flags', 'unknown', {'rows': [], 'collected_at': '2000-01-01T00:00:00Z'})
    add('trust', 'conflicting_direction', 'unknown', {'conflicting_evidence': True})
    for name, encrypted, expected in (('encryption_gap', False, 'unknown'), ('encrypted', True, 'negative')):
        add('laps', name, expected, {'covered': [{'distinguishedName': HOST_DN}],
                                    'encrypted': [{'distinguishedName': HOST_DN}] if encrypted else []})
    add('laps', 'unreadable_encryption', 'unknown', {'covered': [{'distinguishedName': HOST_DN}], 'query_error': True})
    add('laps', 'old_coverage', 'unknown', {'covered': [], 'collected_at': '2000-01-01T00:00:00Z'})
    add('laps', 'conflicting_inventory', 'unknown', {'conflicting_evidence': True})
    add('laps', 'broad_acl_control', 'positive', {'covered': [{'distinguishedName': HOST_DN}],
                                                'acl_grants': [{'mask': 0x40000000, 'sid': 'S-1-1-0'}]})
    principal = 'S-1-5-11'
    gpo = {'id': 'unsafe', 'flags': 0, 'settings': {'ldap_signing_required': False},
           'security_filter': {'read': [principal], 'apply': [principal]}}
    context = {'schema_version': 1, 'targets': [{'dn': HOST_DN, 'kind': 'computer', 'token_complete': True, 'security_groups': [principal]}],
               'containers': [{'dn': BASE, 'gpOptions': 0, 'links': [{'id': 'unsafe', 'order': 1}]},
                              {'dn': 'OU=Lab,' + BASE, 'gpOptions': 0, 'links': []}], 'gpos': [gpo]}
    add('gpo', 'applicable_unsafe', 'positive', {'context': context})
    denied = deepcopy(context)
    denied['gpos'][0]['security_filter']['deny'] = [principal]
    add('gpo', 'security_denied', 'negative', {'context': denied})
    blocked = deepcopy(context)
    blocked['containers'][1]['gpOptions'] = 1
    add('gpo', 'inheritance_blocked', 'negative', {'context': blocked})
    enforced = deepcopy(blocked)
    enforced['containers'][0]['links'][0]['enforced'] = True
    add('gpo', 'enforced_survives_block', 'positive', {'context': enforced})
    wmi = deepcopy(context)
    wmi['gpos'][0]['wmi_filter'] = 'host-filter'
    add('gpo', 'unknown_wmi', 'unknown', {'context': wmi})
    missing = deepcopy(context)
    missing['gpos'][0]['security_filter'] = None
    add('gpo', 'unreadable_filter', 'unknown', {'context': missing})
    safe_override = deepcopy(context)
    safe_override['gpos'].append({**deepcopy(gpo), 'id': 'safe', 'settings': {'ldap_signing_required': True}})
    safe_override['containers'][1]['links'] = [{'id': 'safe', 'order': 1}]
    add('gpo', 'child_safe_override', 'negative', {'context': safe_override})
    add('gpo', 'old_rsop', 'unknown', {'context': context, 'collected_at': '2000-01-01T00:00:00Z'})
    add('gpo', 'conflicting_links', 'unknown', {'conflicting_evidence': True})
    return cases


def evaluate_family(rule, inputs, descriptor):
    if inputs.get('conflicting_evidence'):
        return [], False
    if inputs.get('collected_at'):
        try:
            stamp = datetime.fromisoformat(inputs['collected_at'].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            if stamp.tzinfo is None or not now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5):
                return [], False
        except (ValueError, TypeError) as exc:
            raise ValidationError('Invalid quality evidence timestamp') from exc
    from analysis.rule_quality import FixtureDirectory
    if rule == 'adcs':
        from analysis.adcs_control_plane_analyzer import ADCSControlPlaneAnalyzer
        sd = None if inputs.get('descriptor_unreadable') else descriptor(inputs.get('grants', []))

        class PKIDirectory(FixtureDirectory):
            def search(self, **kwargs):
                if kwargs.get('search_base') == '':
                    return [{'configurationNamingContext': CONFIG}]
                if str(kwargs.get('search_base')).startswith('CN=NTAuthCertificates,'):
                    return [{'cn': 'NTAuthCertificates', 'distinguishedName': 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,' + CONFIG,
                             'nTSecurityDescriptor': sd}]
                return []

        return ADCSControlPlaneAnalyzer(PKIDirectory()).analyze([], [])['risks'], sd is not None
    if rule == 'delegation':
        from analysis.kerberos_delegation import KerberosDelegationAnalyzer
        users = inputs.get('users', [])
        observable = bool(users) and all(as_int(row.get('userAccountControl')) is not None for row in users)
        return (KerberosDelegationAnalyzer()._check_unconstrained_delegation(users, []) if observable else []), observable
    if rule == 'trust':
        from analysis.trust_security_v2_analyzer import TrustSecurityV2Analyzer
        rows = inputs.get('rows', [])
        if inputs.get('query_error'):
            return [], False
        observable = all(all(as_int(row.get(field)) is not None for field in ('trustAttributes', 'trustDirection', 'trustType')) for row in rows)
        return TrustSecurityV2Analyzer(FixtureDirectory(rows)).analyze()['risks'], observable
    if rule == 'laps':
        from analysis.laps_v2_analyzer import WindowsLAPSV2Analyzer
        queries = []
        for attribute, rows in (('msLAPS-PasswordExpirationTime', inputs.get('covered', [])),
                                ('msLAPS-EncryptedPassword', inputs.get('encrypted', [])),
                                ('msLAPS-EncryptedPasswordHistory', inputs.get('encrypted', []))):
            rows = deepcopy(rows)
            if attribute == 'msLAPS-PasswordExpirationTime' and inputs.get('acl_grants'):
                for row in rows:
                    row['nTSecurityDescriptor'] = descriptor(inputs['acl_grants'])
            query = {'filter': f'(&(objectClass=computer)({attribute}=*))', 'rows': rows}
            if inputs.get('query_error') and attribute == 'msLAPS-EncryptedPassword':
                query['error'] = True
            queries.append(query)
        ldap = FixtureDirectory([], queries)
        risks = WindowsLAPSV2Analyzer(ldap).analyze([])
        risks = [risk for risk in risks if risk['type'] in {'windows_laps_encryption_gap', 'windows_laps_broad_acl'}]
        return risks, not ldap.unavailable_queries
    if rule == 'gpo':
        from analysis.effective_gpo_analyzer import analyze_effective_gpo
        result = analyze_effective_gpo(inputs.get('context') or {'schema_version': 1})
        risks, observable = [], True
        for target in result['targets']:
            for name, setting in target['settings'].items():
                if name.endswith('_required') and setting['value'] is False:
                    risks.append({'type': 'gpo_unsafe_setting', 'requires_validation': setting['status'] == 'conditional'})
            observable &= all(row['status'] != 'conditional' for row in target['policies'])
        return risks, observable
    raise ValidationError('Unknown quality family')
