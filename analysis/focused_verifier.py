"""Targeted LDAP configuration verification with explicit rule coverage."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import UUID

from core.ad_security import as_int, as_list, as_text, security_descriptor_bytes, sid_text
from core.security_descriptor_parser import directory_right_granted
from core.exceptions import ValidationError

ATTRIBUTES = ['distinguishedName', 'objectSid', 'userAccountControl', 'tokenGroups', 'sIDHistory', 'msDS-AllowedToDelegateTo']
POLICY_ATTRIBUTES = ['minPwdLength', 'maxPwdAge', 'pwdHistoryLength', 'pwdProperties', 'lockoutThreshold']


def validate_selected_findings(previous, domain, selected_ids):
    if str(previous.get('domain', '')).casefold().strip('.') != domain.casefold().strip('.'):
        raise ValidationError('Focused verification snapshot belongs to another domain')
    findings = previous.get('risks', [])
    if not isinstance(findings, list) or any(not isinstance(row, dict) for row in findings):
        raise ValidationError('Focused verification snapshot has invalid findings')
    selected = set(selected_ids)
    known = {row.get('finding_id') for row in findings}
    if not selected or len(selected) > 100 or selected - known:
        raise ValidationError('Focused verification requires 1..100 known finding IDs')
    for field in ('users', 'computers', 'groups'):
        objects = previous.get(field, [])
        if not isinstance(objects, list) or any(not isinstance(row, dict) for row in objects):
            raise ValidationError('Focused verification snapshot has invalid principal collections')
    return findings, selected


def verify_selected_findings(ldap, previous, selected_ids):
    findings, selected = validate_selected_findings(previous, ldap.domain, selected_ids)
    results, cache = [], {}

    def read(dn, attributes):
        key = (dn.casefold(), tuple(attributes))
        if key not in cache:
            rows = ldap.base_search(dn, attributes)
            if len(rows) != 1:
                raise ValidationError('Targeted object is missing or not uniquely readable')
            cache[key] = rows[0]
        return cache[key]

    accounts = (previous.get('users') or []) + (previous.get('computers') or []) + (previous.get('groups') or [])
    for finding in findings:
        if finding.get('finding_id') not in selected:
            continue
        result = {'finding_id': finding['finding_id'], 'title': finding.get('title'), 'status': 'insufficient_evidence',
                  'reason': 'This rule requires a full or independent runtime check', 'evidence': [], 'local_prerequisites': []}
        kind = finding.get('type', '')
        try:
            if kind in {'unconstrained_delegation', 'unconstrained_delegation_user', 'computer_unconstrained_delegation',
                        'constrained_delegation', 'computer_broad_constrained_delegation', 'dcsync_rights'}:
                label = str(finding.get('affected_object') or '').casefold()
                matches = [row for row in accounts if label in {as_text(row.get(key)).casefold()
                           for key in ('sAMAccountName', 'name', 'distinguishedName', 'objectSid')}]
                if len(matches) != 1:
                    raise ValidationError('Previous finding cannot be bound to one current principal')
                dn = as_text(matches[0].get('distinguishedName'))
                row = read(dn, ATTRIBUTES)
                expected_sid, current_sid = sid_text(matches[0].get('objectSid')), sid_text(row.get('objectSid'))
                if not expected_sid or current_sid != expected_sid:
                    raise ValidationError('Principal SID is missing or changed')
                uac = as_int(row.get('userAccountControl'))
                if uac is None:
                    raise ValidationError('Account state/delegation flags are unreadable')
                if kind == 'dcsync_rights':
                    from core.security_descriptor_parser import parse_security_descriptor
                    descriptor = security_descriptor_bytes(read(ldap.base_dn, ['nTSecurityDescriptor']).get('nTSecurityDescriptor'))
                    if descriptor is None or len(descriptor) < 20 or 'tokenGroups' not in row:
                        raise ValidationError('Domain ACL or current effective token is unreadable')
                    parsed = parse_security_descriptor(descriptor)
                    if parsed.get('parse_valid') is not True or not parsed.get('dacl'):
                        raise ValidationError('Domain ACL cannot establish an effective access decision')
                    if not row['tokenGroups'] or any(sid_text(value) is None for value in as_list(row['tokenGroups'])):
                        raise ValidationError('Current effective token is empty or malformed')
                    groups = {sid_text(value) for value in as_list(row['tokenGroups']) + as_list(row.get('sIDHistory'))}
                    required = ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                    present = all(directory_right_granted(parsed, current_sid, 0x100, UUID(guid).bytes_le, groups) for guid in required)
                    result['evidence'].append({'target': ldap.base_dn, 'attribute': 'nTSecurityDescriptor',
                                               'sha256': hashlib.sha256(descriptor).hexdigest()})
                elif 'unconstrained' in kind:
                    present = bool(uac & 0x80000)
                else:
                    if 'msDS-AllowedToDelegateTo' not in row:
                        raise ValidationError('Delegation target attribute was not observed')
                    present = bool(row['msDS-AllowedToDelegateTo'])
                result['evidence'].append({'target': dn, 'sid': current_sid, 'userAccountControl': uac,
                                           'delegation_targets': as_list(row.get('msDS-AllowedToDelegateTo'))})
                result['status'] = 'still_present' if present else 'configuration_resolved'
                result['reason'] = 'Current targeted configuration supports this decision'
                result['local_prerequisites'] = ['Runtime impact and successful exploitation are not tested']
            elif kind == 'password_policy_weak' and finding.get('affected_object') == 'Domain Password Policy':
                row = read(ldap.base_dn, POLICY_ATTRIBUTES)
                if any(as_int(row.get(attribute)) is None for attribute in POLICY_ATTRIBUTES):
                    raise ValidationError('Domain password policy attributes are incomplete')
                from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
                from core.finding_review import FindingReviewManager

                class PolicyDirectory:
                    base_dn = ldap.base_dn
                    connection = None

                    def __init__(self, attributes):
                        self.attributes = attributes

                    def search(self, **kwargs):
                        return [self.attributes] if kwargs.get('search_filter') == '(objectClass=domainDNS)' else []

                risks = PasswordPolicyAnalyzer(PolicyDirectory(row)).analyze_password_policy()
                FindingReviewManager().apply(risks, {}, ldap.domain)
                present = any(risk['finding_id'] == finding['finding_id'] for risk in risks)
                result['status'] = 'still_present' if present else 'configuration_resolved'
                result['reason'] = 'Domain policy condition reevaluated using fresh BASE attributes'
                result['evidence'].append({'target': ldap.base_dn, 'attributes': {key: row[key] for key in POLICY_ATTRIBUTES}})
            else:
                result['local_prerequisites'] = ['Collect the rule-specific host/service evidence listed in the original finding']
        except Exception as exc:
            result['reason'] = str(exc)[:300]
        results.append(result)
    return {'schema_version': 1, 'domain': ldap.domain, 'collected_at': datetime.now(timezone.utc).isoformat(),
            'mode': 'focused_configuration', 'findings': results, 'objects_read': len(cache),
            'limitation': 'Configuration resolution is scoped to supported rules and is not a full assessment or runtime remediation closure.'}
