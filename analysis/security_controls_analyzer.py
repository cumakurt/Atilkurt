"""Target-bound endpoint, PKI, hybrid and recovery controls with explicit gaps."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import UUID

from core.control_evidence import observation_document
from core.exceptions import ValidationError


CONTROL_NAMES = (
    'lsa_protection', 'credential_guard', 'wdigest', 'remote_credential_guard',
    'adcs_ca_permissions', 'adcs_epa', 'adcs_rpc_signing', 'adcs_role_separation',
    'advanced_audit_policy', 'entra_privileged_mfa', 'entra_conditional_access',
    'hybrid_replication_permissions', 'recovery_backup', 'recovery_isolation',
    'recovery_dsrm_access', 'recovery_restore_test', 'recovery_plan',
)


def _date(value):
    try:
        stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return stamp if stamp.tzinfo else None
    except (ValueError, TypeError):
        return None


def _recent(value, days, now):
    stamp = _date(value)
    return stamp is not None and now - timedelta(days=days) <= stamp <= now + timedelta(minutes=5)


def _boolean(value):
    return 'secure' if value is True else 'insecure' if value is False else 'unknown'


def _audit_flags(values, allowed):
    if not isinstance(values, dict):
        return None
    normalized = {}
    for key, value in values.items():
        try:
            identifier = str(UUID(key)) if isinstance(key, str) else None
        except ValueError:
            return None
        if identifier is None or type(value) is not int or value not in allowed:
            return None
        if identifier in normalized and normalized[identifier] != value:
            return None
        normalized[identifier] = value
    return normalized


def evaluate_control(name, value, *, now):
    """Evaluate observed runtime state; configuration alone cannot prove execution."""
    if name in ('lsa_protection', 'credential_guard', 'remote_credential_guard'):
        return _boolean(value.get('running')) if isinstance(value, dict) else 'unknown'
    if name == 'wdigest':
        return 'secure' if type(value) is int and value == 0 else 'insecure' if type(value) is int and value == 1 else 'unknown'
    if name in ('adcs_epa', 'adcs_rpc_signing', 'adcs_role_separation', 'recovery_isolation'):
        return _boolean(value)
    if not isinstance(value, dict):
        return 'unknown'
    if name == 'adcs_ca_permissions':
        if value.get('dacl_present') is False:
            return 'insecure'
        grants = value.get('grants')
        approved = value.get('approved_trustees')
        if not isinstance(grants, list) or len(grants) > 10000 or not isinstance(approved, list) or not approved or value.get('complete') is not True or value.get('dacl_present') is not True:
            return 'unknown'
        if any(not isinstance(g, dict) or not isinstance(g.get('sid'), str) or type(g.get('mask')) is not int for g in grants):
            return 'unknown'
        # Denies/conditional grants need an effective-access export, not mask arithmetic.
        if any(g.get('denied') or g.get('conditional') for g in grants):
            return 'unknown'
        return 'insecure' if any(g['mask'] & (3 | 0x10000000 | 0x40000 | 0x80000) and g['sid'] not in approved for g in grants) else 'secure'
    if name == 'advanced_audit_policy':
        required = value.get('required_subcategories')
        actual = value.get('subcategories')
        if not isinstance(required, list) or not required or not isinstance(actual, dict):
            return 'unknown'
        if any(not isinstance(item, str) for item in required):
            return 'unknown'
        try:
            required = [str(UUID(item)) for item in required]
        except ValueError:
            return 'unknown'
        actual = _audit_flags(actual, (0, 1, 2, 3))
        flags = _audit_flags(value.get('required_flags', {}), (1, 2, 3))
        if actual is None or flags is None or any(item not in actual for item in required):
            return 'unknown'
        return 'secure' if all(actual[item] & flags.get(item, 3) == flags.get(item, 3) for item in required) else 'insecure'
    if name in ('entra_privileged_mfa', 'entra_conditional_access'):
        if value.get('complete') is not True or type(value.get('total')) is not int or type(value.get('covered')) is not int:
            return 'unknown'
        if not 0 <= value['covered'] <= value['total'] or value['total'] == 0:
            return 'unknown'
        # MFA registration alone does not establish enforcement at sign-in.
        if value.get('basis') != 'effective_enforcement':
            return 'unknown'
        return 'secure' if value['covered'] == value['total'] else 'insecure'
    if name == 'hybrid_replication_permissions':
        if value.get('excessive_permissions') is True:
            return 'insecure'
        if value.get('password_hash_sync') is True and value.get('required_replication_only') is True:
            return 'secure'
        if value.get('password_hash_sync') is False and value.get('has_replication') is True:
            return 'insecure'
        return 'unknown'
    if name == 'recovery_backup':
        stamp = _date(value.get('last_success'))
        if (stamp is None or stamp > now + timedelta(minutes=5) or type(value.get('system_state')) is not bool
                or type(value.get('max_age_days')) is not int or not 1 <= value['max_age_days'] <= 365):
            return 'unknown'
        return 'secure' if _recent(value['last_success'], value['max_age_days'], now) and value['system_state'] else 'insecure'
    if name == 'recovery_dsrm_access':
        if type(value.get('access_reviewed')) is not bool or type(value.get('vaulted')) is not bool:
            return 'unknown'
        return 'secure' if value['access_reviewed'] and value['vaulted'] else 'insecure'
    if name == 'recovery_restore_test':
        if value.get('isolated') is not True or value.get('successful') is not True:
            return 'insecure' if value.get('successful') is False else 'unknown'
        return 'secure' if _recent(value.get('tested_at'), 180, now) else 'unknown' if _date(value.get('tested_at')) is None else 'insecure'
    if name == 'recovery_plan':
        if not all(key in value for key in ('owner', 'domain', 'reviewed_at', 'procedures_verified')):
            return 'unknown'
        return 'secure' if value['owner'] and value['domain'] and value['procedures_verified'] is True and _recent(value['reviewed_at'], 180, now) else 'insecure'
    return 'unknown'


def analyze_security_controls(documents, domain, *, now=None, max_age_days=30, expected_targets=None):
    now = now or datetime.now(timezone.utc)
    rows = []
    inventory, not_applicable = {}, {}
    for document in documents:
        rows.extend(observation_document(document, domain, now=now, max_age_days=max_age_days))
        target_rows = document.get('targets', [])
        if not isinstance(target_rows, list) or len(target_rows) > 1000:
            raise ValidationError('Security targets must be a bounded list')
        for target in target_rows:
            if not isinstance(target, dict) or not isinstance(target.get('target'), str):
                raise ValidationError('Security targets require a target name')
            applicable = target.get('controls', list(CONTROL_NAMES))
            if not isinstance(applicable, list) or any(not isinstance(name, str) for name in applicable) or set(applicable) - set(CONTROL_NAMES):
                raise ValidationError('Unsupported target control')
            inventory.setdefault(target['target'].casefold(), set()).update(applicable)
            exclusions = target.get('not_applicable', {})
            if not isinstance(exclusions, dict) or set(exclusions) - set(CONTROL_NAMES) or any(not isinstance(reason, str) or not reason.strip() for reason in exclusions.values()):
                raise ValidationError('Not-applicable controls require an explicit reason')
            for name, reason in exclusions.items():
                inventory[target['target'].casefold()].add(name)
                not_applicable[(target['target'].casefold(), name)] = reason
    for target in expected_targets or []:
        inventory.setdefault(str(target).casefold(), set()).update(
            ('lsa_protection', 'credential_guard', 'wdigest', 'advanced_audit_policy',
             'recovery_backup', 'recovery_isolation', 'recovery_dsrm_access', 'recovery_restore_test', 'recovery_plan'))
    grouped = defaultdict(list)
    for row in rows:
        if row.get('name') in CONTROL_NAMES:
            grouped[(str(row.get('target') or 'unknown').casefold(), row['name'])].append(row)
            inventory.setdefault(str(row.get('target') or 'unknown').casefold(), set()).add(row['name'])
    checks, risks = [], []
    for target, names in sorted(inventory.items()):
        for name in sorted(names):
            evidence = grouped.get((target, name), [])
            states = [evaluate_control(name, row.get('value'), now=now) for row in evidence if row['status'] == 'available']
            if name == 'recovery_plan' and any(isinstance(row.get('value'), dict) and str(row['value'].get('domain') or '').casefold().strip('.') != domain.casefold().strip('.') for row in evidence):
                states = ['unknown']
            # Conflicting sources include unknown and opposite runtime observations.
            from core.evidence_signing import canonical_json
            conflict = len({canonical_json(row.get('value')) for row in evidence if row['status'] == 'available'}) > 1
            state = 'conflicting' if conflict else 'unknown' if not states or len(states) != len(evidence) or 'unknown' in states else states[0]
            exclusion = not_applicable.get((target, name))
            if exclusion:
                state = 'conflicting' if evidence else 'not_applicable'
            checks.append({'target': target, 'control': name, 'status': state, 'source_count': len(evidence),
                           'sources': [row.get('source') for row in evidence],
                           'reason': exclusion or next((row.get('reason') for row in evidence if row.get('reason')), None) or
                           ('Fresh runtime evidence unavailable' if state == 'unknown' else 'Sources disagree' if conflict else None)})
            if state == 'insecure':
                risks.append({'type': 'security_control_' + name, 'severity': 'High',
                              'title': name.replace('_', ' ').capitalize() + ' protection gap',
                              'affected_object': target, 'object_type': 'configuration',
                              'description': 'Fresh target-bound evidence does not meet the declared control requirements.',
                              'mitigation': 'Review the affected control with its owner, apply compatible protection, and collect new runtime evidence.',
                              'evidence': {'control': name, 'observations': evidence, 'source': 'validated_security_evidence'}})
    transitions = _transitions(rows, now)
    targets = [{'target': target, 'controls': sorted(names),
                'not_applicable': {name: not_applicable[(target, name)] for name in sorted(names)
                                   if (target, name) in not_applicable}}
               for target, names in sorted(inventory.items())]
    return {'schema_version': 1, 'checks': checks, 'risks': risks, 'observations': rows,
            'targets': targets,
            'transition_readiness': transitions,
            'summary': {state: sum(check['status'] == state for check in checks) for state in ('secure', 'insecure', 'unknown', 'conflicting', 'not_applicable')},
            'limitation': 'Results apply only to declared targets and fresh observations. Configured protection, MFA registration and backup job existence do not prove effective protection or recoverability.'}


def _transitions(rows, now):
    dependencies = []
    for row in rows:
        value = row.get('value')
        if row.get('name') != 'legacy_protocol_usage' or row['status'] != 'available' or not isinstance(value, dict):
            continue
        if value.get('protocol') not in ('NTLM', 'RC4') or type(value.get('count')) is not int or value['count'] < 1:
            continue
        expires = _date(value.get('expires_at'))
        dependencies.append({'target': row['target'], 'protocol': value['protocol'],
                             'client': value.get('client'), 'account': value.get('account'), 'service': value.get('service'),
                             'count': value['count'], 'owner': value.get('owner'), 'expires_at': value.get('expires_at'),
                             'exception_status': 'active' if expires and expires > now and value.get('owner') else 'unowned_or_expired',
                             'source': row['source'], 'collected_at': row['collected_at']})
    return {'dependencies': dependencies, 'status': 'dependencies_observed' if dependencies else 'unknown',
            'limitation': 'No observed dependency is not proof that NTLM/RC4 retirement is safe; include all clients and a representative observation period.'}


def reconcile_hybrid_findings(risks, observations):
    """Required PHS privileges remain a sensitive capability, not excess permission."""
    for risk in risks:
        if risk.get('type') != 'hybrid_entra_connect_excessive_rights':
            continue
        account = str(risk.get('affected_object') or '').casefold()
        supporting = [row for row in observations if row.get('name') == 'hybrid_replication_permissions'
                      and row.get('status') == 'available' and isinstance(row.get('value'), dict)
                      and str(row['value'].get('account') or '').casefold() == account]
        if supporting and all(row['value'].get('password_hash_sync') is True and row['value'].get('required_replication_only') is True
                              and row['value'].get('excessive_permissions') is not True for row in supporting):
            risk['type'] = 'hybrid_entra_connect_required_replication'
            risk['title'] = f'Entra Connect account "{risk["affected_object"]}" has required PHS replication capability'
            risk['description'] = 'Validated PHS configuration requires these replication permissions. Protect the account and host as Tier 0; do not remove required permissions.'
            risk['requires_validation'] = True
            risk.setdefault('evidence', {})['required_for_password_hash_sync'] = True
            risk['mitigation'] = 'Retain required PHS rights; restrict host administration and interactive use, monitor replication, and remove independently verified excess rights.'


def refresh_security_findings(previous, result):
    """Expired evidence makes a previous finding unverified, never resolved."""
    from core.finding_evidence import invalidate_finding_evidence
    risks = list(result['risks'])
    states = {(check['target'].casefold(), check['control']): check['status'] for check in result['checks']}
    for original in previous:
        name = str(original.get('type') or '').removeprefix('security_control_')
        state = states.get((str(original.get('affected_object') or '').casefold(), name), 'unknown')
        if state not in ('unknown', 'conflicting'):
            continue
        risks.append(invalidate_finding_evidence(original, state))
    return risks
