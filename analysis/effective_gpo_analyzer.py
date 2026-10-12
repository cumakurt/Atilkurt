"""Static GPO applicability with explicit unknown filters and observed RSoP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from uuid import UUID

from ldap3.utils.dn import parse_dn

from core.assessment_scope import under_dn
from core.ad_security import as_int, as_list, as_text, security_descriptor_bytes, sid_text
from core.exceptions import ValidationError

LINK = re.compile(r'\[LDAP://([^;\]]+);([0-3])\]', re.I)
GUID = re.compile(r'\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?', re.I)


def gpo_id(value):
    match = GUID.search(str(value))
    return match.group(1).casefold() if match else str(value).casefold()


def _validate_policy_fields(policy):
    for field in ('settings', 'target_security'):
        value = policy.get(field)
        if value is not None and not isinstance(value, dict):
            raise ValidationError(f'GPO {field} must be an object')
    filtering = policy.get('security_filter')
    if filtering is not None:
        if not isinstance(filtering, dict):
            raise ValidationError('GPO security_filter must be an object')
        for field in ('read', 'apply', 'deny'):
            values = filtering.get(field, [])
            if (not isinstance(values, list) or len(values) > 10000
                    or any(not isinstance(value, str) or not value for value in values)):
                raise ValidationError('GPO effective permission filters require bounded SID lists')
    for decision in (policy.get('target_security') or {}).values():
        if not isinstance(decision, dict) or any(
            key in decision and not isinstance(decision[key], bool) for key in ('read', 'apply')
        ):
            raise ValidationError('GPO target permissions require boolean Read/Apply decisions')


def parse_rsop(path):
    path = Path(path)
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValidationError('RSoP XML exceeds the size limit')
    raw = path.read_bytes()
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper() or b'\x00' in raw[:100]:
        # Decode Windows UTF-16 before checking declarations.
        text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValidationError('RSoP XML entities/DTDs are unsupported')
    else:
        text = raw.decode('utf-8-sig')
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValidationError('Invalid RSoP XML') from exc
    sections = {}
    for section in root.iter():
        kind = section.tag.split('}')[-1].casefold()
        if kind not in ('computerresults', 'userresults'):
            continue
        applied = []
        for element in section.iter():
            if element.tag.split('}')[-1].casefold() != 'gpo':
                continue
            values = {child.tag.split('}')[-1].casefold(): child.text for child in element.iter() if child.text}
            # gpresult emits FilterAllowed=true for allowed WMI filters.
            denied = str(values.get('accessdenied', '')).casefold() == 'true' or str(values.get('filterallowed', 'true')).casefold() == 'false'
            identifier = values.get('identifier') or values.get('id') or values.get('guid')
            if identifier and not denied:
                applied.append(gpo_id(identifier))
        sections[kind.removesuffix('results')] = sorted(set(applied))
    return {'source': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'sections': sections,
            'limitation': 'Imported RSoP is an observation of the supplied host/user, not a domain-wide proof.'}


def collect_gpo_context(ldap, target_dns, gpos):
    targets, containers, policies = [], {}, []
    errors = []
    for dn in target_dns:
        try:
            rows = ldap.base_search(dn, ['distinguishedName', 'objectClass', 'objectSid', 'tokenGroups'])
            if len(rows) != 1:
                raise ValidationError('GPO target could not be uniquely read')
            row = rows[0]
            tokens = [sid_text(sid) for sid in as_list(row.get('tokenGroups'))]
            tokens += [sid_text(row.get('objectSid'))]
            target = {'dn': dn, 'kind': 'computer' if 'computer' in (row.get('objectClass') or []) else 'user',
                      'sid': sid_text(row.get('objectSid')), 'security_groups': [token for token in tokens if token],
                      'token_complete': bool(row.get('tokenGroups')) and all(token for token in tokens)}
            targets.append(target)
            parts = parse_dn(dn)
            for offset in range(1, len(parts)):
                parent = ''.join(kind + '=' + text + separator for kind, text, separator in parts[offset:])
                if not under_dn(parent, ldap.base_dn):
                    continue
                if parent.casefold() not in containers:
                    entries = ldap.base_search(parent, ['distinguishedName', 'gpLink', 'gpOptions'])
                    if not entries:
                        errors.append({'dn': parent, 'reason': 'Container metadata is unreadable'})
                    else:
                        containers[parent.casefold()] = entries[0]
                        if any(attribute not in entries[0] for attribute in ('gpLink', 'gpOptions')):
                            errors.append({'dn': parent, 'reason': 'Container policy attributes were not observed'})
        except Exception as exc:
            errors.append({'dn': dn, 'reason': str(exc)[:300]})
    for gpo in gpos:
        from core.security_descriptor_parser import directory_right_granted, parse_security_descriptor
        descriptor = security_descriptor_bytes(gpo.get('nTSecurityDescriptor'))
        parsed = parse_security_descriptor(descriptor) if descriptor else {}
        decisions = {}
        for target in targets:
            if target['token_complete'] and target['sid'] and parsed.get('parse_valid') is True and parsed.get('dacl'):
                tokens = set(target['security_groups'])
                decisions[target['dn'].casefold()] = {
                    'read': directory_right_granted(parsed, target['sid'], 0x20010, token_sids=tokens),
                    'apply': directory_right_granted(parsed, target['sid'], 0x100,
                                                      UUID('edacfd8f-ffb3-11d1-b41d-00a0c968f939').bytes_le, tokens)}
        policies.append({'id': gpo_id(as_text(gpo.get('name') or gpo.get('distinguishedName'))), 'name': gpo.get('displayName'),
                         'flags': as_int(gpo.get('flags')), 'wmi_filter': as_text(gpo.get('gPCWQLFilter')),
                         'security_filter': None, 'target_security': decisions})
    return {'schema_version': 1, 'targets': targets, 'containers': list(containers.values()), 'gpos': policies, 'errors': errors}


def analyze_effective_gpo(document, rsop=None, *, now=None):
    if not isinstance(document, dict) or document.get('schema_version') != 1:
        raise ValidationError('Effective GPO input requires schema_version 1')
    for field in ('targets', 'containers', 'gpos'):
        rows = document.get(field, [])
        if not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(row, dict) for row in rows):
            raise ValidationError('Effective GPO input collections are invalid or too large')
    from core.assessment_scope import dn_parts

    containers = {}
    for container in document.get('containers', []):
        identifier = dn_parts(container.get('dn') or container.get('distinguishedName'))
        # Two inheritance descriptions for one DN cannot establish precedence.
        normalized = {key: value for key, value in container.items() if key not in {'dn', 'distinguishedName'}}
        if identifier in containers and containers[identifier][1] != normalized:
            raise ValidationError('Conflicting GPO container metadata')
        containers.setdefault(identifier, (container, normalized))
    policies, conflicts = {}, set()
    for policy in document.get('gpos', []):
        _validate_policy_fields(policy)
        identifier = gpo_id(policy.get('id') or policy.get('name'))
        if identifier in policies and policies[identifier] != policy:
            conflicts.add(identifier)
        policies.setdefault(identifier, policy)
    results = []
    now = now or datetime.now(timezone.utc)
    for target in document.get('targets', []):
        dn, kind = target.get('dn'), target.get('kind', 'computer')
        if not isinstance(dn, str) or kind not in ('computer', 'user'):
            raise ValidationError('GPO targets require a distinguished name and user/computer kind')
        ancestors = [row for row, _ in containers.values() if under_dn(dn, row.get('dn') or row.get('distinguishedName'))]
        ancestors.sort(key=lambda row: len(parse_dn(row.get('dn') or row.get('distinguishedName'))))
        observed_containers = {dn_parts(row.get('dn') or row.get('distinguishedName')) for row in ancestors}
        target_parts = parse_dn(dn)
        first_dc = next((index for index, (name, _, _) in enumerate(target_parts) if name.casefold() == 'dc'), None)
        required_containers = set()
        for index in range(1, len(target_parts)):
            if target_parts[index][0].casefold() == 'ou' or index == first_dc:
                parent = ''.join(name + '=' + value + separator for name, value, separator in target_parts[index:])
                required_containers.add(dn_parts(parent))
        metadata_complete = required_containers <= observed_containers and not document.get('errors')
        candidates = []
        for level, container in enumerate(ancestors):
            options = container.get('gpOptions', 0)
            if isinstance(options, list):
                options = options[0] if options else 0
            if int(options) & 1:
                candidates = [row for row in candidates if row['enforced']]
            links = container.get('links')
            if 'gpOptions' not in container or 'links' not in container and 'gpLink' not in container:
                metadata_complete = False
            if links is None:
                raw = container.get('gpLink') or ''
                if isinstance(raw, list):
                    raw = raw[0] if raw else ''
                matches = list(LINK.finditer(raw))
                if LINK.sub('', raw).strip():
                    raise ValidationError('GPO link string is malformed')
                links = [{'id': gpo_id(match.group(1)), 'disabled': bool(int(match.group(2)) & 1),
                          'enforced': bool(int(match.group(2)) & 2), 'order': index + 1}
                         for index, match in enumerate(matches)]
            if not isinstance(links, list) or any(not isinstance(link, dict) for link in links):
                raise ValidationError('GPO links must be a list')
            for link in links:
                order = link.get('order', 1)
                if (isinstance(order, bool) or not isinstance(order, int) or not 1 <= order <= 10000
                        or any(field in link and not isinstance(link[field], bool) for field in ('disabled', 'enforced'))):
                    raise ValidationError('GPO link order must be positive and enabled/enforced fields must be booleans')
            for link in sorted(links, key=lambda row: row.get('order', 1), reverse=True):
                if not link.get('disabled'):
                    candidates.append({'gpo_id': gpo_id(link.get('id')), 'enforced': bool(link.get('enforced')),
                                       'level': level, 'order': int(link.get('order', 1)),
                                       'container': container.get('dn') or container.get('distinguishedName')})
        # Enforced parent links apply after child links and override conflicting settings.
        candidates.sort(key=lambda row: (row['enforced'], -row['level'] if row['enforced'] else row['level'], -row['order']))
        settings, evaluated = {}, []
        tokens = set(target.get('security_groups') or [])
        for candidate in candidates:
            policy = policies.get(candidate['gpo_id'])
            missing, status = ([] if metadata_complete else ['Domain/OU inheritance metadata is incomplete']), 'predicted'
            if policy is None:
                missing.append('GPO metadata unavailable')
                policy = {}
            if candidate['gpo_id'] in conflicts:
                missing.append('Conflicting GPO metadata')
                # Do not use the first snapshot's flags, filters or settings to
                # exclude a policy or choose a winner when another contradicts it.
                policy = {}
            if 'GPO metadata unavailable' in missing or 'Conflicting GPO metadata' in missing:
                for setting in settings.values():
                    setting['status'] = 'conditional'
                    setting.setdefault('prerequisites', []).append('Higher-precedence GPO metadata is unavailable or conflicting')
            flags = as_int(policy.get('flags'))
            if flags is None:
                missing.append('GPO component enablement unknown')
            elif int(flags) & (2 if kind == 'computer' else 1):
                status = 'excluded'
            filtering = policy.get('security_filter')
            effective = (policy.get('target_security') or {}).get(dn.casefold())
            if isinstance(effective, dict) and isinstance(effective.get('read'), bool) and isinstance(effective.get('apply'), bool):
                if not effective['read'] or not effective['apply']:
                    status = 'excluded'
            elif (not isinstance(filtering, dict) or target.get('token_complete') is not True
                  or not {'read', 'apply'} <= set(filtering)):
                missing.append('Effective Read and Apply Group Policy permissions unknown')
            else:
                # The supplied allow lists represent both Read and Apply permissions, not raw membership.
                read, apply = set(filtering.get('read', [])), set(filtering.get('apply', []))
                if tokens & set(filtering.get('deny', [])) or not tokens & read or not tokens & apply:
                    status = 'excluded'
            if policy.get('wmi_filter'):
                wmi = (target.get('wmi_results') or {}).get(candidate['gpo_id'])
                if wmi is False:
                    status = 'excluded'
                elif wmi is not True:
                    missing.append('WMI filter outcome requires host evidence')
            if policy.get('content_evidence'):
                if any(content.get('unresolved_directives') for content in policy['content_evidence']):
                    missing.append('Registry.pol deletion/security directives require host evidence')
                try:
                    stamp = datetime.fromisoformat(str(policy.get('collected_at')).replace('Z', '+00:00'))
                    fresh_content = stamp.tzinfo is not None and now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5)
                except ValueError:
                    fresh_content = False
                if not fresh_content:
                    missing.append('Policy content collection time is unavailable or stale')
            if missing and status != 'excluded':
                status = 'conditional'
            evaluated.append({**candidate, 'status': status, 'prerequisites': missing})
            if status != 'excluded':
                for key, value in (policy.get('settings') or {}).items():
                    settings[key] = {'value': value, 'gpo_id': candidate['gpo_id'], 'status': status}
        observation = target.get('rsop')
        if observation is None and rsop:
            # XML observations need an explicit target binding in the input document.
            if target.get('rsop_source') == rsop.get('source'):
                observation = {'applied_gpos': rsop.get('sections', {}).get(kind, []), 'collected_at': target.get('rsop_collected_at')}
        observed, differences = [], {}
        if observation:
            try:
                stamp = datetime.fromisoformat(str(observation.get('collected_at')).replace('Z', '+00:00'))
                fresh = stamp.tzinfo is not None and now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5)
            except ValueError:
                fresh = False
            observed = [gpo_id(value) for value in observation.get('applied_gpos', [])]
            predicted = {row['gpo_id'] for row in evaluated if row['status'] != 'excluded'}
            differences = {'status': 'observed' if fresh else 'stale', 'only_observed': sorted(set(observed) - predicted),
                           'only_predicted': sorted(predicted - set(observed))}
        observed_settings = observation.get('settings', {}) if observation else {}
        setting_comparison = {key: {'predicted': setting['value'], 'observed': observed_settings[key],
                                    'matches': setting['value'] == observed_settings[key],
                                    'status': differences.get('status', 'unknown')}
                              for key, setting in settings.items() if key in observed_settings}
        results.append({'target': dn, 'kind': kind, 'policies': evaluated, 'settings': settings,
                        'setting_comparison': setting_comparison,
                        'metadata_complete': metadata_complete, 'observed_applied_gpos': observed, 'comparison': differences})
    return {'schema_version': 1, 'targets': results, 'errors': document.get('errors', []),
            'limitation': 'Predictions require complete container metadata, Read/Apply permissions and WMI outcomes. Local/site policy and loopback require RSoP confirmation.'}
