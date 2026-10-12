"""Bounded parsing of offline GPO policy content; no policy execution."""

from __future__ import annotations

import configparser
import csv
import hashlib
import io
from pathlib import Path
import struct
from uuid import UUID

from core.exceptions import ValidationError

MAX_BYTES = 4 * 1024 * 1024
POLICIES = {
    ('software\\policies\\microsoft\\windows\\ntds\\parameters', 'ldapserverintegrity'): 'LDAPServerIntegrity',
    ('system\\currentcontrolset\\services\\ntds\\parameters', 'ldapserverintegrity'): 'LDAPServerIntegrity',
    ('system\\currentcontrolset\\services\\ntds\\parameters', 'ldapserverenforceintegrity'): 'LDAPServerEnforceIntegrity',
    ('system\\currentcontrolset\\services\\ntds\\parameters', 'ldapenforcechannelbinding'): 'LdapEnforceChannelBinding',
    ('system\\currentcontrolset\\services\\lanmanserver\\parameters', 'requiresecuritysignature'): 'RequireSecuritySignature',
    ('system\\currentcontrolset\\services\\netlogon\\parameters', 'restrictntlmindomain'): 'RestrictNTLMInDomain',
    ('system\\currentcontrolset\\control\\lsa\\msv1_0', 'restrictreceivingntlmtraffic'): 'RestrictReceivingNTLMTraffic',
    ('system\\currentcontrolset\\control\\lsa\\msv1_0', 'restrictsendingntlmtraffic'): 'RestrictSendingNTLMTraffic',
}


def parse_registry_pol(raw):
    if len(raw) > MAX_BYTES or raw[:8] != b'PReg\x01\x00\x00\x00':
        raise ValidationError('Invalid Registry.pol header or file size')
    offset, rows = 8, []

    def expect(value):
        nonlocal offset
        if raw[offset:offset + len(value)] != value:
            raise ValidationError('Malformed Registry.pol delimiter')
        offset += len(value)

    def text():
        nonlocal offset
        start = offset
        while offset + 2 <= len(raw):
            if raw[offset:offset + 2] == b'\x00\x00':
                value = raw[start:offset].decode('utf-16-le')
                offset += 2
                return value
            offset += 2
        raise ValidationError('Unterminated Registry.pol string')

    def integer():
        nonlocal offset
        if offset + 4 > len(raw):
            raise ValidationError('Truncated Registry.pol integer')
        value = struct.unpack_from('<I', raw, offset)[0]
        offset += 4
        return value

    try:
        while offset < len(raw):
            if len(rows) >= 10000:
                raise ValidationError('Registry.pol entry limit exceeded')
            expect(b'[\x00')
            key = text()
            expect(b';\x00')
            name = text()
            expect(b';\x00')
            kind = integer()
            expect(b';\x00')
            size = integer()
            expect(b';\x00')
            if size > MAX_BYTES or offset + size > len(raw):
                raise ValidationError('Registry.pol value exceeds remaining input')
            payload = raw[offset:offset + size]
            offset += size
            expect(b']\x00')
            rows.append({'key': key, 'name': name, 'type': kind,
                         'value': struct.unpack('<I', payload)[0] if kind == 4 and size == 4 else None})
    except UnicodeError as exc:
        raise ValidationError('Invalid Registry.pol UTF-16 string') from exc
    return rows


def read_policy_file(path):
    try:
        return _read_policy_file(path)
    except (UnicodeError, ValueError, configparser.Error, csv.Error) as exc:
        raise ValidationError(f'Invalid {Path(path).name} policy content') from exc


def _read_policy_file(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValidationError('GPO policy content exceeds 4 MiB')
    settings, audit, directives = {}, {}, []
    if Path(path).name.casefold() == 'registry.pol':
        rows = parse_registry_pol(raw)
    else:
        text = raw.decode('utf-16' if raw.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
        if Path(path).name.casefold() == 'gpttmpl.inf':
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string(text)
            rows = []
            for key, value in parser.items('Registry Values') if parser.has_section('Registry Values') else []:
                kind, separator, scalar = value.partition(',')
                if separator and kind.strip() == '4':
                    location = key.removeprefix('machine\\').rsplit('\\', 1)
                    if len(location) == 2:
                        rows.append({'key': location[0], 'name': location[1], 'value': int(scalar.strip(), 0)})
        elif Path(path).name.casefold() == 'audit.csv':
            rows = []
            for row in csv.reader(io.StringIO(text)):
                if len(row) < 7:
                    continue
                try:
                    identifier = str(UUID(row[3].strip('{}')))
                    value = int(row[-1])
                except ValueError:
                    continue
                if value not in (0, 1, 2, 3):
                    raise ValidationError('Invalid audit.csv setting value')
                if identifier in audit and audit[identifier] != value:
                    raise ValidationError('Conflicting audit.csv subcategory values')
                audit[identifier] = value
        else:
            raise ValidationError('Unsupported policy file; expected Registry.pol, GptTmpl.inf or audit.csv')
    for row in rows:
        if row['name'].startswith('**'):
            directives.append({'key': row['key'], 'name': row['name']})
        setting = POLICIES.get((row['key'].casefold(), row['name'].casefold()))
        if setting and row['value'] is not None:
            if setting in settings and settings[setting] != row['value']:
                raise ValidationError('Conflicting policy setting values')
            settings[setting] = row['value']
    return {'settings': settings, 'audit_subcategories': audit, 'unresolved_directives': directives, 'source': str(path),
            'sha256': hashlib.sha256(raw).hexdigest()}


def attach_policy_content(context, paths, *, require_signed=False):
    """Bind files to explicit GPO IDs; signed contexts must authenticate their hashes."""
    from copy import deepcopy
    from analysis.effective_gpo_analyzer import gpo_id
    result = deepcopy(context)
    if not isinstance(result, dict):
        raise ValidationError('GPO policy content requires --gpo-context')
    rows = result.get('gpos', [])
    if not isinstance(rows, list) or len(rows) > 10000 or any(not isinstance(row, dict) for row in rows):
        raise ValidationError('GPO policy content requires a bounded list of GPO objects')
    policies = {}
    for policy in rows:
        if not isinstance(policy.get('settings', {}), dict):
            raise ValidationError('GPO settings must be an object')
        for field in ('policy_sha256', 'content_evidence'):
            if not isinstance(policy.get(field, []), list):
                raise ValidationError(f'GPO {field} must be a list')
        identifier = gpo_id(policy.get('id') or policy.get('name'))
        if identifier in policies:
            raise ValidationError('Policy content requires unique GPO identifiers')
        policies[identifier] = policy
    for specification in paths:
        identifier, separator, path = specification.partition('=')
        if not separator or gpo_id(identifier) not in policies:
            raise ValidationError('Policy files require GPO_ID=PATH matching an imported GPO')
        content = read_policy_file(path)
        policy = policies[gpo_id(identifier)]
        if require_signed and content['sha256'] not in policy.get('policy_sha256', []):
            raise ValidationError('Signed GPO context does not authenticate the policy content digest')
        existing = policy.setdefault('settings', {})
        for name, value in content['settings'].items():
            if name in existing and existing[name] != value:
                raise ValidationError('Imported policy content contradicts supplied GPO settings')
            existing[name] = value
        policy.setdefault('content_evidence', []).append(content)
    return result
