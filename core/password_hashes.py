"""Bounded, read-only DRS collection of current domain account key material.

Impacket runs in an isolated process: its diagnostic messages never become
report evidence or console output, and a stalled RPC cannot hang the scan.
Only accounts already returned by the scoped LDAP inventory are requested.
"""

from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter
import logging
import multiprocessing
import re
import time

from uuid import UUID

from core.ad_security import as_text, sid_text
from core.assessment_scope import ScopeLimitError
from core.security_descriptor_parser import directory_right_granted, parse_security_descriptor

HEX_HASH = re.compile(r'^[0-9a-fA-F]{32}$')
_HISTORY_ACCOUNT = re.compile(r'(?i)^(?P<name>.*)_history(?P<index>\d+)$')
EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'
EMPTY_LM = 'aad3b435b51404eeaad3b435b51404ee'
GET_CHANGES = UUID('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2').bytes_le
GET_CHANGES_ALL = UUID('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2').bytes_le
DENIED_CODES = {5, 8453, 0xC0000022, 0xC000006D, 0xC000006A}
LIMITATION = (
    'Current LM/NTLM values, NT password-history digests and available Kerberos long-term keys for '
    'LDAP-inventoried users and computers only. Local SAM/LSA, deleted objects, trust secrets and roast '
    'ticket responses are not collected. Empty-hash placeholders do not prove an empty password. '
    'No privilege escalation or directory writes are performed.'
)


def _error(exc):
    """Keep stable diagnostic codes, never exception text that may contain secrets."""
    getter = getattr(exc, 'get_error_code', None) or getattr(exc, 'getErrorCode', None)
    code = getter() if getter else None
    reason = 'access_denied' if code in DENIED_CODES else {
        8439: 'replication_bad_dn', 8440: 'replication_bad_naming_context',
    }.get(code, 'transport_or_protocol_error')
    return {'reason': reason,
            'exception_type': type(exc).__name__, 'code': code if isinstance(code, int) else None}


def _digest(value):
    """Accept a 32-character digest. A blank LM field is the empty LM placeholder."""
    if value == '':
        return EMPTY_LM
    if not HEX_HASH.fullmatch(value):
        raise ValueError('Invalid NTDS callback')
    return value.lower()


def _store_ntlm(record, account, lm, ntlm):
    history = _HISTORY_ACCOUNT.fullmatch(account)
    if history:
        if history.group('name').casefold() != record['account'].casefold():
            raise ValueError('Invalid NTDS callback')
        if ntlm == EMPTY_NT:
            return
        entry = {'index': int(history.group('index')), 'lm': lm, 'ntlm': ntlm,
                 'empty_lm_placeholder': lm == EMPTY_LM}
        record.setdefault('nt_history', [])
        if entry not in record['nt_history']:
            record['nt_history'].append(entry)
        return
    if account.casefold() != record['account'].casefold():
        raise ValueError('Invalid NTDS callback')
    record['lm'], record['ntlm'] = lm, ntlm
    record['empty_lm_placeholder'] = lm == EMPTY_LM
    record['empty_hash_placeholder'] = ntlm == EMPTY_NT


def accept_secret(record, kind, value):
    """Parse Impacket's typed callbacks, retaining only hash/key material."""
    if kind == 1:  # NTDS_CLEARTEXT: outside the requested hash collection.
        return
    if kind == 0:
        parts = value.split(':')
        if len(parts) != 7 or parts[1] != record['sid'].rsplit('-', 1)[-1]:
            raise ValueError('Invalid NTDS callback')
        _store_ntlm(record, parts[0].rsplit('\\', 1)[-1], _digest(parts[2]), _digest(parts[3]))
    elif kind == 2:
        account, algorithm, key = value.rsplit(':', 2)
        # Impacket 0.13 uses these legacy labels in KERBEROS_TYPE.
        algorithm = {'dec-cbc-crc': 'des-cbc-crc', 'rc4_hmac': 'rc4-hmac'}.get(algorithm, algorithm)
        lengths = {'aes256-cts-hmac-sha1-96': 64, 'aes128-cts-hmac-sha1-96': 32,
                   'des-cbc-md5': 16, 'des-cbc-crc': 16, 'rc4-hmac': 32}
        if (account.rsplit('\\', 1)[-1].casefold() != record['account'].casefold()
                or algorithm not in lengths or not re.fullmatch(rf'[0-9a-fA-F]{{{lengths[algorithm]}}}', key)):
            raise ValueError('Invalid Kerberos callback')
        entry = {'algorithm': algorithm, 'kerberos_key': key.lower()}
        if entry not in record['kerberos_keys']:
            record['kerberos_keys'].append(entry)
    else:
        raise ValueError('Unknown NTDS callback type')


class _DiagnosticCounter(logging.Handler):
    """Notice upstream swallowed errors without retaining their text."""
    def __init__(self):
        super().__init__(logging.WARNING)
        self.count = 0

    def emit(self, record):
        self.count += 1


def _worker(pipe, config):
    # This logging change is process-local; scanner logging remains intact.
    diagnostics = _DiagnosticCounter()
    logging.basicConfig(handlers=[diagnostics], level=logging.WARNING, force=True)
    smb = remote = None
    try:
        from impacket.examples.secretsdump import NTDSHashes, RemoteOperations
        from impacket.smbconnection import SMBConnection

        class ReusedRemoteOperations(RemoteOperations):
            samr_ready = False
            inventory_record = None

            def connectSamr(self, domain):
                if not self.samr_ready:
                    super().connectSamr(domain)
                    self.samr_ready = True

            def getDomainUsersLDAP(self, searchFilter):
                # Reuse the scoped inventory instead of opening an unscoped second LDAP session.
                row = self.inventory_record
                return [(self.getMachineNameAndDomain()[1] + '\\' + row['account'], row['sid'])]

        smb = SMBConnection(config['host'], config['host'], timeout=config['timeout'])
        smb.login(config['username'], config['password'], config['domain'])
        remote = ReusedRemoteOperations(smb, False)
        smb.setTimeout(config['timeout'])  # RemoteOperations otherwise resets this to five minutes.
        # NTDSHashes otherwise silently returns when this preflight fails.
        remote.connectSamr(remote.getMachineNameAndDomain()[1])
        while True:
            pipe.send({'event': 'ready'})
            record = pipe.recv()
            if record is None:
                break
            diagnostics.count = 0
            dumper = None
            fatal = False
            try:
                remote.inventory_record = record
                dumper = NTDSHashes(None, None, isRemote=True, remoteOps=remote,
                                    ldapFilter='(objectSid=' + record['sid'] + ')', justNTLM=False,
                                    history=True, noLMHash=False, outputFileName=None,
                                    perSecretCallback=lambda kind, value, record=record: accept_secret(record, kind, value))
                dumper.dump()
                if diagnostics.count:
                    record['errors'].append({'reason': 'upstream_processing_error', 'count': diagnostics.count})
                if not record['ntlm']:
                    record['errors'].append({'reason': 'no_hash_returned'})
            except Exception as exc:
                error = _error(exc)
                record['errors'].append(error)
                fatal = error['reason'] == 'access_denied'
            finally:
                if dumper is not None:
                    dumper.finish()
            record['status'] = 'partial' if record['ntlm'] and record['errors'] else (
                'collected' if record['ntlm'] else 'failed')
            pipe.send({'event': 'record', 'record': record})
            if fatal:
                pipe.send({'event': 'error', 'error': {'reason': 'access_denied'}})
                break
    except Exception as exc:
        pipe.send({'event': 'error', 'error': _error(exc)})
    finally:
        for resource, method in ((remote, 'finish'), (smb, 'close')):
            if resource is not None:
                try:
                    getattr(resource, method)()
                except Exception as exc:
                    pipe.send({'event': 'error', 'error': {'reason': 'cleanup_failed', 'exception_type': type(exc).__name__}})
        pipe.send({'event': 'done'})
        pipe.close()


def _descriptor_bytes(value):
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, str):
        value = value.encode('latin-1')
    return bytes(value) if isinstance(value, (bytes, bytearray)) else None


def replication_authorization(parsed, sid, token_sids):
    """Both replication controls are required before any account hash is requested."""
    token = set(token_sids or ())
    rights = {
        'get_changes': directory_right_granted(parsed, sid, 0x100, GET_CHANGES, token),
        'get_changes_all': directory_right_granted(parsed, sid, 0x100, GET_CHANGES_ALL, token),
    }
    return {'status': 'authorized' if all(rights.values()) else 'not_authorized', 'rights': rights}


def domain_replication_authorization(ldap, identity):
    """Read the domain DACL once and decide whether DRS collection can succeed."""
    identity = identity or {}
    sid = identity.get('sid')
    groups = identity.get('token_groups') or {}
    if not sid or groups.get('status') != 'collected':
        return {'status': 'unknown', 'reason': 'identity_unresolved',
                'rights': {'get_changes': None, 'get_changes_all': None}}
    search, base = getattr(ldap, 'base_search', None), getattr(ldap, 'base_dn', None)
    if not callable(search) or not base:
        return {'status': 'unknown', 'reason': 'descriptor_unreadable',
                'rights': {'get_changes': None, 'get_changes_all': None}}
    try:
        rows = search(base, ['nTSecurityDescriptor'])
        raw = _descriptor_bytes((rows or [None])[0].get('nTSecurityDescriptor') if len(rows or []) == 1 else None)
        parsed = parse_security_descriptor(raw) if raw else {'parse_valid': False}
    except Exception as exc:
        return {'status': 'unknown', 'reason': type(exc).__name__,
                'rights': {'get_changes': None, 'get_changes_all': None}}
    if parsed.get('parse_valid') is False:
        return {'status': 'unknown', 'reason': 'descriptor_unreadable',
                'rights': {'get_changes': None, 'get_changes_all': None}}
    return replication_authorization(parsed, sid, groups.get('sids'))


def collect_password_hashes(data, *, host, domain, username, password, timeout=30, max_seconds=300, scope=None,
                            authorization=None):
    """Collect in a killable child, preserving completed records on timeout/denial."""
    started = time.monotonic()
    result = {'schema_version': 1, 'status': 'failed', 'method': 'DRSUAPI', 'target': host,
              'collected_at': datetime.now(timezone.utc).isoformat(), 'records': [], 'errors': [],
              'limitation': LIMITATION, 'inventory_status': (data.get('collection_health') or {}).get('status', 'unknown')}
    seen = set()
    for obj in [*data.get('users', []), *data.get('computers', [])]:
        account, sid = as_text(obj.get('sAMAccountName')), sid_text(obj.get('objectSid'))
        if not account or not sid:
            result['errors'].append({'reason': 'inventory_missing_account_or_sid'})
            continue
        if sid in seen:
            continue
        seen.add(sid)
        if scope and not scope.allows_dn(obj.get('distinguishedName') or ''):
            continue
        result['records'].append({'account': account, 'sid': sid, 'dn': obj.get('distinguishedName'),
                                  'status': 'not_attempted', 'lm': None, 'ntlm': None, 'nt_history': [],
                                  'kerberos_keys': [], 'errors': []})
    records = result['records']
    result['authorization'] = authorization or {'status': 'unknown'}
    parent = child = process = None
    try:
        if timeout <= 0 or max_seconds <= 0:
            raise ValueError('Collection timeouts must be positive')
        if result['authorization'].get('status') == 'not_authorized':
            result['errors'].append({'reason': 'replication_not_authorized'})
        elif not records:
            result['errors'].append({'reason': 'no_inventory_accounts'})
        else:
            if scope:
                scope.check_host(host, 'drs')
                scope.consume(host, 'smb')
                max_seconds = min(max_seconds, scope.max_seconds - (scope.clock() - scope.started))
            context = multiprocessing.get_context('spawn')
            parent, child = context.Pipe()
            process = context.Process(target=_worker, args=(child, {
                'host': host, 'domain': domain, 'username': username, 'password': password, 'timeout': timeout,
            }), daemon=True)
            process.start()
            child.close()
            index = 0
            while True:
                remaining = max_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    result['errors'].append({'reason': 'time_budget_exceeded'})
                    break
                if not parent.poll(min(0.2, remaining)):
                    if not process.is_alive():
                        result['errors'].append({'reason': 'worker_exited_without_completion'})
                        break
                    continue
                message = parent.recv()
                if message['event'] == 'ready':
                    if index == len(records):
                        parent.send(None)
                    else:
                        if scope:
                            scope.consume(host, 'drs')
                        records[index]['status'] = 'attempting'
                        parent.send(records[index])
                        index += 1
                elif message['event'] == 'record':
                    records[index - 1] = message['record']
                elif message['event'] == 'error':
                    result['errors'].append(message['error'])
                elif message['event'] == 'done':
                    break
    except ScopeLimitError:
        result['errors'].append({'reason': 'scope_or_request_budget_exceeded'})
    except Exception as exc:
        result['errors'].append(_error(exc))
    finally:
        if process is not None and process.pid is not None:
            process.join(timeout=0.5)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
            process.close()
        for connection in (parent, child):
            if connection is not None:
                connection.close()
    for record in records:
        if record['status'] == 'attempting':
            record['status'] = 'failed'
            record['errors'].append({'reason': 'interrupted'})
    collected = sum(bool(record['ntlm']) for record in records)
    result['summary'] = {'requested': len(records), 'collected': collected,
                         'attempted': sum(record['status'] != 'not_attempted' for record in records),
                         'failed': sum(record['status'] in {'failed', 'partial'} for record in records),
                         'not_attempted': sum(record['status'] == 'not_attempted' for record in records),
                         'kerberos_keys': sum(len(record['kerberos_keys']) for record in records),
                         'password_history': sum(len(record.get('nt_history') or []) for record in records)}
    complete = bool(records) and all(record['status'] == 'collected' for record in records) and not result['errors']
    result['status'] = 'completed' if complete and result['inventory_status'] == 'completed' else ('partial' if collected else 'failed')
    result['elapsed_seconds'] = round(time.monotonic() - started, 3)
    counts = Counter((error.get('reason'), error.get('code')) for row in records for error in row['errors'])
    result['error_summary'] = [{'reason': reason, 'code': code, 'accounts': count} for (reason, code), count in counts.items()]
    return result
