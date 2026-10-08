"""Opt-in scoped service observations; no relay, exploitation or credential probes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.client
import socket
import ssl
from urllib.parse import urlsplit

from core.exceptions import ValidationError


def verify_protocols(targets, endpoints, scope, *, timeout=10, local_evidence=None, smb_factory=None):
    records = []
    if len(targets) > 100 or len(endpoints) > 100:
        raise ValidationError('Protocol verification is limited to 100 hosts and 100 endpoints')
    for host in targets:
        connection = None
        try:
            scope.consume(host, 'smb')
            if smb_factory is None:
                from impacket.smbconnection import SMBConnection
                factory = SMBConnection
            else:
                factory = smb_factory
            connection = factory(host, host, sess_port=445, timeout=timeout)
            required = bool(connection.isSigningRequired())
            records.append({'target': host, 'check': 'smb_signing_required', 'status': 'observed', 'value': required,
                            'evidence': 'Unauthenticated SMB negotiation; signing requirement bit observed'})
        except Exception as exc:
            records.append({'target': host, 'check': 'smb_signing_required', 'status': 'unknown', 'reason': str(exc)[:300]})
        finally:
            if connection:
                try:
                    connection.close()
                except Exception as exc:
                    records.append({'target': host, 'check': 'smb_cleanup', 'status': 'unknown', 'reason': str(exc)[:200]})
        try:
            scope.consume(host, 'ldaps')
            with socket.create_connection((host, 636), timeout=timeout) as transport:
                with ssl.create_default_context().wrap_socket(transport, server_hostname=host) as tls:
                    records.append({'target': host, 'check': 'ldaps_tls', 'status': 'observed', 'value': True,
                                    'tls_version': tls.version(), 'evidence': 'Certificate chain and hostname verified'})
        except Exception as exc:
            records.append({'target': host, 'check': 'ldaps_tls', 'status': 'unknown', 'reason': str(exc)[:300]})
    for endpoint in endpoints:
        parts = urlsplit(endpoint)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValidationError('Enrollment endpoints require HTTP(S) URLs without credentials/fragments')
        if parts.port not in (None, 80, 443):
            raise ValidationError('Enrollment probes support only standard HTTP(S) ports')
        connection = None
        try:
            scope.consume(parts.hostname, 'adcs_http')
            cls = http.client.HTTPSConnection if parts.scheme == 'https' else http.client.HTTPConnection
            connection = cls(parts.hostname, port=parts.port, timeout=timeout)
            connection.request('HEAD', parts.path or '/', headers={'User-Agent': 'AtilKurt-read-only-assessment'})
            response = connection.getresponse()
            challenge = response.getheader('WWW-Authenticate', '')
            records.append({'target': endpoint, 'check': 'adcs_endpoint', 'status': 'observed', 'http_status': response.status,
                            'tls_verified': parts.scheme == 'https', 'ntlm_advertised': 'ntlm' in challenge.casefold(),
                            'redirect_followed': False, 'epa_required': 'unknown'})
        except Exception as exc:
            records.append({'target': endpoint, 'check': 'adcs_endpoint', 'status': 'unknown', 'reason': str(exc)[:300]})
        finally:
            if connection:
                connection.close()
    now = datetime.now(timezone.utc)
    policies = (local_evidence or {}).get('policies', [])
    if not isinstance(policies, list) or len(policies) > 1000:
        raise ValidationError('Protocol policy evidence must be a bounded list')
    grouped = {}
    for row in policies:
        if not isinstance(row, dict) or row.get('check') not in {'epa_required', 'ldap_signing_required', 'channel_binding_required'}:
            raise ValidationError('Unsupported protocol policy evidence')
        target, check = row.get('target'), row['check']
        if not isinstance(target, str) or not isinstance(row.get('value'), bool):
            raise ValidationError('Protocol evidence requires target and a boolean value')
        scope.check_host(target, 'adcs_http' if check == 'epa_required' else 'ldaps')
        try:
            stamp = datetime.fromisoformat(str(row.get('collected_at')).replace('Z', '+00:00'))
            fresh = stamp.tzinfo is not None and now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5)
        except ValueError:
            fresh = False
        grouped.setdefault((target.casefold(), check), []).append((row, fresh))
    for (_, check), rows in grouped.items():
        row = rows[0][0]
        observed = all(fresh and item.get('source') for item, fresh in rows) and len({item['value'] for item, _ in rows}) == 1
        records.append({'target': row['target'], 'check': check, 'status': 'observed' if observed else 'unknown',
                        'value': row['value'] if observed else None, 'evidence': 'Local configuration evidence',
                        'reason': None if observed else 'Stale, conflicting or incomplete policy evidence'})
    risks = []
    for row in records:
        if row.get('status') == 'observed' and row.get('value') is False:
            risks.append({'type': 'protocol_' + row['check'], 'title': row['check'].replace('_', ' ').capitalize() + ' disabled',
                          'severity': 'Medium', 'affected_object': row['target'], 'description': row['evidence'],
                          'recommendation': 'Review compatibility and enforce the service protection policy.',
                          'source': 'protocol_verification', 'requires_validation': False})
    return {'schema_version': 1, 'collected_at': now.isoformat(), 'checks': records, 'risks': risks,
            'limitation': 'TLS availability does not prove LDAP signing, channel binding or AD CS EPA. Those require fresh local configuration evidence.'}
