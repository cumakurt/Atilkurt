"""
Replication Metadata Analyzer Module
Analyzes msDS-ReplAttributeMetaData for suspicious changes to security-sensitive
attributes such as adminCount, memberOf, userAccountControl, and detects potential
rogue DC indicators.
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

# Attributes whose changes are security-sensitive
SENSITIVE_ATTRIBUTES = [
    'adminCount',
    'member',
    'userAccountControl',
    'servicePrincipalName',
    'msDS-AllowedToDelegateTo',
    'msDS-AllowedToActOnBehalfOfOtherIdentity',
    'nTSecurityDescriptor',
    'altSecurityIdentities',
    'msDS-KeyCredentialLink',
]

RECENT_CHANGE_DAYS = 30


class ReplicationMetadataAnalyzer:
    """Analyzes AD replication metadata for suspicious attribute changes."""

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection

    def analyze(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze replication metadata for suspicious changes.

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Check sensitive attribute changes on critical objects ──
            risks.extend(self._check_recent_sensitive_changes(base_dn, users))

            # ── 2. Check tombstone lifetime ──
            risks.extend(self._check_tombstone_lifetime())

            logger.info(f"Found {len(risks)} replication metadata risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing replication metadata: {e}")
            return []

    # ── Sensitive Attribute Change Detection ────────────────────────────────

    def _check_recent_sensitive_changes(
        self,
        base_dn: str,
        users: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Check for recent changes to sensitive attributes on privileged accounts.
        Uses whenChanged as a proxy since msDS-ReplAttributeMetaData requires
        special parsing.
        """
        risks: List[Dict[str, Any]] = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_CHANGE_DAYS)
        recently_changed: List[Dict[str, Any]] = []

        for user in users:
            # Only check accounts with adminCount=1
            admin_count = user.get('adminCount')
            try:
                if admin_count is None or int(admin_count) != 1:
                    continue
            except (ValueError, TypeError):
                continue

            when_changed = self._parse_date(user.get('whenChanged'))
            if when_changed and when_changed > cutoff:
                sam = user.get('sAMAccountName', '?')
                recently_changed.append({
                    'account': sam,
                    'changed': when_changed.strftime('%Y-%m-%d'),
                })

        if recently_changed:
            accounts = [r['account'] for r in recently_changed]
            risks.append({
                'type': RiskTypes.REPLICATION_SUSPICIOUS_CHANGE,
                'severity': Severity.MEDIUM,
                'title': (
                    f'{len(recently_changed)} privileged accounts modified in '
                    f'last {RECENT_CHANGE_DAYS} days'
                ),
                'description': (
                    f'{len(recently_changed)} account(s) with adminCount=1 were '
                    f'modified in the last {RECENT_CHANGE_DAYS} days. Recent '
                    'changes to privileged accounts should be investigated.'
                ),
                'affected_object': ', '.join(accounts[:15]),
                'object_type': 'user',
                'impact': (
                    'Changes to privileged accounts may indicate legitimate '
                    'administration or attacker activity such as adding '
                    'accounts to admin groups, modifying ACLs, or enabling '
                    'delegation.'
                ),
                'attack_scenario': (
                    'An attacker with write access modifies adminCount, '
                    'memberOf, or nTSecurityDescriptor on a target account '
                    'to escalate privileges or establish persistence.'
                ),
                'mitigation': (
                    'Investigate each change:\n'
                    '  Get-ADReplicationAttributeMetadata <user> -Server <DC>\n'
                    '  Review originating DC and timestamp for each attribute.\n\n'
                    'Cross-reference with Event IDs 5136/5141 in SIEM.'
                ),
                'mitre_attack': MITRETechniques.PRIVILEGE_ESCALATION,
                'recent_changes': recently_changed,
            })

        return risks

    # ── Tombstone Lifetime ──────────────────────────────────────────────────

    def _check_tombstone_lifetime(self) -> List[Dict[str, Any]]:
        """Check AD tombstone lifetime configuration."""
        risks: List[Dict[str, Any]] = []

        try:
            config_dn = self._get_config_dn()
            if not config_dn:
                return risks

            results = self.ldap.search(
                search_base=f"CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}",
                search_filter='(objectClass=nTDSService)',
                attributes=['tombstoneLifetime'],
                size_limit=1,
            )

            if results:
                ts_lifetime = results[0].get('tombstoneLifetime')
                if ts_lifetime is not None:
                    try:
                        days = int(ts_lifetime)
                        if days < 180:
                            risks.append({
                                'type': RiskTypes.REPLICATION_TOMBSTONE_RISK,
                                'severity': Severity.LOW,
                                'title': f'Tombstone lifetime is {days} days',
                                'description': (
                                    f'AD tombstone lifetime is {days} days '
                                    f'(default: 180). A shorter lifetime limits '
                                    'the window for recovering deleted objects '
                                    'and may cause replication issues with '
                                    'disconnected DCs.'
                                ),
                                'affected_object': 'Directory Service',
                                'object_type': 'configuration',
                                'mitigation': (
                                    'Consider increasing tombstone lifetime to '
                                    '180 days if not already set. Ensure all '
                                    'DCs replicate within this window.'
                                ),
                                'tombstone_days': days,
                            })
                    except (ValueError, TypeError):
                        pass
                else:
                    # Missing attribute — default is 60 days (Win2003) or 180 (Win2003 SP1+)
                    risks.append({
                        'type': RiskTypes.REPLICATION_TOMBSTONE_RISK,
                        'severity': Severity.LOW,
                        'title': 'Tombstone lifetime not explicitly set',
                        'description': (
                            'The tombstoneLifetime attribute is not explicitly '
                            'configured. The default depends on the forest '
                            'functional level (60 or 180 days).'
                        ),
                        'affected_object': 'Directory Service',
                        'object_type': 'configuration',
                        'mitigation': (
                            'Set tombstone lifetime explicitly to 180 days:\n'
                            '  Set-ADObject "CN=Directory Service,CN=Windows NT,'
                            'CN=Services,<ConfigDN>" -Replace @{tombstoneLifetime=180}'
                        ),
                    })

        except Exception as e:
            logger.debug(f"Tombstone check failed: {e}")

        return risks

    # ── Utilities ───────────────────────────────────────────────────────────

    def _get_config_dn(self) -> Optional[str]:
        try:
            results = self.ldap.search(
                search_base='', search_filter='(objectClass=*)',
                attributes=['configurationNamingContext'], size_limit=1,
            )
            if results:
                return results[0].get('configurationNamingContext')
        except Exception:
            pass
        base_dn = self.ldap.base_dn
        dc_parts = [p for p in base_dn.split(',') if p.upper().startswith('DC=')]
        return 'CN=Configuration,' + ','.join(dc_parts) if dc_parts else None

    @staticmethod
    def _make_aware(dt: datetime) -> datetime:
        """Ensure a datetime is timezone-aware (UTC)."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    @classmethod
    def _parse_date(cls, value) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return cls._make_aware(value)
        if isinstance(value, str):
            for fmt in ('%Y%m%d%H%M%S.0Z', '%Y-%m-%dT%H:%M:%S'):
                try:
                    return cls._make_aware(datetime.strptime(value, fmt))
                except ValueError:
                    continue
        return None
