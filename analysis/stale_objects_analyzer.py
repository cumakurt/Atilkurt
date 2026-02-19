"""
Stale Objects Analyzer Module
Detects dormant, orphaned, and hygiene-risk AD objects that expand the attack surface:
  - Long-inactive enabled accounts
  - Ancient passwords on enabled accounts
  - Descriptions containing credentials
  - Orphan ACEs referencing deleted SIDs
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

# Thresholds (days)
INACTIVE_ACCOUNT_DAYS = 180
ANCIENT_PASSWORD_DAYS = 365
STALE_COMPUTER_DAYS = 180

# Patterns that suggest credentials in description/info fields.
# Intentional: Turkish keywords (sifre, parola) for multilingual credential detection.
_CREDENTIAL_PATTERNS = re.compile(
    r'(?:password|passwd|pass|şifre|parola|pwd)\s*[:=]\s*\S+',
    re.IGNORECASE,
)


class StaleObjectsAnalyzer:
    """Detects stale, orphaned, and hygiene-risk AD objects."""

    def __init__(self, ldap_connection=None):
        """
        Initialize stale objects analyzer.

        Args:
            ldap_connection: Optional LDAPConnection instance
                             (only needed for orphan-ACE checks)
        """
        self.ldap = ldap_connection

    def analyze(
        self,
        users: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze all AD objects for staleness and hygiene issues.

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        risks.extend(self._check_inactive_users(users))
        risks.extend(self._check_ancient_passwords(users))
        risks.extend(self._check_description_leaks(users, groups))
        risks.extend(self._check_stale_computers(computers))
        risks.extend(self._check_orphan_sids(users, groups))

        logger.info(f"Found {len(risks)} stale-object risks")
        return risks

    # ── Inactive Enabled Users ──────────────────────────────────────────────

    def _check_inactive_users(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect enabled accounts that have not logged in for a long time."""
        risks: List[Dict[str, Any]] = []
        inactive: List[str] = []
        now = datetime.now(timezone.utc)

        for user in users:
            if self._is_disabled(user):
                continue

            last_logon = self._parse_date(
                user.get('lastLogonTimestamp') or user.get('lastLogon')
            )
            if last_logon is None:
                continue

            days_idle = (now - last_logon).days
            if days_idle >= INACTIVE_ACCOUNT_DAYS:
                inactive.append(user.get('sAMAccountName', '?'))

        if inactive:
            risks.append({
                'type': RiskTypes.STALE_INACTIVE_ACCOUNT,
                'severity': Severity.MEDIUM,
                'title': f'{len(inactive)} enabled accounts inactive >{INACTIVE_ACCOUNT_DAYS} days',
                'description': (
                    f'{len(inactive)} enabled user account(s) have not logged '
                    f'in for over {INACTIVE_ACCOUNT_DAYS} days. Dormant '
                    'accounts are prime targets for credential stuffing and '
                    'pass-the-hash attacks.'
                ),
                'affected_object': ', '.join(inactive[:20])
                    + (f' ... (+{len(inactive)-20} more)' if len(inactive) > 20 else ''),
                'object_type': 'user',
                'impact': (
                    'Dormant accounts may have weak or cached passwords and are '
                    'unlikely to be monitored, making them ideal for attackers.'
                ),
                'mitigation': (
                    'Disable or delete accounts that no longer need access. '
                    'Implement an automated account lifecycle policy that '
                    'disables accounts after 90 days of inactivity.'
                ),
                'cis_reference': 'CIS Benchmark §1.1.4 — Disable dormant accounts',
                'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                'inactive_accounts': inactive,
                'inactive_count': len(inactive),
            })

        return risks

    # ── Ancient Passwords ───────────────────────────────────────────────────

    def _check_ancient_passwords(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect enabled accounts whose passwords haven't been changed in >1 year."""
        risks: List[Dict[str, Any]] = []
        ancient: List[str] = []
        now = datetime.now(timezone.utc)

        for user in users:
            if self._is_disabled(user):
                continue

            pwd_date = self._parse_date(user.get('pwdLastSet'))
            if pwd_date is None:
                continue

            days_old = (now - pwd_date).days
            if days_old >= ANCIENT_PASSWORD_DAYS:
                ancient.append(user.get('sAMAccountName', '?'))

        if ancient:
            risks.append({
                'type': RiskTypes.STALE_ANCIENT_PASSWORD,
                'severity': Severity.MEDIUM,
                'title': f'{len(ancient)} accounts with password >{ANCIENT_PASSWORD_DAYS} days old',
                'description': (
                    f'{len(ancient)} enabled account(s) have passwords '
                    f'older than {ANCIENT_PASSWORD_DAYS} days. Old passwords '
                    'increase the window of opportunity if a credential is '
                    'compromised.'
                ),
                'affected_object': ', '.join(ancient[:20])
                    + (f' ... (+{len(ancient)-20} more)' if len(ancient) > 20 else ''),
                'object_type': 'user',
                'impact': (
                    'Old passwords may have been exposed in previous breaches '
                    'or collected via Kerberoasting without being rotated.'
                ),
                'mitigation': (
                    'Enforce a maximum password age policy (e.g., 90-180 days). '
                    'Require immediate rotation for any accounts with passwords '
                    'older than 1 year.'
                ),
                'cis_reference': 'CIS Benchmark §1.1.5 — Maximum password age',
                'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                'ancient_accounts': ancient,
                'ancient_count': len(ancient),
            })

        return risks

    # ── Credential Leaks in Description ─────────────────────────────────────

    def _check_description_leaks(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Detect objects whose description/info fields contain credential hints."""
        risks: List[Dict[str, Any]] = []
        leaks: List[Dict[str, str]] = []

        for obj in list(users) + list(groups):
            name = obj.get('sAMAccountName') or obj.get('name', '?')
            for field_name in ('description', 'info', 'comment'):
                value = obj.get(field_name)
                if not value:
                    continue
                if isinstance(value, list):
                    value = ' '.join(str(v) for v in value)
                if _CREDENTIAL_PATTERNS.search(str(value)):
                    leaks.append({'name': name, 'field': field_name})

        if leaks:
            severity = Severity.CRITICAL if len(leaks) >= 5 else Severity.HIGH
            risks.append({
                'type': RiskTypes.STALE_DESCRIPTION_CREDENTIAL,
                'severity': severity,
                'title': f'{len(leaks)} objects with credentials in description',
                'description': (
                    f'{len(leaks)} AD object(s) appear to contain passwords '
                    'or credentials in their description/info fields. '
                    'Any domain user can read these fields via LDAP.'
                ),
                'affected_object': ', '.join(
                    f"{l['name']} ({l['field']})" for l in leaks[:10]
                ),
                'object_type': 'configuration',
                'impact': (
                    'Credential data in cleartext LDAP attributes is visible '
                    'to every authenticated domain user, enabling trivial '
                    'account takeover.'
                ),
                'attack_scenario': (
                    '1. Attacker runs: Get-ADUser -Filter * -Properties Description\n'
                    '2. Finds plaintext passwords in the description field\n'
                    '3. Logs into the account with the discovered password'
                ),
                'mitigation': (
                    'Remove all credentials from AD object descriptions immediately. '
                    'Store passwords in a PAM vault, not in LDAP attributes. '
                    'Run periodic audits to prevent recurrence.'
                ),
                'mitre_attack': MITRETechniques.UNSECURED_CREDENTIALS,
                'leaks': leaks,
                'leak_count': len(leaks),
            })

        return risks

    # ── Stale Computers ─────────────────────────────────────────────────────

    def _check_stale_computers(
        self, computers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect computer accounts that haven't contacted AD in a long time."""
        risks: List[Dict[str, Any]] = []
        stale: List[str] = []
        now = datetime.now(timezone.utc)

        for comp in computers:
            last_logon = self._parse_date(
                comp.get('lastLogonTimestamp') or comp.get('lastLogon')
            )
            if last_logon is None:
                continue

            days_idle = (now - last_logon).days
            if days_idle >= STALE_COMPUTER_DAYS:
                stale.append(comp.get('name', '?'))

        if stale:
            risks.append({
                'type': RiskTypes.STALE_COMPUTER_ACCOUNT,
                'severity': Severity.LOW,
                'title': f'{len(stale)} computer accounts inactive >{STALE_COMPUTER_DAYS} days',
                'description': (
                    f'{len(stale)} computer account(s) have not contacted the '
                    f'domain in over {STALE_COMPUTER_DAYS} days. These may be '
                    'decommissioned machines whose accounts were never cleaned up.'
                ),
                'affected_object': ', '.join(stale[:20])
                    + (f' ... (+{len(stale)-20} more)' if len(stale) > 20 else ''),
                'object_type': 'computer',
                'mitigation': (
                    'Disable or delete computer accounts for decommissioned machines. '
                    'Implement automated cleanup of stale computer objects.'
                ),
                'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                'stale_computers': stale,
                'stale_count': len(stale),
            })

        return risks

    # ── Orphan SIDs in memberOf ──────────────────────────────────────────────

    def _check_orphan_sids(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Detect group members whose DNs reference non-existent objects
        (orphaned SIDs / deleted accounts still in group membership).
        """
        risks: List[Dict[str, Any]] = []

        # Build set of all known DNs
        known_dns = set()
        for obj in list(users) + list(groups):
            dn = obj.get('distinguishedName')
            if dn:
                known_dns.add(str(dn).lower())

        orphan_groups: List[str] = []
        for group in groups:
            members = group.get('member', []) or []
            if isinstance(members, str):
                members = [members]
            for member_dn in members:
                dn_lower = str(member_dn).lower()
                # Deleted objects typically have a special RDN
                if 'del:' in dn_lower or '\\0adel:' in dn_lower:
                    gname = group.get('sAMAccountName') or group.get('name', '?')
                    if gname not in orphan_groups:
                        orphan_groups.append(gname)

        if orphan_groups:
            risks.append({
                'type': RiskTypes.STALE_ORPHAN_SID,
                'severity': Severity.LOW,
                'title': f'{len(orphan_groups)} groups with orphaned member references',
                'description': (
                    f'{len(orphan_groups)} group(s) contain member references '
                    'to deleted objects. These orphan entries should be cleaned '
                    'up to maintain AD hygiene.'
                ),
                'affected_object': ', '.join(orphan_groups[:15]),
                'object_type': 'group',
                'mitigation': (
                    'Remove orphan member references from the affected groups. '
                    'Use PowerShell: Get-ADGroupMember <group> | '
                    'Where { $_.objectClass -eq $null }'
                ),
                'orphan_groups': orphan_groups,
            })

        return risks

    # ── Utility ─────────────────────────────────────────────────────────────

    @staticmethod
    def _is_disabled(user: Dict[str, Any]) -> bool:
        """Check whether a user account is disabled via UAC flag."""
        uac = user.get('userAccountControl')
        if uac is None:
            return False
        try:
            return bool(int(uac) & 0x2)  # ACCOUNTDISABLE
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _make_aware(dt: datetime) -> datetime:
        """Ensure a datetime is timezone-aware (UTC)."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    @classmethod
    def _parse_date(cls, value) -> Optional[datetime]:
        """Parse a date field that may be datetime, string, or Windows FILETIME.

        Always returns a timezone-aware (UTC) datetime, or None.
        """
        if value is None:
            return None
        if isinstance(value, datetime):
            return cls._make_aware(value)
        if isinstance(value, str):
            for fmt in ('%Y%m%d%H%M%S.0Z', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                try:
                    return cls._make_aware(datetime.strptime(value, fmt))
                except ValueError:
                    continue
            try:
                ticks = int(value)
                if ticks > 0:
                    return cls._make_aware(
                        datetime(1601, 1, 1) + timedelta(microseconds=ticks // 10)
                    )
            except (ValueError, OverflowError):
                pass
        if isinstance(value, (int, float)):
            try:
                if value > 0:
                    return cls._make_aware(
                        datetime(1601, 1, 1) + timedelta(microseconds=int(value) // 10)
                    )
            except (OverflowError, OSError):
                pass
        return None
