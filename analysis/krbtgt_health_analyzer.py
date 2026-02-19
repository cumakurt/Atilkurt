"""
KRBTGT Health Analyzer Module
Evaluates the krbtgt account's password age, encryption types, and RODC krbtgt
accounts to assess Golden Ticket attack exposure.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

# Encryption type bit flags (msDS-SupportedEncryptionTypes)
ENC_DES_CBC_CRC = 0x01
ENC_DES_CBC_MD5 = 0x02
ENC_RC4_HMAC = 0x04
ENC_AES128 = 0x08
ENC_AES256 = 0x10

# Recommended rotation interval in days
KRBTGT_ROTATION_WARNING_DAYS = 180
KRBTGT_ROTATION_CRITICAL_DAYS = 365


class KRBTGTHealthAnalyzer:
    """Analyzes krbtgt account health for Golden Ticket exposure."""

    def __init__(self, ldap_connection):
        """
        Initialize KRBTGT health analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Analyze krbtgt account health.

        Returns:
            List of risk dictionaries for krbtgt issues
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Analyze primary krbtgt ──
            krbtgt = self._get_krbtgt_account(base_dn)
            if krbtgt:
                risks.extend(self._assess_password_age(krbtgt))
                risks.extend(self._assess_encryption_types(krbtgt))

            # ── 2. Analyze RODC krbtgt accounts ──
            rodc_accounts = self._get_rodc_krbtgt_accounts(base_dn)
            for rodc in rodc_accounts:
                risks.extend(self._assess_password_age(rodc, is_rodc=True))

            logger.info(f"Found {len(risks)} KRBTGT health risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing KRBTGT health: {e}")
            return []

    # ── Helper Methods ──────────────────────────────────────────────────────

    def _get_krbtgt_account(self, base_dn: str) -> Optional[Dict[str, Any]]:
        """Retrieve the primary krbtgt account."""
        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(&(objectClass=user)(sAMAccountName=krbtgt))',
                attributes=[
                    'sAMAccountName', 'pwdLastSet', 'whenChanged',
                    'msDS-SupportedEncryptionTypes', 'userAccountControl',
                    'distinguishedName',
                ],
                size_limit=1,
            )
            return results[0] if results else None
        except Exception as e:
            logger.debug(f"Could not retrieve krbtgt account: {e}")
            return None

    def _get_rodc_krbtgt_accounts(self, base_dn: str) -> List[Dict[str, Any]]:
        """Retrieve RODC-specific krbtgt accounts (krbtgt_*)."""
        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(&(objectClass=user)(sAMAccountName=krbtgt_*))',
                attributes=[
                    'sAMAccountName', 'pwdLastSet', 'whenChanged',
                    'msDS-SupportedEncryptionTypes', 'distinguishedName',
                ],
            )
            return results if results else []
        except Exception as e:
            logger.debug(f"Could not retrieve RODC krbtgt accounts: {e}")
            return []

    @staticmethod
    def _make_aware(dt: datetime) -> datetime:
        """Ensure a datetime is timezone-aware (UTC)."""
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    def _parse_pwd_last_set(self, account: Dict[str, Any]) -> Optional[datetime]:
        """Parse pwdLastSet into a timezone-aware datetime, handling various formats."""
        pwd_last_set = account.get('pwdLastSet')
        if not pwd_last_set:
            return None

        if isinstance(pwd_last_set, datetime):
            return self._make_aware(pwd_last_set)

        if isinstance(pwd_last_set, str):
            # Try common AD generalized time format
            for fmt in ('%Y%m%d%H%M%S.0Z', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S'):
                try:
                    return self._make_aware(datetime.strptime(pwd_last_set, fmt))
                except ValueError:
                    continue
            # Windows FILETIME (100-ns intervals since 1601-01-01)
            try:
                ticks = int(pwd_last_set)
                if ticks > 0:
                    epoch = datetime(1601, 1, 1) + timedelta(
                        microseconds=ticks // 10
                    )
                    return self._make_aware(epoch)
            except (ValueError, OverflowError):
                pass

        if isinstance(pwd_last_set, (int, float)):
            if pwd_last_set > 0:
                try:
                    epoch = datetime(1601, 1, 1) + timedelta(
                        microseconds=int(pwd_last_set) // 10
                    )
                    return self._make_aware(epoch)
                except (OverflowError, OSError):
                    pass

        return None

    def _assess_password_age(
        self, account: Dict[str, Any], is_rodc: bool = False
    ) -> List[Dict[str, Any]]:
        """Check krbtgt password age and generate risks."""
        risks: List[Dict[str, Any]] = []
        sam = account.get('sAMAccountName', 'krbtgt')
        label = f"RODC {sam}" if is_rodc else 'krbtgt'

        pwd_date = self._parse_pwd_last_set(account)
        if pwd_date is None:
            risks.append({
                'type': RiskTypes.KRBTGT_PASSWORD_AGE,
                'severity': Severity.HIGH,
                'title': f'{label} password last-set date unknown',
                'description': (
                    f'Could not determine password last-set date for {label}. '
                    'Manual verification is required.'
                ),
                'affected_object': sam,
                'object_type': 'user',
                'mitigation': (
                    'Verify the krbtgt password last-set date with '
                    'Get-ADUser krbtgt -Properties PasswordLastSet.'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
            })
            return risks

        age_days = (datetime.now(timezone.utc) - pwd_date).days

        if age_days >= KRBTGT_ROTATION_CRITICAL_DAYS:
            severity = Severity.CRITICAL
        elif age_days >= KRBTGT_ROTATION_WARNING_DAYS:
            severity = Severity.HIGH
        else:
            severity = None

        if severity:
            risks.append({
                'type': RiskTypes.KRBTGT_PASSWORD_AGE,
                'severity': severity,
                'title': f'{label} password not changed for {age_days} days',
                'description': (
                    f'The {label} password was last set on '
                    f'{pwd_date.strftime("%Y-%m-%d")} ({age_days} days ago). '
                    'An attacker who has ever obtained this hash can forge '
                    'Golden Tickets indefinitely until the password is rotated '
                    'twice (to purge both the current and previous hashes).'
                ),
                'affected_object': sam,
                'object_type': 'user',
                'impact': (
                    'Golden Ticket attacks grant domain-wide, unrestricted access. '
                    'The ticket lifetime set by the attacker is limited only by the '
                    'krbtgt password rotation. A stale krbtgt password means any '
                    'historical compromise still provides full domain access.'
                ),
                'attack_scenario': (
                    '1. Attacker obtains krbtgt NTLM hash via DCSync or NTDS.dit\n'
                    '2. Forges a Golden Ticket with arbitrary user/group SIDs\n'
                    '3. Gains unrestricted access to all domain resources\n'
                    '4. Ticket remains valid until krbtgt password is rotated TWICE'
                ),
                'mitigation': (
                    'Rotate the krbtgt password twice (with at least 10-12 hours '
                    'between rotations to allow replication):\n'
                    '  Reset-KrbtgtKeyInteractive (Microsoft script)\n\n'
                    'Best practice: rotate every 180 days. After a suspected '
                    'breach, rotate immediately (double reset).'
                ),
                'cis_reference': (
                    'CIS Benchmark recommends regular krbtgt password rotation'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
                'password_last_set': pwd_date.strftime('%Y-%m-%d %H:%M:%S'),
                'password_age_days': age_days,
            })

        return risks

    def _assess_encryption_types(
        self, account: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check krbtgt supported encryption types for weak ciphers."""
        risks: List[Dict[str, Any]] = []
        enc_raw = account.get('msDS-SupportedEncryptionTypes')

        if enc_raw is None:
            # If attribute is missing, RC4 is effectively the default
            risks.append({
                'type': RiskTypes.KRBTGT_WEAK_ENCRYPTION,
                'severity': Severity.MEDIUM,
                'title': 'krbtgt encryption types not explicitly configured',
                'description': (
                    'msDS-SupportedEncryptionTypes is not set on the krbtgt '
                    'account. Windows defaults to RC4-HMAC which is weaker '
                    'than AES-256. Explicit AES-256 configuration is recommended.'
                ),
                'affected_object': 'krbtgt',
                'object_type': 'user',
                'mitigation': (
                    'Set msDS-SupportedEncryptionTypes on krbtgt to include '
                    'AES-256 (0x18 = AES128 + AES256). After changing, '
                    'rotate the krbtgt password for the new enc-type to take effect.'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
            })
            return risks

        try:
            enc_types = int(enc_raw)
        except (ValueError, TypeError):
            return risks

        has_des = bool(enc_types & (ENC_DES_CBC_CRC | ENC_DES_CBC_MD5))
        has_rc4 = bool(enc_types & ENC_RC4_HMAC)
        has_aes = bool(enc_types & (ENC_AES128 | ENC_AES256))

        if has_des:
            risks.append({
                'type': RiskTypes.KRBTGT_WEAK_ENCRYPTION,
                'severity': Severity.HIGH,
                'title': 'krbtgt supports DES encryption (deprecated)',
                'description': (
                    'The krbtgt account supports DES encryption which is '
                    'cryptographically broken. DES Kerberos tickets can be '
                    'cracked in seconds.'
                ),
                'affected_object': 'krbtgt',
                'object_type': 'user',
                'mitigation': (
                    'Remove DES support from msDS-SupportedEncryptionTypes. '
                    'Ensure all clients and services support AES encryption '
                    'before disabling RC4/DES.'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
                'encryption_types': enc_types,
            })

        if has_rc4 and not has_aes:
            risks.append({
                'type': RiskTypes.KRBTGT_WEAK_ENCRYPTION,
                'severity': Severity.MEDIUM,
                'title': 'krbtgt uses only RC4-HMAC (no AES)',
                'description': (
                    'The krbtgt account supports RC4-HMAC but not AES encryption. '
                    'RC4 is significantly weaker than AES-256 and more susceptible '
                    'to offline attacks.'
                ),
                'affected_object': 'krbtgt',
                'object_type': 'user',
                'mitigation': (
                    'Enable AES-256 support on the krbtgt account and all '
                    'domain controllers. Set msDS-SupportedEncryptionTypes '
                    'to 0x18 (AES128 + AES256) or 0x1C (RC4 + AES128 + AES256).'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_GOLDEN,
                'encryption_types': enc_types,
            })

        return risks
