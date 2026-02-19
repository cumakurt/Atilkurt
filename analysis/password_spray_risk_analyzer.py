"""
Password Spray Risk Analyzer Module
Evaluates the domain's susceptibility to password spray attacks by analyzing
lockout policies, MFA coverage, and password age patterns.
"""

import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class PasswordSprayRiskAnalyzer:
    """Analyzes domain readiness against password spray attacks."""

    def __init__(self, ldap_connection):
        """
        Initialize password spray risk analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze password spray attack susceptibility.

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Lockout policy analysis ──
            risks.extend(self._analyze_lockout_policy(base_dn))

            # ── 2. Accounts without MFA/SmartCard ──
            risks.extend(self._analyze_mfa_coverage(users))

            # ── 3. Bulk password change pattern ──
            risks.extend(self._analyze_password_patterns(users))

            # ── 4. Calculate overall spray readiness score ──
            risks.extend(self._calculate_spray_score(users, base_dn))

            logger.info(f"Found {len(risks)} password spray risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing password spray risk: {e}")
            return []

    # ── Lockout Policy ──────────────────────────────────────────────────────

    def _analyze_lockout_policy(
        self, base_dn: str
    ) -> List[Dict[str, Any]]:
        """Evaluate account lockout policy against password spray attacks."""
        risks: List[Dict[str, Any]] = []

        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=[
                    'lockoutThreshold', 'lockoutDuration',
                    'lockOutObservationWindow',
                ],
                size_limit=1,
            )
            if not results:
                return risks

            domain = results[0]
            threshold = self._parse_int(domain.get('lockoutThreshold'))
            duration = domain.get('lockoutDuration')
            observation = domain.get('lockOutObservationWindow')

            if threshold is None or threshold == 0:
                risks.append({
                    'type': RiskTypes.PASSWORD_SPRAY_NO_LOCKOUT,
                    'severity': Severity.CRITICAL,
                    'title': 'No account lockout policy configured',
                    'description': (
                        'The domain does not have an account lockout threshold. '
                        'Attackers can perform unlimited password guesses '
                        'against any account without triggering a lockout.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'impact': (
                        'Without lockout, attackers can brute-force passwords '
                        'at full speed. Password spray attacks become trivial '
                        'and nearly undetectable.'
                    ),
                    'attack_scenario': (
                        '1. Attacker enumerates all domain users\n'
                        '2. Tests common passwords (Summer2026!, Company123) '
                        'against every account simultaneously\n'
                        '3. No lockout means no alerts and no interruption\n'
                        '4. Compromised accounts used for lateral movement'
                    ),
                    'mitigation': (
                        'Configure account lockout:\n'
                        '  lockoutThreshold: 5-10 attempts\n'
                        '  lockoutDuration: 30 minutes\n'
                        '  lockOutObservationWindow: 30 minutes\n\n'
                        'Also consider fine-grained password policies (PSO) '
                        'for privileged accounts with lower thresholds.'
                    ),
                    'cis_reference': (
                        'CIS Benchmark §1.2.1 — Account lockout threshold ≤ 5'
                    ),
                    'mitre_attack': 'T1110.003',  # Brute Force: Password Spraying
                    'lockout_threshold': 0,
                })
            elif threshold > 10:
                risks.append({
                    'type': RiskTypes.PASSWORD_SPRAY_RISK,
                    'severity': Severity.HIGH,
                    'title': f'Account lockout threshold is too high ({threshold})',
                    'description': (
                        f'The lockout threshold is {threshold} attempts. '
                        'This allows attackers to try many passwords before '
                        'triggering a lockout. CIS recommends ≤ 5.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'mitigation': (
                        'Reduce lockout threshold to 5 (CIS recommendation). '
                        'For privileged accounts, use fine-grained password '
                        'policies with a threshold of 3.'
                    ),
                    'cis_reference': (
                        'CIS Benchmark §1.2.1 — Account lockout threshold ≤ 5'
                    ),
                    'mitre_attack': 'T1110.003',
                    'lockout_threshold': threshold,
                })

            # Check observation window
            obs_minutes = self._parse_duration_minutes(observation)
            if obs_minutes is not None and obs_minutes < 15:
                risks.append({
                    'type': RiskTypes.PASSWORD_SPRAY_RISK,
                    'severity': Severity.MEDIUM,
                    'title': f'Lockout observation window is only {obs_minutes} min',
                    'description': (
                        f'The lockout observation window is {obs_minutes} minutes. '
                        'Attackers can space out spray attempts to stay under '
                        'the lockout threshold.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'mitigation': (
                        'Increase lockOutObservationWindow to at least 30 minutes.'
                    ),
                    'mitre_attack': 'T1110.003',
                    'observation_window_minutes': obs_minutes,
                })

        except Exception as e:
            logger.debug(f"Could not analyze lockout policy: {e}")

        return risks

    # ── MFA / Smart Card Coverage ───────────────────────────────────────────

    def _analyze_mfa_coverage(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect privileged accounts without smart card requirement."""
        risks: List[Dict[str, Any]] = []
        no_smartcard_admins: List[str] = []

        for user in users:
            if self._is_disabled(user):
                continue

            # Check if user is in a privileged group
            member_of = user.get('memberOf', []) or []
            if isinstance(member_of, str):
                member_of = [member_of]

            is_privileged = any(
                g.upper() in str(dn).upper()
                for dn in member_of
                for g in [
                    'DOMAIN ADMINS', 'ENTERPRISE ADMINS',
                    'SCHEMA ADMINS', 'ADMINISTRATORS',
                ]
            )
            if not is_privileged:
                continue

            # Check smart card requirement
            uac = user.get('userAccountControl')
            smartcard_required = False
            if uac:
                try:
                    smartcard_required = bool(int(uac) & 0x40000)
                except (ValueError, TypeError):
                    pass

            if not smartcard_required:
                no_smartcard_admins.append(
                    user.get('sAMAccountName', '?')
                )

        if no_smartcard_admins:
            risks.append({
                'type': RiskTypes.PASSWORD_SPRAY_RISK,
                'severity': Severity.HIGH,
                'title': f'{len(no_smartcard_admins)} privileged accounts without smart card',
                'description': (
                    f'{len(no_smartcard_admins)} privileged account(s) do not '
                    'require smart card authentication. These accounts are '
                    'vulnerable to password spray attacks.'
                ),
                'affected_object': f'{len(no_smartcard_admins)} privileged account(s)',
                'affected_objects': list(no_smartcard_admins),
                'object_type': 'user',
                'mitigation': (
                    'Enable "Smart card is required for interactive logon" '
                    'for all privileged accounts. This makes password-based '
                    'attacks impossible for these accounts.'
                ),
                'mitre_attack': 'T1110.003',
                'accounts': no_smartcard_admins,
                'no_smartcard_count': len(no_smartcard_admins),
            })

        return risks

    # ── Password Age Patterns ───────────────────────────────────────────────

    def _analyze_password_patterns(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect bulk password changes (suggesting forced resets with weak patterns)."""
        risks: List[Dict[str, Any]] = []
        date_counts: Counter = Counter()

        for user in users:
            pwd_date = self._parse_date(user.get('pwdLastSet'))
            if pwd_date:
                date_counts[pwd_date.strftime('%Y-%m-%d')] += 1

        # Flag dates with an unusually large number of password changes
        for date_str, count in date_counts.most_common(5):
            if count >= 20:
                risks.append({
                    'type': RiskTypes.PASSWORD_SPRAY_RISK,
                    'severity': Severity.MEDIUM,
                    'title': f'{count} accounts changed passwords on {date_str}',
                    'description': (
                        f'{count} accounts changed their passwords on '
                        f'{date_str}. Bulk password resets often result in '
                        'predictable patterns (e.g., Company2026!) that are '
                        'easily sprayed.'
                    ),
                    'affected_object': f'Bulk reset on {date_str}',
                    'object_type': 'user',
                    'mitigation': (
                        'Ensure forced password resets enforce true randomness. '
                        'Consider using a banned-password list to prevent '
                        'predictable patterns.'
                    ),
                    'mitre_attack': 'T1110.003',
                    'bulk_reset_date': date_str,
                    'bulk_reset_count': count,
                })

        return risks

    # ── Spray Readiness Score ───────────────────────────────────────────────

    def _calculate_spray_score(
        self,
        users: List[Dict[str, Any]],
        base_dn: str,
    ) -> List[Dict[str, Any]]:
        """Calculate an overall password spray readiness score (0-100)."""
        risks: List[Dict[str, Any]] = []
        score = 100  # Start perfect, deduct for each weakness

        # Lockout threshold
        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['lockoutThreshold'],
                size_limit=1,
            )
            if results:
                threshold = self._parse_int(
                    results[0].get('lockoutThreshold')
                )
                if threshold is None or threshold == 0:
                    score -= 40
                elif threshold > 10:
                    score -= 20
                elif threshold > 5:
                    score -= 10
        except Exception as e:
            logger.debug("Could not evaluate lockout threshold for spray score: %s", e)

        # Account with password never expires
        enabled_users = [u for u in users if not self._is_disabled(u)]
        if enabled_users:
            pwd_never_expires = sum(
                1 for u in enabled_users
                if self._has_uac_flag(u, 0x10000)
            )
            ratio = pwd_never_expires / len(enabled_users) if enabled_users else 0
            if ratio > 0.5:
                score -= 20
            elif ratio > 0.2:
                score -= 10

        # No pre-auth accounts (AS-REP roasting amplifies spray risk)
        no_preauth = sum(
            1 for u in enabled_users
            if self._has_uac_flag(u, 0x400000)
        )
        if no_preauth > 0:
            score -= 10

        score = max(0, min(100, score))

        risks.append({
            'type': RiskTypes.PASSWORD_SPRAY_RISK,
            'severity': (
                Severity.CRITICAL if score < 30
                else Severity.HIGH if score < 50
                else Severity.MEDIUM if score < 70
                else Severity.LOW
            ),
            'title': f'Password Spray Readiness Score: {score}/100',
            'description': (
                f'The domain scored {score}/100 on password spray resilience. '
                f'{"Urgent hardening needed." if score < 50 else "Room for improvement." if score < 70 else "Good posture."}'
            ),
            'affected_object': 'Domain',
            'object_type': 'configuration',
            'mitigation': (
                'Key actions to improve spray readiness:\n'
                '• Set lockout threshold ≤ 5\n'
                '• Enforce smart card for privileged accounts\n'
                '• Deploy Azure AD Password Protection / banned-word list\n'
                '• Enable Kerberos pre-authentication for all accounts\n'
                '• Monitor Event IDs 4625, 4771 for spray patterns'
            ),
            'mitre_attack': 'T1110.003',
            'spray_readiness_score': score,
        })

        return risks

    # ── Utilities ───────────────────────────────────────────────────────────

    @staticmethod
    def _is_disabled(user: Dict[str, Any]) -> bool:
        uac = user.get('userAccountControl')
        if uac is None:
            return False
        try:
            return bool(int(uac) & 0x2)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _has_uac_flag(user: Dict[str, Any], flag: int) -> bool:
        uac = user.get('userAccountControl')
        if uac is None:
            return False
        try:
            return bool(int(uac) & flag)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _parse_int(val) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_date(value) -> Optional[datetime]:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            for fmt in ('%Y%m%d%H%M%S.0Z', '%Y-%m-%dT%H:%M:%S'):
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            try:
                ticks = int(value)
                if ticks > 0:
                    return datetime(1601, 1, 1) + timedelta(microseconds=ticks // 10)
            except (ValueError, OverflowError):
                pass
        if isinstance(value, (int, float)) and value > 0:
            try:
                return datetime(1601, 1, 1) + timedelta(microseconds=int(value) // 10)
            except (OverflowError, OSError):
                pass
        return None

    @staticmethod
    def _parse_duration_minutes(value) -> Optional[int]:
        """Parse AD duration (negative 100-ns intervals) to minutes."""
        if value is None:
            return None
        try:
            ticks = abs(int(value))
            return int(ticks / 10_000_000 / 60)
        except (ValueError, TypeError, OverflowError):
            return None
