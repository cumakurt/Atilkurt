"""
Honeypot & Deception Detector Module
Identifies potential honeypot / decoy accounts already in AD and provides
recommendations for deploying effective deception objects.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity

logger = logging.getLogger(__name__)


class HoneypotDetector:
    """Detects existing honeypot indicators and recommends deception strategies."""

    def analyze(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze AD objects for honeypot characteristics.

        Returns:
            List of risk/info dictionaries
        """
        risks: List[Dict[str, Any]] = []

        risks.extend(self._detect_honeypot_candidates(users))
        risks.extend(self._recommend_deception(users, groups))

        logger.info(f"Found {len(risks)} honeypot/deception findings")
        return risks

    # ── Detect Existing Honeypot Candidates ─────────────────────────────────

    def _detect_honeypot_candidates(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify accounts that look like honeypots:
          - adminCount=1 but never logged in
          - SPN set but never received a TGS
          - Account with attractive name (e.g. 'admin', 'svc_backup')
            but disabled / never used
        """
        risks: List[Dict[str, Any]] = []
        candidates: List[str] = []

        for user in users:
            sam = user.get('sAMAccountName', '')
            admin_count = user.get('adminCount')
            last_logon = user.get('lastLogonTimestamp') or user.get('lastLogon')

            has_admin_count = False
            if admin_count is not None:
                try:
                    has_admin_count = int(admin_count) == 1
                except (ValueError, TypeError):
                    pass

            never_logged_in = self._never_logged_in(last_logon)

            # Honeypot indicator: has adminCount but never logged in
            if has_admin_count and never_logged_in:
                candidates.append(sam)
                continue

            # Honeypot indicator: has SPN but never logged in and disabled
            spns = user.get('servicePrincipalName', [])
            is_disabled = self._is_disabled(user)
            if spns and is_disabled and never_logged_in:
                candidates.append(sam)

        if candidates:
            risks.append({
                'type': RiskTypes.HONEYPOT_CANDIDATE,
                'severity': Severity.LOW,
                'title': f'{len(candidates)} potential honeypot/decoy accounts detected',
                'description': (
                    f'{len(candidates)} account(s) have characteristics of '
                    'honeypots: adminCount=1 but never logged in, or SPN set '
                    'but disabled and never used. If these are intentional '
                    'deception objects, ensure they are monitored.'
                ),
                'affected_object': ', '.join(candidates[:15]),
                'object_type': 'user',
                'impact': (
                    'If these are unintentional, they represent stale accounts. '
                    'If intentional, ensure SACL auditing and SIEM alerting '
                    'are properly configured to detect interaction.'
                ),
                'mitigation': (
                    'If honeypots: Enable SACL auditing, monitor Event IDs '
                    '4624/4625/4768 for any interaction.\n'
                    'If stale: Clean up to reduce attack surface.'
                ),
                'candidates': candidates,
            })

        return risks

    # ── Recommend Deception Strategy ────────────────────────────────────────

    def _recommend_deception(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Provide deception recommendations based on current AD posture."""
        risks: List[Dict[str, Any]] = []

        # Count privileged users
        admin_count = sum(
            1 for u in users
            if not self._is_disabled(u) and self._is_privileged(u)
        )

        recommendations: List[str] = []

        # 1. Decoy Domain Admin
        recommendations.append(
            '🎯 Create a decoy DA account (e.g., "admin_backup") with '
            'adminCount=1 but disabled. Alert on ANY Kerberos/NTLM '
            'activity for this SPN.'
        )

        # 2. Fake SPN for Kerberoasting detection
        recommendations.append(
            '🎣 Create a user with attractive SPNs (e.g., '
            'MSSQLSvc/sql01.domain.com). Any TGS request = attacker activity.'
        )

        # 3. Canary OU
        recommendations.append(
            '📁 Create a "Canary OU" (e.g., OU=FinanceServers) and set SACL '
            'to audit all reads. Attackers enumerating the domain will trigger it.'
        )

        # 4. Fake credential in description
        recommendations.append(
            '🔑 Place a fake password in a non-sensitive account description. '
            'Alert on any logon attempt with this credential.'
        )

        risks.append({
            'type': RiskTypes.HONEYPOT_RECOMMENDATION,
            'severity': Severity.LOW,
            'title': 'Deception strategy recommendations',
            'description': (
                'Consider deploying deception objects in AD to detect '
                'attackers early. Below are recommended deception strategies.'
            ),
            'affected_object': 'Domain',
            'object_type': 'configuration',
            'impact': (
                'Deception objects provide early warning of attacker activity. '
                'Any interaction with a honeypot is a strong indicator of '
                'compromise that should trigger incident response.'
            ),
            'mitigation': '\n'.join(recommendations),
            'current_admin_count': admin_count,
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
    def _is_privileged(user: Dict[str, Any]) -> bool:
        member_of = user.get('memberOf', []) or []
        if isinstance(member_of, str):
            member_of = [member_of]
        return any(
            g in str(dn).upper()
            for dn in member_of
            for g in ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS']
        )

    @staticmethod
    def _never_logged_in(last_logon) -> bool:
        if last_logon is None:
            return True
        if isinstance(last_logon, (int, float)):
            return last_logon == 0
        if isinstance(last_logon, str):
            try:
                return int(last_logon) == 0
            except ValueError:
                pass
        return False
