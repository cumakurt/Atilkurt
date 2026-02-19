"""
Lateral Movement Analyzer Module
Evaluates lateral movement potential by analyzing:
  - Privileged accounts without logon workstation restrictions
  - Tier model violations (Tier 0 credentials on Tier 2 systems)
  - RDP / WinRM group membership exposure
  - Admin credential re-use across tiers
"""

import logging
from typing import List, Dict, Any
from core.constants import (
    RiskTypes, Severity, MITRETechniques, PRIVILEGED_GROUPS,
)

logger = logging.getLogger(__name__)

# Groups that grant remote access
REMOTE_ACCESS_GROUPS = [
    'Remote Desktop Users',
    'Remote Management Users',
]


class LateralMovementAnalyzer:
    """Analyzes lateral movement potential across the domain."""

    def analyze(
        self,
        users: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze lateral movement risk.

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        risks.extend(self._check_unrestricted_logon(users))
        risks.extend(self._check_tier_violations(users, computers))
        risks.extend(self._check_rdp_exposure(groups))

        logger.info(f"Found {len(risks)} lateral movement risks")
        return risks

    # ── Unrestricted Logon Workstations ─────────────────────────────────────

    def _check_unrestricted_logon(
        self, users: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Detect privileged accounts without logonWorkstation restrictions."""
        risks: List[Dict[str, Any]] = []
        unrestricted: List[str] = []

        for user in users:
            if self._is_disabled(user):
                continue

            if not self._is_privileged(user):
                continue

            # Check logonWorkstation attribute
            allowed_ws = user.get('userWorkstations') or user.get('logonWorkstation')
            if not allowed_ws:
                unrestricted.append(user.get('sAMAccountName', '?'))

        if unrestricted:
            risks.append({
                'type': RiskTypes.LATERAL_MOVEMENT_UNRESTRICTED,
                'severity': Severity.HIGH,
                'title': (
                    f'{len(unrestricted)} privileged accounts can log into any workstation'
                ),
                'description': (
                    f'{len(unrestricted)} privileged account(s) have no '
                    'logonWorkstation restrictions. These accounts can be '
                    'used to log into any domain-joined computer, increasing '
                    'credential exposure across tiers.'
                ),
                'affected_object': ', '.join(unrestricted[:15])
                    + (f' ... (+{len(unrestricted)-15} more)'
                       if len(unrestricted) > 15 else ''),
                'object_type': 'user',
                'impact': (
                    'If a privileged account logs into a workstation, its '
                    'credential hash remains in LSASS memory. An attacker '
                    'who compromises that workstation can harvest the hash '
                    'and escalate to domain-level access.'
                ),
                'attack_scenario': (
                    '1. Domain Admin logs into a user workstation\n'
                    '2. Attacker compromises the workstation via phishing\n'
                    '3. Dumps LSASS to extract DA NTLM hash\n'
                    '4. Pass-the-hash to Domain Controller for full compromise'
                ),
                'mitigation': (
                    'Restrict logonWorkstation for all privileged accounts:\n'
                    '  Set-ADUser <admin> -LogonWorkstations "PAW01,PAW02"\n\n'
                    'Deploy Privileged Access Workstations (PAWs) and only '
                    'allow admin accounts to log into them.'
                ),
                'cis_reference': (
                    'CIS Benchmark recommends logonWorkstation restrictions '
                    'for all admin accounts'
                ),
                'mitre_attack': MITRETechniques.PASS_THE_HASH,
                'unrestricted_accounts': unrestricted,
                'unrestricted_count': len(unrestricted),
            })

        return risks

    # ── Tier Violations ─────────────────────────────────────────────────────

    def _check_tier_violations(
        self,
        users: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Detect Tier 0 accounts that appear to authenticate to non-Tier0 systems.
        Heuristic: Tier 0 accounts with no logon restrictions have implicit
        cross-tier risk.
        """
        risks: List[Dict[str, Any]] = []
        tier0_accounts: List[str] = []

        tier0_groups = {'ENTERPRISE ADMINS', 'SCHEMA ADMINS', 'DOMAIN CONTROLLERS'}

        for user in users:
            if self._is_disabled(user):
                continue

            member_of = user.get('memberOf', []) or []
            if isinstance(member_of, str):
                member_of = [member_of]

            in_tier0 = any(
                g in str(dn).upper()
                for dn in member_of
                for g in tier0_groups
            )
            if not in_tier0:
                continue

            allowed_ws = user.get('userWorkstations') or user.get('logonWorkstation')
            if not allowed_ws:
                tier0_accounts.append(user.get('sAMAccountName', '?'))

        workstation_count = sum(
            1 for c in computers
            if 'SERVER' not in str(c.get('operatingSystem', '') or '').upper()
        )

        if tier0_accounts and workstation_count > 0:
            risks.append({
                'type': RiskTypes.LATERAL_MOVEMENT_TIER_VIOLATION,
                'severity': Severity.CRITICAL,
                'title': (
                    f'{len(tier0_accounts)} Tier 0 accounts can reach '
                    f'{workstation_count} workstations'
                ),
                'description': (
                    f'{len(tier0_accounts)} Tier 0 account(s) have no '
                    f'logon restrictions and could potentially access '
                    f'{workstation_count} workstation(s). This violates '
                    'the Tier Model and exposes Tier 0 credentials to '
                    'Tier 2 threats.'
                ),
                'affected_object': ', '.join(tier0_accounts[:10]),
                'object_type': 'user',
                'mitigation': (
                    'Implement the Microsoft Privileged Access Model:\n'
                    '• Restrict Tier 0 accounts to DCs and PAWs only\n'
                    '• Deploy Authentication Policy Silos (Win2012R2+)\n'
                    '• Use Protected Users group for Tier 0 accounts'
                ),
                'mitre_attack': MITRETechniques.PASS_THE_HASH,
                'tier0_accounts': tier0_accounts,
                'workstation_count': workstation_count,
            })

        return risks

    # ── RDP / WinRM Exposure ────────────────────────────────────────────────

    def _check_rdp_exposure(
        self, groups: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Check Remote Desktop Users and Remote Management Users membership."""
        risks: List[Dict[str, Any]] = []

        for group in groups:
            gname = group.get('sAMAccountName') or group.get('name', '')
            if not gname:
                continue

            matched = any(
                rg.upper() in gname.upper() for rg in REMOTE_ACCESS_GROUPS
            )
            if not matched:
                continue

            members = group.get('member', []) or []
            if isinstance(members, str):
                members = [members]

            if len(members) > 20:
                member_names = [self._extract_cn(dn) for dn in members[:15]]
                risks.append({
                    'type': RiskTypes.LATERAL_MOVEMENT_RDP_EXPOSURE,
                    'severity': Severity.MEDIUM,
                    'title': f'"{gname}" has {len(members)} members',
                    'description': (
                        f'The "{gname}" group has {len(members)} members. '
                        'Large remote access groups increase the lateral '
                        'movement attack surface.'
                    ),
                    'affected_object': gname,
                    'object_type': 'group',
                    'mitigation': (
                        f'Review "{gname}" membership and remove users who '
                        'do not need remote access. Use JIT/PAM solutions '
                        'for temporary access instead of permanent membership.'
                    ),
                    'mitre_attack': MITRETechniques.LATERAL_MOVEMENT,
                    'member_count': len(members),
                    'member_names': member_names,
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
            g.upper() in str(dn).upper()
            for dn in member_of
            for g in PRIVILEGED_GROUPS
        )

    @staticmethod
    def _extract_cn(dn: str) -> str:
        for part in dn.split(','):
            p = part.strip()
            if p.upper().startswith('CN='):
                return p[3:]
        return dn
