"""
Backup Operators & Sensitive Groups Analyzer Module
Deep analysis of high-privilege operational groups: Backup Operators, Account Operators,
Server Operators, Print Operators.  These groups have dangerous implicit rights that are
often overlooked.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

# Groups and their implicit dangers
SENSITIVE_GROUPS = {
    'Backup Operators': {
        'danger': (
            'Can read ANY file on DCs (SeBackupPrivilege), including NTDS.dit '
            'and registry SAM/SYSTEM hives. Enables offline credential extraction.'
        ),
        'mitre': 'T1003.003',  # OS Credential Dumping: NTDS
        'severity': Severity.HIGH,
        'max_safe_members': 0,
    },
    'Account Operators': {
        'danger': (
            'Can create, modify, and delete users and groups in the domain '
            '(except admin groups). Can reset passwords on non-admin accounts.'
        ),
        'mitre': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        'severity': Severity.HIGH,
        'max_safe_members': 0,
    },
    'Server Operators': {
        'danger': (
            'Can log into DCs, start/stop services, back up and restore files, '
            'and shut down DCs. Can install malicious services for persistence.'
        ),
        'mitre': 'T1543.003',  # Create or Modify System Process: Windows Service
        'severity': Severity.HIGH,
        'max_safe_members': 0,
    },
    'Print Operators': {
        'danger': (
            'Can load printer drivers on DCs. A malicious driver executes as '
            'SYSTEM — this is the PrintNightmare attack vector.'
        ),
        'mitre': 'T1068',  # Exploitation for Privilege Escalation
        'severity': Severity.HIGH,
        'max_safe_members': 0,
    },
    'Remote Desktop Users': {
        'danger': (
            'Can RDP into servers/DCs. Excessive membership expands the '
            'attack surface for lateral movement.'
        ),
        'mitre': MITRETechniques.LATERAL_MOVEMENT,
        'severity': Severity.MEDIUM,
        'max_safe_members': 10,
    },
    'DnsAdmins': {
        'danger': (
            'Can load arbitrary DLLs into the DNS service on DCs. '
            'The DLL runs as SYSTEM, enabling code execution on DCs.'
        ),
        'mitre': 'T1574.002',  # Hijack Execution Flow: DLL Side-Loading
        'severity': Severity.HIGH,
        'max_safe_members': 2,
    },
}


class BackupOperatorAnalyzer:
    """Analyzes membership and risk of high-privilege operational groups."""

    def analyze(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze sensitive operator group membership.

        Args:
            users: List of user dictionaries
            groups: List of group dictionaries

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        for group in groups:
            group_name = group.get('sAMAccountName') or group.get('name', '')
            if not group_name:
                continue

            config = self._match_sensitive_group(group_name)
            if config is None:
                continue

            members = group.get('member', []) or []
            if isinstance(members, str):
                members = [members]
            member_count = len(members)
            max_safe = config['max_safe_members']

            if member_count > max_safe:
                member_names = [
                    self._extract_cn(dn) for dn in members[:20]
                ]
                risks.append({
                    'type': RiskTypes.BACKUP_OPERATOR_RISK
                        if 'Backup' in group_name or 'Server' in group_name
                        else RiskTypes.SENSITIVE_OPERATOR_RISK,
                    'severity': config['severity'],
                    'title': (
                        f'"{group_name}" has {member_count} member(s) '
                        f'(max recommended: {max_safe})'
                    ),
                    'description': (
                        f'The "{group_name}" group has {member_count} member(s). '
                        f'{config["danger"]}'
                    ),
                    'affected_object': group_name,
                    'object_type': 'group',
                    'impact': config['danger'],
                    'attack_scenario': self._get_attack_scenario(group_name),
                    'mitigation': (
                        f'Review and remove unnecessary members from "{group_name}". '
                        'Ideally this group should have '
                        f'{"no members" if max_safe == 0 else f"at most {max_safe} members"}. '
                        'Use time-limited PAM/JIT access if occasional use is needed.'
                    ),
                    'cis_reference': (
                        f'CIS Benchmark recommends empty "{group_name}" group'
                    ),
                    'mitre_attack': config['mitre'],
                    'member_count': member_count,
                    'member_names': member_names,
                })

        logger.info(f"Found {len(risks)} sensitive operator risks")
        return risks

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _match_sensitive_group(group_name: str) -> Optional[Dict]:
        """Match group name against sensitive group configurations."""
        upper = group_name.upper()
        for name, config in SENSITIVE_GROUPS.items():
            if name.upper() in upper:
                return config
        return None

    @staticmethod
    def _extract_cn(dn: str) -> str:
        """Extract CN from a distinguished name."""
        for part in dn.split(','):
            part = part.strip()
            if part.upper().startswith('CN='):
                return part[3:]
        return dn

    @staticmethod
    def _get_attack_scenario(group_name: str) -> str:
        """Return concrete attack scenario for the group."""
        scenarios = {
            'Backup Operators': (
                '1. Attacker compromises a Backup Operators member\n'
                '2. Uses SeBackupPrivilege to copy NTDS.dit from DC\n'
                '3. Extracts all domain hashes offline\n'
                '4. Performs pass-the-hash for Domain Admin access'
            ),
            'Account Operators': (
                '1. Attacker compromises an Account Operators member\n'
                '2. Creates a new domain user account\n'
                '3. Adds the account to a non-protected group with '
                'admin-like permissions\n'
                '4. Uses the new account for persistent access'
            ),
            'Server Operators': (
                '1. Attacker compromises a Server Operators member\n'
                '2. Installs a malicious Windows service on a DC\n'
                '3. Service runs as SYSTEM, granting full DC control\n'
                '4. Dumps credentials and achieves domain compromise'
            ),
            'Print Operators': (
                '1. Attacker compromises a Print Operators member\n'
                '2. Loads a malicious printer driver DLL on DC\n'
                '3. DLL executes as SYSTEM, granting full DC control\n'
                '4. Classic PrintNightmare exploitation path'
            ),
            'DnsAdmins': (
                '1. Attacker compromises a DnsAdmins member\n'
                '2. Configures DNS to load a malicious DLL\n'
                '3. Restarts DNS service; DLL runs as SYSTEM on DC\n'
                '4. Full domain compromise achieved'
            ),
        }
        for key, scenario in scenarios.items():
            if key.upper() in group_name.upper():
                return scenario
        return 'Compromised member can leverage group privileges for lateral movement.'
