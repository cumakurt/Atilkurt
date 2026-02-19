"""
Coercion Attack Surface Analyzer Module
Identifies NTLM authentication coercion vectors beyond PetitPotam:
  - Print Spooler (SpoolSample / PrinterBug)
  - DFS (DFSCoerce)
  - WebClient (WebDAV relay)
  - EFS (PetitPotam — supplements existing scanner)
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class CoerceAttackAnalyzer:
    """Identifies NTLM coercion attack vectors via LDAP heuristics."""

    def __init__(self, ldap_connection):
        """
        Initialize coercion attack analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze(
        self, computers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Analyze coercion attack surface.

        Args:
            computers: List of computer dictionaries

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Print Spooler (SpoolSample) ──
            risks.extend(self._check_spooler(computers))

            # ── 2. DFS Namespace service ──
            risks.extend(self._check_dfs(base_dn, computers))

            # ── 3. WebClient / WebDAV ──
            risks.extend(self._check_webclient(computers))

            logger.info(f"Found {len(risks)} coercion attack risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing coercion attacks: {e}")
            return []

    # ── Print Spooler / SpoolSample ─────────────────────────────────────────

    def _check_spooler(
        self, computers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect servers/DCs likely running Print Spooler.
        Heuristic: all Windows Servers have spooler enabled by default.
        DCs are the highest-value targets.
        """
        risks: List[Dict[str, Any]] = []
        dc_targets: List[str] = []
        server_targets: List[str] = []

        for comp in computers:
            os_name = str(comp.get('operatingSystem', '') or '').upper()
            name = comp.get('name', '?')

            if 'SERVER' not in os_name and 'WINDOWS' not in os_name:
                continue

            is_dc = 'DOMAIN CONTROLLER' in os_name or 'DC' in name.upper()
            if is_dc:
                dc_targets.append(name)
            elif 'SERVER' in os_name:
                server_targets.append(name)

        if dc_targets:
            risks.append({
                'type': RiskTypes.COERCION_SPOOLSAMPLE,
                'severity': Severity.HIGH,
                'title': f'Print Spooler likely active on {len(dc_targets)} DC(s)',
                'description': (
                    f'{len(dc_targets)} Domain Controller(s) are likely running '
                    'the Print Spooler service (default on Windows Server). '
                    'An attacker can force the DC to authenticate to an '
                    'attacker-controlled host using the SpoolSample/PrinterBug '
                    'technique, enabling NTLM relay attacks.'
                ),
                'affected_object': ', '.join(dc_targets[:10]),
                'object_type': 'computer',
                'impact': (
                    'SpoolSample forces DC machine account authentication, '
                    'which can be relayed to LDAP (if signing not required) '
                    'or AD CS HTTP endpoints for full domain compromise.'
                ),
                'attack_scenario': (
                    '1. Attacker runs SpoolSample.exe against DC\n'
                    '2. DC authenticates to attacker-controlled host\n'
                    '3. NTLM is relayed to AD CS /certsrv/certfnsh.asp (ESC8)\n'
                    '4. Attacker obtains DC certificate → DCSync → full compromise'
                ),
                'mitigation': (
                    'Disable the Print Spooler service on all DCs:\n'
                    '  Stop-Service Spooler -Force\n'
                    '  Set-Service Spooler -StartupType Disabled\n\n'
                    'Also enable LDAP signing and EPA to mitigate relay.'
                ),
                'cis_reference': (
                    'CIS Benchmark §2.2.1 — Disable unnecessary services on DCs'
                ),
                'mitre_attack': 'T1187',  # Forced Authentication
                'dc_targets': dc_targets,
                'server_targets': server_targets,
            })

        return risks

    # ── DFS Coerce ──────────────────────────────────────────────────────────

    def _check_dfs(
        self,
        base_dn: str,
        computers: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Check for DFS Namespace servers (DFSCoerce target).
        Heuristic: search for fTDfs or DFSR objects in AD.
        """
        risks: List[Dict[str, Any]] = []

        try:
            # Check for DFS-related objects
            dfs_results = self.ldap.search(
                search_base=base_dn,
                search_filter='(|(objectClass=fTDfs)(objectClass=msDFS-Namespacev2))',
                attributes=['cn', 'distinguishedName'],
            )
            if dfs_results:
                dfs_servers = [r.get('cn', '?') for r in dfs_results[:20]]
                risks.append({
                    'type': RiskTypes.COERCION_DFSCOERCE,
                    'severity': Severity.MEDIUM,
                    'title': f'{len(dfs_results)} DFS namespace(s) found — DFSCoerce possible',
                    'description': (
                        f'{len(dfs_results)} DFS namespace(s) exist in the domain. '
                        'DFSCoerce can force servers hosting DFS namespaces to '
                        'authenticate to an attacker-controlled host via NTLM.'
                    ),
                    'affected_object': ', '.join(dfs_servers[:10]),
                    'object_type': 'computer',
                    'impact': (
                        'DFSCoerce enables NTLM relay from DFS servers. '
                        'If the target is a DC running DFS, the impact is '
                        'equivalent to SpoolSample.'
                    ),
                    'attack_scenario': (
                        '1. Attacker identifies DFS namespace servers\n'
                        '2. Uses DFSCoerce to trigger NTLM authentication\n'
                        '3. Relays NTLM to AD CS or LDAP\n'
                        '4. Obtains certificates or modifies AD objects'
                    ),
                    'mitigation': (
                        'Enable LDAP signing and channel binding on all DCs. '
                        'Remove DFS namespaces that are no longer needed. '
                        'Enable Extended Protection for Authentication (EPA) '
                        'on AD CS web enrollment.'
                    ),
                    'mitre_attack': 'T1187',
                    'dfs_namespaces': dfs_servers,
                })
        except Exception as e:
            logger.debug(f"DFS check failed: {e}")

        return risks

    # ── WebClient / WebDAV ──────────────────────────────────────────────────

    def _check_webclient(
        self, computers: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Identify workstations likely running WebClient service.
        WebClient is enabled by default on Windows 10/11 desktops,
        enabling HTTP-based NTLM relay (no SMB signing requirement).
        """
        risks: List[Dict[str, Any]] = []
        workstations: List[str] = []

        for comp in computers:
            os_name = str(comp.get('operatingSystem', '') or '').upper()
            name = comp.get('name', '?')

            # Windows 10/11 desktops typically have WebClient
            if 'WINDOWS 10' in os_name or 'WINDOWS 11' in os_name:
                workstations.append(name)

        if len(workstations) >= 5:
            risks.append({
                'type': RiskTypes.COERCION_WEBCLIENT,
                'severity': Severity.MEDIUM,
                'title': f'{len(workstations)} workstations may have WebClient enabled',
                'description': (
                    f'{len(workstations)} Windows 10/11 workstations detected. '
                    'The WebClient service (WebDAV) is enabled by default on '
                    'these systems, allowing HTTP-based NTLM relay that '
                    'bypasses SMB signing requirements.'
                ),
                'affected_object': f'{len(workstations)} workstations',
                'object_type': 'computer',
                'impact': (
                    'WebDAV-based coercion enables NTLM relay over HTTP, '
                    'which is not subject to SMB signing. This is a key '
                    'step in many modern relay attacks against AD CS.'
                ),
                'attack_scenario': (
                    '1. Attacker starts HTTP listener (ntlmrelayx)\n'
                    '2. Triggers WebClient auth from target workstation\n'
                    '3. NTLM relay over HTTP to AD CS web enrollment\n'
                    '4. Obtains certificate as the relayed identity'
                ),
                'mitigation': (
                    'Disable WebClient service via GPO on all machines '
                    'that do not need WebDAV:\n'
                    '  Set-Service WebClient -StartupType Disabled\n\n'
                    'Enable EPA on AD CS and all web endpoints.'
                ),
                'mitre_attack': 'T1187',
                'workstation_count': len(workstations),
            })

        return risks
