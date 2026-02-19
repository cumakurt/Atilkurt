"""
Machine Account Quota Analyzer Module
Checks ms-DS-MachineAccountQuota to detect unauthorized computer account creation risk.
A non-zero quota enables NoPac, RBCD, and rogue domain join attacks.
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class MachineQuotaAnalyzer:
    """Analyzes ms-DS-MachineAccountQuota and related machine account creation risks."""

    def __init__(self, ldap_connection):
        """
        Initialize machine quota analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Analyze machine account quota configuration.

        Returns:
            List of risk dictionaries for machine quota issues
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Read ms-DS-MachineAccountQuota from domain root ──
            quota_value = self._get_machine_account_quota(base_dn)

            if quota_value is None:
                logger.info("Could not read ms-DS-MachineAccountQuota – attribute may require elevated privileges")
                risks.append({
                    'type': RiskTypes.MACHINE_ACCOUNT_QUOTA_HIGH,
                    'severity': Severity.LOW,
                    'title': 'Machine Account Quota could not be read',
                    'description': (
                        'The ms-DS-MachineAccountQuota attribute could not be '
                        'read from the domain root object. This may be due to '
                        'insufficient permissions or schema differences. '
                        'Manual verification is recommended.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'mitigation': (
                        'Verify manually with PowerShell:\n'
                        '  Get-ADObject (Get-ADDomain).DistinguishedName '
                        '-Properties ms-DS-MachineAccountQuota'
                    ),
                })
                return risks

            if quota_value > 0:
                risks.append({
                    'type': RiskTypes.MACHINE_ACCOUNT_QUOTA_HIGH,
                    'severity': Severity.HIGH,
                    'title': f'Machine Account Quota is {quota_value} (should be 0)',
                    'description': (
                        f'ms-DS-MachineAccountQuota is set to {quota_value}. '
                        'Any authenticated user can create up to '
                        f'{quota_value} computer account(s) in the domain. '
                        'This enables NoPac (CVE-2021-42278/42287), RBCD, '
                        'and rogue domain join attacks.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'impact': (
                        'An authenticated attacker can create machine accounts '
                        'to abuse Resource-Based Constrained Delegation (RBCD), '
                        'perform NoPac privilege escalation to Domain Admin, '
                        'or join rogue computers to the domain.'
                    ),
                    'attack_scenario': (
                        '1. Attacker creates a machine account with known password\n'
                        '2. Configures RBCD on a target via msDS-AllowedToActOnBehalfOfOtherIdentity\n'
                        '3. Requests S4U2Self + S4U2Proxy ticket to impersonate Domain Admin\n'
                        '4. Gains admin access to the target system\n\n'
                        'Alternatively (NoPac): Attacker creates a machine account, '
                        'renames it to match a DC sAMAccountName, requests a TGT, '
                        'then renames it back and requests a S4U2Self ticket as DA.'
                    ),
                    'mitigation': (
                        'Set ms-DS-MachineAccountQuota to 0:\n'
                        '  Set-ADDomain -Identity <domain> '
                        '-Replace @{"ms-DS-MachineAccountQuota"="0"}\n\n'
                        'Delegate computer account creation only to authorized '
                        'accounts via OU-level permissions.'
                    ),
                    'cis_reference': 'CIS Benchmark §2.3.6 — Limit machine account creation',
                    'mitre_attack': 'T1136.002',  # Create Account: Domain Account
                    'quota_value': quota_value,
                })

            # ── 2. Find user-created computer accounts ──
            creator_stats = self._analyze_creator_sids(base_dn)
            if creator_stats:
                for creator, count in creator_stats.items():
                    if count >= 3:
                        risks.append({
                            'type': RiskTypes.MACHINE_ACCOUNT_QUOTA_HIGH,
                            'severity': Severity.MEDIUM,
                            'title': f'User created {count} machine accounts',
                            'description': (
                                f'Account "{creator}" created {count} computer '
                                'account(s). This may indicate abuse of '
                                'ms-DS-MachineAccountQuota for RBCD or NoPac attacks.'
                            ),
                            'affected_object': creator,
                            'object_type': 'user',
                            'impact': (
                                'Multiple machine accounts created by a single user '
                                'may indicate an attacker staging RBCD or NoPac attacks.'
                            ),
                            'mitigation': (
                                'Investigate the purpose of these machine accounts. '
                                'Disable or delete unauthorized accounts. '
                                'Set ms-DS-MachineAccountQuota to 0.'
                            ),
                            'mitre_attack': 'T1136.002',
                            'created_count': count,
                        })

            logger.info(f"Found {len(risks)} machine quota risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing machine account quota: {e}")
            return []

    # ── Helper Methods ──────────────────────────────────────────────────────

    def _get_machine_account_quota(self, base_dn: str):
        """Read ms-DS-MachineAccountQuota from the domain root object.

        Handles multiple attribute-name casings that different LDAP servers
        may return, and tries several search filters for compatibility.
        """
        # Attribute names the server might use (case-insensitive matching)
        attr_variants = [
            'ms-DS-MachineAccountQuota',
            'ms-ds-machineaccountquota',
            'msDS-MachineAccountQuota',
        ]
        # Filters to try (some schemas use 'domain' instead of 'domainDNS')
        filters = [
            '(objectClass=domainDNS)',
            '(objectClass=domain)',
        ]

        for search_filter in filters:
            try:
                results = self.ldap.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    attributes=['ms-DS-MachineAccountQuota'],
                    size_limit=1,
                )
                if not results:
                    continue

                entry = results[0]
                # Case-insensitive attribute lookup
                for key, value in entry.items():
                    if key.lower().replace('-', '') == 'msdsmachineaccountquota':
                        if value is not None:
                            try:
                                return int(value)
                            except (ValueError, TypeError):
                                pass
                # Also try exact-name variants
                for attr in attr_variants:
                    val = entry.get(attr)
                    if val is not None:
                        try:
                            return int(val)
                        except (ValueError, TypeError):
                            pass
            except Exception as e:
                logger.debug(f"MachineAccountQuota search failed with filter {search_filter}: {e}")
                continue

        logger.debug("Could not read MachineAccountQuota with any filter/attribute variant")
        return None

    def _analyze_creator_sids(self, base_dn: str) -> Dict[str, int]:
        """
        Count computer accounts per creator SID (ms-DS-CreatorSID).

        Returns:
            Dictionary mapping creator display name → count of created computers
        """
        stats: Dict[str, int] = {}
        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter=(
                    '(&(objectClass=computer)(ms-DS-CreatorSID=*))'
                ),
                attributes=['name', 'ms-DS-CreatorSID'],
            )
            if not results:
                return stats

            for entry in results:
                creator_sid = entry.get('ms-DS-CreatorSID', 'Unknown')
                if isinstance(creator_sid, bytes):
                    creator_sid = creator_sid.hex()
                creator_sid = str(creator_sid)
                stats[creator_sid] = stats.get(creator_sid, 0) + 1

        except Exception as e:
            logger.debug(f"Could not enumerate creator SIDs: {e}")

        return stats
