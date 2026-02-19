"""
Golden gMSA Analyzer Module
Detects KDS Root Key exposure that enables offline derivation of all gMSA passwords.
If an attacker obtains the KDS Root Key, every gMSA password in the forest can be
computed without touching AD again — a "Golden gMSA" attack.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class GoldenGMSAAnalyzer:
    """Analyzes KDS Root Key and gMSA configuration for Golden gMSA exposure."""

    def __init__(self, ldap_connection):
        """
        Initialize Golden gMSA analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze(self) -> List[Dict[str, Any]]:
        """
        Analyze KDS Root Keys and gMSA accounts.

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Find KDS Root Keys ──
            root_keys = self._get_kds_root_keys()
            gmsa_accounts = self._get_gmsa_accounts(base_dn)

            if not root_keys and not gmsa_accounts:
                logger.info("No KDS Root Keys or gMSA accounts found — skipping")
                return risks

            # ── 2. Assess KDS Root Key security ──
            if root_keys:
                risks.extend(self._assess_root_key_security(root_keys))

            # ── 3. Assess gMSA password readers ──
            if gmsa_accounts:
                risks.extend(
                    self._assess_gmsa_password_readers(gmsa_accounts)
                )

            logger.info(f"Found {len(risks)} Golden gMSA risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing Golden gMSA: {e}")
            return []

    # ── KDS Root Key Retrieval ──────────────────────────────────────────────

    def _get_kds_root_keys(self) -> List[Dict[str, Any]]:
        """Retrieve all msKds-ProvRootKey objects in the forest."""
        try:
            config_dn = self._get_config_dn()
            if not config_dn:
                return []

            search_base = f"CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,{config_dn}"
            results = self.ldap.search(
                search_base=search_base,
                search_filter='(objectClass=msKds-ProvRootKey)',
                attributes=[
                    'cn', 'whenCreated', 'whenChanged',
                    'msKds-KDFAlgorithmID', 'msKds-CreateTime',
                    'msKds-UseStartTime', 'msKds-DomainID',
                ],
            )
            return results if results else []
        except Exception as e:
            logger.debug(f"Could not retrieve KDS Root Keys: {e}")
            return []

    def _get_config_dn(self) -> Optional[str]:
        """Get the Configuration naming context DN."""
        try:
            results = self.ldap.search(
                search_base='',
                search_filter='(objectClass=*)',
                attributes=['configurationNamingContext'],
                size_limit=1,
            )
            if results:
                return results[0].get('configurationNamingContext')
        except Exception as e:
            logger.debug(f"Could not retrieve config DN: {e}")
            # Fallback: derive from base_dn
            base_dn = self.ldap.base_dn
            dc_parts = [p for p in base_dn.split(',') if p.upper().startswith('DC=')]
            if dc_parts:
                return 'CN=Configuration,' + ','.join(dc_parts)
        return None

    # ── gMSA Account Retrieval ──────────────────────────────────────────────

    def _get_gmsa_accounts(self, base_dn: str) -> List[Dict[str, Any]]:
        """Retrieve all gMSA accounts."""
        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(objectClass=msDS-GroupManagedServiceAccount)',
                attributes=[
                    'sAMAccountName', 'distinguishedName',
                    'msDS-ManagedPasswordInterval',
                    'msDS-GroupMSAMembership',
                    'PrincipalsAllowedToRetrieveManagedPassword',
                    'whenCreated', 'userAccountControl',
                    'servicePrincipalName',
                ],
            )
            return results if results else []
        except Exception as e:
            logger.debug(f"Could not retrieve gMSA accounts: {e}")
            return []

    # ── Root Key Security Assessment ────────────────────────────────────────

    def _assess_root_key_security(
        self, root_keys: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Assess the security posture of KDS Root Keys."""
        risks: List[Dict[str, Any]] = []

        # Multiple root keys increase the attack surface
        if len(root_keys) > 1:
            risks.append({
                'type': RiskTypes.GOLDEN_GMSA_ROOT_KEY,
                'severity': Severity.MEDIUM,
                'title': f'{len(root_keys)} KDS Root Keys exist',
                'description': (
                    f'There are {len(root_keys)} KDS Root Keys in the forest. '
                    'Each key can be used to derive gMSA passwords. '
                    'Only one active key is needed; excess keys increase '
                    'the attack surface.'
                ),
                'affected_object': 'KDS Root Keys',
                'object_type': 'configuration',
                'mitigation': (
                    'Review and remove unnecessary KDS Root Keys. '
                    'Keep only the most recent active key.'
                ),
                'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                'key_count': len(root_keys),
            })

        # Assess each root key
        for key in root_keys:
            key_cn = key.get('cn', 'Unknown')
            created = key.get('whenCreated')
            kdf_algo = key.get('msKds-KDFAlgorithmID', 'Unknown')

            # Warn about Golden gMSA attack potential
            risks.append({
                'type': RiskTypes.GOLDEN_GMSA_ROOT_KEY,
                'severity': Severity.HIGH,
                'title': f'KDS Root Key found — Golden gMSA attack possible',
                'description': (
                    f'KDS Root Key "{key_cn}" exists '
                    f'(KDF: {kdf_algo}). '
                    'An attacker with Domain Admin or equivalent access can '
                    'extract this key and compute ALL gMSA passwords offline, '
                    'without generating any further LDAP traffic. '
                    'This is the "Golden gMSA" attack.'
                ),
                'affected_object': f'KDS Root Key: {key_cn}',
                'object_type': 'configuration',
                'impact': (
                    'Golden gMSA gives an attacker persistent access to every '
                    'service using gMSA accounts — databases, web apps, '
                    'scheduled tasks — even after a domain-wide password reset.'
                ),
                'attack_scenario': (
                    '1. Attacker obtains DA-level access\n'
                    '2. Extracts KDS Root Key via "GoldenGMSA" tool or LDAP\n'
                    '3. Computes gMSA passwords offline for any point in time\n'
                    '4. Uses the passwords to access all services that run '
                    'under gMSA accounts\n'
                    '5. Access persists even after krbtgt rotation'
                ),
                'mitigation': (
                    '• Monitor access to KDS Root Key objects (SACL auditing)\n'
                    '• Restrict DCSync and replication rights\n'
                    '• After a suspected breach: create a NEW KDS Root Key, '
                    'delete the compromised one, and force-rotate all gMSA passwords\n'
                    '• Implement Tier-0 isolation for accounts that can read '
                    'configuration partition'
                ),
                'cis_reference': (
                    'CIS Benchmark recommends monitoring KDS Root Key access '
                    'and restricting replication rights'
                ),
                'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                'key_cn': key_cn,
                'kdf_algorithm': str(kdf_algo),
            })

        return risks

    # ── gMSA Password Reader Assessment ─────────────────────────────────────

    def _assess_gmsa_password_readers(
        self, gmsa_accounts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Check how many principals can read each gMSA password."""
        risks: List[Dict[str, Any]] = []

        for gmsa in gmsa_accounts:
            sam = gmsa.get('sAMAccountName', '?')
            readers_raw = gmsa.get(
                'PrincipalsAllowedToRetrieveManagedPassword'
            ) or gmsa.get('msDS-GroupMSAMembership')

            if readers_raw is None:
                risks.append({
                    'type': RiskTypes.GOLDEN_GMSA_EXCESSIVE_READERS,
                    'severity': Severity.MEDIUM,
                    'title': f'gMSA "{sam}" has no explicit password readers',
                    'description': (
                        f'The gMSA account "{sam}" does not have any '
                        'principals configured to retrieve its managed password. '
                        'This may indicate misconfiguration.'
                    ),
                    'affected_object': sam,
                    'object_type': 'user',
                    'mitigation': (
                        'Verify that PrincipalsAllowedToRetrieveManagedPassword '
                        'is properly configured for this gMSA account.'
                    ),
                })
                continue

            # Count readers (may be a list of DNs or a single DN)
            if isinstance(readers_raw, list):
                reader_count = len(readers_raw)
            elif isinstance(readers_raw, str):
                reader_count = len([r for r in readers_raw.split(';') if r.strip()])
            else:
                reader_count = 1

            if reader_count > 5:
                risks.append({
                    'type': RiskTypes.GOLDEN_GMSA_EXCESSIVE_READERS,
                    'severity': Severity.MEDIUM,
                    'title': f'gMSA "{sam}" readable by {reader_count} principals',
                    'description': (
                        f'The gMSA account "{sam}" allows {reader_count} '
                        'principal(s) to retrieve its managed password. '
                        'Excessive readers increase the risk of credential exposure.'
                    ),
                    'affected_object': sam,
                    'object_type': 'user',
                    'mitigation': (
                        'Restrict PrincipalsAllowedToRetrieveManagedPassword '
                        'to only the specific computer accounts that need it.'
                    ),
                    'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                    'reader_count': reader_count,
                })

            # Check password rotation interval
            interval = gmsa.get('msDS-ManagedPasswordInterval')
            if interval:
                try:
                    interval_days = int(interval)
                    if interval_days > 60:
                        risks.append({
                            'type': RiskTypes.GOLDEN_GMSA_EXCESSIVE_READERS,
                            'severity': Severity.LOW,
                            'title': f'gMSA "{sam}" password interval is {interval_days} days',
                            'description': (
                                f'The gMSA "{sam}" rotates its password every '
                                f'{interval_days} days. The default is 30 days. '
                                'A longer interval increases the window of '
                                'opportunity after a credential compromise.'
                            ),
                            'affected_object': sam,
                            'object_type': 'user',
                            'mitigation': (
                                'Consider reducing msDS-ManagedPasswordInterval '
                                'to 30 days or less.'
                            ),
                            'password_interval_days': interval_days,
                        })
                except (ValueError, TypeError):
                    pass

        return risks
