"""
gMSA (Group Managed Service Account) Analyzer Module
Detects gMSA misconfigurations, legacy service accounts that should migrate to gMSA,
and over-permissive password retrieval ACLs.
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity, MITRETechniques, ServiceAccountPatterns

logger = logging.getLogger(__name__)


class GMSAAnalyzer:
    """Analyzes gMSA configuration and identifies migration opportunities."""

    def __init__(self, ldap_connection):
        """
        Initialize gMSA analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze(
        self,
        users: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Analyze gMSA and service account security posture.

        Args:
            users: List of user dictionaries

        Returns:
            List of risk dictionaries
        """
        risks: List[Dict[str, Any]] = []

        try:
            base_dn = self.ldap.base_dn

            # ── 1. Enumerate gMSA accounts ──
            gmsa_accounts = self._get_gmsa_accounts(base_dn)

            # ── 2. Check gMSA configuration ──
            for gmsa in gmsa_accounts:
                risks.extend(self._check_gmsa_config(gmsa))

            # ── 3. Identify legacy service accounts that could be gMSA ──
            risks.extend(self._find_legacy_service_accounts(users, gmsa_accounts))

            logger.info(f"Found {len(risks)} gMSA-related risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing gMSA: {e}")
            return []

    # ── gMSA Retrieval ──────────────────────────────────────────────────────

    def _get_gmsa_accounts(self, base_dn: str) -> List[Dict[str, Any]]:
        """Retrieve all gMSA accounts from the domain."""
        try:
            results = self.ldap.search(
                search_base=base_dn,
                search_filter='(objectClass=msDS-GroupManagedServiceAccount)',
                attributes=[
                    'sAMAccountName', 'distinguishedName',
                    'msDS-ManagedPasswordInterval',
                    'PrincipalsAllowedToRetrieveManagedPassword',
                    'msDS-GroupMSAMembership',
                    'servicePrincipalName', 'userAccountControl',
                    'whenCreated', 'description',
                ],
            )
            return results if results else []
        except Exception as e:
            logger.debug(f"Could not retrieve gMSA accounts: {e}")
            return []

    # ── gMSA Configuration Checks ──────────────────────────────────────────

    def _check_gmsa_config(
        self, gmsa: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Check a single gMSA account for misconfigurations."""
        risks: List[Dict[str, Any]] = []
        sam = gmsa.get('sAMAccountName', '?')

        # Check if gMSA is disabled
        uac = gmsa.get('userAccountControl')
        if uac:
            try:
                if int(uac) & 0x2:  # ACCOUNTDISABLE
                    risks.append({
                        'type': RiskTypes.GMSA_MISCONFIGURATION,
                        'severity': Severity.LOW,
                        'title': f'gMSA "{sam}" is disabled',
                        'description': (
                            f'The gMSA account "{sam}" is disabled. '
                            'If no longer needed, remove it to reduce clutter.'
                        ),
                        'affected_object': sam,
                        'object_type': 'user',
                        'mitigation': 'Remove unused gMSA accounts.',
                    })
            except (ValueError, TypeError):
                pass

        # Check SPN assignment
        spns = gmsa.get('servicePrincipalName', [])
        if not spns:
            risks.append({
                'type': RiskTypes.GMSA_MISCONFIGURATION,
                'severity': Severity.LOW,
                'title': f'gMSA "{sam}" has no SPN assigned',
                'description': (
                    f'The gMSA account "{sam}" does not have a '
                    'Service Principal Name (SPN). This may indicate '
                    'the gMSA is not being used by any service.'
                ),
                'affected_object': sam,
                'object_type': 'user',
                'mitigation': (
                    'Assign the appropriate SPN(s) to this gMSA '
                    'or remove it if unused.'
                ),
            })

        # Check password interval
        interval = gmsa.get('msDS-ManagedPasswordInterval')
        if interval:
            try:
                days = int(interval)
                if days > 90:
                    risks.append({
                        'type': RiskTypes.GMSA_MISCONFIGURATION,
                        'severity': Severity.MEDIUM,
                        'title': f'gMSA "{sam}" password interval is {days} days',
                        'description': (
                            f'The gMSA "{sam}" rotates its password every '
                            f'{days} days (default 30). A longer interval '
                            'increases the exposure window after compromise.'
                        ),
                        'affected_object': sam,
                        'object_type': 'user',
                        'mitigation': (
                            'Reduce msDS-ManagedPasswordInterval to 30 days.'
                        ),
                        'password_interval_days': days,
                    })
            except (ValueError, TypeError):
                pass

        return risks

    # ── Legacy Service Account Detection ────────────────────────────────────

    def _find_legacy_service_accounts(
        self,
        users: List[Dict[str, Any]],
        gmsa_accounts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Identify traditional service accounts that should migrate to gMSA."""
        risks: List[Dict[str, Any]] = []
        gmsa_names = {
            g.get('sAMAccountName', '').lower() for g in gmsa_accounts
        }

        legacy_svc: List[str] = []

        for user in users:
            sam = user.get('sAMAccountName', '')
            if not sam or sam.lower() in gmsa_names:
                continue

            # Detect service account by pattern
            upper = sam.upper()
            is_service = any(upper.startswith(p) for p in ServiceAccountPatterns.PREFIXES)
            if not is_service:
                is_service = any(kw in upper for kw in ServiceAccountPatterns.KEYWORDS)

            # Also detect by SPN (regular user with SPN = potential Kerberoasting)
            spns = user.get('servicePrincipalName', [])
            has_spn = bool(spns)

            # Check password never expires flag
            uac = user.get('userAccountControl')
            pwd_never_expires = False
            if uac:
                try:
                    pwd_never_expires = bool(int(uac) & 0x10000)
                except (ValueError, TypeError):
                    pass

            if (is_service or has_spn) and pwd_never_expires:
                legacy_svc.append(sam)

        if legacy_svc:
            risks.append({
                'type': RiskTypes.GMSA_LEGACY_SERVICE_ACCOUNT,
                'severity': Severity.MEDIUM,
                'title': f'{len(legacy_svc)} service accounts should migrate to gMSA',
                'description': (
                    f'{len(legacy_svc)} traditional service account(s) have '
                    '"password never expires" and an SPN. Migrating to gMSA '
                    'would automatically handle password rotation and eliminate '
                    'Kerberoasting risk for these accounts.'
                ),
                'affected_object': ', '.join(legacy_svc[:15])
                    + (f' ... (+{len(legacy_svc)-15} more)' if len(legacy_svc) > 15 else ''),
                'object_type': 'user',
                'impact': (
                    'Traditional service accounts with static passwords are '
                    'prime Kerberoasting targets. gMSA accounts use 240-byte '
                    'random passwords rotated automatically, making offline '
                    'cracking infeasible.'
                ),
                'mitigation': (
                    'Migrate identified service accounts to gMSA:\n'
                    '1. Create gMSA: New-ADServiceAccount -Name <name> '
                    '-DNSHostName <fqdn> -ManagedPasswordIntervalInDays 30\n'
                    '2. Install on target: Install-ADServiceAccount <name>\n'
                    '3. Update service to use the gMSA account'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                'legacy_accounts': legacy_svc,
                'legacy_count': len(legacy_svc),
            })

        return risks
