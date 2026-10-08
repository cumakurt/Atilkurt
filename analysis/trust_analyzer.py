"""
Trust Relationship Analyzer Module
Analyzes forest trusts, external trusts, and trust configurations
"""

import logging
from typing import Any
from core.ad_identity import forest_configuration_dn
from core.ad_security import as_int
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class TrustAnalyzer:
    """Analyzes trust relationships in Active Directory."""

    def __init__(self, ldap_connection):
        """
        Initialize trust analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze_trusts(self) -> list[dict[str, Any]]:
        """
        Analyze trust relationships.

        Returns:
            List of risk dictionaries for trust relationships
        """
        risks = []

        try:
            base_dn = self.ldap.base_dn
            trusts_found = []

            # Search for trust objects - try multiple locations
            search_filter = '(objectClass=trustedDomain)'
            attributes = [
                'name',
                'trustDirection',
                'trustType',
                'trustAttributes',
                'flatName',
                'distinguishedName'
            ]

            # Approach 1: Search in System container (most common location)
            try:
                results = self.ldap.search(
                    search_base=f"CN=System,{base_dn}",
                    search_filter=search_filter,
                    attributes=attributes
                )
                if results:
                    trusts_found.extend(results)
                    logger.debug(f"Found {len(results)} trusts in System container")
            except Exception as e:
                logger.debug(f"Error searching System container for trusts: {e}")

            # Approach 2: Search from domain root
            if not trusts_found:
                try:
                    results = self.ldap.search(
                        search_base=base_dn,
                        search_filter=search_filter,
                        attributes=attributes
                    )
                    if results:
                        trusts_found.extend(results)
                        logger.debug(f"Found {len(results)} trusts from domain root")
                except Exception as e:
                    logger.debug(f"Error searching domain root for trusts: {e}")

            # Approach 3: Search without base (search entire domain)
            if not trusts_found:
                try:
                    results = self.ldap.search(
                        search_filter=search_filter,
                        attributes=attributes
                    )
                    if results:
                        trusts_found.extend(results)
                        logger.debug(f"Found {len(results)} trusts via domain-wide search")
                except Exception as e:
                    logger.debug(f"Error doing domain-wide trust search: {e}")

            # Approach 4: Try to find trusts in Configuration partition
            if not trusts_found:
                try:
                    config_dn = forest_configuration_dn(self.ldap)
                    if not config_dn:
                        logger.debug("Configuration naming context unavailable for trust search")
                    else:
                        results = self.ldap.search(
                            search_base=config_dn,
                            search_filter=search_filter,
                            attributes=attributes
                        )
                        if results:
                            trusts_found.extend(results)
                            logger.debug(f"Found {len(results)} trusts in Configuration partition")
                except Exception as e:
                    logger.debug(f"Error searching Configuration partition: {e}")

            # Remove duplicates based on DN
            seen_dns = set()
            unique_trusts = []
            for trust in trusts_found:
                trust_dn = trust.get('distinguishedName') or trust.get('dn')
                if trust_dn and trust_dn not in seen_dns:
                    seen_dns.add(trust_dn)
                    unique_trusts.append(trust)

            if not unique_trusts:
                logger.info("No trust relationships found in the domain")
                return risks

            logger.info(f"Found {len(unique_trusts)} trust relationship(s)")

            for trust in unique_trusts:
                trust_name = trust.get('name')
                if not trust_name:
                    continue

                trust_direction = as_int(trust.get('trustDirection'))
                trust_type = as_int(trust.get('trustType'))
                trust_attributes = as_int(trust.get('trustAttributes'))
                if trust_direction not in (2, 3) or trust_type is None or trust_attributes is None:
                    continue
                # Intra-forest trusts do not use the external-domain quarantine
                # flag as their SID-filtering boundary.
                if trust_attributes & 0x20:
                    continue
                direction_str = self._get_trust_direction_str(trust_direction)
                forest = bool(trust_attributes & 0x8)
                type_str = 'Forest Trust' if forest else 'External Trust'
                trust_risks = []
                if not forest and not trust_attributes & 0x4:
                    trust_risks.append({
                        'issue': 'External trust does not enable SID quarantine',
                        'severity': Severity.CRITICAL,
                        'description': 'An external domain is trusted locally without the QUARANTINED_DOMAIN protection.',
                    })
                if not trust_attributes & 0x10:
                    trust_risks.append({
                        'issue': 'Selective authentication is disabled',
                        'severity': Severity.MEDIUM,
                        'description': 'The trusted external domain can authenticate locally without selective-authentication restrictions.',
                    })

                # Create risk entries
                for trust_risk in trust_risks:
                    risks.append({
                        'type': RiskTypes.TRUST_RELATIONSHIP_RISK,
                        'severity': trust_risk['severity'],
                        'title': f'Trust Risk: {trust_name} - {trust_risk["issue"]}',
                        'description': f"Trust '{trust_name}' ({type_str}, {direction_str}): {trust_risk['description']}",
                        'affected_object': trust_name,
                        'object_type': 'trust',
                        'evidence': {'trust_direction': trust_direction, 'trust_attributes': trust_attributes},
                        'trust_details': {
                            'name': trust_name,
                            'type': type_str,
                            'direction': direction_str,
                            'direction_value': trust_direction,
                            'sid_filtering': bool(trust_attributes & 0x4) if not forest else None,
                            'selective_authentication': bool(trust_attributes & 0x10)
                        },
                        'impact': trust_risk['description'],
                        'attack_scenario': (
                            f'An attacker who compromises the trusted domain "{trust_name}" could '
                            'potentially use the trust relationship to gain access to resources '
                            'in our domain, especially if SID filtering is disabled.'
                        ),
                        'mitigation': (
                            'Review trust relationships regularly. Enable SID filtering. Use selective '
                            'authentication where possible. Consider if bidirectional trusts are necessary. '
                            'Monitor for suspicious cross-trust authentication.'
                        ),
                        'cis_reference': 'CIS Benchmark requires SID filtering on all trusts',
                        'mitre_attack': MITRETechniques.LATERAL_MOVEMENT
                    })

            logger.info(f"Found {len(risks)} trust relationship risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing trusts: {str(e)}")
            return []

    def _get_trust_direction_str(self, direction: int) -> str:
        """Get human-readable trust direction string."""
        directions = {
            0: 'Disabled',
            1: 'Inbound',
            2: 'Outbound',
            3: 'Bidirectional'
        }
        return directions.get(direction, 'Unknown')
