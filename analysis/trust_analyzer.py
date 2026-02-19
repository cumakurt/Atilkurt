"""
Trust Relationship Analyzer Module
Analyzes forest trusts, external trusts, and trust configurations
"""

import logging
from typing import List, Dict, Any, Optional
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
    
    def analyze_trusts(self) -> List[Dict[str, Any]]:
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
                    config_dn = f"CN=Configuration,{base_dn}"
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
                # Create informational risk if no trusts found
                risks.append({
                    'type': RiskTypes.TRUST_RELATIONSHIP_RISK,
                    'severity': Severity.LOW,
                    'title': 'No Trust Relationships Found',
                    'description': 'No trust relationships were found in the domain. This may indicate that trusts are configured at a different location, or the domain has no external/forest trusts.',
                    'affected_object': 'Domain Trusts',
                    'object_type': 'trust',
                    'trust_details': {
                        'trust_count': 0
                    },
                    'impact': 'No trust relationships detected. If trusts exist but are not visible, they may be configured in a way that is not accessible via standard LDAP queries.',
                    'attack_scenario': 'If trusts exist but are not detected, they may pose security risks that are not being monitored.',
                    'mitigation': 'Verify trust relationships manually using: Get-ADTrust (PowerShell) or nltest /domain_trusts (command line). Ensure LDAP read permissions for trust objects.',
                    'cis_reference': 'CIS Benchmark requires trust relationship review',
                    'mitre_attack': MITRETechniques.LATERAL_MOVEMENT
                })
                return risks
            
            logger.info(f"Found {len(unique_trusts)} trust relationship(s)")
            
            for trust in unique_trusts:
                trust_name = trust.get('name')
                if not trust_name:
                    continue
                
                trust_direction = trust.get('trustDirection', 0)
                trust_type = trust.get('trustType', 0)
                trust_attributes = trust.get('trustAttributes', 0)
                
                # Convert to integers if strings
                if isinstance(trust_direction, str):
                    trust_direction = int(trust_direction)
                if isinstance(trust_type, str):
                    trust_type = int(trust_type)
                if isinstance(trust_attributes, str):
                    trust_attributes = int(trust_attributes)
                
                # Analyze trust direction
                # 0 = Disabled, 1 = Inbound, 2 = Outbound, 3 = Bidirectional
                direction_str = self._get_trust_direction_str(trust_direction)
                
                # Analyze trust type
                # 1 = Downlevel (external), 2 = Uplevel (forest)
                type_str = 'Forest Trust' if trust_type == 2 else 'External Trust'
                
                # Check for security risks
                trust_risks = []
                
                # Bidirectional trusts are riskier
                if trust_direction == 3:
                    trust_risks.append({
                        'issue': 'Bidirectional trust allows authentication in both directions',
                        'severity': Severity.HIGH,
                        'description': (
                            'Bidirectional trusts allow users from both domains to authenticate '
                            'to resources in either domain, increasing attack surface.'
                        )
                    })
                
                # Outbound-only trusts (we trust them, they don't trust us)
                if trust_direction == 2:
                    trust_risks.append({
                        'issue': 'Outbound-only trust - we trust external domain',
                        'severity': Severity.MEDIUM,
                        'description': (
                            'Outbound trust allows users from external domain to access resources '
                            'in our domain, but we cannot access their domain.'
                        )
                    })
                
                # Check for SID filtering
                # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x4
                if not (trust_attributes & 0x4):
                    trust_risks.append({
                        'issue': 'SID filtering is disabled (quarantined domain attribute not set)',
                        'severity': Severity.CRITICAL,
                        'description': (
                            'SID filtering prevents SID history attacks. Without it, an attacker '
                            'could use SID history to gain unauthorized access.'
                        )
                    })
                
                # Check for selective authentication
                # TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x10 means selective authentication
                if trust_attributes & 0x10:
                    trust_risks.append({
                        'issue': 'Selective authentication is enabled',
                        'severity': Severity.LOW,
                        'description': (
                            'Selective authentication restricts which accounts can authenticate '
                            'across the trust, reducing risk.'
                        )
                    })
                else:
                    trust_risks.append({
                        'issue': 'Selective authentication is disabled - all accounts can authenticate',
                        'severity': Severity.MEDIUM,
                        'description': (
                            'Without selective authentication, all accounts from the trusted domain '
                            'can authenticate to resources in our domain.'
                        )
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
                        'trust_details': {
                            'name': trust_name,
                            'type': type_str,
                            'direction': direction_str,
                            'direction_value': trust_direction,
                            'sid_filtering': bool(trust_attributes & 0x4),
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
