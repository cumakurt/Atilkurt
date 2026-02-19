"""
LAPS (Local Administrator Password Solution) Analyzer Module
Detects LAPS configuration and access rights
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class LAPSAnalyzer:
    """Analyzes LAPS configuration and access rights."""
    
    def __init__(self, ldap_connection):
        """
        Initialize LAPS analyzer.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
    
    def analyze_laps(self, computers: List[Dict[str, Any]], 
                    users: List[Dict[str, Any]], 
                    groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze LAPS configuration and access.
        
        Args:
            computers: List of computer dictionaries
            users: List of user dictionaries
            groups: List of group dictionaries
        
        Returns:
            List of risk dictionaries for LAPS issues
        """
        risks = []
        
        try:
            base_dn = self.ldap.base_dn
            
            # Check if LAPS is installed (ms-Mcs-AdmPwd attribute exists)
            laps_installed = False
            computers_with_laps = []
            
            for computer in computers:
                computer_name = computer.get('name')
                if not computer_name:
                    continue
                
                # Check for LAPS password attribute
                # Note: We can't read the password without proper permissions, but we can check if attribute exists
                computer_dn = computer.get('distinguishedName')
                if computer_dn:
                    # Try to read LAPS attributes with different name variations
                    # LAPS attributes may have different names in different AD versions
                    # If attributes don't exist, that's normal (LAPS not installed or no permissions)
                    laps_attributes = ['ms-Mcs-AdmPwdExpirationTime', 'msMcs-AdmPwdExpirationTime', 
                                     'msMcsAdmPwdExpirationTime']
                    
                    for attr_name in laps_attributes:
                        try:
                            # Use size_limit=1 and disable paging for single object search
                            # This avoids retry attempts for non-existent attributes
                            results = self.ldap.search(
                                search_base=computer_dn,
                                search_filter='(objectClass=computer)',
                                attributes=[attr_name],
                                size_limit=1
                            )
                            
                            if results and results[0].get(attr_name):
                                laps_installed = True
                                computers_with_laps.append(computer_name)
                                break
                        except Exception as e:
                            # Attribute doesn't exist or can't be read - this is normal if LAPS not installed
                            # Only log at debug level, don't retry
                            error_msg = str(e).lower()
                            if 'invalid attribute' in error_msg or 'no such attribute' in error_msg:
                                # Attribute doesn't exist - this is expected if LAPS not installed
                                logger.debug(f"LAPS attribute {attr_name} not found for {computer_name} (LAPS may not be installed)")
                            else:
                                logger.debug(f"Could not read LAPS attribute {attr_name} for {computer_name}: {str(e)}")
                            continue
            
            # Check LAPS configuration
            if not laps_installed:
                risks.append({
                    'type': RiskTypes.LAPS_NOT_CONFIGURED,
                    'severity': Severity.HIGH,
                    'title': 'LAPS Not Configured',
                    'description': (
                        'Local Administrator Password Solution (LAPS) is not configured. '
                        'Computers may have weak or shared local administrator passwords.'
                    ),
                    'affected_object': 'Domain',
                    'object_type': 'configuration',
                    'impact': (
                        'Without LAPS, local administrator passwords may be weak, shared, or never rotated. '
                        'This allows attackers to use the same password across multiple systems after '
                        'compromising one system.'
                    ),
                    'attack_scenario': (
                        'An attacker who compromises one system can use the local administrator password '
                        'to access other systems with the same password. This enables lateral movement.'
                    ),
                    'mitigation': (
                        'Install and configure LAPS. LAPS automatically manages unique, complex passwords '
                        'for local administrator accounts and rotates them regularly. Grant read access '
                        'only to authorized accounts.'
                    ),
                    'cis_reference': 'CIS Benchmark recommends using LAPS for local admin password management',
                    'mitre_attack': MITRETechniques.LATERAL_MOVEMENT
                })
            else:
                # Check who can read LAPS passwords
                # LAPS passwords are readable by accounts with "Read ms-Mcs-AdmPwd" permission
                # Typically granted to specific groups or users
                
                # Check if too many accounts can read LAPS passwords
                # This would require ACL analysis which is complex
                # For now, we'll provide general guidance
                
                if len(computers_with_laps) > 0:
                    risks.append({
                        'type': RiskTypes.LAPS_ACCESS_ANALYSIS,
                        'severity': Severity.MEDIUM,
                        'title': f'LAPS Configured on {len(computers_with_laps)} Computers',
                        'description': (
                            f'LAPS is configured on {len(computers_with_laps)} computers. '
                            'Review who has access to read LAPS passwords.'
                        ),
                        'affected_object': f'{len(computers_with_laps)} computers',
                        'object_type': 'configuration',
                        'computers_with_laps': computers_with_laps,
                        'impact': (
                            'LAPS passwords should only be readable by authorized accounts. '
                            'Too many accounts with LAPS read access increases the risk of password exposure.'
                        ),
                        'attack_scenario': (
                            'An attacker who compromises an account with LAPS read permissions can '
                            'extract local administrator passwords for all computers, enabling lateral movement.'
                        ),
                        'mitigation': (
                            'Review and restrict LAPS read permissions. Only grant access to accounts '
                            'that absolutely need it. Use privileged access management solutions. '
                            'Monitor for unauthorized LAPS password reads.'
                        ),
                        'cis_reference': 'CIS Benchmark requires strict control over LAPS access',
                        'mitre_attack': MITRETechniques.LATERAL_MOVEMENT
                    })
            
            logger.info(f"Found {len(risks)} LAPS-related risks")
            return risks
            
        except Exception as e:
            logger.error(f"Error analyzing LAPS: {str(e)}")
            return []
