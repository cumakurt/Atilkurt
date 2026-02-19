"""
Certificate-Based Attack Analyzer Module
Detects AD CS vulnerabilities: ESC1, ESC2, ESC3, ESC4, ESC6, ESC8
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class CertificateAnalyzer:
    """Analyzes Active Directory Certificate Services for vulnerabilities."""
    
    def __init__(self, ldap_connection):
        """
        Initialize certificate analyzer.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
    
    def analyze_certificate_services(self) -> List[Dict[str, Any]]:
        """
        Analyze AD Certificate Services for vulnerabilities.
        
        Returns:
            List of risk dictionaries for certificate-based attacks
        """
        risks = []
        
        try:
            base_dn = self.ldap.base_dn
            config_dn = f"CN=Configuration,{base_dn}"
            
            # Search for Certificate Templates
            search_filter = '(objectClass=pKICertificateTemplate)'
            # Use standard attribute names that are more likely to work
            attributes = [
                'name',
                'displayName',
                'distinguishedName'
            ]
            
            try:
                templates = self.ldap.search(
                    search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
                    search_filter=search_filter,
                    attributes=attributes
                )
                
                for template in templates:
                    template_name = template.get('name') or template.get('displayName', 'Unknown')
                    
                    # Try to get additional attributes for detailed analysis
                    template_dn = template.get('dn') or template.get('distinguishedName')
                    if template_dn:
                        try:
                            # Try to read certificate template attributes with proper names
                            detailed_template = self.ldap.search(
                                search_base=template_dn,
                                search_filter='(objectClass=pKICertificateTemplate)',
                                attributes=['*']  # Get all attributes
                            )
                            if detailed_template:
                                template.update(detailed_template[0])
                        except Exception as e:
                            logger.debug(f"Could not read detailed template attributes: {str(e)}")
                    
                    # Analyze template for various ESC vulnerabilities
                    template_risks = self._analyze_template_vulnerabilities(template, template_name)
                    risks.extend(template_risks)
            
            except Exception as e:
                logger.debug(f"Error searching for certificate templates: {str(e)}")
                # Provide general guidance even if templates can't be read
                risks.append({
                    'type': RiskTypes.CERTIFICATE_SERVICES_DETECTED,
                    'severity': Severity.MEDIUM,
                    'title': 'AD Certificate Services Detected',
                    'description': (
                        'Active Directory Certificate Services (AD CS) is configured. '
                        'Review certificate templates for vulnerabilities (ESC1-ESC8).'
                    ),
                    'affected_object': 'AD CS',
                    'object_type': 'service',
                    'impact': (
                        'Misconfigured certificate templates can allow privilege escalation. '
                        'Attackers can request certificates that enable domain compromise.'
                    ),
                    'attack_scenario': (
                        'Attackers can exploit misconfigured certificate templates to request certificates '
                        'that allow authentication as other users or with elevated privileges.'
                    ),
                    'mitigation': (
                        'Review all certificate templates. Ensure templates do not allow enrollment by '
                        'unauthenticated users. Remove dangerous EKUs. Restrict certificate enrollment. '
                        'Use tools like Certipy or PSPKIAudit to audit templates.'
                    ),
                    'cis_reference': 'CIS Benchmark requires secure certificate template configuration',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER
                })
            
            logger.info(f"Found {len(risks)} certificate service risks")
            return risks
            
        except Exception as e:
            logger.error(f"Error analyzing certificate services: {str(e)}")
            return []
    
    def _analyze_template_vulnerabilities(self, template: Dict, template_name: str) -> List[Dict[str, Any]]:
        """
        Analyze a certificate template for vulnerabilities.
        
        Args:
            template: Template dictionary
            template_name: Name of the template
        
        Returns:
            List of risk dictionaries
        """
        risks = []
        
        # Try different attribute name variations
        enrollment_flags = 0
        for attr_name in ['pKIEnrollmentFlags', 'pKIEnrollmentFlags', 'msPKI-Enrollment-Flag']:
            if attr_name in template:
                try:
                    enrollment_flags = template.get(attr_name, 0)
                    if isinstance(enrollment_flags, str):
                        enrollment_flags = int(enrollment_flags)
                    break
                except (ValueError, TypeError):
                    pass
        
        name_flags = 0
        for attr_name in ['msPKI-Certificate-Name-Flag', 'msPKICertificateNameFlag']:
            if attr_name in template:
                try:
                    name_flags = template.get(attr_name, 0)
                    if isinstance(name_flags, str):
                        name_flags = int(name_flags)
                    break
                except (ValueError, TypeError):
                    pass
        
        # ESC1: Enrollee Supplies Subject + No Manager Approval + Autoenroll Enabled
        # ENROLLEE_SUPPLIES_SUBJECT = 0x1
        # AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x20
        if (enrollment_flags & 0x1) and (enrollment_flags & 0x20):
            # Check if template allows client authentication
            ekus = template.get('pKIExtendedKeyUsage', []) or []
            if not isinstance(ekus, list):
                ekus = [ekus] if ekus else []
            
            has_client_auth = any('1.3.6.1.5.5.7.3.2' in str(eku) for eku in ekus)
            
            if has_client_auth:
                risks.append({
                    'type': RiskTypes.CERTIFICATE_ESC1,
                    'severity': Severity.CRITICAL,
                    'title': f'ESC1 Vulnerability: {template_name}',
                    'description': (
                        f"Certificate template '{template_name}' is vulnerable to ESC1. "
                        "It allows enrollees to supply the subject and enables client authentication."
                    ),
                    'affected_object': template_name,
                    'object_type': 'certificate_template',
                    'vulnerability': 'ESC1',
                    'impact': (
                        'ESC1 allows attackers to request certificates for any user, enabling '
                        'authentication as that user and privilege escalation.'
                    ),
                    'attack_scenario': (
                        f"An attacker can request a certificate from template '{template_name}' "
                        "for a Domain Admin account, then use that certificate to authenticate "
                        "as Domain Admin."
                    ),
                    'mitigation': (
                        'Remove ENROLLEE_SUPPLIES_SUBJECT flag. Require manager approval. '
                        'Remove client authentication EKU or restrict enrollment.'
                    ),
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER
                })
        
        # ESC2: Any Purpose EKU or No EKU
        ekus = template.get('pKIExtendedKeyUsage', []) or []
        if not isinstance(ekus, list):
            ekus = [ekus] if ekus else []
        
        has_any_purpose = any('2.5.29.37.0' in str(eku) for eku in ekus)  # Any Purpose OID
        has_no_eku = len(ekus) == 0
        
        if has_any_purpose or has_no_eku:
            risks.append({
                'type': RiskTypes.CERTIFICATE_ESC2,
                'severity': Severity.CRITICAL,
                'title': f'ESC2 Vulnerability: {template_name}',
                'description': (
                    f"Certificate template '{template_name}' is vulnerable to ESC2. "
                    "It has Any Purpose EKU or no EKU restrictions."
                ),
                'affected_object': template_name,
                'object_type': 'certificate_template',
                'vulnerability': 'ESC2',
                'impact': (
                    'ESC2 allows certificates to be used for any purpose, enabling various '
                    'attack scenarios including client authentication and code signing.'
                ),
                'attack_scenario': (
                    f"An attacker can request a certificate from template '{template_name}' "
                    "and use it for client authentication or other purposes to gain unauthorized access."
                ),
                'mitigation': (
                    'Remove Any Purpose EKU. Add specific EKUs. Restrict certificate usage.'
                ),
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER
            })
        
        # Additional ESC vulnerabilities would require more detailed analysis
        # ESC3, ESC4, ESC6, ESC8 require checking specific permissions and configurations
        
        return risks
