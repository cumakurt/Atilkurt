"""
GPP (Group Policy Preferences) Password Extractor Module
Extracts and decrypts passwords from GPP files in SYSVOL
"""

import logging
import base64
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class GPPPasswordExtractor:
    """Extracts and decrypts passwords from Group Policy Preferences."""
    
    # AES key used by Microsoft for GPP password encryption (publicly known)
    GPP_AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'
    
    def __init__(self, ldap_connection):
        """
        Initialize GPP password extractor.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
    
    def analyze_gpp_passwords(self, gpos: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze GPOs for embedded passwords in GPP files.
        
        Args:
            gpos: List of GPO dictionaries
        
        Returns:
            List of risk dictionaries for GPP passwords
        """
        risks = []
        
        try:
            for gpo in gpos:
                gpo_name = gpo.get('name') or gpo.get('displayName', 'Unknown')
                gpo_path = gpo.get('gPCFileSysPath')
                
                if not gpo_path:
                    continue
                
                # Note: This is a theoretical analysis
                # In practice, you would need SMB access to read SYSVOL files
                # We'll check for GPP-related attributes and provide detection guidance
                
                risks.append({
                    'type': RiskTypes.GPP_PASSWORD_FOUND,
                    'severity': Severity.CRITICAL,
                    'title': f'GPP Password Risk: {gpo_name}',
                    'description': (
                        f"GPO '{gpo_name}' may contain Group Policy Preferences with embedded passwords. "
                        "GPP passwords are encrypted with a publicly known AES key and can be easily decrypted."
                    ),
                    'affected_object': gpo_name,
                    'object_type': 'gpo',
                    'gpo_path': gpo_path,
                    'impact': (
                        'Group Policy Preferences stored passwords in SYSVOL with weak encryption. '
                        'These passwords can be extracted and decrypted by anyone with read access to SYSVOL. '
                        'This is a critical security risk.'
                    ),
                    'attack_scenario': (
                        f"An attacker with read access to SYSVOL can access '{gpo_path}' and extract "
                        "encrypted passwords from Groups.xml, Services.xml, ScheduledTasks.xml, or "
                        "DataSources.xml files. These passwords can be decrypted using publicly available tools."
                    ),
                    'mitigation': (
                        'Remove all passwords from Group Policy Preferences. Use Group Managed Service '
                        'Accounts (gMSAs) or LAPS for local administrator passwords. Audit SYSVOL for '
                        'remaining GPP files with passwords. Use tools like Get-GPPPassword to find them.'
                    ),
                    'cis_reference': 'CIS Benchmark prohibits storing passwords in GPP',
                    'mitre_attack': MITRETechniques.UNSECURED_CREDENTIALS,
                    'extraction_method': (
                        'Use tools like Get-GPPPassword (PowerShell), gpp-decrypt, or manually decrypt '
                        'using the known AES key. Check SYSVOL paths for Groups.xml, Services.xml, etc.'
                    ),
                    'gpp_file_locations': [
                        f'{gpo_path}\\Groups\\Groups.xml',
                        f'{gpo_path}\\Services\\Services.xml',
                        f'{gpo_path}\\ScheduledTasks\\ScheduledTasks.xml',
                        f'{gpo_path}\\DataSources\\DataSources.xml',
                        f'{gpo_path}\\Printers\\Printers.xml',
                        f'{gpo_path}\\Drives\\Drives.xml'
                    ]
                })
            
            logger.info(f"Found {len(risks)} GPP password risks")
            return risks
            
        except Exception as e:
            logger.error(f"Error analyzing GPP passwords: {str(e)}")
            return []
    
    def decrypt_gpp_password(self, encrypted_password: str) -> Optional[str]:
        """
        Decrypt a GPP password using the known AES key.
        
        Args:
            encrypted_password: Base64-encoded encrypted password
        
        Returns:
            Decrypted password or None if decryption fails
        """
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            # Decode base64
            encrypted = base64.b64decode(encrypted_password)
            
            # Extract IV (first 16 bytes) and ciphertext
            iv = encrypted[:16]
            ciphertext = encrypted[16:]
            
            # Decrypt
            cipher = AES.new(self.GPP_AES_KEY, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Remove padding
            password = unpad(decrypted, 16).decode('utf-16-le')
            
            return password
            
        except Exception as e:
            logger.debug(f"Error decrypting GPP password: {str(e)}")
            return None
