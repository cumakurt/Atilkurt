"""
Kerberoasting and AS-REP Roasting Detection Module
Detects accounts vulnerable to Kerberoasting and AS-REP roasting attacks
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class KerberoastingDetector:
    """Detects accounts vulnerable to Kerberoasting and AS-REP roasting."""
    
    def __init__(self):
        """Initialize Kerberoasting detector."""
        pass
    
    def detect_kerberoasting_targets(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect users vulnerable to Kerberoasting attacks.
        
        Args:
            users: List of user dictionaries
        
        Returns:
            List of risk dictionaries for Kerberoasting targets
        """
        risks = []
        
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            spns = user.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            
            # User must have SPN to be vulnerable to Kerberoasting
            if not spns or len(spns) == 0:
                continue
            
            # Check if user is in privileged groups (higher risk)
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            privileged_groups = []
            is_privileged = False
            for group_dn in member_of:
                group_name = self._extract_group_name(group_dn)
                if group_name:
                    if any(priv in group_name.upper() for priv in 
                          ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS']):
                        is_privileged = True
                        privileged_groups.append(group_name)
            
            # Determine severity
            severity = Severity.CRITICAL if is_privileged else Severity.HIGH
            
            risks.append({
                'type': RiskTypes.KERBEROASTING_TARGET,
                'severity': severity,
                'title': f'Kerberoasting Target: {username}',
                'description': f"User '{username}' has {len(spns)} Service Principal Name(s) and is vulnerable to Kerberoasting attacks",
                'affected_object': username,
                'object_type': 'user',
                'spns': spns,
                'is_privileged': is_privileged,
                'privileged_groups': privileged_groups,
                'impact': 'This account can be targeted for Kerberoasting attacks. If the password is cracked, attackers gain access to the account and its associated permissions.',
                'attack_scenario': (
                    f"An attacker can request Kerberos service tickets for the SPNs associated with '{username}' "
                    "using tools like Impacket GetUserSPNs or Rubeus. The encrypted ticket can then be cracked "
                    "offline to obtain the account password without triggering account lockout."
                ),
                'mitigation': (
                    'Use strong, complex passwords for service accounts. Consider using managed service accounts '
                    '(MSAs) or group managed service accounts (gMSAs) instead of regular user accounts for services. '
                    'Implement monitoring for Kerberoasting attempts.'
                ),
                'cis_reference': 'CIS Benchmark recommends using managed service accounts for services',
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                'exploitation_tools': [
                    'Impacket GetUserSPNs',
                    'Rubeus kerberoast',
                    'CrackMapExec',
                    'hashcat (for password cracking)'
                ],
                'export_format': self._generate_export_format(username, spns, 'kerberoasting')
            })
        
        logger.info(f"Found {len(risks)} Kerberoasting targets")
        return risks
    
    def detect_asrep_roasting_targets(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect users vulnerable to AS-REP roasting attacks.
        
        Args:
            users: List of user dictionaries
        
        Returns:
            List of risk dictionaries for AS-REP roasting targets
        """
        risks = []
        
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            uac = user.get('userAccountControl', 0)
            if isinstance(uac, str):
                try:
                    uac = int(uac)
                except ValueError:
                    continue
            
            # Check if preauthentication is disabled
            # DONT_REQUIRE_PREAUTH = 4194304 (0x400000)
            if not (uac & 4194304):
                continue
            
            # Check if user is in privileged groups
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            privileged_groups = []
            is_privileged = False
            for group_dn in member_of:
                group_name = self._extract_group_name(group_dn)
                if group_name:
                    if any(priv in group_name.upper() for priv in 
                          ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS']):
                        is_privileged = True
                        privileged_groups.append(group_name)
            
            # Determine severity
            severity = Severity.CRITICAL if is_privileged else Severity.CRITICAL  # Always critical
            
            risks.append({
                'type': RiskTypes.ASREP_ROASTING_TARGET,
                'severity': severity,
                'title': f'AS-REP Roasting Target: {username}',
                'description': f"User '{username}' has Kerberos preauthentication disabled and is vulnerable to AS-REP roasting attacks",
                'affected_object': username,
                'object_type': 'user',
                'is_privileged': is_privileged,
                'privileged_groups': privileged_groups,
                'impact': 'This account can be targeted for AS-REP roasting attacks. Attackers can request Kerberos tickets without knowing the password and crack them offline without triggering account lockout.',
                'attack_scenario': (
                    f"An attacker can request a Kerberos ticket for '{username}' without preauthentication "
                    "using tools like Impacket GetNPUsers or Rubeus asreproast. The encrypted ticket can then "
                    "be cracked offline to obtain the account password without triggering account lockout policies."
                ),
                'mitigation': (
                    'IMMEDIATELY enable Kerberos preauthentication for this account. This is a critical security '
                    'setting that should never be disabled. Review why preauthentication was disabled and ensure '
                    'it is not needed for legitimate purposes.'
                ),
                'cis_reference': 'CIS Benchmark requires Kerberos preauthentication for all accounts',
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                'exploitation_tools': [
                    'Impacket GetNPUsers',
                    'Rubeus asreproast',
                    'CrackMapExec',
                    'hashcat (for password cracking)'
                ],
                'export_format': self._generate_export_format(username, [], 'asrep')
            })
        
        logger.info(f"Found {len(risks)} AS-REP roasting targets")
        return risks
    
    def _extract_group_name(self, group_dn: str) -> str:
        """Extract group name from DN."""
        if not group_dn:
            return ''
        if 'CN=' in group_dn:
            try:
                cn_part = group_dn.split('CN=')[1].split(',')[0]
                return cn_part
            except Exception:
                return ''
        return group_dn
    
    def _generate_export_format(self, username: str, spns: List[str], attack_type: str) -> Dict[str, Any]:
        """
        Generate export format for exploitation tools.
        
        Args:
            username: Username
            spns: List of SPNs (for Kerberoasting)
            attack_type: 'kerberoasting' or 'asrep'
        
        Returns:
            Dictionary with export formats
        """
        export = {
            'username': username,
            'attack_type': attack_type
        }
        
        if attack_type == 'kerberoasting':
            # Impacket format
            export['impacket_command'] = f"GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/{username}"
            
            # Rubeus format
            export['rubeus_command'] = f"Rubeus.exe kerberoast /user:{username}"
            
            # CrackMapExec format
            export['cme_command'] = f"crackmapexec ldap <DC_IP> -u {username} -p <PASSWORD> --kerberoasting"
            
            # SPN list for manual testing
            export['spns'] = spns
        
        elif attack_type == 'asrep':
            # Impacket format
            export['impacket_command'] = f"GetNPUsers.py -dc-ip <DC_IP> <DOMAIN>/{username} -no-pass"
            
            # Rubeus format
            export['rubeus_command'] = f"Rubeus.exe asreproast /user:{username}"
            
            # CrackMapExec format
            export['cme_command'] = f"crackmapexec ldap <DC_IP> -u {username} --asreproast"
        
        return export
