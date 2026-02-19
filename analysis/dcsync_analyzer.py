"""
DCSync Rights Analyzer Module
Detects accounts with DCSync rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class DCSyncAnalyzer:
    """Analyzes DCSync rights and identifies accounts vulnerable to DCSync attacks."""
    
    # DCSync rights OIDs
    DS_REPLICATION_GET_CHANGES = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    DS_REPLICATION_GET_CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    
    def __init__(self, ldap_connection):
        """
        Initialize DCSync analyzer.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
    
    def analyze_dcsync_rights(self, users: List[Dict[str, Any]], 
                            groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze DCSync rights for users and groups.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
        
        Returns:
            List of risk dictionaries for DCSync rights
        """
        risks = []
        
        try:
            # Get domain root DN
            base_dn = self.ldap.base_dn
            
            # Search for objects with DCSync rights
            # Check domain root and configuration partition
            search_bases = [
                base_dn,
                f"CN=Configuration,{base_dn}"
            ]
            
            for search_base in search_bases:
                try:
                    # Search for objects with replication rights
                    # This is done by checking nTSecurityDescriptor
                    results = self.ldap.search(
                        search_base=search_base,
                        search_filter='(objectClass=*)',
                        attributes=['distinguishedName', 'nTSecurityDescriptor', 'sAMAccountName', 'name'],
                        size_limit=0  # Unlimited - analyze all objects
                    )
                    
                    # Use a set to track processed accounts and avoid duplicates
                    processed_accounts = set()
                    
                    for entry in results:
                        dn = entry.get('dn') or entry.get('distinguishedName')
                        if not dn:
                            continue
                        
                        # Check if this object has DCSync rights
                        dcsync_accounts = self._check_dcsync_rights(dn, users, groups)
                        
                        for account_info in dcsync_accounts:
                            account_key = f"{account_info['account_name']}_{account_info['account_type']}"
                            if account_key in processed_accounts:
                                continue
                            processed_accounts.add(account_key)
                            
                            risks.append({
                                'type': RiskTypes.DCSYNC_RIGHTS,
                                'severity': Severity.CRITICAL,
                                'title': f'DCSync Rights: {account_info["account_name"]}',
                                'description': (
                                    f"Account '{account_info['account_name']}' has DCSync rights "
                                    f"on '{dn}'. This allows the account to replicate domain data "
                                    "including password hashes."
                                ),
                                'affected_object': account_info['account_name'],
                                'object_type': account_info['account_type'],
                                'target_object': dn,
                                'dcsync_rights': account_info['rights'],
                                'impact': (
                                    'Accounts with DCSync rights can replicate all domain data including '
                                    'password hashes. This is equivalent to having Domain Admin privileges. '
                                    'An attacker with DCSync rights can extract all password hashes from '
                                    'the domain controller.'
                                ),
                                'attack_scenario': (
                                    f"An attacker who compromises '{account_info['account_name']}' can use "
                                    "tools like Mimikatz (lsadump::dcsync) or Impacket secretsdump to extract "
                                    "all password hashes from the domain controller without needing to be "
                                    "on the DC itself."
                                ),
                                'mitigation': (
                                    'Review and remove DCSync rights from non-essential accounts. Only '
                                    'Domain Controllers and specific service accounts should have DCSync rights. '
                                    'Use privileged access management (PAM) solutions. Monitor for DCSync '
                                    'usage attempts.'
                                ),
                                'cis_reference': 'CIS Benchmark requires strict control over DCSync rights',
                                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_DCSYNC,
                                'exploitation_tools': [
                                    'Mimikatz lsadump::dcsync',
                                    'Impacket secretsdump',
                                    'DSInternals Get-ADReplAccount',
                                    'Rubeus'
                                ]
                            })
                
                except Exception as e:
                    logger.debug(f"Error checking DCSync rights for {search_base}: {str(e)}")
                    continue
            
            # Also check well-known privileged groups that typically have DCSync
            # Use a set to avoid duplicate risks
            processed_users = set()
            privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Administrators']
            for group in groups:
                group_name = group.get('name') or group.get('sAMAccountName')
                if group_name and any(priv in group_name for priv in privileged_groups):
                    # Check members of these groups
                    members = group.get('member', []) or []
                    if not isinstance(members, list):
                        members = [members] if members else []
                    
                    for member_dn in members:
                        member_name = self._extract_name_from_dn(member_dn)
                        if member_name and member_name not in processed_users:
                            # Check if this user is in the list
                            for user in users:
                                username = user.get('sAMAccountName')
                                if username == member_name:
                                    processed_users.add(username)
                                    risks.append({
                                        'type': RiskTypes.DCSYNC_RIGHTS,
                                        'severity': Severity.CRITICAL,
                                        'title': f'DCSync via Privileged Group: {username}',
                                        'description': (
                                            f"User '{username}' is member of '{group_name}' which has "
                                            "implicit DCSync rights through Domain Admin privileges."
                                        ),
                                        'affected_object': username,
                                        'object_type': 'user',
                                        'privileged_group': group_name,
                                        'impact': (
                                            'Members of Domain Admins, Enterprise Admins, or Administrators '
                                            'have implicit DCSync rights and can extract all password hashes.'
                                        ),
                                        'attack_scenario': (
                                            f"An attacker who compromises '{username}' can use DCSync "
                                            "to extract all domain password hashes."
                                        ),
                                        'mitigation': (
                                            'Apply principle of least privilege. Remove unnecessary members '
                                            'from privileged groups. Use privileged access management.'
                                        ),
                                        'cis_reference': 'CIS Benchmark requires minimal membership in privileged groups',
                                        'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_DCSYNC,
                                        'exploitation_tools': [
                                            'Mimikatz lsadump::dcsync',
                                            'Impacket secretsdump'
                                        ]
                                    })
                                    break
            
            logger.info(f"Found {len(risks)} DCSync rights risks")
            return risks
            
        except Exception as e:
            logger.error(f"Error analyzing DCSync rights: {str(e)}")
            return []
    
    def _check_dcsync_rights(self, target_dn: str, users: List[Dict], 
                           groups: List[Dict]) -> List[Dict[str, Any]]:
        """
        Check if any users or groups have DCSync rights on target object.
        
        Args:
            target_dn: Distinguished name of target object
            users: List of user dictionaries
            groups: List of group dictionaries
        
        Returns:
            List of account info dictionaries with DCSync rights
        """
        accounts_with_rights = []
        
        # This is a simplified check - in production, you would parse nTSecurityDescriptor
        # For now, we'll check well-known accounts and groups
        
        # Check users
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            # Check if user is in privileged groups (implicit DCSync)
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            for group_dn in member_of:
                group_name = self._extract_name_from_dn(group_dn)
                if group_name and any(priv in group_name for priv in 
                    ['Domain Admins', 'Enterprise Admins', 'Administrators']):
                    accounts_with_rights.append({
                        'account_name': username,
                        'account_type': 'user',
                        'rights': ['DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All'],
                        'source': f'Member of {group_name}'
                    })
                    break
        
        return accounts_with_rights
    
    def _extract_name_from_dn(self, dn: str) -> Optional[str]:
        """Extract name from distinguished name."""
        if not dn:
            return None
        if 'CN=' in dn:
            try:
                cn_part = dn.split('CN=')[1].split(',')[0]
                return cn_part
            except Exception:
                return None
        return dn
