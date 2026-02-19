"""
Service Account Analyzer Module
Analyzes service accounts for security risks
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class ServiceAccountAnalyzer:
    """Analyzes service accounts for security risks."""
    
    def __init__(self):
        """Initialize service account analyzer."""
        pass
    
    def analyze_service_accounts(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze service accounts for security risks.
        
        Args:
            users: List of user dictionaries
        
        Returns:
            List of risk dictionaries
        """
        risks = []
        
        for user in users:
            username = user.get('sAMAccountName', '')
            if not username:
                continue
            
            # Identify service accounts (users with SPNs)
            spns = user.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            
            if not spns or len(spns) == 0:
                continue
            
            # Check for high privilege
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
            
            # Check if using MSA/gMSA (would have specific naming or attributes)
            is_managed = self._is_managed_service_account(username, user)
            
            # Risk: Service account with high privileges
            if is_privileged:
                risks.append({
                    'type': RiskTypes.SERVICE_ACCOUNT_HIGH_PRIVILEGE,
                    'severity': Severity.CRITICAL,
                    'title': f'Service Account with High Privileges: {username}',
                    'description': f"Service account '{username}' has SPNs and is member of privileged groups",
                    'affected_object': username,
                    'object_type': 'user',
                    'spns': spns,
                    'privileged_groups': privileged_groups,
                    'is_managed': is_managed,
                    'impact': 'Service accounts with high privileges are prime targets for attackers. If compromised, they provide immediate access to critical systems.',
                    'attack_scenario': 'An attacker can target this service account for Kerberoasting. If successful, they gain access to a highly privileged account.',
                    'mitigation': 'Remove privileged group memberships from service accounts. Use managed service accounts (MSAs) or group managed service accounts (gMSAs) instead.',
                    'cis_reference': 'CIS Benchmark recommends using managed service accounts for services',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING
                })
            
            # Risk: Service account not using MSA/gMSA
            if not is_managed:
                risks.append({
                    'type': RiskTypes.SERVICE_ACCOUNT_WITHOUT_MSA,
                    'severity': Severity.HIGH,
                    'title': f'Service Account Not Using MSA/gMSA: {username}',
                    'description': f"Service account '{username}' is not using managed service account (MSA) or group managed service account (gMSA)",
                    'affected_object': username,
                    'object_type': 'user',
                    'spns': spns,
                    'is_privileged': is_privileged,
                    'impact': 'Regular user accounts used as service accounts require manual password management and are more vulnerable to attacks.',
                    'attack_scenario': 'Service accounts using regular user accounts can be targeted for password attacks and Kerberoasting.',
                    'mitigation': 'Migrate to managed service accounts (MSAs) or group managed service accounts (gMSAs) which provide automatic password management and better security.',
                    'cis_reference': 'CIS Benchmark recommends using managed service accounts for services',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING
                })
        
        logger.info(f"Found {len(risks)} service account risks")
        return risks
    
    def _is_managed_service_account(self, username: str, user: Dict[str, Any]) -> bool:
        """
        Check if account is a managed service account.
        
        Args:
            username: Username
            user: User dictionary
        
        Returns:
            True if managed service account
        """
        # MSA accounts typically have specific naming patterns or attributes
        # This is a simplified check - in production, check msDS-ManagedServiceAccount
        
        # Check naming patterns
        if username.endswith('$'):
            return True
        
        # Check description for MSA indicators
        description = user.get('description') or ''
        if description:
            description = description.lower()
            if 'managed service account' in description or 'msa' in description:
                return True
        
        return False
    
    def _extract_group_name(self, group_dn: str) -> str:
        """Extract group name from DN."""
        if not group_dn:
            return ''
        if 'CN=' in group_dn:
            try:
                return group_dn.split('CN=')[1].split(',')[0]
            except Exception:
                return ''
        return group_dn
