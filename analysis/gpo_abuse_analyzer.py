"""
GPO Abuse Analyzer Module
Analyzes Group Policy Objects for abuse potential
"""

import logging
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class GPOAbuseAnalyzer:
    """Analyzes GPOs for abuse potential."""
    
    PRIVILEGED_OU_KEYWORDS = [
        'domain controllers',
        'domain admins',
        'enterprise admins',
        'administrators'
    ]
    
    def __init__(self):
        """Initialize GPO abuse analyzer."""
        pass
    
    def analyze_gpo_risks(self, gpos: List[Dict[str, Any]], 
                         users: List[Dict[str, Any]],
                         groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze GPOs for abuse potential.
        
        Args:
            gpos: List of GPO dictionaries
            users: List of user dictionaries
            groups: List of group dictionaries
        
        Returns:
            List of risk dictionaries
        """
        risks = []
        
        # Build user privilege map
        privileged_users = self._build_privileged_user_map(users, groups)
        
        for gpo in gpos:
            gpo_name = gpo.get('name') or gpo.get('displayName', '')
            if not gpo_name:
                continue
            
            # Check if GPO is linked to privileged OUs
            linked_ous = gpo.get('linkedOUs', []) or []
            if not isinstance(linked_ous, list):
                linked_ous = [linked_ous] if linked_ous else []
            
            privileged_ous = []
            for ou_dn in linked_ous:
                ou_name = self._extract_ou_name(ou_dn)
                if self._is_privileged_ou(ou_name):
                    privileged_ous.append(ou_name)
            
            if privileged_ous:
                risks.append({
                    'type': RiskTypes.GPO_LINKED_TO_PRIVILEGED_OU,
                    'severity': Severity.HIGH,
                    'title': f'GPO Linked to Privileged OU: {gpo_name}',
                    'description': f"GPO '{gpo_name}' is linked to {len(privileged_ous)} privileged OU(s)",
                    'affected_object': gpo_name,
                    'object_type': 'gpo',
                    'linked_ous': linked_ous,
                    'privileged_ous': privileged_ous,
                    'impact': 'GPOs linked to privileged OUs can be used to escalate privileges or maintain persistence. If an attacker can modify the GPO, they can execute code on all computers in the OU.',
                    'attack_scenario': 'If an attacker gains modification rights to a GPO linked to a privileged OU, they can add a scheduled task or startup script that executes with high privileges on all computers in the OU.',
                    'mitigation': 'Review GPOs linked to privileged OUs regularly. Ensure only authorized administrators can modify these GPOs. Implement monitoring for GPO changes.',
                    'cis_reference': 'CIS Benchmark recommends reviewing GPO permissions and links',
                    'mitre_attack': 'T1484 - Group Policy Modification'
                })
            
            # Check GPO modification rights (simplified - would need ACL analysis)
            # This is a placeholder - full implementation would parse ACLs
            risks.append({
                'type': RiskTypes.GPO_MODIFICATION_RIGHTS,
                'severity': Severity.MEDIUM,
                'title': f'GPO Modification Rights Review: {gpo_name}',
                'description': f"Review modification rights for GPO '{gpo_name}'",
                'affected_object': gpo_name,
                'object_type': 'gpo',
                'impact': 'GPOs with excessive modification rights can be abused to escalate privileges or maintain persistence.',
                'attack_scenario': 'If non-privileged users can modify GPOs, they may be able to add malicious settings that execute on target computers.',
                'mitigation': 'Ensure only authorized administrators can modify GPOs. Review ACLs on all GPOs regularly. Implement change monitoring.',
                'cis_reference': 'CIS Benchmark recommends limiting GPO modification rights',
                'mitre_attack': 'T1484 - Group Policy Modification'
            })
        
        logger.info(f"Found {len(risks)} GPO-related risks")
        return risks
    
    def _build_privileged_user_map(self, users: List[Dict[str, Any]], 
                                   groups: List[Dict[str, Any]]) -> Dict[str, bool]:
        """
        Build map of privileged users.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
        
        Returns:
            Dictionary mapping username to privileged status
        """
        privileged_map = {}
        
        for user in users:
            username = user.get('sAMAccountName', '')
            if not username:
                continue
            
            is_privileged = False
            
            # Check adminCount
            if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                is_privileged = True
            
            # Check group memberships
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            for group_dn in member_of:
                group_name = self._extract_group_name(group_dn)
                if group_name:
                    if any(priv in group_name.upper() for priv in 
                          ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS']):
                        is_privileged = True
                        break
            
            privileged_map[username] = is_privileged
        
        return privileged_map
    
    def _is_privileged_ou(self, ou_name: str) -> bool:
        """
        Check if OU name indicates privileged OU.
        
        Args:
            ou_name: OU name
        
        Returns:
            True if privileged OU
        """
        if not ou_name:
            return False
        
        ou_lower = ou_name.lower()
        return any(keyword in ou_lower for keyword in self.PRIVILEGED_OU_KEYWORDS)
    
    def _extract_ou_name(self, ou_dn: str) -> str:
        """Extract OU name from DN."""
        if not ou_dn:
            return ''
        if 'OU=' in ou_dn:
            try:
                return ou_dn.split('OU=')[1].split(',')[0]
            except Exception:
                return ''
        return ''
    
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
