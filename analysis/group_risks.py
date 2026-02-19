"""
Group Risk Analysis Module
Analyzes group objects for security risks including nested admin groups
"""

import logging

logger = logging.getLogger(__name__)


class GroupRiskAnalyzer:
    """Analyzes group objects for security risks."""
    
    PRIVILEGED_GROUPS = [
        'Domain Admins',
        'Enterprise Admins',
        'Schema Admins',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'Administrators'
    ]
    
    def __init__(self):
        """Initialize group risk analyzer."""
        pass
    
    def analyze(self, groups, users):
        """
        Analyze groups for security risks.
        
        Args:
            groups: List of group dictionaries
            users: List of user dictionaries
        
        Returns:
            list: List of risk dictionaries
        """
        risks = []
        
        # Build group membership map
        group_membership_map = self._build_membership_map(groups)
        
        for group in groups:
            # Check for too many Domain Admins
            risks.extend(self._check_too_many_domain_admins(group, users))
            
            # Check for nested admin groups
            risks.extend(self._check_nested_admin_groups(group, groups, group_membership_map))
            
            # Check for Backup/Account Operators members
            risks.extend(self._check_operators_members(group, users))
        
        logger.info(f"Found {len(risks)} group-related risks")
        return risks
    
    def _build_membership_map(self, groups):
        """Build a map of group names to their members."""
        membership_map = {}
        for group in groups:
            group_name = group.get('name') or group.get('sAMAccountName')
            if group_name:
                members = group.get('member', []) or []
                if not isinstance(members, list):
                    members = [members] if members else []
                membership_map[group_name] = members
        return membership_map
    
    def _check_too_many_domain_admins(self, group, users):
        """Check if Domain Admins group has too many members."""
        risks = []
        
        group_name = group.get('name') or group.get('sAMAccountName')
        if not group_name or 'Domain Admins' not in group_name:
            return risks
        
        members = group.get('member', []) or []
        if not isinstance(members, list):
            members = [members] if members else []
        
        # CIS Benchmark recommends maximum 2-3 Domain Admins
        if len(members) > 3:
            risks.append({
                'type': 'too_many_domain_admins',
                'severity': 'high',
                'title': 'Too Many Domain Admins',
                'description': f"Domain Admins group has {len(members)} members (recommended: 2-3)",
                'affected_object': group_name,
                'object_type': 'group',
                'member_count': len(members),
                'impact': 'Having too many Domain Admins increases the attack surface and makes it harder to monitor and secure privileged access',
                'attack_scenario': 'Each Domain Admin account is a potential target for attackers. More accounts mean more opportunities for compromise',
                'mitigation': 'Reduce Domain Admins to the minimum necessary (2-3 accounts). Use role-based access control and separate administrative accounts for different functions',
                'cis_reference': 'CIS Benchmark recommends limiting Domain Admins to 2-3 accounts',
                'mitre_attack': 'T1078.002 - Valid Accounts: Domain Accounts'
            })
        
        return risks
    
    def _check_nested_admin_groups(self, group, all_groups, membership_map):
        """Check for nested admin groups."""
        risks = []
        
        group_name = group.get('name') or group.get('sAMAccountName')
        if not group_name:
            return risks
        
        # Check if this is a privileged group
        is_privileged = any(priv_group.lower() in group_name.lower() for priv_group in self.PRIVILEGED_GROUPS)
        
        if not is_privileged:
            return risks
        
        # Check if this group is a member of another privileged group
        member_of = group.get('memberOf', []) or []
        if not isinstance(member_of, list):
            member_of = [member_of] if member_of else []
        
        for parent_group_dn in member_of:
            parent_group_name = self._extract_group_name(parent_group_dn)
            if parent_group_name and any(priv_group.lower() in parent_group_name.lower() for priv_group in self.PRIVILEGED_GROUPS):
                risks.append({
                    'type': 'nested_admin_group',
                    'severity': 'high',
                    'title': 'Nested Admin Group',
                    'description': f"Privileged group '{group_name}' is nested within another privileged group '{parent_group_name}'",
                    'affected_object': group_name,
                    'object_type': 'group',
                    'parent_group': parent_group_name,
                    'impact': 'Nested admin groups can lead to unintended privilege escalation and make it difficult to track who has administrative access',
                    'attack_scenario': 'If a user is added to a nested admin group, they may gain more privileges than intended, creating an escalation path',
                    'mitigation': 'Avoid nesting privileged groups. Use flat group structure and explicit membership. Regularly audit group memberships',
                    'cis_reference': 'CIS Benchmark recommends avoiding nested admin groups',
                    'mitre_attack': 'T1078.002 - Valid Accounts: Domain Accounts'
                })
        
        return risks
    
    def _check_operators_members(self, group, users):
        """Check for members in Backup/Account Operators groups."""
        risks = []
        
        group_name = group.get('name') or group.get('sAMAccountName')
        if not group_name:
            return risks
        
        # Check if this is Backup Operators or Account Operators
        if 'Backup Operators' not in group_name and 'Account Operators' not in group_name:
            return risks
        
        members = group.get('member', []) or []
        if not isinstance(members, list):
            members = [members] if members else []
        
        if len(members) > 0:
            risks.append({
                'type': 'operators_group_members',
                'severity': 'high',
                'title': f'{group_name} Has Members',
                'description': f"{group_name} group has {len(members)} member(s). These groups have significant privileges and should be carefully managed",
                'affected_object': group_name,
                'object_type': 'group',
                'member_count': len(members),
                'impact': f'{group_name} members have significant privileges. Backup Operators can access all files, and Account Operators can modify user accounts',
                'attack_scenario': f'If an attacker compromises a {group_name} member, they can use the group\'s privileges to escalate access or modify critical accounts',
                'mitigation': f'Regularly review {group_name} membership. Remove unnecessary members. Consider using just-in-time access instead of permanent membership',
                'cis_reference': 'CIS Benchmark recommends limiting membership in operators groups',
                'mitre_attack': 'T1078.002 - Valid Accounts: Domain Accounts'
            })
        
        return risks
    
    def _extract_group_name(self, group_dn):
        """Extract group name from DN."""
        if not group_dn:
            return None
        if 'CN=' in group_dn:
            try:
                cn_part = group_dn.split('CN=')[1].split(',')[0]
                return cn_part
            except Exception:
                return None
        return group_dn
