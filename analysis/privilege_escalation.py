"""
Privilege Escalation Path Analysis Module
Analyzes theoretical privilege escalation paths without providing exploit code
"""

import logging
from typing import Dict, List, Set
from collections import deque

logger = logging.getLogger(__name__)


class PrivilegeEscalationAnalyzer:
    """Analyzes privilege escalation paths in Active Directory."""
    
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
        """Initialize privilege escalation analyzer."""
        self.risks = []
        # Optimized data structures for graph-based operations
        self.group_map: Dict[str, Dict] = {}
        self.user_group_map: Dict[str, List[str]] = {}
        self.privileged_groups: set = set()
        self.group_hierarchy: Dict[str, set] = {}  # Group -> set of parent groups
        self.users_list: List[Dict] = []  # Store users list for admin checking
    
    def analyze(self, users, groups, computers):
        """
        Analyze privilege escalation paths with optimized graph-based approach.
        Skips users who are already Domain Admin or Enterprise Admin.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
        
        Returns:
            list: List of privilege escalation path risk dictionaries
        """
        risks = []
        
        # Build optimized graph structures (O(n) instead of O(n²))
        self._build_optimized_maps(users, groups)
        
        # Store users list for admin checking
        self.users_list = users
        
        # Analyze paths to privileged groups (optimized)
        risks.extend(self._analyze_group_escalation_paths_optimized(users))
        
        # Analyze delegation-based escalation
        risks.extend(self._analyze_delegation_escalation(users, computers))
        
        # Analyze SPN-based escalation
        risks.extend(self._analyze_spn_escalation(users))
        
        # Analyze computer-to-privilege paths
        risks.extend(self._analyze_computer_privilege_paths(users, computers))
        
        logger.info(f"Found {len(risks)} privilege escalation paths (excluding users who are already admins)")
        return risks
    
    def _build_optimized_maps(self, users, groups):
        """
        Build optimized graph structures for efficient path finding.
        Uses O(n) complexity instead of O(n²) nested loops.
        """
        # Build group map with hierarchy
        for group in groups:
            group_name = group.get('name') or group.get('sAMAccountName')
            if not group_name:
                continue
            
            # Check if privileged
            if self._is_privileged_group(group_name):
                self.privileged_groups.add(group_name)
            
            # Build group hierarchy
            member_of = group.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            self.group_hierarchy[group_name] = set()
            for parent_dn in member_of:
                parent_name = self._extract_group_name(parent_dn)
                if parent_name:
                    self.group_hierarchy[group_name].add(parent_name)
            
            self.group_map[group_name] = {
                'members': group.get('member', []),
                'member_of': member_of,
                'dn': group.get('distinguishedName')
            }
        
        # Build user-group map (normalized to group names, not DNs)
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            member_of = user.get('memberOf') or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            # Convert DNs to group names for faster lookups
            user_groups = []
            for group_dn in member_of:
                group_name = self._extract_group_name(group_dn)
                if group_name:
                    user_groups.append(group_name)
            
            self.user_group_map[username] = user_groups
    
    def _is_privileged_group(self, group_name):
        """Check if a group is privileged."""
        if not group_name:
            return False
        return any(priv_group.lower() in group_name.lower() for priv_group in self.PRIVILEGED_GROUPS)
    
    def _is_user_already_privileged(self, user, user_group_map):
        """Check if user is already in a privileged group (legacy method, kept for compatibility)."""
        username = user.get('sAMAccountName')
        if not username:
            return False
        
        # Check adminCount flag
        if user.get('adminCount') == 1 or user.get('adminCount') == '1':
            return True
        
        # Check group memberships (optimized)
        return self._is_user_already_privileged_optimized(username)
    
    def _analyze_group_escalation_paths_optimized(self, users):
        """
        Analyze group-based privilege escalation paths with optimized graph traversal.
        Uses BFS for efficient path finding instead of nested loops.
        """
        risks = []
        
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            # Skip users who are already privileged (check both groups and adminCount)
            if self._is_user_already_privileged_optimized(username, users):
                logger.debug(f"Skipping user '{username}' - already has admin privileges")
                continue
            
            user_groups = self.user_group_map.get(username, [])
            if not user_groups:
                continue
            
            # Find paths to privileged groups using BFS
            paths_to_privilege = self._find_paths_to_privileged_groups(username, user_groups)
            
            if paths_to_privilege:
                direct_privileged = [g for g in user_groups if g in self.privileged_groups]
                
                risks.append({
                    'type': 'privilege_escalation_path',
                    'severity': 'high',
                    'title': 'Privilege Escalation Path Detected',
                    'description': f"User '{username}' has potential paths to privileged groups",
                    'affected_object': username,
                    'object_type': 'user',
                    'escalation_path': {
                        'user': username,
                        'direct_groups': direct_privileged,
                        'indirect_paths': paths_to_privilege
                    },
                    'impact': 'Users with paths to privileged groups pose a significant security risk if their accounts are compromised',
                    'attack_scenario': 'If an attacker compromises a user account with paths to privileged groups, they could potentially escalate privileges through group membership relationships',
                    'mitigation': 'Review group memberships regularly. Apply principle of least privilege. Remove unnecessary group memberships. Monitor privileged group access',
                    'cis_reference': 'CIS Benchmark recommends regular review of group memberships',
                    'mitre_attack': 'T1078.002 - Valid Accounts: Domain Accounts'
                })
        
        return risks
    
    def _find_paths_to_privileged_groups(self, username: str, user_groups: List[str], max_depth: int = 5) -> List[Dict]:
        """
        Find paths from user groups to privileged groups using BFS.
        
        Args:
            username: Username
            user_groups: List of group names user is member of
            max_depth: Maximum depth to search
        
        Returns:
            List of path dictionaries
        """
        paths = []
        visited = set()
        from collections import deque
        
        # BFS from each user group
        for start_group in user_groups:
            if start_group in visited:
                continue
            
            queue = deque([(start_group, [start_group], 0)])
            visited.add(start_group)
            
            while queue:
                current_group, path, depth = queue.popleft()
                
                if depth > max_depth:
                    continue
                
                # Check if we reached a privileged group
                if current_group in self.privileged_groups and current_group != start_group:
                    paths.append({
                        'path': ' -> '.join(path),
                        'target_group': current_group,
                        'depth': depth
                    })
                    continue
                
                # Explore parent groups
                parent_groups = self.group_hierarchy.get(current_group, set())
                for parent in parent_groups:
                    if parent not in visited:
                        visited.add(parent)
                        queue.append((parent, path + [parent], depth + 1))
        
        return paths
    
    def _is_user_already_privileged_optimized(self, username: str, users: List[Dict] = None) -> bool:
        """
        Check if user is already in a privileged group (optimized version).
        Also checks adminCount flag.
        
        Args:
            username: Username to check
            users: Optional list of users to check adminCount flag
        
        Returns:
            True if user is privileged
        """
        # Check group memberships
        user_groups = self.user_group_map.get(username, [])
        # Check for Domain Admin, Enterprise Admin, Schema Admin specifically
        privileged_group_names_lower = {g.lower() for g in self.privileged_groups}
        user_groups_lower = {g.lower() for g in user_groups}
        
        # Check if user is in Domain Admins or Enterprise Admins
        if any('domain admin' in g or 'enterprise admin' in g or 'schema admin' in g 
               for g in user_groups_lower):
            return True
        
        # Check if any user group matches privileged groups
        if any(g in privileged_group_names_lower for g in user_groups_lower):
            return True
        
        # Check adminCount flag if users list provided
        users_to_check = users if users else (self.users_list if hasattr(self, 'users_list') else [])
        if users_to_check:
            for user in users_to_check:
                if user.get('sAMAccountName') == username:
                    if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                        return True
                    break
        
        return False
    
    def _analyze_delegation_escalation(self, users, computers):
        """Analyze delegation-based privilege escalation (optimized)."""
        risks = []
        
        # Find users with delegation rights
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            # Skip users who are already privileged (optimized check)
            if self._is_user_already_privileged_optimized(username, users):
                logger.debug(f"Skipping user '{username}' - already has admin privileges")
                continue
            
            uac = user.get('userAccountControl', 0)
            if isinstance(uac, str):
                try:
                    uac = int(uac)
                except ValueError:
                    continue
            
            # Check for delegation flags
            has_delegation = bool(uac & 524288) or bool(uac & 16777216)
            
            if has_delegation:
                user_groups = self.user_group_map.get(username, [])
                privileged_groups = [g for g in user_groups if g in self.privileged_groups]
                
                if privileged_groups:
                    risks.append({
                        'type': 'delegation_privilege_escalation',
                        'severity': 'critical',
                        'title': 'Delegation with Privileged Access',
                        'description': f"User '{username}' has delegation enabled and is member of privileged groups",
                        'affected_object': username,
                        'object_type': 'user',
                        'escalation_path': {
                            'user': username,
                            'delegation_type': 'unconstrained' if (uac & 524288) else 'constrained',
                            'privileged_groups': privileged_groups
                        },
                        'impact': 'Users with both delegation rights and privileged group membership create a critical security risk',
                        'attack_scenario': 'If an attacker compromises this account, they can use delegation to impersonate other users while having privileged group access, creating a severe escalation path',
                        'mitigation': 'Immediately review and remove delegation rights from privileged accounts, or remove privileged group memberships from accounts with delegation. These should never be combined',
                        'cis_reference': 'CIS Benchmark prohibits delegation on privileged accounts',
                        'mitre_attack': 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
                    })
        
        return risks
    
    def _analyze_spn_escalation(self, users):
        """Analyze SPN-based privilege escalation (optimized)."""
        risks = []
        
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            # Skip users who are already privileged (optimized check)
            if self._is_user_already_privileged_optimized(username, users):
                logger.debug(f"Skipping user '{username}' - already has admin privileges")
                continue
            
            spns = user.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            if not spns:
                continue
            
            user_groups = self.user_group_map.get(username, [])
            privileged_groups = [g for g in user_groups if g in self.privileged_groups]
            
            if privileged_groups:
                risks.append({
                    'type': 'spn_privilege_escalation',
                    'severity': 'high',
                    'title': 'SPN on Privileged Account',
                    'description': f"Privileged user '{username}' has Service Principal Names defined",
                    'affected_object': username,
                    'object_type': 'user',
                    'escalation_path': {
                        'user': username,
                        'spns': spns,
                        'privileged_groups': privileged_groups
                    },
                    'impact': 'Privileged accounts with SPNs are high-value targets for Kerberoasting attacks',
                    'attack_scenario': 'An attacker can target privileged accounts with SPNs for Kerberoasting, potentially gaining access to high-privilege accounts',
                    'mitigation': 'Remove SPNs from privileged user accounts. Use managed service accounts (MSAs) or group managed service accounts (gMSAs) for services instead',
                    'cis_reference': 'CIS Benchmark recommends using managed service accounts for services',
                    'mitre_attack': 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
                })
        
        return risks
    
    def _extract_group_name(self, group_dn):
        """Extract group name from DN."""
        if not group_dn:
            return None
        # Extract CN from DN (simplified)
        if 'CN=' in group_dn:
            try:
                cn_part = group_dn.split('CN=')[1].split(',')[0]
                return cn_part
            except Exception:
                return None
        return group_dn
    
    def _find_indirect_paths(self, group_name, group_map, user_group_map):
        """Find indirect paths to privileged groups through nested groups (legacy method)."""
        # This method is kept for compatibility but uses optimized structures
        paths = []
        
        parent_groups = self.group_hierarchy.get(group_name, set())
        for parent_name in parent_groups:
            if parent_name in self.privileged_groups:
                paths.append({
                    'path': f"{group_name} -> {parent_name}",
                    'target_group': parent_name
                })
        
        return paths
    
    def _analyze_computer_privilege_paths(self, users, computers):
        """Analyze computer-based privilege escalation paths (optimized)."""
        risks = []
        
        # Pre-filter computers with unconstrained delegation
        delegation_computers = [
            (c.get('name'), c) 
            for c in computers 
            if c.get('unconstrainedDelegation')
        ]
        
        if not delegation_computers:
            return risks
        
        # Pre-filter privileged users (optimized)
        # Note: This method checks for privileged users accessing delegation computers,
        # which is a different risk than privilege escalation, so we keep privileged users here
        privileged_users = {
            username: self.user_group_map.get(username, [])
            for username in self.user_group_map.keys()
            if self._is_user_already_privileged_optimized(username, users)
        }
        
        # Check each delegation computer against privileged users
        for computer_name, computer in delegation_computers:
            for username, user_groups in privileged_users.items():
                privileged_group_names = [g for g in user_groups if g in self.privileged_groups]
                
                if privileged_group_names:
                    risks.append({
                        'type': 'computer_delegation_privilege_path',
                        'severity': 'critical',
                        'title': 'Computer Delegation Privilege Escalation Path',
                        'description': f"Privileged user '{username}' could authenticate to computer '{computer_name}' with unconstrained delegation, creating a critical escalation path",
                        'affected_object': username,
                        'object_type': 'user',
                        'escalation_path': {
                            'user': username,
                            'privileged_groups': privileged_group_names,
                            'target_computer': computer_name,
                            'delegation_type': 'unconstrained',
                            'path_description': f"User '{username}' (member of {len(privileged_group_names)} privileged group(s)) → Computer '{computer_name}' (unconstrained delegation) → Potential domain-wide access"
                        },
                        'impact': 'If a privileged user authenticates to a computer with unconstrained delegation, an attacker compromising that computer can steal their Kerberos tickets and gain domain-wide access',
                        'attack_scenario': 'An attacker who compromises a computer with unconstrained delegation can capture Kerberos tickets from any user who authenticates to it. If a privileged user authenticates, the attacker gains their privileges',
                        'mitigation': 'Disable unconstrained delegation on all computers. If delegation is necessary, use constrained or resource-based constrained delegation. Ensure privileged users do not authenticate to computers with delegation enabled',
                        'cis_reference': 'CIS Benchmark prohibits unconstrained delegation',
                        'mitre_attack': 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
                    })
        
        return risks
