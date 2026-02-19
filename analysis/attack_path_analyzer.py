"""
Attack Path Analyzer Module
Analyzes and visualizes attack paths for privilege escalation
"""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class AttackPathAnalyzer:
    """Analyzes attack paths for privilege escalation scenarios."""
    
    def __init__(self):
        """Initialize attack path analyzer."""
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.user_group_map: Dict[str, Set[str]] = {}
        self.group_member_map: Dict[str, Set[str]] = {}
        self.privileged_groups: Set[str] = set()
    
    def build_graph(self, users: List[Dict[str, Any]], groups: List[Dict[str, Any]]) -> None:
        """
        Build graph structure from users and groups.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
        """
        # Build user to groups mapping
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            user_groups = set()
            member_of = user.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            for group_dn in member_of:
                group_name = self._extract_group_name(group_dn)
                if group_name:
                    user_groups.add(group_name)
                    self.graph[username].add(group_name)
            
            self.user_group_map[username] = user_groups
        
        # Build group to members mapping and group hierarchy
        for group in groups:
            group_name = group.get('name') or group.get('sAMAccountName')
            if not group_name:
                continue
            
            # Check if privileged
            if self._is_privileged_group(group_name):
                self.privileged_groups.add(group_name)
            
            # Add members
            members = group.get('member', []) or []
            if not isinstance(members, list):
                members = [members] if members else []
            
            group_members = set()
            for member_dn in members:
                member_name = self._extract_member_name(member_dn)
                if member_name:
                    group_members.add(member_name)
                    self.graph[group_name].add(member_name)
            
            self.group_member_map[group_name] = group_members
            
            # Add nested groups
            member_of = group.get('memberOf', []) or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            
            for parent_group_dn in member_of:
                parent_group_name = self._extract_group_name(parent_group_dn)
                if parent_group_name:
                    self.graph[group_name].add(parent_group_name)
    
    def find_paths_to_privileged_group(self, source_user: str, 
                                       target_group: Optional[str] = None,
                                       max_depth: int = 10) -> List[Dict[str, Any]]:
        """
        Find all paths from a user to privileged groups.
        
        Args:
            source_user: Source username
            target_group: Target group name (None = any privileged group)
            max_depth: Maximum path depth to search
        
        Returns:
            List of path dictionaries
        """
        if target_group is None:
            target_groups = self.privileged_groups
        else:
            target_groups = {target_group}
        
        paths = []
        
        # BFS to find all paths
        queue = deque([(source_user, [source_user], 0)])
        visited_paths: Set[Tuple[str, ...]] = set()
        
        while queue:
            current, path, depth = queue.popleft()
            
            if depth > max_depth:
                continue
            
            # Check if we reached a privileged group
            if current in target_groups:
                paths.append({
                    'source': source_user,
                    'target': current,
                    'path': path,
                    'depth': depth,
                    'risk_score': self._calculate_path_risk(path)
                })
                continue
            
            # Explore neighbors
            neighbors = self.graph.get(current, set())
            for neighbor in neighbors:
                new_path = path + [neighbor]
                path_key = tuple(new_path)
                
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    queue.append((neighbor, new_path, depth + 1))
        
        # Sort by risk score (highest first)
        paths.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return paths
    
    def find_shortest_path(self, source_user: str, target_group: str) -> Optional[Dict[str, Any]]:
        """
        Find shortest path from user to target group.
        
        Args:
            source_user: Source username
            target_group: Target group name
        
        Returns:
            Path dictionary or None if no path exists
        """
        paths = self.find_paths_to_privileged_group(source_user, target_group, max_depth=10)
        if paths:
            # Return shortest path
            return min(paths, key=lambda x: x['depth'])
        return None
    
    def find_all_privilege_escalation_paths(self, users: List[Dict[str, Any]], 
                                           groups: List[Dict[str, Any]],
                                           max_depth: int = 10) -> List[Dict[str, Any]]:
        """
        Find all privilege escalation paths for all users.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            max_depth: Maximum path depth
        
        Returns:
            List of escalation path dictionaries
        """
        self.build_graph(users, groups)
        
        all_paths = []
        
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            
            # Skip if user is already in privileged group
            user_groups = self.user_group_map.get(username, set())
            if any(g in self.privileged_groups for g in user_groups):
                continue
            
            # Find paths to privileged groups
            paths = self.find_paths_to_privileged_group(username, max_depth=max_depth)
            
            if paths:
                all_paths.append({
                    'user': username,
                    'paths': paths,
                    'shortest_path': paths[0] if paths else None,
                    'path_count': len(paths)
                })
        
        return all_paths
    
    def _calculate_path_risk(self, path: List[str]) -> float:
        """
        Calculate risk score for an attack path.
        
        Args:
            path: List of nodes in the path
        
        Returns:
            Risk score (0-100)
        """
        if not path:
            return 0.0
        
        # Base score based on path length (shorter = higher risk)
        base_score = max(0, 100 - (len(path) * 10))
        
        # Bonus for privileged groups in path
        privileged_bonus = 0
        for node in path:
            if self._is_privileged_group(node):
                privileged_bonus += 20
        
        # Cap at 100
        return min(100.0, base_score + privileged_bonus)
    
    def _is_privileged_group(self, group_name: str) -> bool:
        """Check if group is privileged."""
        if not group_name:
            return False
        
        privileged_keywords = [
            'domain admins', 'enterprise admins', 'schema admins',
            'account operators', 'backup operators', 'server operators',
            'administrators'
        ]
        
        group_lower = group_name.lower()
        return any(keyword in group_lower for keyword in privileged_keywords)
    
    def _extract_group_name(self, group_dn: str) -> Optional[str]:
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
    
    def _extract_member_name(self, member_dn: str) -> Optional[str]:
        """Extract member name from DN."""
        return self._extract_group_name(member_dn)
    
    def generate_graph_data(self) -> Dict[str, Any]:
        """
        Generate graph data for visualization.
        
        Returns:
            Dictionary with nodes and edges
        """
        nodes = []
        edges = []
        node_ids = {}
        node_id_counter = 0
        
        # Add all nodes
        for node in self.graph.keys():
            if node not in node_ids:
                node_ids[node] = node_id_counter
                nodes.append({
                    'id': node_id_counter,
                    'label': node,
                    'type': 'group' if self._is_privileged_group(node) else 'user',
                    'privileged': self._is_privileged_group(node)
                })
                node_id_counter += 1
        
        # Add edges
        for source, targets in self.graph.items():
            source_id = node_ids.get(source)
            if source_id is None:
                continue
            
            for target in targets:
                target_id = node_ids.get(target)
                if target_id is None:
                    # Add target node if not exists
                    node_ids[target] = node_id_counter
                    nodes.append({
                        'id': node_id_counter,
                        'label': target,
                        'type': 'group' if self._is_privileged_group(target) else 'user',
                        'privileged': self._is_privileged_group(target)
                    })
                    target_id = node_id_counter
                    node_id_counter += 1
                
                edges.append({
                    'source': source_id,
                    'target': target_id,
                    'type': 'membership'
                })
        
        return {
            'nodes': nodes,
            'edges': edges
        }
