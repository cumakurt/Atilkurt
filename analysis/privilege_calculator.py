"""
Privilege Escalation Calculator Module
Calculates if a user can escalate to target privileges
"""

import logging
from typing import List, Dict, Any, Optional, Set
from analysis.attack_path_analyzer import AttackPathAnalyzer

logger = logging.getLogger(__name__)


class PrivilegeCalculator:
    """Calculates privilege escalation paths."""
    
    def __init__(self):
        """Initialize privilege calculator."""
        self.path_analyzer = AttackPathAnalyzer()
    
    def can_user_become_domain_admin(self, username: str, users: List[Dict[str, Any]], 
                                     groups: List[Dict[str, Any]], 
                                     computers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check if a user can become Domain Admin.
        
        Args:
            username: Username to check
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
        
        Returns:
            Dictionary with escalation analysis
        """
        # Build graph
        self.path_analyzer.build_graph(users, groups)
        
        # Find paths to Domain Admins
        paths = self.path_analyzer.find_paths_to_privileged_group(
            username, 
            target_group='Domain Admins',
            max_depth=10
        )
        
        result = {
            'user': username,
            'target': 'Domain Admins',
            'can_escalate': len(paths) > 0,
            'path_count': len(paths),
            'shortest_path': paths[0] if paths else None,
            'all_paths': paths[:5],  # Top 5 paths
            'probability': self._calculate_probability(paths),
            'required_compromises': self._get_required_compromises(paths),
            'recommendations': self._generate_recommendations(paths)
        }
        
        return result
    
    def calculate_escalation_path(self, source_user: str, target_group: str,
                                 users: List[Dict[str, Any]], 
                                 groups: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate escalation path from user to target group.
        
        Args:
            source_user: Source username
            target_group: Target group name
            users: List of user dictionaries
            groups: List of group dictionaries
        
        Returns:
            Dictionary with path analysis
        """
        self.path_analyzer.build_graph(users, groups)
        
        path = self.path_analyzer.find_shortest_path(source_user, target_group)
        
        if path:
            return {
                'can_escalate': True,
                'path': path['path'],
                'depth': path['depth'],
                'risk_score': path['risk_score'],
                'steps': self._format_path_steps(path['path'])
            }
        else:
            return {
                'can_escalate': False,
                'path': None,
                'message': f'No path found from {source_user} to {target_group}'
            }
    
    def _calculate_probability(self, paths: List[Dict[str, Any]]) -> str:
        """
        Calculate probability of successful escalation.
        
        Args:
            paths: List of path dictionaries
        
        Returns:
            Probability string
        """
        if not paths:
            return 'None'
        
        shortest_depth = min(p['depth'] for p in paths)
        
        if shortest_depth <= 2:
            return 'High'
        elif shortest_depth <= 4:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_required_compromises(self, paths: List[Dict[str, Any]]) -> List[str]:
        """
        Get list of required compromises for escalation.
        
        Args:
            paths: List of path dictionaries
        
        Returns:
            List of required compromises
        """
        if not paths:
            return []
        
        # Get shortest path
        shortest = min(paths, key=lambda x: x['depth'])
        path = shortest['path']
        
        compromises = []
        for i, node in enumerate(path[1:], 1):  # Skip source user
            if i < len(path) - 1:  # Not the target
                compromises.append(f"Compromise '{node}'")
        
        return compromises
    
    def _generate_recommendations(self, paths: List[Dict[str, Any]]) -> List[str]:
        """
        Generate recommendations based on paths.
        
        Args:
            paths: List of path dictionaries
        
        Returns:
            List of recommendation strings
        """
        if not paths:
            return ['No escalation paths detected. Current configuration is secure.']
        
        recommendations = []
        
        shortest = min(paths, key=lambda x: x['depth'])
        if shortest['depth'] <= 2:
            recommendations.append('CRITICAL: Immediate action required. Short escalation path detected.')
        
        recommendations.append(f"Remove unnecessary group memberships from intermediate accounts in the path.")
        recommendations.append("Implement monitoring for privilege escalation attempts.")
        recommendations.append("Review and apply principle of least privilege.")
        
        return recommendations
    
    def _format_path_steps(self, path: List[str]) -> List[str]:
        """
        Format path as human-readable steps.
        
        Args:
            path: List of nodes in path
        
        Returns:
            List of formatted step strings
        """
        if not path or len(path) < 2:
            return []
        
        steps = []
        for i in range(len(path) - 1):
            steps.append(f"{path[i]} → {path[i+1]}")
        
        return steps
