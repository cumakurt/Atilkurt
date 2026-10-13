"""
Privilege Escalation Path Analysis Module
Analyzes theoretical privilege escalation paths without providing exploit code
"""

import logging
from collections import deque

from core.ad_identity import first_ldap_rdn, is_privileged_group_name, is_privileged_group_record, nested_privileged_groups
from core.ad_security import as_list

logger = logging.getLogger(__name__)


class PrivilegeEscalationAnalyzer:
    """Analyzes privilege escalation paths in Active Directory."""

    def __init__(self):
        """Initialize privilege escalation analyzer."""
        self.risks = []
        # Optimized data structures for graph-based operations
        self.group_map: dict[str, dict] = {}
        self.user_group_map: dict[str, list[str]] = {}
        self.privileged_groups: set = set()
        self.privileged_groups_folded: set[str] = set()
        self.group_hierarchy: dict[str, set] = {}  # Group -> set of parent groups
        self.hierarchy_by_fold: dict[str, set[str]] = {}
        self.label_by_fold: dict[str, str] = {}
        self.users_by_name: dict[str, dict] = {}

    def analyze(self, users, groups, computers):
        """
        Analyze privilege escalation paths with optimized graph-based approach.
        Nested paths skip users who already hold a privileged group. SPN and
        delegation findings are reported only for those privileged users.

        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries

        Returns:
            list: List of privilege escalation path risk dictionaries
        """
        risks = []

        self.__init__()
        self.current_privileged_users = {
            user.get("sAMAccountName") for user in users if nested_privileged_groups(user, groups)
        }
        self._build_optimized_maps(users, groups)

        # Analyze paths to privileged groups (optimized)
        risks.extend(self._analyze_group_escalation_paths_optimized(users))

        # Delegation on privileged users. Computer unconstrained delegation is
        # reported by the Kerberos analyzer, including the DC exclusion.
        del computers
        risks.extend(self._analyze_delegation_escalation(users))

        # Analyze SPN-based escalation
        risks.extend(self._analyze_spn_escalation(users))

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
            group_key = self._remember_group(group_name)
            if is_privileged_group_record(group):
                self.privileged_groups.add(group_name)
                self.privileged_groups_folded.add(group_key)

            member_of = as_list(group.get('memberOf'))

            self.group_hierarchy[group_name] = set()
            parent_keys: set[str] = set()
            for parent_dn in member_of:
                parent_name = self._extract_group_name(parent_dn)
                if parent_name:
                    self.group_hierarchy[group_name].add(parent_name)
                    parent_keys.add(self._remember_group(parent_name))
            self.hierarchy_by_fold[group_key] = parent_keys

            self.group_map[group_name] = {
                'members': group.get('member', []),
                'member_of': member_of,
                'dn': group.get('distinguishedName')
            }

        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue
            self.users_by_name[username] = user
            user_groups = []
            for group_dn in as_list(user.get('memberOf')):
                group_name = self._extract_group_name(group_dn)
                if group_name:
                    user_groups.append(self.label_by_fold.get(group_name.casefold(), group_name))
            self.user_group_map[username] = user_groups

    def _is_privileged_group(self, group_name):
        """Return True when a group name exactly matches a well-known privileged group."""
        return is_privileged_group_name(first_ldap_rdn(group_name))

    def _is_user_already_privileged(self, user, user_group_map=None):
        """Return True when the user currently holds a well-known privileged group."""
        username = user.get('sAMAccountName') if isinstance(user, dict) else None
        if not username:
            return False
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

            if self._is_user_already_privileged_optimized(username):
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

    def _find_paths_to_privileged_groups(self, username: str, user_groups: list[str], max_depth: int = 5) -> list[dict]:
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
        for start_group in user_groups:
            start_key = start_group.casefold()
            visited = {start_key}
            queue = deque([(start_key, [self.label_by_fold.get(start_key, start_group)], 0)])

            while queue:
                current_key, path, depth = queue.popleft()
                if depth > max_depth:
                    continue
                label = path[-1]
                # A well-known parent name still counts when that group object
                # was not present in the collected group list.
                reached_privileged = (
                    current_key in self.privileged_groups_folded or is_privileged_group_name(label)
                )
                if reached_privileged and current_key != start_key:
                    paths.append({
                        'path': ' -> '.join(path),
                        'target_group': path[-1],
                        'depth': depth
                    })
                    continue
                for parent_key in self.hierarchy_by_fold.get(current_key, set()):
                    if parent_key not in visited:
                        visited.add(parent_key)
                        parent_label = self.label_by_fold.get(parent_key, parent_key)
                        queue.append((parent_key, path + [parent_label], depth + 1))

        return paths

    def _is_user_already_privileged_optimized(self, username: str, users: list[dict] = None) -> bool:
        """Return True when current membership is a well-known privileged group.

        adminCount alone is not treated as current Domain Admin membership.
        """
        if username in getattr(self, "current_privileged_users", set()):
            return True
        user_groups = self.user_group_map.get(username, [])
        if any(is_privileged_group_name(group) for group in user_groups):
            return True
        if any(group.casefold() in self.privileged_groups_folded for group in user_groups):
            return True
        return False

    def _analyze_delegation_escalation(self, users):
        """Analyze delegation-based privilege escalation (optimized)."""
        risks = []

        # Find users with delegation rights
        for user in users:
            username = user.get('sAMAccountName')
            if not username:
                continue

            if not self._is_user_already_privileged_optimized(username):
                continue

            uac = user.get('userAccountControl', 0)
            if isinstance(uac, str):
                try:
                    uac = int(uac)
                except ValueError:
                    continue

            # Protocol transition alone is not delegation. Constrained
            # delegation requires an explicit allowed-target list.
            unconstrained = bool(uac & 524288)
            allowed_targets = [item for item in as_list(user.get('msDS-AllowedToDelegateTo')) if item]
            if not unconstrained and not allowed_targets:
                continue
            user_groups = self.user_group_map.get(username, [])
            privileged_groups = [
                group for group in user_groups
                if group.casefold() in self.privileged_groups_folded or is_privileged_group_name(group)
            ]
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

            if not self._is_user_already_privileged_optimized(username):
                continue

            spns = user.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            if not spns:
                continue

            user_groups = self.user_group_map.get(username, [])
            privileged_groups = [
                group for group in user_groups
                if group.casefold() in self.privileged_groups_folded or is_privileged_group_name(group)
            ]

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

    def _remember_group(self, group_name: str) -> str:
        """Store one display label per case-insensitive group name."""
        key = str(group_name).casefold()
        self.label_by_fold.setdefault(key, group_name)
        return key

    def _extract_group_name(self, group_dn):
        """Extract the first RDN from a group DN or return the bare name."""
        name = first_ldap_rdn(group_dn)
        return name or None

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
