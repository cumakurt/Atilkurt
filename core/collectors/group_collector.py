"""
Group Collector Module
Collects all group objects and memberships from Active Directory
"""

import logging
from core.ad_identity import is_privileged_group_record
from core.progress_tracker import ProgressTracker, create_progress_callback

logger = logging.getLogger(__name__)


class GroupCollector:
    """Collects group objects from Active Directory via LDAP."""

    def __init__(self, ldap_connection, show_progress: bool = True):
        """
        Initialize group collector.

        Args:
            ldap_connection: LDAPConnection instance
            show_progress: Whether to show progress messages
        """
        self.ldap = ldap_connection
        self.show_progress = show_progress

    def collect(self):
        """
        Collect all group objects from Active Directory.

        Returns:
            list: List of group dictionaries with collected attributes
        """
        groups = []

        try:
            # Initialize progress tracker
            progress = ProgressTracker(
                operation_name="Collecting groups",
                total_items=None,
                show_progress=self.show_progress
            )

            # Search for all group objects
            search_filter = '(&(objectClass=group)(objectCategory=group))'
            attributes = [
                'name',
                'sAMAccountName',
                'objectSid',
                'member',
                'memberOf',
                'description',
                'distinguishedName',
                'whenCreated',
                'whenChanged',
                'groupType'
            ]

            # Create progress callback
            progress_callback = create_progress_callback(progress)

            results = self.ldap.search(
                search_filter=search_filter,
                attributes=attributes,
                progress_callback=progress_callback
            )

            # Update progress with known total
            progress.update(len(results), len(results))

            for entry in results:
                group_name = entry.get('name') or entry.get('sAMAccountName')

                members = entry.get('member') or []
                if not isinstance(members, list):
                    members = [members] if members else []

                member_of = entry.get('memberOf') or []
                if not isinstance(member_of, list):
                    member_of = [member_of] if member_of else []

                group = {
                    'name': group_name,
                    'sAMAccountName': entry.get('sAMAccountName'),
                    'objectSid': entry.get('objectSid'),
                    'member': members or [],
                    'memberOf': member_of or [],
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'groupType': entry.get('groupType'),
                    'isPrivileged': False,
                }
                group['isPrivileged'] = is_privileged_group_record(group)

                groups.append(group)

            progress.finish()
            logger.info(f"Collected {len(groups)} groups")
            return groups

        except Exception as e:
            logger.error(f"Error collecting groups: {str(e)}")
            raise

    def _is_privileged_group(self, group_name):
        """Return True when a group name matches a well-known privileged group."""
        return is_privileged_group_record({"name": group_name, "sAMAccountName": group_name})
