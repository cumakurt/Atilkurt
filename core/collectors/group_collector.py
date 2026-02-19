"""
Group Collector Module
Collects all group objects and memberships from Active Directory
"""

import logging
from core.progress_tracker import ProgressTracker, create_progress_callback

logger = logging.getLogger(__name__)


class GroupCollector:
    """Collects group objects from Active Directory via LDAP."""
    
    # Privileged groups to flag
    PRIVILEGED_GROUPS = [
        'Domain Admins',
        'Enterprise Admins',
        'Account Operators',
        'Backup Operators',
        'Server Operators',
        'Print Operators',
        'Schema Admins',
        'Administrators',
        'Domain Controllers',
        'Replicator',
        'DnsAdmins',
        'Group Policy Creator Owners'
    ]
    
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
                    'member': members or [],
                    'memberOf': member_of or [],
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'groupType': entry.get('groupType'),
                    'isPrivileged': self._is_privileged_group(group_name)
                }
                
                groups.append(group)
            
            progress.finish()
            logger.info(f"Collected {len(groups)} groups")
            return groups
            
        except Exception as e:
            logger.error(f"Error collecting groups: {str(e)}")
            raise
    
    def _is_privileged_group(self, group_name):
        """
        Check if group is a privileged security group.
        
        Args:
            group_name: Group name to check
        
        Returns:
            bool: True if group is privileged
        """
        if not group_name:
            return False
        
        return any(priv_group.lower() in group_name.lower() for priv_group in self.PRIVILEGED_GROUPS)
