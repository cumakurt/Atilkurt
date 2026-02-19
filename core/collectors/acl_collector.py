"""
ACL (Access Control List) Collector Module
Collects ACL information for critical AD objects
"""

import logging

logger = logging.getLogger(__name__)


class ACLCollector:
    """Collects ACL information from Active Directory objects."""
    
    # Dangerous permissions
    DANGEROUS_PERMISSIONS = {
        'GenericAll': 0xF01FF,  # Full control
        'GenericWrite': 0x40000000,
        'WriteDACL': 0x40000,
        'WriteOwner': 0x80000,
        'AllExtendedRights': 0x100,
        'UserForceChangePassword': 0x100,
        'DS-Replication-Get-Changes': 0x40,
        'DS-Replication-Get-Changes-All': 0x80
    }
    
    def __init__(self, ldap_connection):
        """
        Initialize ACL collector.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
    
    def collect_acl_risks(self, users, groups, computers):
        """
        Collect ACL-based risks for critical objects.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
        
        Returns:
            list: List of ACL risk dictionaries
        """
        acl_risks = []
        
        try:
            # Check ACLs on critical objects
            critical_objects = []
            
            # Add privileged groups
            for group in groups:
                if group.get('isPrivileged'):
                    critical_objects.append({
                        'type': 'group',
                        'name': group.get('name'),
                        'dn': group.get('distinguishedName')
                    })
            
            # Add admin users
            for user in users:
                if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                    critical_objects.append({
                        'type': 'user',
                        'name': user.get('sAMAccountName'),
                        'dn': user.get('distinguishedName')
                    })
            
            # Add domain controllers
            for computer in computers:
                if 'DC' in (computer.get('name') or '').upper() or 'CONTROLLER' in (computer.get('name') or '').upper():
                    critical_objects.append({
                        'type': 'computer',
                        'name': computer.get('name'),
                        'dn': computer.get('distinguishedName')
                    })
            
            # Analyze ACLs for each critical object
            for obj in critical_objects:
                risks = self._analyze_object_acl(obj)
                acl_risks.extend(risks)
            
            logger.info(f"Found {len(acl_risks)} ACL-based risks")
            return acl_risks
            
        except Exception as e:
            logger.error(f"Error collecting ACL risks: {str(e)}")
            return []
    
    def _analyze_object_acl(self, obj):
        """
        Analyze ACL for a specific object.
        
        Args:
            obj: Object dictionary with type, name, dn
        
        Returns:
            list: List of ACL risk dictionaries
        """
        risks = []
        
        try:
            # Get nTSecurityDescriptor
            results = self.ldap.search(
                search_base=obj['dn'],
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor', 'distinguishedName']
            )
            
            if not results:
                return risks
            
            entry = results[0]
            sd = entry.get('nTSecurityDescriptor')
            
            if not sd:
                return risks
            
            # Parse security descriptor (simplified - full parsing would require more complex logic)
            # For now, we'll check if dangerous permissions exist
            # In a full implementation, you would parse the SD and check ACEs
            
            # This is a placeholder - full ACL parsing requires binary SD parsing
            # For demonstration, we'll create risks based on object type and known issues
            
        except Exception as e:
            logger.debug(f"Error analyzing ACL for {obj['dn']}: {str(e)}")
        
        return risks
    
    def check_dangerous_permissions(self, trustee, target_dn, permission_name):
        """
        Check if a trustee has dangerous permissions on a target.
        
        Args:
            trustee: Trustee name (user/group)
            target_dn: Target object DN
            permission_name: Permission name to check
        
        Returns:
            bool: True if dangerous permission exists
        """
        # This would require full SD parsing
        # For now, return False as placeholder
        return False
