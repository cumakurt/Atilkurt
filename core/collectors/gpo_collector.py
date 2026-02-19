"""
GPO (Group Policy Object) Collector Module
Collects GPO objects and their configurations from Active Directory
"""

import logging
from ldap3.utils.conv import escape_filter_chars
from core.progress_tracker import ProgressTracker, create_progress_callback

logger = logging.getLogger(__name__)


class GPOCollector:
    """Collects GPO objects from Active Directory via LDAP."""
    
    def __init__(self, ldap_connection, show_progress: bool = True):
        """
        Initialize GPO collector.
        
        Args:
            ldap_connection: LDAPConnection instance
            show_progress: Whether to show progress messages
        """
        self.ldap = ldap_connection
        self.show_progress = show_progress
    
    def collect(self):
        """
        Collect all GPO objects from Active Directory.
        
        Returns:
            list: List of GPO dictionaries with collected attributes
        """
        gpos = []
        
        try:
            # Initialize progress tracker
            progress = ProgressTracker(
                operation_name="Collecting GPOs",
                total_items=None,
                show_progress=self.show_progress
            )
            
            # Search for all GPO objects
            search_filter = '(objectClass=groupPolicyContainer)'
            attributes = [
                'name',
                'displayName',
                'gPCFileSysPath',
                'gPCFunctionalityVersion',
                'description',
                'distinguishedName',
                'whenCreated',
                'whenChanged',
                'nTSecurityDescriptor'
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
                gpo = {
                    'name': entry.get('name'),
                    'displayName': entry.get('displayName'),
                    'gPCFileSysPath': entry.get('gPCFileSysPath'),
                    'gPCFunctionalityVersion': entry.get('gPCFunctionalityVersion'),
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'nTSecurityDescriptor': entry.get('nTSecurityDescriptor')
                }
                
                # Get linked OUs
                gpo['linkedOUs'] = self._get_linked_ous(gpo['distinguishedName'])
                
                gpos.append(gpo)
            
            progress.finish()
            logger.info(f"Collected {len(gpos)} GPOs")
            return gpos
            
        except Exception as e:
            logger.error(f"Error collecting GPOs: {str(e)}")
            # Return empty list if GPO collection fails (may not have permissions)
            return []
    
    def _get_linked_ous(self, gpo_dn):
        """
        Get OUs linked to this GPO.
        
        Args:
            gpo_dn: Distinguished name of the GPO
        
        Returns:
            list: List of linked OU DNs
        """
        linked_ous = []
        
        try:
            # Extract GPO GUID from DN (format: CN={GUID},CN=Policies,CN=System,DC=...)
            if 'CN={' in gpo_dn:
                gpo_guid = gpo_dn.split('CN={')[1].split('}')[0] if '}' in gpo_dn.split('CN={')[1] else None
                
                if gpo_guid:
                    # Search for OUs with gPLink attribute containing this GPO
                    search_filter = f'(gPLink=*{escape_filter_chars(gpo_guid)}*)'
                    results = self.ldap.search(
                        search_filter=search_filter,
                        attributes=['distinguishedName', 'gPLink']
                    )
                    
                    for entry in results:
                        ou_dn = entry.get('dn', entry.get('distinguishedName'))
                        if ou_dn:
                            linked_ous.append(ou_dn)
        except Exception as e:
            logger.debug(f"Error getting linked OUs for {gpo_dn}: {str(e)}")
        
        return linked_ous
