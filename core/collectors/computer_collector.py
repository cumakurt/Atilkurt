"""
Computer Collector Module
Collects all computer objects from Active Directory
"""

import logging
from datetime import datetime
from core.progress_tracker import ProgressTracker, create_progress_callback

logger = logging.getLogger(__name__)


class ComputerCollector:
    """Collects computer objects from Active Directory via LDAP."""
    
    def __init__(self, ldap_connection, show_progress: bool = True):
        """
        Initialize computer collector.
        
        Args:
            ldap_connection: LDAPConnection instance
            show_progress: Whether to show progress messages
        """
        self.ldap = ldap_connection
        self.show_progress = show_progress
    
    def collect(self):
        """
        Collect all computer objects from Active Directory.
        
        Returns:
            list: List of computer dictionaries with collected attributes
        """
        computers = []
        
        try:
            # Initialize progress tracker
            progress = ProgressTracker(
                operation_name="Collecting computers",
                total_items=None,
                show_progress=self.show_progress
            )
            
            # Search for all computer objects
            search_filter = '(&(objectClass=computer)(objectCategory=computer))'
            attributes = [
                'name',
                'operatingSystem',
                'operatingSystemVersion',
                'lastLogonTimestamp',
                'userAccountControl',
                'servicePrincipalName',
                'dNSHostName',
                'description',
                'distinguishedName',
                'whenCreated',
                'whenChanged',
                'msDS-AllowedToDelegateTo',
                'accountExpires'
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
                uac = entry.get('userAccountControl', 0)
                if isinstance(uac, str):
                    try:
                        uac = int(uac)
                    except ValueError:
                        uac = 0
                
                computer = {
                    'name': entry.get('name'),
                    'dNSHostName': entry.get('dNSHostName'),
                    'operatingSystem': entry.get('operatingSystem'),
                    'operatingSystemVersion': entry.get('operatingSystemVersion'),
                    'lastLogonTimestamp': self._convert_timestamp(entry.get('lastLogonTimestamp')),
                    'userAccountControl': uac,
                    'servicePrincipalName': entry.get('servicePrincipalName', []),
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'unconstrainedDelegation': self._check_unconstrained_delegation(uac),
                    'trustedForDelegation': self._check_trusted_for_delegation(uac),
                    'msDS-AllowedToDelegateTo': entry.get('msDS-AllowedToDelegateTo', []),
                    'accountExpires': entry.get('accountExpires')
                }
                
                # Normalize msDS-AllowedToDelegateTo to list
                if computer['msDS-AllowedToDelegateTo'] is None:
                    computer['msDS-AllowedToDelegateTo'] = []
                elif not isinstance(computer['msDS-AllowedToDelegateTo'], list):
                    computer['msDS-AllowedToDelegateTo'] = [computer['msDS-AllowedToDelegateTo']]
                
                # Normalize servicePrincipalName to list
                if computer['servicePrincipalName'] is None:
                    computer['servicePrincipalName'] = []
                elif not isinstance(computer['servicePrincipalName'], list):
                    computer['servicePrincipalName'] = [computer['servicePrincipalName']]
                
                computers.append(computer)
            
            progress.finish()
            logger.info(f"Collected {len(computers)} computers")
            return computers
            
        except Exception as e:
            logger.error(f"Error collecting computers: {str(e)}")
            raise
    
    def _check_unconstrained_delegation(self, user_account_control):
        """
        Check if computer has unconstrained delegation enabled.
        
        Args:
            user_account_control: UAC flag value
        
        Returns:
            bool: True if unconstrained delegation is enabled
        """
        # TRUSTED_FOR_DELEGATION flag = 524288 (0x80000)
        return bool(user_account_control & 524288)
    
    def _check_trusted_for_delegation(self, user_account_control):
        """
        Check if computer is trusted for delegation.
        
        Args:
            user_account_control: UAC flag value
        
        Returns:
            bool: True if trusted for delegation
        """
        # Same flag as unconstrained delegation
        return bool(user_account_control & 524288)
    
    def _convert_timestamp(self, timestamp):
        """
        Convert Windows timestamp to datetime.
        
        Args:
            timestamp: Windows timestamp (100-nanosecond intervals since 1601-01-01)
        
        Returns:
            datetime or None: Converted datetime object
        """
        if not timestamp:
            return None
        
        try:
            if isinstance(timestamp, (int, str)):
                timestamp = int(timestamp)
                if timestamp == 0:
                    return None
                # Convert to Unix timestamp
                unix_timestamp = (timestamp / 10000000) - 11644473600
                return datetime.fromtimestamp(unix_timestamp)
            return timestamp
        except (ValueError, TypeError, OSError):
            return None
