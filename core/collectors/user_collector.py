"""
User Collector Module
Collects all user objects from Active Directory
"""

import logging
from datetime import datetime
from typing import Optional
from core.progress_tracker import ProgressTracker, create_progress_callback

logger = logging.getLogger(__name__)


class UserCollector:
    """Collects user objects from Active Directory via LDAP."""
    
    def __init__(self, ldap_connection, show_progress: bool = True):
        """
        Initialize user collector.
        
        Args:
            ldap_connection: LDAPConnection instance
            show_progress: Whether to show progress messages
        """
        self.ldap = ldap_connection
        self.show_progress = show_progress
    
    def collect(self):
        """
        Collect all user objects from Active Directory.
        
        Returns:
            list: List of user dictionaries with collected attributes
        """
        users = []
        
        try:
            # Initialize progress tracker
            progress = ProgressTracker(
                operation_name="Collecting users",
                total_items=None,  # Unknown until search completes
                show_progress=self.show_progress
            )
            
            # Search for all user objects
            search_filter = '(&(objectClass=user)(objectCategory=person))'
            attributes = [
                'sAMAccountName',
                'objectSid',
                'memberOf',
                'lastLogonTimestamp',
                'pwdLastSet',
                'userAccountControl',
                'adminCount',
                'servicePrincipalName',
                'displayName',
                'mail',
                'whenCreated',
                'whenChanged',
                'description',
                'distinguishedName',
                'lockoutTime',
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
                
                user = {
                    'sAMAccountName': entry.get('sAMAccountName'),
                    'displayName': entry.get('displayName'),
                    'memberOf': entry.get('memberOf', []),
                    'lastLogonTimestamp': self._convert_timestamp(entry.get('lastLogonTimestamp')),
                    'pwdLastSet': self._convert_timestamp(entry.get('pwdLastSet')),
                    'userAccountControl': uac,
                    'adminCount': entry.get('adminCount'),
                    'servicePrincipalName': entry.get('servicePrincipalName', []),
                    'mail': entry.get('mail'),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'lockoutTime': self._convert_timestamp(entry.get('lockoutTime')),
                    'accountExpires': self._convert_timestamp(entry.get('accountExpires')),
                    'isDisabled': bool(uac & 0x2),  # ACCOUNTDISABLE flag
                    'isLocked': self._is_account_locked(entry.get('lockoutTime'))
                }
                
                # Normalize memberOf to list
                if user['memberOf'] is None:
                    user['memberOf'] = []
                elif not isinstance(user['memberOf'], list):
                    user['memberOf'] = [user['memberOf']]
                
                # Normalize servicePrincipalName to list
                if user['servicePrincipalName'] is None:
                    user['servicePrincipalName'] = []
                elif not isinstance(user['servicePrincipalName'], list):
                    user['servicePrincipalName'] = [user['servicePrincipalName']]
                
                users.append(user)
            
            progress.finish()
            logger.info(f"Collected {len(users)} users")
            return users
            
        except Exception as e:
            logger.error(f"Error collecting users: {str(e)}")
            raise
    
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
            # Windows timestamp: number of 100-nanosecond intervals since 1601-01-01
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
    
    def _is_account_locked(self, lockout_time):
        """
        Check if account is locked based on lockoutTime.
        
        Args:
            lockout_time: Lockout timestamp
        
        Returns:
            bool: True if account is locked
        """
        if not lockout_time:
            return False
        
        try:
            # If lockoutTime is 0 or None, account is not locked
            if isinstance(lockout_time, (int, str)):
                lockout_time = int(lockout_time)
                if lockout_time == 0:
                    return False
            
            # If lockoutTime is a datetime, check if it's recent (within last 30 days)
            # Lockout typically expires after lockout duration, but we check if it's set
            if isinstance(lockout_time, datetime):
                # If lockoutTime is set and recent, account might be locked
                # Note: Actual lockout status depends on lockout duration policy
                days_ago = (datetime.now() - lockout_time.replace(tzinfo=None)).days
                return days_ago < 30  # Consider locked if lockoutTime is within last 30 days
            
            return False
        except (ValueError, TypeError):
            return False
