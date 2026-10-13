"""
User Collector Module
Collects all user objects from Active Directory
"""

import logging
from core.ad_security import as_int, filetime_utc
from core.constants import UACFlags
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
                'msDS-User-Account-Control-Computed',
                'adminCount',
                'servicePrincipalName',
                'msDS-SupportedEncryptionTypes',
                'displayName',
                'mail',
                'whenCreated',
                'whenChanged',
                'description',
                'distinguishedName',
                'lockoutTime',
                'accountExpires',
                'primaryGroupID',
                'msDS-ExternalDirectoryObjectId',
                'msDS-KeyCredentialLink',
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
                    'objectSid': entry.get('objectSid'),
                    'displayName': entry.get('displayName'),
                    'memberOf': entry.get('memberOf', []),
                    'lastLogonTimestamp': self._convert_timestamp(entry.get('lastLogonTimestamp')),
                    'pwdLastSet': self._convert_timestamp(entry.get('pwdLastSet')),
                    'userAccountControl': uac,
                    'adminCount': entry.get('adminCount'),
                    'servicePrincipalName': entry.get('servicePrincipalName', []),
                    'msDS-SupportedEncryptionTypes': entry.get('msDS-SupportedEncryptionTypes'),
                    'mail': entry.get('mail'),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'lockoutTime': self._convert_timestamp(entry.get('lockoutTime')),
                    'accountExpires': self._convert_timestamp(entry.get('accountExpires')),
                    'primaryGroupID': entry.get('primaryGroupID'),
                    'msDS-ExternalDirectoryObjectId': entry.get('msDS-ExternalDirectoryObjectId'),
                    'hasKeyCredentialLink': bool(entry.get('msDS-KeyCredentialLink')),
                    'isDisabled': bool(uac & UACFlags.ACCOUNTDISABLE),
                    'isLocked': bool(uac & UACFlags.LOCKOUT) or self._is_account_locked(
                        entry.get('lockoutTime'), entry.get('msDS-User-Account-Control-Computed'),
                    ),
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
        return filetime_utc(timestamp)

    def _is_account_locked(self, lockout_time, computed_uac=None):
        """
        Use the DC's effective lockout flag, including the applicable PSO.

        Args:
            lockout_time: Lockout timestamp
            computed_uac: msDS-User-Account-Control-Computed flags

        Returns:
            bool or None: Current lockout state, or unknown without computed flags.
        """
        flags = as_int(computed_uac)
        if flags is not None:
            return bool(flags & UACFlags.LOCKOUT)
        if lockout_time in (0, "0"):
            return False
        # A nonzero timestamp can remain after the effective lockout expires.
        return None
