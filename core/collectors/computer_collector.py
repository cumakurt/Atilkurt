"""
Computer Collector Module
Collects all computer objects from Active Directory
"""

import logging
from datetime import datetime
from core.progress_tracker import ProgressTracker, create_progress_callback

logger = logging.getLogger(__name__)


# These attributes depend on the AD functional level or an optional schema
# extension.  Requesting an unknown attribute makes ldap3 reject the entire
# search, so they must never prevent the core computer inventory from loading.
SCHEMA_OPTIONAL_ATTRIBUTES = frozenset({
    'msDS-SupportedEncryptionTypes',
    'msDS-AllowedToDelegateTo',
    'msDS-ExternalDirectoryObjectId',
    'ms-Mcs-AdmPwdExpirationTime',
    'msLAPS-PasswordExpirationTime',
    'msLAPS-EncryptedPasswordExpirationTime',
    'msDS-RevealOnDemandGroup',
    'msDS-NeverRevealGroup',
    'msDS-RevealedUsers',
})


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
                'objectSid',
                'operatingSystem',
                'operatingSystemVersion',
                'lastLogonTimestamp',
                'userAccountControl',
                'servicePrincipalName',
                'msDS-SupportedEncryptionTypes',
                'dNSHostName',
                'description',
                'distinguishedName',
                'whenCreated',
                'whenChanged',
                'msDS-AllowedToDelegateTo',
                'accountExpires',
                'primaryGroupID',
                'msDS-ExternalDirectoryObjectId',
                'sAMAccountName',
                'ms-Mcs-AdmPwdExpirationTime',
                'msLAPS-PasswordExpirationTime',
                'msLAPS-EncryptedPasswordExpirationTime',
                'msDS-RevealOnDemandGroup',
                'msDS-NeverRevealGroup',
                'msDS-RevealedUsers',
                'managedBy',
            ]

            # Create progress callback
            progress_callback = create_progress_callback(progress)

            results = self._search_computers(
                search_filter,
                attributes,
                progress_callback,
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
                    'sAMAccountName': entry.get('sAMAccountName'),
                    'primaryGroupID': entry.get('primaryGroupID'),
                    'msDS-ExternalDirectoryObjectId': entry.get('msDS-ExternalDirectoryObjectId'),
                    'objectSid': entry.get('objectSid'),
                    'dNSHostName': entry.get('dNSHostName'),
                    'operatingSystem': entry.get('operatingSystem'),
                    'operatingSystemVersion': entry.get('operatingSystemVersion'),
                    'lastLogonTimestamp': self._convert_timestamp(entry.get('lastLogonTimestamp')),
                    'userAccountControl': uac,
                    'servicePrincipalName': entry.get('servicePrincipalName', []),
                    'msDS-SupportedEncryptionTypes': entry.get('msDS-SupportedEncryptionTypes'),
                    'description': entry.get('description'),
                    'distinguishedName': entry.get('dn', entry.get('distinguishedName')),
                    'whenCreated': entry.get('whenCreated'),
                    'whenChanged': entry.get('whenChanged'),
                    'unconstrainedDelegation': self._check_unconstrained_delegation(uac),
                    'trustedForDelegation': self._check_trusted_for_delegation(uac),
                    'msDS-AllowedToDelegateTo': entry.get('msDS-AllowedToDelegateTo', []),
                    'accountExpires': entry.get('accountExpires'),
                    'ms-Mcs-AdmPwdExpirationTime': entry.get('ms-Mcs-AdmPwdExpirationTime'),
                    'msLAPS-PasswordExpirationTime': entry.get('msLAPS-PasswordExpirationTime'),
                    'msLAPS-EncryptedPasswordExpirationTime': entry.get('msLAPS-EncryptedPasswordExpirationTime'),
                    'msDS-RevealOnDemandGroup': entry.get('msDS-RevealOnDemandGroup'),
                    'msDS-NeverRevealGroup': entry.get('msDS-NeverRevealGroup'),
                    'msDS-RevealedUsers': entry.get('msDS-RevealedUsers'),
                    'managedBy': entry.get('managedBy'),
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

    def _search_computers(self, search_filter, attributes, progress_callback):
        """Search computers without failing on unavailable schema extensions."""
        remaining_attributes = self._attributes_available_in_schema(attributes)

        while True:
            try:
                return self.ldap.search(
                    search_filter=search_filter,
                    attributes=remaining_attributes,
                    progress_callback=progress_callback,
                )
            except Exception as exc:
                invalid_attribute = self._invalid_optional_attribute(
                    exc,
                    remaining_attributes,
                )
                if invalid_attribute is None:
                    raise

                if invalid_attribute:
                    removed_attributes = [invalid_attribute]
                else:
                    # Some LDAP implementations omit the offending attribute
                    # name. Fall back to the portable inventory in that case.
                    removed_attributes = [
                        attribute for attribute in remaining_attributes
                        if attribute in SCHEMA_OPTIONAL_ATTRIBUTES
                    ]

                if not removed_attributes:
                    raise

                removed = {attribute.casefold() for attribute in removed_attributes}
                remaining_attributes = [
                    attribute for attribute in remaining_attributes
                    if attribute.casefold() not in removed
                ]
                logger.warning(
                    "Skipping unsupported AD schema attribute(s): %s",
                    ", ".join(removed_attributes),
                )

    def _attributes_available_in_schema(self, attributes):
        """Prune known optional attributes when ldap3 loaded the server schema."""
        connection = getattr(self.ldap, 'connection', None)
        server = getattr(connection, 'server', None)
        schema = getattr(server, 'schema', None)
        attribute_types = getattr(schema, 'attribute_types', None)
        if attribute_types is None:
            return list(attributes)

        unsupported = [
            attribute for attribute in attributes
            if attribute in SCHEMA_OPTIONAL_ATTRIBUTES
            and attribute not in attribute_types
        ]
        if unsupported:
            logger.debug(
                "Skipping AD attributes absent from the server schema: %s",
                ", ".join(unsupported),
            )
        unsupported_folded = {attribute.casefold() for attribute in unsupported}
        return [
            attribute for attribute in attributes
            if attribute.casefold() not in unsupported_folded
        ]

    @staticmethod
    def _invalid_optional_attribute(exc, attributes):
        """Return the offending optional attribute, or ``''`` if unnamed."""
        message = str(exc).casefold()
        invalid_markers = (
            'invalid attribute',
            'no such attribute',
            'undefined attribute',
            'undefinedattributetype',
        )
        if not any(marker in message for marker in invalid_markers):
            return None

        for attribute in attributes:
            if (
                attribute in SCHEMA_OPTIONAL_ATTRIBUTES
                and attribute.casefold() in message
            ):
                return attribute
        return ''

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
