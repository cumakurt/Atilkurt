"""
Security Descriptor Parser Module
Parses Windows Security Descriptor binary format from LDAP
"""

from __future__ import annotations

import logging
from typing import Any
from struct import unpack
from uuid import UUID

logger = logging.getLogger(__name__)


class SecurityDescriptorParser:
    """
    Parser for Windows Security Descriptor binary format.
    Based on MS-DTYP specification: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
    """

    # Security Descriptor Control Flags
    SE_OWNER_DEFAULTED = 0x0001
    SE_GROUP_DEFAULTED = 0x0002
    SE_DACL_PRESENT = 0x0004
    SE_DACL_DEFAULTED = 0x0008
    SE_SACL_PRESENT = 0x0010
    SE_SACL_DEFAULTED = 0x0020
    SE_DACL_AUTO_INHERITED = 0x0400
    SE_SACL_AUTO_INHERITED = 0x0800
    SE_DACL_PROTECTED = 0x1000
    SE_SACL_PROTECTED = 0x2000
    SE_RM_CONTROL_VALID = 0x4000
    SE_SELF_RELATIVE = 0x8000

    # ACE Types
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02
    SYSTEM_ALARM_ACE_TYPE = 0x03
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08

    # ACE Flags
    OBJECT_INHERIT_ACE = 0x01
    CONTAINER_INHERIT_ACE = 0x02
    NO_PROPAGATE_INHERIT_ACE = 0x04
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
    FAILED_ACCESS_ACE_FLAG = 0x80

    # Access Mask Flags
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000

    # Directory Service Access Rights
    ADS_RIGHT_DS_CREATE_CHILD = 0x0001
    ADS_RIGHT_DS_DELETE_CHILD = 0x0002
    ADS_RIGHT_DS_LIST = 0x0004
    ADS_RIGHT_DS_SELF = 0x0008
    ADS_RIGHT_DS_READ_PROP = 0x0010
    ADS_RIGHT_DS_WRITE_PROP = 0x0020
    ADS_RIGHT_DS_DELETE_TREE = 0x0040
    ADS_RIGHT_DS_LIST_OBJECT = 0x0080
    ADS_RIGHT_DS_CONTROL_ACCESS = 0x0100

    # Extended Rights GUIDs (common ones)
    EXTRIGHTS_GUID_MAPPING = {
        UUID('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2').bytes_le: 'DS-Replication-Get-Changes',
        UUID('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2').bytes_le: 'DS-Replication-Get-Changes-All',
        UUID('89e95b76-444d-4c62-991a-0facbeda640c').bytes_le: 'DS-Replication-Get-Changes-In-Filtered-Set',
        UUID('00299570-246d-11d0-a768-00aa006e0529').bytes_le: 'UserForceChangePassword',
    }
    PROPERTY_GUID_MAPPING = {
        UUID('bf9679c0-0de6-11d0-a285-00aa003049e2').bytes_le: 'WriteMember',
        UUID('bf967a0e-0de6-11d0-a285-00aa003049e2').bytes_le: 'WriteServicePrincipalName',
        UUID('bf967a68-0de6-11d0-a285-00aa003049e2').bytes_le: 'WriteUserAccountControl',
    }

    def __init__(self, sd_bytes: bytes):
        """
        Initialize parser with security descriptor binary data.

        Args:
            sd_bytes: Binary security descriptor data from LDAP (bytes or str from LDAP)
        """
        if isinstance(sd_bytes, str):
            sd_bytes = sd_bytes.encode("latin-1")
        self.sd_bytes = sd_bytes
        self.offset = 0
        self.owner_sid = None
        self.group_sid = None
        self.dacl = None
        self.sacl = None
        self.control = 0

    def parse(self) -> dict[str, Any]:
        """
        Parse security descriptor.

        Returns:
            dict: Parsed security descriptor with owner, group, DACL, SACL
        """
        if not self.sd_bytes or len(self.sd_bytes) < 20:
            return {
                'owner_sid': None,
                'group_sid': None,
                'dacl': [],
                'sacl': [],
                'is_protected': False,
                'parse_valid': False,
            }

        try:
            # Parse Security Descriptor header
            # Offset 0: Revision (1 byte)
            if self.sd_bytes[0] != 1:
                raise ValueError(f"Unsupported security descriptor revision: {self.sd_bytes[0]}")

            # Offset 1: Sbz1 (1 byte) - reserved
            # Offset 2-3: Control (2 bytes, little-endian)
            self.control = unpack('<H', self.sd_bytes[2:4])[0]

            # Offset 4-7: OffsetOwner (4 bytes, little-endian)
            offset_owner = unpack('<I', self.sd_bytes[4:8])[0]

            # Offset 8-11: OffsetGroup (4 bytes, little-endian)
            offset_group = unpack('<I', self.sd_bytes[8:12])[0]

            # Offset 12-15: OffsetSacl (4 bytes, little-endian)
            offset_sacl = unpack('<I', self.sd_bytes[12:16])[0]

            # Offset 16-19: OffsetDacl (4 bytes, little-endian)
            offset_dacl = unpack('<I', self.sd_bytes[16:20])[0]

            # Parse owner SID
            if offset_owner > 0:
                self.owner_sid = self._parse_sid_at_offset(offset_owner)

            # Parse group SID
            if offset_group > 0:
                self.group_sid = self._parse_sid_at_offset(offset_group)

            # Parse DACL
            dacl_aces = []
            if offset_dacl > 0 and (self.control & self.SE_DACL_PRESENT):
                dacl_aces = self._parse_acl_at_offset(offset_dacl)

            # Parse SACL
            sacl_aces = []
            if offset_sacl > 0 and (self.control & self.SE_SACL_PRESENT):
                sacl_aces = self._parse_acl_at_offset(offset_sacl)

            return {
                'owner_sid': self.owner_sid,
                'group_sid': self.group_sid,
                'dacl': dacl_aces,
                'sacl': sacl_aces,
                'parse_valid': True,
                'is_protected': bool(self.control & self.SE_DACL_PROTECTED),
                'is_auto_inherited': bool(self.control & self.SE_DACL_AUTO_INHERITED)
            }

        except Exception as e:
            logger.error(f"Error parsing security descriptor: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return {
                'owner_sid': None,
                'group_sid': None,
                'dacl': [],
                'sacl': [],
                'is_protected': False,
                'parse_valid': False,
            }

    def _parse_sid_at_offset(self, offset: int) -> str | None:
        """
        Parse SID at given offset.

        Args:
            offset: Offset in bytes

        Returns:
            str: SID in string format (e.g., S-1-5-21-...) or None
        """
        try:
            if offset + 8 > len(self.sd_bytes):
                raise ValueError('Truncated SID header')

            # SID structure:
            # Byte 0: Revision (1 byte)
            revision = self.sd_bytes[offset]

            # Byte 1: SubAuthorityCount (1 byte)
            sub_auth_count = self.sd_bytes[offset + 1]
            if revision != 1 or offset + 8 + sub_auth_count * 4 > len(self.sd_bytes):
                raise ValueError('Invalid or truncated SID')

            # Bytes 2-7: IdentifierAuthority (6 bytes, big-endian)
            identifier_auth_bytes = self.sd_bytes[offset + 2:offset + 8]

            # Convert identifier authority
            if len(identifier_auth_bytes) == 6:
                # First 4 bytes are usually 0, last 2 bytes contain the value
                identifier_auth = (identifier_auth_bytes[0] << 40) | \
                                 (identifier_auth_bytes[1] << 32) | \
                                 (identifier_auth_bytes[2] << 24) | \
                                 (identifier_auth_bytes[3] << 16) | \
                                 (identifier_auth_bytes[4] << 8) | \
                                 identifier_auth_bytes[5]
            else:
                return None

            # Build SID string
            sid = f"S-{revision}-{identifier_auth}"

            # Parse sub-authorities (4 bytes each, little-endian)
            current_offset = offset + 8
            for _ in range(sub_auth_count):
                if current_offset + 4 > len(self.sd_bytes):
                    break
                sub_auth = unpack('<I', self.sd_bytes[current_offset:current_offset + 4])[0]
                sid += f"-{sub_auth}"
                current_offset += 4

            return sid

        except Exception as e:
            raise ValueError(f'Invalid SID at offset {offset}') from e

    def _parse_acl_at_offset(self, offset: int) -> list[dict[str, Any]]:
        """
        Parse ACL (Access Control List) at given offset.

        Args:
            offset: Offset in bytes

        Returns:
            list: List of ACE dictionaries
        """
        aces = []

        try:
            if offset < 20 or offset + 8 > len(self.sd_bytes):
                raise ValueError('Invalid ACL offset')

            # ACL structure:
            # Bytes 0-1: AclRevision (1 byte) + Sbz1 (1 byte)
            # Bytes 2-3: AclSize (2 bytes, little-endian)
            acl_size = unpack('<H', self.sd_bytes[offset + 2:offset + 4])[0]
            acl_end = offset + acl_size
            if acl_size < 8 or acl_end > len(self.sd_bytes):
                raise ValueError("ACL size exceeds the security descriptor boundary")

            # Bytes 4-5: AceCount (2 bytes, little-endian)
            ace_count = unpack('<H', self.sd_bytes[offset + 4:offset + 6])[0]

            # Bytes 6-7: Sbz2 (2 bytes) - reserved

            # Parse each ACE
            current_offset = offset + 8
            for _ in range(ace_count):
                if current_offset + 4 > acl_end:
                    raise ValueError('Truncated ACE header')

                ace = self._parse_ace_at_offset(current_offset)
                if ace:
                    ace_size = ace.get('size', 0)
                    if ace_size < 4 or current_offset + ace_size > acl_end:
                        raise ValueError("ACE size exceeds the ACL boundary")
                    aces.append(ace)
                    # Move to next ACE (AceSize includes the header)
                    current_offset += ace_size
                else:
                    raise ValueError('Invalid ACE')

        except Exception as e:
            raise ValueError(f'Invalid ACL at offset {offset}') from e

        return aces

    def _parse_ace_at_offset(self, offset: int) -> dict[str, Any] | None:
        """
        Parse ACE (Access Control Entry) at given offset.

        Args:
            offset: Offset in bytes

        Returns:
            dict: ACE dictionary or None
        """
        try:
            if offset + 8 > len(self.sd_bytes):
                return None

            # ACE header:
            # Byte 0: AceType (1 byte)
            ace_type = self.sd_bytes[offset]

            # Byte 1: AceFlags (1 byte)
            ace_flags = self.sd_bytes[offset + 1]

            # Bytes 2-3: AceSize (2 bytes, little-endian)
            ace_size = unpack('<H', self.sd_bytes[offset + 2:offset + 4])[0]

            if ace_size < 8 or offset + ace_size > len(self.sd_bytes):
                return None

            # Check if inherited
            is_inherited = bool(ace_flags & self.INHERITED_ACE)

            # Parse ACE data
            ace_data = self.sd_bytes[offset + 4:offset + ace_size]
            types = {
                self.ACCESS_ALLOWED_ACE_TYPE: 'ACCESS_ALLOWED',
                self.ACCESS_DENIED_ACE_TYPE: 'ACCESS_DENIED',
                self.SYSTEM_AUDIT_ACE_TYPE: 'SYSTEM_AUDIT',
                self.ACCESS_ALLOWED_OBJECT_ACE_TYPE: 'ACCESS_ALLOWED_OBJECT',
                self.ACCESS_DENIED_OBJECT_ACE_TYPE: 'ACCESS_DENIED_OBJECT',
                self.SYSTEM_AUDIT_OBJECT_ACE_TYPE: 'SYSTEM_AUDIT_OBJECT',
            }
            if ace_type not in types:
                return {'type': 'UNSUPPORTED', 'ace_flags': ace_flags, 'size': ace_size, 'permissions': {}}
            if ace_type in (0, 1, 2):
                ace = self._parse_access_allowed_ace(ace_data, ace_flags, is_inherited, ace_size)
            else:
                ace = self._parse_access_allowed_object_ace(ace_data, ace_flags, is_inherited, ace_size)
            if ace:
                ace['type'] = types[ace_type]
            return ace

        except Exception as e:
            logger.debug(f"Error parsing ACE at offset {offset}: {e}")

        return None

    def _parse_access_allowed_ace(self, ace_data: bytes, ace_flags: int,
                                   is_inherited: bool, ace_size: int) -> dict[str, Any]:
        """
        Parse ACCESS_ALLOWED_ACE.

        Structure:
        - Mask (4 bytes, little-endian)
        - SID (variable length)
        """
        try:
            if len(ace_data) < 4:
                return None

            # Parse access mask
            access_mask = unpack('<I', ace_data[0:4])[0]

            # Parse SID
            sid = self._parse_sid_from_bytes(ace_data[4:])

            if not sid:
                return None

            # Extract permissions
            permissions = self._extract_permissions(access_mask, None)

            return {
                'type': 'ACCESS_ALLOWED',
                'sid': sid,
                'access_mask': access_mask,
                'permissions': permissions,
                'is_inherited': is_inherited,
                'ace_flags': ace_flags,
                'size': ace_size
            }

        except Exception as e:
            logger.debug(f"Error parsing ACCESS_ALLOWED_ACE: {e}")
            return None

    def _parse_access_allowed_object_ace(self, ace_data: bytes, ace_flags: int,
                                         is_inherited: bool, ace_size: int) -> dict[str, Any]:
        """
        Parse ACCESS_ALLOWED_OBJECT_ACE.

        Structure:
        - Mask (4 bytes, little-endian)
        - Flags (4 bytes, little-endian)
        - ObjectType (16 bytes, if Flags & 0x01)
        - InheritedObjectType (16 bytes, if Flags & 0x02)
        - SID (variable length)
        """
        try:
            if len(ace_data) < 8:
                return None

            # Parse access mask
            access_mask = unpack('<I', ace_data[0:4])[0]

            # Parse flags
            flags = unpack('<I', ace_data[4:8])[0]

            current_offset = 8

            # ObjectType present if Flags & 0x01
            object_type = None
            if flags & 0x01:
                if current_offset + 16 > len(ace_data):
                    return None
                object_type = ace_data[current_offset:current_offset + 16]
                current_offset += 16

            # InheritedObjectType present if Flags & 0x02
            inherited_object_type = None
            if flags & 0x02:
                if current_offset + 16 > len(ace_data):
                    return None
                inherited_object_type = ace_data[current_offset:current_offset + 16]
                current_offset += 16

            # Parse SID
            sid = self._parse_sid_from_bytes(ace_data[current_offset:])

            if not sid:
                return None

            # Extract permissions
            permissions = self._extract_permissions(access_mask, object_type)

            return {
                'type': 'ACCESS_ALLOWED_OBJECT',
                'sid': sid,
                'access_mask': access_mask,
                'permissions': permissions,
                'is_inherited': is_inherited,
                'ace_flags': ace_flags,
                'object_type': object_type,
                'inherited_object_type': inherited_object_type,
                'size': ace_size
            }

        except Exception as e:
            logger.debug(f"Error parsing ACCESS_ALLOWED_OBJECT_ACE: {e}")
            return None

    def _parse_sid_from_bytes(self, sid_bytes: bytes) -> str | None:
        """
        Parse SID from byte array.

        Args:
            sid_bytes: SID bytes (bytes or str when LDAP returns decoded binary)

        Returns:
            str: SID in string format or None
        """
        try:
            if isinstance(sid_bytes, str):
                sid_bytes = sid_bytes.encode("latin-1")
            if len(sid_bytes) < 8:
                return None

            # Revision
            revision = sid_bytes[0]

            # SubAuthorityCount
            sub_auth_count = sid_bytes[1]
            if revision != 1 or len(sid_bytes) < 8 + sub_auth_count * 4:
                return None

            # IdentifierAuthority (6 bytes)
            if len(sid_bytes) < 8:
                return None

            identifier_auth_bytes = sid_bytes[2:8]
            identifier_auth = (identifier_auth_bytes[0] << 40) | \
                             (identifier_auth_bytes[1] << 32) | \
                             (identifier_auth_bytes[2] << 24) | \
                             (identifier_auth_bytes[3] << 16) | \
                             (identifier_auth_bytes[4] << 8) | \
                             identifier_auth_bytes[5]

            # Build SID string
            sid = f"S-{revision}-{identifier_auth}"

            # Parse sub-authorities
            current_offset = 8
            for _ in range(sub_auth_count):
                if current_offset + 4 > len(sid_bytes):
                    break
                sub_auth = unpack('<I', sid_bytes[current_offset:current_offset + 4])[0]
                sid += f"-{sub_auth}"
                current_offset += 4

            return sid

        except Exception as e:
            logger.debug(f"Error parsing SID from bytes: {e}")
            return None

    def _extract_permissions(self, access_mask: int, object_type: bytes | None) -> dict[str, Any]:
        """
        Extract permission names from access mask.

        Args:
            access_mask: Access mask value
            object_type: Object type GUID (for object ACEs)

        Returns:
            dict: Dictionary of permission names and their details
        """
        permissions = {}
        access_mask = _directory_mask(access_mask)

        # Check generic permissions
        if not object_type and access_mask & 0xF01FF == 0xF01FF:
            permissions['GenericAll'] = {
                'mask': self.GENERIC_ALL,
                'severity': 'critical',
                'description': 'Full control over the object'
            }

        if not object_type and access_mask & 0x20028 == 0x20028:
            permissions['GenericWrite'] = {
                'mask': self.GENERIC_WRITE,
                'severity': 'high',
                'description': 'Write access to all properties'
            }

        if access_mask & self.WRITE_DACL:
            permissions['WriteDACL'] = {
                'mask': self.WRITE_DACL,
                'severity': 'critical',
                'description': 'Modify access control list'
            }

        if access_mask & self.WRITE_OWNER:
            permissions['WriteOwner'] = {
                'mask': self.WRITE_OWNER,
                'severity': 'critical',
                'description': 'Change object owner'
            }

        # Check directory service specific permissions
        if access_mask & self.ADS_RIGHT_DS_WRITE_PROP:
            # A scoped property write must never imply control of every attribute.
            property_name = self.PROPERTY_GUID_MAPPING.get(object_type)
            if not object_type:
                property_name = 'WriteProperty'
            elif not property_name:
                property_name = f'WriteProperty:{UUID(bytes_le=object_type)}'
            permissions[property_name] = {
                'mask': self.ADS_RIGHT_DS_WRITE_PROP,
                'severity': 'high',
                'description': 'Write access to specific properties'
            }

        if access_mask & self.ADS_RIGHT_DS_CONTROL_ACCESS:
            # Check for specific extended rights
            if object_type:
                ext_right_name = self.EXTRIGHTS_GUID_MAPPING.get(object_type)
                if ext_right_name:
                    permissions[ext_right_name] = {
                        'mask': self.ADS_RIGHT_DS_CONTROL_ACCESS,
                        'severity': 'critical',
                        'description': f'Extended right: {ext_right_name}'
                    }
                else:
                    permissions[f'ExtendedRight:{UUID(bytes_le=object_type)}'] = {
                        'mask': self.ADS_RIGHT_DS_CONTROL_ACCESS,
                        'severity': 'critical',
                        'description': 'A single scoped extended right'
                    }
            else:
                # No object type means all extended rights
                permissions['AllExtendedRights'] = {
                    'mask': self.ADS_RIGHT_DS_CONTROL_ACCESS,
                    'severity': 'critical',
                    'description': 'All extended rights (includes DCSync)'
                }

        return permissions


def _directory_mask(mask: int) -> int:
    """Expand AD generic rights before evaluating individual access bits."""
    if mask & SecurityDescriptorParser.GENERIC_ALL:
        mask |= 0xF01FF
    if mask & SecurityDescriptorParser.GENERIC_WRITE:
        mask |= 0x20028
    if mask & SecurityDescriptorParser.GENERIC_READ:
        mask |= 0x20094
    return mask & 0x0FFFFFFF


def directory_right_granted(parsed: dict[str, Any], sid: str, mask: int,
                            object_type: bytes | None = None,
                            token_sids: set[str] | None = None) -> bool:
    """Evaluate a directory right in DACL order for the known principal token.

    Inherit-only and audit ACEs do not grant access to the current object.
    Callers can supply group SIDs when membership evidence is available.
    """
    if parsed.get('parse_valid') is False or not sid:
        return False
    trustees = {sid, 'S-1-1-0', *(token_sids or set())}
    if sid.startswith('S-1-5-21-'):
        trustees.add('S-1-5-11')
    remaining = _directory_mask(mask)
    for ace in parsed.get('dacl') or []:
        if ace.get('sid') not in trustees or int(ace.get('ace_flags') or 0) & 0x08:
            continue
        scope = ace.get('object_type')
        access_mask = _directory_mask(int(ace.get('access_mask') or 0))
        # ObjectType scopes DS rights; standard rights such as WriteDACL
        # remain rights on the object itself.
        if scope and object_type is not None and scope != object_type:
            access_mask &= ~0x1FF
        kind = ace.get('type', '')
        if kind in ('ACCESS_DENIED', 'ACCESS_DENIED_OBJECT'):
            if access_mask & remaining:
                return False
        elif kind in ('ACCESS_ALLOWED', 'ACCESS_ALLOWED_OBJECT'):
            if scope and object_type is None:
                access_mask &= ~0x1FF
            remaining &= ~access_mask
            if not remaining:
                return True
    return False


def effective_allow_aces(parsed: dict[str, Any] | None,
                         tokens: dict[str, set[str]] | None = None) -> list[dict[str, Any]]:
    """Return supported grants that survive applicable DACL denials."""
    if not parsed or parsed.get('parse_valid') is False:
        return []
    grants = []
    for ace in parsed.get('dacl') or []:
        if ace.get('type') not in ('ACCESS_ALLOWED', 'ACCESS_ALLOWED_OBJECT'):
            continue
        if int(ace.get('ace_flags') or 0) & 0x08:
            continue
        permissions = {
            name: details for name, details in (ace.get('permissions') or {}).items()
            if directory_right_granted(
                parsed, ace.get('sid'), details.get('mask', 0), ace.get('object_type'),
                (tokens or {}).get(ace.get('sid')),
            )
        }
        if permissions:
            grants.append({**ace, 'permissions': permissions})
    return grants


def parse_security_descriptor(sd_bytes: bytes) -> dict[str, Any]:
    """
    Convenience function to parse security descriptor.

    Args:
        sd_bytes: Binary security descriptor data

    Returns:
        dict: Parsed security descriptor
    """
    parser = SecurityDescriptorParser(sd_bytes)
    return parser.parse()
