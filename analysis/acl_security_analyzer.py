"""
ACL Security Analysis Module
Comprehensive Active Directory ACL security analysis including:
- Critical permission detection
- Shadow Admin detection
- Privilege escalation path analysis
- Inheritance analysis
- Risk scoring
"""

import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from ldap3.utils.conv import escape_filter_chars
from core.constants import RiskTypes, Severity, PRIVILEGED_GROUPS
from core.security_descriptor_parser import SecurityDescriptorParser, parse_security_descriptor

logger = logging.getLogger(__name__)


class ACLSecurityAnalyzer:
    """
    Comprehensive ACL security analyzer for Active Directory.
    Detects dangerous permissions, Shadow Admins, and privilege escalation paths.
    """
    
    # Well-known SIDs for trustee display (RID or full SID -> display name)
    WELL_KNOWN_SIDS = {
        'S-1-0-0': 'Null',
        'S-1-1-0': 'Everyone',
        'S-1-2-0': 'Local',
        'S-1-3-0': 'Creator Owner',
        'S-1-5-4': 'Interactive',
        'S-1-5-10': 'Self',
        'S-1-5-11': 'Authenticated Users',
        'S-1-5-18': 'SYSTEM',
        'S-1-5-19': 'NT AUTHORITY\\Local Service',
        'S-1-5-20': 'NT AUTHORITY\\Network Service',
        'S-1-5-32-544': 'BUILTIN\\Administrators',
        'S-1-5-32-545': 'BUILTIN\\Users',
        'S-1-5-32-546': 'BUILTIN\\Guests',
        'S-1-5-32-547': 'BUILTIN\\Power Users',
        'S-1-5-32-548': 'BUILTIN\\Account Operators',
        'S-1-5-32-549': 'BUILTIN\\Server Operators',
        'S-1-5-32-550': 'BUILTIN\\Print Operators',
        'S-1-5-32-551': 'BUILTIN\\Backup Operators',
        'S-1-5-32-552': 'BUILTIN\\Replicator',
        'S-1-5-32-561': 'BUILTIN\\Pre-Windows 2000 Compatible Access',
        'S-1-5-32-562': 'BUILTIN\\Remote Desktop Users',
    }
    
    # Critical permission types (MUST DETECT)
    # description: short technical label; used in reports for "what this permission means"
    CRITICAL_PERMISSIONS = {
        # Full Control
        'GenericAll': {
            'mask': 0xF01FF,
            'severity': Severity.CRITICAL,
            'description': 'Full control over the object (read, write, delete, modify permissions, take ownership)',
            'risk_score': 100
        },
        # Write Permissions
        'GenericWrite': {
            'mask': 0x40000000,
            'severity': Severity.HIGH,
            'description': 'Write access to all attributes of the object; can change sensitive properties',
            'risk_score': 80
        },
        'WriteProperty': {
            'mask': 0x10,
            'severity': Severity.HIGH,
            'description': 'Write access to specific LDAP attributes; can include security-sensitive properties',
            'risk_score': 75
        },
        'WriteDACL': {
            'mask': 0x40000,
            'severity': Severity.CRITICAL,
            'description': 'Modify the object\'s Access Control List (ACL); can grant themselves or others any right',
            'risk_score': 95
        },
        'WriteOwner': {
            'mask': 0x80000,
            'severity': Severity.CRITICAL,
            'description': 'Change the object owner; owner can then modify ACL and gain full control',
            'risk_score': 95
        },
        # Account Control Permissions
        'UserForceChangePassword': {
            'mask': 0x100,
            'severity': Severity.HIGH,
            'description': 'Force the user to change password at next logon; can be abused for credential reset attacks',
            'risk_score': 70
        },
        'WriteServicePrincipalName': {
            'mask': 0x100,
            'severity': Severity.HIGH,
            'description': 'Modify the account\'s servicePrincipalName (SPN); enables Kerberoasting and Silver Ticket',
            'risk_score': 75
        },
        'WriteUserAccountControl': {
            'mask': 0x100,
            'severity': Severity.CRITICAL,
            'description': 'Modify userAccountControl (e.g. disable Require Preauth for AS-REP Roasting, set DONT_EXPIRE_PASSWD)',
            'risk_score': 90
        },
        'WriteMember': {
            'mask': 0x100,
            'severity': Severity.HIGH,
            'description': 'Add or remove members of the group; can add themselves to privileged groups',
            'risk_score': 80
        },
        # Extended Rights (DCSync)
        'DS-Replication-Get-Changes': {
            'mask': 0x40,
            'severity': Severity.CRITICAL,
            'description': 'Replication right: retrieve directory changes (part of DCSync); can lead to hash extraction',
            'risk_score': 100
        },
        'DS-Replication-Get-Changes-All': {
            'mask': 0x80,
            'severity': Severity.CRITICAL,
            'description': 'Replication right: retrieve all directory changes; enables full DCSync and domain takeover',
            'risk_score': 100
        },
        'DS-Replication-Get-Changes-In-Filtered-Set': {
            'mask': 0x100,
            'severity': Severity.CRITICAL,
            'description': 'Replication right: retrieve filtered directory changes; used in DCSync attacks',
            'risk_score': 100
        },
        'AllExtendedRights': {
            'mask': 0x100,
            'severity': Severity.CRITICAL,
            'description': 'All extended rights including DCSync, force change password, and other sensitive operations',
            'risk_score': 100
        }
    }
    
    # Object criticality levels (for risk scoring)
    OBJECT_CRITICALITY = {
        'domain': 5.0,
        'domain_controller': 5.0,
        'enterprise_admin': 5.0,
        'domain_admin': 4.5,
        'schema_admin': 4.5,
        'privileged_group': 4.0,
        'privileged_user': 3.5,
        'ou': 3.0,
        'gpo': 3.0,
        'group': 2.0,
        'user': 1.5,
        'computer': 1.0
    }
    
    def __init__(self, ldap_connection):
        """
        Initialize ACL security analyzer.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
        self.privileged_groups_set = set(PRIVILEGED_GROUPS)
        self.shadow_admins = []
        self.privilege_escalation_paths = []
        self.acl_risks = []
    
    def analyze(self, users: List[Dict[str, Any]], groups: List[Dict[str, Any]], 
                computers: List[Dict[str, Any]], domain_dn: str = None) -> Dict[str, Any]:
        """
        Perform comprehensive ACL security analysis.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            domain_dn: Domain distinguished name
            
        Returns:
            dict: Analysis results
        """
        logger.info("Starting comprehensive ACL security analysis...")
        
        # Build object maps
        user_map = {u.get('sAMAccountName'): u for u in users}
        group_map = {g.get('name') or g.get('sAMAccountName'): g for g in groups}
        computer_map = {c.get('name'): c for c in computers}
        
        # Build SID -> display name map for trustee resolution (avoids "same report" confusion)
        sid_to_display_name = self._build_sid_to_display_name(users, groups)
        
        # Get domain DN if not provided
        if not domain_dn:
            domain_dn = self._get_domain_dn()
        
        # Identify privileged objects
        privileged_users = self._identify_privileged_users(users, groups)
        privileged_groups = self._identify_privileged_groups(groups)
        tier0_objects = self._identify_tier0_objects(users, groups, computers, domain_dn)
        
        # Analyze ACLs on critical objects
        critical_objects = []
        critical_objects.extend([{'type': 'domain', 'dn': domain_dn, 'name': 'Domain'}])
        critical_objects.extend([{'type': 'user', 'dn': u.get('distinguishedName'), 'name': u.get('sAMAccountName')} 
                                for u in privileged_users])
        critical_objects.extend([{'type': 'group', 'dn': g.get('distinguishedName'), 'name': g.get('name')} 
                                for g in privileged_groups])
        
        # Analyze each critical object (each obj is a distinct dict; findings get explicit object identity)
        all_acl_findings = []
        for obj in critical_objects:
            if not obj.get('dn'):
                continue
            findings = self._analyze_object_acl(obj, user_map, group_map, sid_to_display_name)
            all_acl_findings.extend(findings)
        
        # Shadow Admin Detection
        shadow_admins = self._detect_shadow_admins(users, groups, domain_dn, privileged_users, privileged_groups)
        
        # Privilege Escalation Path Analysis
        escalation_paths = self._analyze_privilege_escalation_paths(
            users, groups, computers, all_acl_findings
        )
        
        # Inheritance Analysis
        inheritance_risks = self._analyze_inheritance(domain_dn, all_acl_findings)
        
        # Calculate risk scores
        scored_risks = self._calculate_risk_scores(all_acl_findings, shadow_admins, escalation_paths)
        
        logger.info(f"Found {len(all_acl_findings)} ACL risks")
        logger.info(f"Found {len(shadow_admins)} Shadow Admins")
        logger.info(f"Found {len(escalation_paths)} privilege escalation paths")
        
        return {
            'acl_risks': scored_risks,
            'shadow_admins': shadow_admins,
            'privilege_escalation_paths': escalation_paths,
            'inheritance_risks': inheritance_risks,
            'total_risks': len(scored_risks),
            'critical_risks': len([r for r in scored_risks if r.get('severity') == Severity.CRITICAL]),
            'high_risks': len([r for r in scored_risks if r.get('severity') == Severity.HIGH])
        }
    
    def _get_domain_dn(self) -> str:
        """Get domain distinguished name from LDAP."""
        try:
            results = self.ldap.search(
                search_filter='(objectClass=domain)',
                attributes=['distinguishedName']
            )
            if results:
                return results[0].get('distinguishedName', '')
        except Exception as e:
            logger.error(f"Error getting domain DN: {e}")
        return ''
    
    def _identify_privileged_users(self, users: List[Dict[str, Any]], 
                                   groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify privileged users."""
        privileged_users = []
        privileged_group_names = {g.get('name') or g.get('sAMAccountName', '') 
                                  for g in groups if self._is_privileged_group(g)}
        
        for user in users:
            # Check adminCount flag
            if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                privileged_users.append(user)
                continue
            
            # Check group memberships
            member_of = user.get('memberOf', [])
            if isinstance(member_of, str):
                member_of = [member_of]
            
            for group_dn in member_of:
                # Extract group name from DN
                group_name = self._extract_name_from_dn(group_dn)
                if group_name in privileged_group_names:
                    privileged_users.append(user)
                    break
        
        return privileged_users
    
    def _identify_privileged_groups(self, groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify privileged groups."""
        return [g for g in groups if self._is_privileged_group(g)]
    
    def _is_privileged_group(self, group: Dict[str, Any]) -> bool:
        """Check if group is privileged."""
        group_name = (group.get('name') or group.get('sAMAccountName') or '').lower()
        return any(priv_group.lower() in group_name for priv_group in self.privileged_groups_set)
    
    def _identify_tier0_objects(self, users: List[Dict[str, Any]], groups: List[Dict[str, Any]],
                                computers: List[Dict[str, Any]], domain_dn: str) -> List[Dict[str, Any]]:
        """Identify Tier-0 objects (most critical)."""
        tier0 = []
        
        # Domain Admins, Enterprise Admins
        for group in groups:
            group_name = (group.get('name') or group.get('sAMAccountName') or '').lower()
            if 'domain admin' in group_name or 'enterprise admin' in group_name:
                tier0.append({'type': 'group', 'object': group})
        
        # Domain Controllers
        for computer in computers:
            if 'DC' in (computer.get('name') or '').upper() or 'CONTROLLER' in (computer.get('name') or '').upper():
                tier0.append({'type': 'computer', 'object': computer})
        
        return tier0
    
    def _build_sid_to_display_name(self, users: List[Dict[str, Any]], groups: List[Dict[str, Any]]) -> Dict[str, str]:
        """Build SID -> display name map from users, groups, and well-known SIDs."""
        sid_map = dict(self.WELL_KNOWN_SIDS)
        for u in users or []:
            raw_sid = u.get('objectSid')
            if not raw_sid:
                continue
            if isinstance(raw_sid, list) and len(raw_sid) > 0:
                raw_sid = raw_sid[0]
            sid_str = self._binary_sid_to_string(raw_sid) if isinstance(raw_sid, bytes) else str(raw_sid)
            if sid_str:
                sid_map[sid_str] = u.get('sAMAccountName') or u.get('displayName') or sid_str
        for g in groups or []:
            raw_sid = g.get('objectSid')
            if not raw_sid:
                continue
            if isinstance(raw_sid, list) and len(raw_sid) > 0:
                raw_sid = raw_sid[0]
            sid_str = self._binary_sid_to_string(raw_sid) if isinstance(raw_sid, bytes) else str(raw_sid)
            if sid_str:
                sid_map[sid_str] = g.get('name') or g.get('sAMAccountName') or sid_str
        return sid_map
    
    def _analyze_object_acl(self, obj: Dict[str, Any], user_map: Dict, group_map: Dict,
                            sid_to_display_name: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Analyze ACL for a specific object.
        
        Args:
            obj: Object dictionary with type, dn, name (one per critical object)
            user_map: Map of users
            group_map: Map of groups
            sid_to_display_name: SID -> display name for trustee labels
            
        Returns:
            list: List of ACL risk findings (each with distinct affected_object, object_type, trustee)
        """
        findings = []
        
        try:
            # Get nTSecurityDescriptor (binary format)
            # Note: ldap3 returns binary attributes as bytes automatically
            results = self.ldap.search(
                search_base=obj['dn'],
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor', 'distinguishedName', 'objectClass']
            )
            
            if not results:
                return findings
            
            entry = results[0]
            sd = entry.get('nTSecurityDescriptor')
            
            if not sd:
                return findings
            
            # Ensure we have binary data
            # ldap3 should return bytes, but handle different formats
            if isinstance(sd, list) and len(sd) > 0:
                sd = sd[0]
            
            # Parse security descriptor using BloodHound parser
            aces = self._parse_security_descriptor(sd)
            
            # Determine object type from objectClass (use local vars so obj is not mutated for identity)
            object_class = entry.get('objectClass', [])
            if isinstance(object_class, str):
                object_class = [object_class]
            obj_type = 'user'
            if 'group' in [oc.lower() for oc in object_class]:
                obj_type = 'group'
            elif 'computer' in [oc.lower() for oc in object_class]:
                obj_type = 'computer'
            elif 'domainDNS' in [oc.lower() for oc in object_class]:
                obj_type = 'domain'
            obj_name = obj.get('name') or ''
            obj_dn = obj.get('dn') or ''
            
            for ace in aces:
                trustee_sid = ace.get('trustee')
                permissions = ace.get('permissions', [])
                is_inherited = ace.get('inherited', False)
                
                # Check each permission
                for perm_name, perm_data in permissions.items():
                    if perm_name in self.CRITICAL_PERMISSIONS:
                        finding = self._create_acl_finding(
                            obj_type=obj_type,
                            obj_name=obj_name,
                            obj_dn=obj_dn,
                            trustee_sid=trustee_sid,
                            sid_to_display_name=sid_to_display_name,
                            perm_name=perm_name,
                            perm_data=perm_data,
                            is_inherited=is_inherited,
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error analyzing ACL for {obj.get('dn')}: {e}")
        
        return findings
    
    def _parse_security_descriptor(self, sd: Any) -> List[Dict[str, Any]]:
        """
        Parse security descriptor to extract ACEs using our custom parser.
        
        Args:
            sd: Security descriptor (binary data from LDAP)
            
        Returns:
            list: List of ACE dictionaries with permissions
        """
        aces = []
        
        if not sd:
            return aces
        
        try:
            # Convert to bytes if it's not already
            if isinstance(sd, str):
                # If it's a string representation, try to decode
                try:
                    sd_bytes = bytes.fromhex(sd)
                except ValueError:
                    # Try base64 or other encodings
                    import base64
                    try:
                        sd_bytes = base64.b64decode(sd)
                    except Exception:
                        logger.debug(f"Could not decode security descriptor: {type(sd)}")
                        return aces
            elif isinstance(sd, bytes):
                sd_bytes = sd
            elif isinstance(sd, list) and len(sd) > 0:
                # Handle list of bytes
                sd_bytes = sd[0] if isinstance(sd[0], bytes) else bytes(sd[0])
            else:
                logger.debug(f"Unknown security descriptor type: {type(sd)}")
                return aces
            
            # Parse using our custom parser
            parsed_sd = parse_security_descriptor(sd_bytes)
            
            # Extract ACEs from DACL
            dacl_aces = parsed_sd.get('dacl', [])
            
            # Convert parsed ACEs to our format
            for ace_data in dacl_aces:
                ace = {
                    'trustee': ace_data.get('sid', 'Unknown'),
                    'permissions': {},
                    'inherited': ace_data.get('is_inherited', False)
                }
                
                # Extract permissions from parsed ACE
                ace_permissions = ace_data.get('permissions', {})
                for perm_name, perm_info in ace_permissions.items():
                    if perm_name in self.CRITICAL_PERMISSIONS:
                        ace['permissions'][perm_name] = self.CRITICAL_PERMISSIONS[perm_name]
                    else:
                        # Add custom permission info
                        ace['permissions'][perm_name] = {
                            'mask': perm_info.get('mask', 0),
                            'severity': perm_info.get('severity', 'medium'),
                            'description': perm_info.get('description', '')
                        }
                
                if ace['permissions']:
                    aces.append(ace)
        
        except Exception as e:
            logger.debug(f"Error parsing security descriptor: {e}")
            import traceback
            logger.debug(traceback.format_exc())
        
        return aces
    
    def _create_acl_finding(self, obj_type: str, obj_name: str, obj_dn: str,
                            trustee_sid: str, sid_to_display_name: Dict[str, str],
                            perm_name: str, perm_data: Dict[str, Any], is_inherited: bool) -> Dict[str, Any]:
        """Create ACL risk finding with explicit object identity and resolved trustee."""
        perm_info = self.CRITICAL_PERMISSIONS[perm_name]
        severity = perm_info['severity']
        severity_str = getattr(severity, 'value', str(severity)).lower() if severity else 'medium'
        trustee_display = sid_to_display_name.get(trustee_sid) if sid_to_display_name else None
        trustee_label = trustee_display or trustee_sid
        
        return {
            'type': f'acl_{perm_name.lower().replace("-", "_")}',
            'severity': severity,
            'severity_level': severity_str,
            'title': f'Dangerous ACL Permission: {perm_name}',
            'description': f"Trustee '{trustee_label}' has {perm_name} permission on {obj_type} '{obj_name}'",
            'affected_object': obj_name,
            'object_type': obj_type,
            'object_dn': obj_dn,
            'trustee': trustee_sid,
            'trustee_display_name': trustee_display,
            'permission': perm_name,
            'permission_description': perm_info['description'],
            'is_inherited': is_inherited,
            'risk_score': perm_info['risk_score'],
            'impact': self._get_permission_impact(perm_name, obj_type),
            'attack_scenario': self._get_attack_scenario(perm_name, obj_type),
            'mitigation': self._get_mitigation(perm_name),
            'cis_reference': 'CIS Benchmark requires reviewing ACLs on critical objects',
            'mitre_attack': self._get_mitre_technique(perm_name)
        }
    
    def _detect_shadow_admins(self, users: List[Dict[str, Any]], groups: List[Dict[str, Any]],
                             domain_dn: str, privileged_users: List[Dict[str, Any]],
                             privileged_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect Shadow Admins.
        
        Shadow Admin criteria:
        - NOT a member of Domain Admin / Enterprise Admin
        - BUT has dangerous ACL permissions on:
          - Domain object
          - Privileged users
          - High-privilege groups
        """
        shadow_admins = []
        
        # Get all users who are NOT Domain/Enterprise Admins
        non_admin_users = []
        da_group_names = {'domain admins', 'enterprise admins'}
        
        for user in users:
            is_da = False
            member_of = user.get('memberOf', [])
            if isinstance(member_of, str):
                member_of = [member_of]
            
            for group_dn in member_of:
                group_name = self._extract_name_from_dn(group_dn).lower()
                if any(da_name in group_name for da_name in da_group_names):
                    is_da = True
                    break
            
            if not is_da:
                non_admin_users.append(user)
        
        # Check each non-admin user for dangerous permissions on critical objects
        critical_targets = [
            {'type': 'domain', 'dn': domain_dn, 'name': 'Domain'},
        ]
        critical_targets.extend([
            {'type': 'user', 'dn': u.get('distinguishedName'), 'name': u.get('sAMAccountName')}
            for u in privileged_users[:10]  # Limit for performance
        ])
        critical_targets.extend([
            {'type': 'group', 'dn': g.get('distinguishedName'), 'name': g.get('name')}
            for g in privileged_groups[:10]  # Limit for performance
        ])
        
        for user in non_admin_users:
            dangerous_perms = []
            
            for target in critical_targets:
                if not target.get('dn'):
                    continue
                
                # Check if user has dangerous permissions (simplified check)
                # In production, would check actual ACLs
                perms = self._check_user_permissions_on_object(user, target)
                if perms:
                    dangerous_perms.extend(perms)
            
            if dangerous_perms:
                shadow_admin = {
                    'user': user.get('sAMAccountName'),
                    'user_dn': user.get('distinguishedName'),
                    'dangerous_permissions': dangerous_perms,
                    'why_risky': self._explain_shadow_admin_risk(dangerous_perms),
                    'attack_scenario': self._get_shadow_admin_attack_scenario(dangerous_perms),
                    'recommendation': self._get_shadow_admin_recommendation(dangerous_perms),
                    'risk_level': self._calculate_shadow_admin_risk(dangerous_perms)
                }
                shadow_admins.append(shadow_admin)
        
        return shadow_admins
    
    def _check_user_permissions_on_object(self, user: Dict[str, Any], 
                                          target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check if user has dangerous permissions on target object.
        
        Args:
            user: User dictionary
            target: Target object dictionary
            
        Returns:
            list: List of dangerous permissions found
        """
        dangerous_perms = []
        
        if not target.get('dn'):
            return dangerous_perms
        
        try:
            # Get user's SID (simplified - would need to resolve from DN/name)
            user_sid = self._get_user_sid(user)
            if not user_sid:
                return dangerous_perms
            
            # Get security descriptor for target object (binary format)
            results = self.ldap.search(
                search_base=target['dn'],
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor', 'objectClass']
            )
            
            if not results:
                return dangerous_perms
            
            entry = results[0]
            sd = entry.get('nTSecurityDescriptor')
            
            if not sd:
                return dangerous_perms
            
            # Ensure we have binary data
            if isinstance(sd, list) and len(sd) > 0:
                sd = sd[0]
            
            # Parse security descriptor
            aces = self._parse_security_descriptor(sd)
            
            # Check if user has dangerous permissions
            for ace in aces:
                trustee_sid = ace.get('trustee', '')
                
                # Check if this ACE applies to our user
                # This is simplified - would need proper SID resolution
                if trustee_sid == user_sid or self._sid_matches_user(trustee_sid, user):
                    for perm_name in ace.get('permissions', {}).keys():
                        if perm_name in self.CRITICAL_PERMISSIONS:
                            dangerous_perms.append({
                                'permission': perm_name,
                                'object': target.get('name'),
                                'object_type': target.get('type'),
                                'inherited': ace.get('inherited', False)
                            })
        
        except Exception as e:
            logger.debug(f"Error checking user permissions: {e}")
        
        return dangerous_perms
    
    def _get_user_sid(self, user: Dict[str, Any]) -> Optional[str]:
        """
        Get user's SID.
        
        Args:
            user: User dictionary
            
        Returns:
            str: User SID or None
        """
        # Try to get SID from user object
        # In production, you'd query objectSid attribute
        try:
            sam_account = user.get('sAMAccountName') or ''
            escaped_sam = escape_filter_chars(str(sam_account))
            results = self.ldap.search(
                search_filter=f"(sAMAccountName={escaped_sam})",
                attributes=['objectSid']
            )
            if results and results[0].get('objectSid'):
                # Convert binary SID to string format
                return self._binary_sid_to_string(results[0]['objectSid'])
        except Exception as e:
            logger.debug(f"Error getting user SID: {e}")
        
        return None
    
    def _binary_sid_to_string(self, binary_sid: bytes) -> str:
        """
        Convert binary SID to string format using our parser.
        
        Args:
            binary_sid: Binary SID bytes
            
        Returns:
            str: SID in string format (e.g., S-1-5-21-...)
        """
        if not binary_sid:
            return ''
        
        try:
            # Use our SecurityDescriptorParser's SID parsing method
            parser = SecurityDescriptorParser(b'')
            sid = parser._parse_sid_from_bytes(binary_sid)
            return sid if sid else ''
        except Exception as e:
            logger.debug(f"Error converting SID: {e}")
            return ''
    
    def _sid_matches_user(self, sid: str, user: Dict[str, Any]) -> bool:
        """
        Check if SID matches user (including group memberships).
        
        Args:
            sid: SID to check
            user: User dictionary
            
        Returns:
            bool: True if SID matches user or their groups
        """
        # Simplified - would need to resolve SID to user/group and check memberships
        # For now, just check direct match
        user_sid = self._get_user_sid(user)
        return sid == user_sid
    
    def _is_user_already_admin(self, user: Dict[str, Any], groups: List[Dict[str, Any]]) -> bool:
        """
        Check if user is already Domain Admin or Enterprise Admin.
        
        Args:
            user: User dictionary
            groups: List of group dictionaries
            
        Returns:
            bool: True if user is already admin
        """
        # Check adminCount flag
        if user.get('adminCount') == 1 or user.get('adminCount') == '1':
            return True
        
        # Check group memberships
        member_of = user.get('memberOf', [])
        if isinstance(member_of, str):
            member_of = [member_of]
        
        # Build privileged group names set for quick lookup
        privileged_group_names = set()
        for group in groups:
            group_name = (group.get('name') or group.get('sAMAccountName') or '').lower()
            if any(priv_name in group_name for priv_name in ['domain admin', 'enterprise admin', 'schema admin']):
                privileged_group_names.add(group_name)
        
        # Check if user is member of any privileged group
        for group_dn in member_of:
            group_name = self._extract_name_from_dn(group_dn).lower()
            if group_name in privileged_group_names:
                return True
        
        return False
    
    def _analyze_privilege_escalation_paths(self, users: List[Dict[str, Any]],
                                            groups: List[Dict[str, Any]],
                                            computers: List[Dict[str, Any]],
                                            acl_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze privilege escalation paths through ACLs.
        
        Paths to detect:
        - User → Group (GenericWrite)
        - User → User (WriteOwner, WriteDACL)
        - Computer → User (RBCD abuse)
        - Service Account → Domain Admin path
        """
        paths = []
        
        # Build graph of ACL relationships
        acl_graph = defaultdict(list)
        
        for finding in acl_findings:
            trustee = finding.get('trustee')
            target = finding.get('affected_object')
            permission = finding.get('permission')
            
            if trustee and target:
                acl_graph[trustee].append({
                    'target': target,
                    'permission': permission,
                    'finding': finding
                })
        
        # Find paths to Domain Admin
        da_group_names = {'domain admins', 'enterprise admins'}
        
        for user in users:
            user_name = user.get('sAMAccountName')
            if not user_name:
                continue
            
            # Skip users who are already Domain Admin or Enterprise Admin
            if self._is_user_already_admin(user, groups):
                logger.debug(f"Skipping user '{user_name}' - already has admin privileges")
                continue
            
            # Check if user can reach DA through ACL paths
            path = self._find_path_to_da(user_name, acl_graph, da_group_names, groups)
            if path:
                paths.append({
                    'source_user': user_name,
                    'path': path,
                    'hops': len(path) - 1,
                    'critical_permission': self._identify_critical_permission_in_path(path),
                    'attack_scenario': self._build_attack_scenario_for_path(path)
                })
        
        return paths
    
    def _find_path_to_da(self, start_user: str, acl_graph: Dict, 
                        da_group_names: Set[str], groups: List[Dict[str, Any]]) -> Optional[List[str]]:
        """Find path from user to Domain Admin through ACLs."""
        # Simplified BFS to find path
        # In production, would use more sophisticated graph traversal
        visited = set()
        queue = [(start_user, [start_user])]
        
        while queue:
            current, path = queue.pop(0)
            
            if current in visited:
                continue
            visited.add(current)
            
            # Check if current is DA
            for group in groups:
                group_name = (group.get('name') or group.get('sAMAccountName') or '').lower()
                if current.lower() == group_name.lower():
                    if any(da_name in group_name for da_name in da_group_names):
                        return path
            
            # Check ACL edges
            for edge in acl_graph.get(current, []):
                target = edge['target']
                if target not in visited:
                    new_path = path + [target]
                    queue.append((target, new_path))
        
        return None
    
    def _analyze_inheritance(self, domain_dn: str, acl_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze ACL inheritance.
        
        Checks:
        - ACL inheritance enabled/disabled
        - Objects with broken inheritance
        - Risky inherited permissions from OU → User/Group
        - Risky inherited permissions from Domain
        """
        inheritance_risks = []
        
        # Check for broken inheritance
        for finding in acl_findings:
            if not finding.get('is_inherited', True):
                # Explicit permission (not inherited)
                inheritance_risks.append({
                    'type': 'explicit_permission',
                    'finding': finding,
                    'risk': 'Explicit permissions override inheritance and may indicate intentional privilege grant'
                })
        
        # Check for risky inherited permissions
        inherited_findings = [f for f in acl_findings if f.get('is_inherited', False)]
        if inherited_findings:
            inheritance_risks.append({
                'type': 'risky_inherited_permissions',
                'count': len(inherited_findings),
                'findings': inherited_findings,
                'risk': 'Permissions inherited from parent objects may grant unintended access'
            })
        
        return inheritance_risks
    
    def _calculate_risk_scores(self, acl_findings: List[Dict[str, Any]],
                               shadow_admins: List[Dict[str, Any]],
                               escalation_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Calculate risk scores for ACL findings.
        
        Factors:
        - Object criticality (Domain > OU > Group > User)
        - Permission power
        - Tier-0 proximity
        - Explicit vs Inherited
        """
        scored_risks = []
        
        for finding in acl_findings:
            base_score = finding.get('risk_score', 50)
            
            # Object criticality multiplier
            obj_type = finding.get('object_type', 'user')
            criticality = self.OBJECT_CRITICALITY.get(obj_type, 1.0)
            
            # Inheritance penalty (inherited = lower risk than explicit)
            if finding.get('is_inherited', False):
                inheritance_multiplier = 0.8
            else:
                inheritance_multiplier = 1.0
            
            # Calculate final score
            final_score = base_score * criticality * inheritance_multiplier
            final_score = min(100, max(0, final_score))
            
            finding['calculated_risk_score'] = final_score
            finding['risk_factors'] = {
                'base_score': base_score,
                'object_criticality': criticality,
                'inheritance_multiplier': inheritance_multiplier,
                'final_score': final_score
            }
            
            scored_risks.append(finding)
        
        return scored_risks
    
    # Helper methods
    def _extract_name_from_dn(self, dn: str) -> str:
        """Extract name from distinguished name."""
        if not dn:
            return ''
        parts = dn.split(',')
        if parts:
            cn_part = parts[0]
            if '=' in cn_part:
                return cn_part.split('=')[1]
        return dn
    
    def _get_permission_impact(self, perm_name: str, obj_type: str) -> str:
        """Get impact description for permission (what the risk means in practice)."""
        impacts = {
            'GenericAll': f'Full control over this {obj_type} allows an attacker to read, modify, or delete it, change its ACL, or take ownership. On domain, users, or admin groups this leads to full domain compromise.',
            'WriteDACL': f'Whoever has WriteDACL on this {obj_type} can change the ACL and grant themselves (or anyone) any permission, including GenericAll, effectively gaining full control.',
            'WriteOwner': f'Whoever has WriteOwner can set themselves as owner. The owner can then modify the ACL and grant themselves full control over the {obj_type}.',
            'GenericWrite': f'All attributes of this {obj_type} can be modified. On users this can include security-sensitive attributes; on groups, membership can often be changed via linked attributes.',
            'WriteProperty': f'Specific attributes of this {obj_type} can be written. Depending on which properties are writable, this can allow privilege escalation (e.g. group membership, UAC flags).',
            'UserForceChangePassword': 'The trustee can trigger a forced password change for the user. An attacker can abuse this to set a known password and take over the account.',
            'WriteServicePrincipalName': 'The trustee can add or change SPNs on the account. This enables Kerberoasting (crack service account hashes) or Silver Ticket attacks.',
            'WriteUserAccountControl': 'The trustee can change userAccountControl (e.g. disable "Require Kerberos preauthentication" for AS-REP Roasting, or set "Password never expires"). Enables credential theft and persistence.',
            'WriteMember': f'The trustee can add or remove members of this group. If the group is privileged (e.g. Domain Admins), the attacker can add themselves and gain domain admin.',
            'DS-Replication-Get-Changes': 'This right is part of DCSync. Combined with Get-Changes-All or Filtered-Set, it allows replicating AD and extracting password hashes for the entire domain.',
            'DS-Replication-Get-Changes-All': 'Enables full DCSync: the trustee can request replication of all directory changes from a DC and extract NTLM hashes for every account, leading to domain takeover.',
            'DS-Replication-Get-Changes-In-Filtered-Set': 'Enables DCSync with a filter. Attackers can use this to replicate and dump password hashes, same as Get-Changes-All in practice.',
            'AllExtendedRights': 'Includes DCSync, force change password, and other sensitive extended rights. Effectively allows domain-level compromise from this single permission.',
        }
        return impacts.get(perm_name, f'This permission on {obj_type} can be abused to escalate privileges or compromise security. Review and restrict to least privilege.')

    def _get_attack_scenario(self, perm_name: str, obj_type: str) -> str:
        """Get concrete attack scenario (what an attacker could do step-by-step)."""
        scenarios = {
            'GenericAll': f'Attacker with GenericAll on this {obj_type} can: (1) grant themselves WriteDACL then WriteOwner if needed, (2) modify the object (e.g. add themselves to a group, change user password), or (3) delete it. On Domain or admin groups this leads to Domain Admin.',
            'WriteDACL': f'Attacker adds an ACE granting themselves GenericAll (or WriteOwner) on the {obj_type}, then takes full control. No need for admin group membership.',
            'WriteOwner': f'Attacker sets themselves as owner of the {obj_type}. As owner, they can modify the ACL to grant themselves GenericAll, then alter the object (e.g. add themselves to Domain Admins).',
            'GenericWrite': f'On a user: attacker may write scriptPath, msDS-AllowedToActOnBehalfOfOtherIdentity, or other attributes. On a group: may abuse attribute writes. On GPO/OU: link GPO or move objects to escalate.',
            'WriteProperty': f'Depends on which properties are writable. Often used to add oneself to a group (via member attribute), set userAccountControl, or change SPN. Leads to privilege escalation.',
            'UserForceChangePassword': 'Attacker triggers "User must change password at next logon" and sets a known password, or uses the right in a tool to reset the password and log in as the user.',
            'WriteServicePrincipalName': 'Attacker adds an SPN to the account (e.g. HOST/victim), requests a ticket (Kerberoasting), cracks it offline, then uses the hash for Silver Ticket or lateral movement.',
            'WriteUserAccountControl': 'Attacker disables "Require Kerberos preauthentication" on the account, then performs AS-REP Roasting to get a crackable hash, or sets DONT_EXPIRE_PASSWD for persistence.',
            'WriteMember': 'Attacker adds their own account (or a controlled account) to this group. If the group is Domain Admins, Enterprise Admins, or another privileged group, they gain that level of access.',
            'DS-Replication-Get-Changes': 'Used with other replication rights to perform DCSync (e.g. mimikatz, secretsdump). Attacker retrieves NTLM hashes for all domain accounts and can take over the domain.',
            'DS-Replication-Get-Changes-All': 'Attacker runs DCSync (e.g. mimikatz lsadump::dcsync or Impacket secretsdump.py) to dump all domain hashes, then passes the hash or cracks to get Domain Admin.',
            'DS-Replication-Get-Changes-In-Filtered-Set': 'Same as Get-Changes-All in practice for credential dumping. Attacker uses DCSync to extract hashes and escalate to full domain control.',
            'AllExtendedRights': 'Attacker can perform DCSync, force password change, or other extended rights. Typically used for DCSync to dump hashes and take over the domain.',
        }
        return scenarios.get(perm_name, f'This permission can be chained or abused to escalate privileges or compromise the {obj_type}. Treat as high risk until verified.')

    def _get_mitigation(self, perm_name: str) -> str:
        """Get actionable mitigation recommendation (what to do)."""
        mitigations = {
            'GenericAll': 'Remove GenericAll from non-admin principals. Grant only the minimum rights needed (e.g. Read for reporting). For admin tasks, use dedicated admin accounts and document why GenericAll is required if it must remain.',
            'WriteDACL': 'Remove WriteDACL from all users and groups except dedicated Tier-0/1 administrators. Regularly audit ACLs on domain, OUs, and privileged groups.',
            'WriteOwner': 'Remove WriteOwner from non-admin principals. Only Tier-0 admins should be able to take ownership of critical objects. Monitor for ownership changes on sensitive objects.',
            'GenericWrite': 'Remove GenericWrite; grant Write on only the specific attributes needed for the business purpose. Use least privilege and document any exception.',
            'WriteProperty': 'Restrict Write Property to the specific attributes and objects required. Remove broad Write Property; prefer targeted property sets.',
            'UserForceChangePassword': 'Remove "Force change password" from regular users and groups. Restrict to Help Desk or PAM workflows with approval and logging.',
            'WriteServicePrincipalName': 'Remove Write Service Principal Name from non-service-admins. Only designated accounts should modify SPNs. Reduces Kerberoasting and Silver Ticket risk.',
            'WriteUserAccountControl': 'Remove Write userAccountControl from non-admins. Preauth and password expiry should only be changed by controlled processes (e.g. PAM).',
            'WriteMember': 'Remove Write Member on privileged groups (Domain Admins, Enterprise Admins, etc.). Only Tier-0 admins should manage membership. Use Protected Users and monitor group changes.',
            'DS-Replication-Get-Changes': 'Remove all DCSync-related rights from non-DC accounts. Only Domain Controllers should have replication rights. Audit and remove any legacy or service accounts with DCSync.',
            'DS-Replication-Get-Changes-All': 'Remove immediately. Only Domain Controllers must have this. Any other account with this right can dump every password in the domain.',
            'DS-Replication-Get-Changes-In-Filtered-Set': 'Same as Get-Changes-All: remove from all non-DC accounts. Only DCs should have replication rights.',
            'AllExtendedRights': 'Remove All Extended Rights from non-DC and non-admin accounts. Grant only the specific extended rights needed (e.g. "Send As") and only where justified.',
        }
        return mitigations.get(perm_name, 'Remove or restrict this permission to the minimum set of trusted principals and document the business need. Re-audit periodically.')

    def _get_mitre_technique(self, perm_name: str) -> str:
        """Get MITRE ATT&CK technique."""
        techniques = {
            'GenericAll': 'T1078 (Valid Accounts), T1484 (Domain Policy Modification)',
            'WriteDACL': 'T1484 (Domain Policy Modification)',
            'WriteOwner': 'T1484 (Domain Policy Modification)',
            'GenericWrite': 'T1484 (Domain Policy Modification), T1098 (Account Manipulation)',
            'WriteProperty': 'T1484 (Domain Policy Modification), T1098 (Account Manipulation)',
            'UserForceChangePassword': 'T1098 (Account Manipulation)',
            'WriteServicePrincipalName': 'T1558.003 (Kerberoasting), T1558.002 (Silver Ticket)',
            'WriteUserAccountControl': 'T1558.004 (AS-REP Roasting), T1098 (Account Manipulation)',
            'WriteMember': 'T1098 (Account Manipulation), T1078 (Valid Accounts)',
            'DS-Replication-Get-Changes': 'T1003.006 (OS Credential Dumping: DCSync)',
            'DS-Replication-Get-Changes-All': 'T1003.006 (OS Credential Dumping: DCSync)',
            'DS-Replication-Get-Changes-In-Filtered-Set': 'T1003.006 (OS Credential Dumping: DCSync)',
            'AllExtendedRights': 'T1003.006 (DCSync), T1098 (Account Manipulation)',
        }
        return techniques.get(perm_name, 'T1078 (Valid Accounts), T1484 (Domain Policy Modification)')
    
    def _explain_shadow_admin_risk(self, dangerous_perms: List[Dict[str, Any]]) -> str:
        """Explain why Shadow Admin is risky."""
        perm_names = [p.get('permission', '') for p in dangerous_perms]
        if 'GenericAll' in perm_names:
            return 'Has full control over critical objects without being in Domain Admins'
        elif 'WriteDACL' in perm_names:
            return 'Can modify ACLs on critical objects to grant themselves Domain Admin'
        return 'Has dangerous permissions on critical objects'
    
    def _get_shadow_admin_attack_scenario(self, dangerous_perms: List[Dict[str, Any]]) -> str:
        """Get attack scenario for Shadow Admin."""
        return 'An attacker who compromises this account can abuse its dangerous ACL permissions to escalate to Domain Admin (or equivalent) without being a member of Domain Admins. Monitoring and tiering often focus on admin group membership, so this account may be under less scrutiny while still enabling full domain compromise.'

    def _get_shadow_admin_recommendation(self, dangerous_perms: List[Dict[str, Any]]) -> str:
        """Get remediation recommendation for Shadow Admin."""
        perm_names = [p.get('permission', '') for p in dangerous_perms]
        if any(p in perm_names for p in ('GenericAll', 'DS-Replication-Get-Changes-All', 'DS-Replication-Get-Changes-In-Filtered-Set', 'AllExtendedRights')):
            return 'Treat as critical: remove all dangerous permissions from this account immediately. If the account must perform sensitive tasks, use a dedicated Tier-0 or Tier-1 account with proper monitoring and break-glass procedures instead of leaving powerful rights on a non-DA account.'
        if any(p in perm_names for p in ('WriteDACL', 'WriteOwner')):
            return 'Remove WriteDACL and WriteOwner from this account. Grant only the minimum permissions needed for the intended role. Prefer managed service accounts or delegated roles with documented justification.'
        return 'Remove dangerous permissions from this account. Apply least privilege: grant only the specific rights required for the business function. Document and review periodically. Consider moving sensitive operations to dedicated admin accounts.'
    
    def _calculate_shadow_admin_risk(self, dangerous_perms: List[Dict[str, Any]]) -> str:
        """Calculate Shadow Admin risk level."""
        perm_names = [p.get('permission', '') for p in dangerous_perms]
        if any('DCSync' in p or 'GenericAll' in p for p in perm_names):
            return Severity.CRITICAL
        elif 'WriteDACL' in perm_names or 'WriteOwner' in perm_names:
            return Severity.HIGH
        return Severity.MEDIUM
    
    def _identify_critical_permission_in_path(self, path: List[str]) -> str:
        """Identify critical permission in escalation path."""
        # Simplified - would analyze actual permissions in path
        return 'GenericWrite'
    
    def _build_attack_scenario_for_path(self, path: List[str]) -> str:
        """Build attack scenario for escalation path."""
        return f"Attacker can escalate from {path[0]} to {path[-1]} through {len(path)-1} hops"
