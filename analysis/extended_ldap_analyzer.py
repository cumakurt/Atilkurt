"""
Extended LDAP Security Analyzer Module
Performs additional LDAP-based security checks:
- RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
- sIDHistory
- Foreign Security Principals
- Fine-grained Password Policies (PSO)
- BitLocker recovery in AD
- AdminSDHolder
- OU structure and GPO links
- Empty/deeply nested groups
- Computer account expiration
- OU delegation
- AD Recycle Bin
- Printer objects
- Exchange objects
- DNS zones
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)

# Well-known SIDs (not groups - built-in security principals)
WELL_KNOWN_SIDS = {
    'S-1-5-4': 'Interactive',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-17': 'IIS/IUSR (or This Organization in AD)',
    'S-1-5-7': 'Anonymous',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority (Local Service)',
    'S-1-5-20': 'NT Authority (Network Service)',
    'S-1-5-21': 'NT Authority (Authenticated Users)',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
}


class ExtendedLDAPAnalyzer:
    """Performs extended LDAP-based security analysis."""

    def __init__(self, ldap_connection):
        self.ldap = ldap_connection
        self.base_dn = ldap_connection.base_dn

    def analyze_all(self, users: List[Dict], computers: List[Dict],
                    groups: List[Dict], gpos: List[Dict]) -> List[Dict[str, Any]]:
        """Run all extended LDAP analyses and return combined risks."""
        risks = []

        try:
            risks.extend(self._analyze_rbcd(users, computers))
            risks.extend(self._analyze_key_credential_link(users, computers))
            risks.extend(self._analyze_sid_history(users, computers))
            risks.extend(self._analyze_foreign_security_principals())
            risks.extend(self._analyze_fine_grained_password_policy())
            risks.extend(self._analyze_bitlocker_recovery())
            risks.extend(self._analyze_adminsdholder())
            risks.extend(self._analyze_ou_structure(gpos))
            risks.extend(self._analyze_empty_nested_groups(groups))
            risks.extend(self._analyze_computer_expiration(computers))
            risks.extend(self._analyze_printer_objects())
            risks.extend(self._analyze_exchange_objects())
            risks.extend(self._analyze_dns_zones())
            risks.extend(self._analyze_recycle_bin())
        except Exception as e:
            logger.error(f"Extended LDAP analysis error: {e}")

        return risks

    def _analyze_rbcd(self, users: List[Dict], computers: List[Dict]) -> List[Dict]:
        """Resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)."""
        risks = []
        try:
            # Search for objects with RBCD configured
            results = self.ldap.search(
                search_filter='(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
                search_base=self.base_dn,
                attributes=['sAMAccountName', 'distinguishedName', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'objectClass']
            )
            for obj in results:
                name = obj.get('sAMAccountName') or obj.get('name') or obj.get('cn', 'Unknown')
                risks.append({
                    'type': RiskTypes.RBCD_DELEGATION,
                    'severity': Severity.HIGH,
                    'title': f'RBCD Configured: {name}',
                    'description': f'Object {name} has msDS-AllowedToActOnBehalfOfOtherIdentity set - allows another account to act on its behalf.',
                    'affected_object': name,
                    'object_type': 'user' if ('user' in str(obj.get('objectClass', [])).lower() and 'computer' not in str(obj.get('objectClass', [])).lower()) else 'computer',
                    'impact': 'RBCD can be abused for privilege escalation. An attacker with Write privileges can add themselves.',
                    'attack_scenario': 'Add SELF to msDS-AllowedToActOnBehalfOfOtherIdentity and impersonate the account.',
                    'mitigation': 'Review RBCD configurations. Restrict who can modify this attribute.',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
                })
        except Exception as e:
            logger.debug(f"RBCD analysis: {e}")
        return risks

    def _analyze_key_credential_link(self, users: List[Dict], computers: List[Dict]) -> List[Dict]:
        """Objects with msDS-KeyCredentialLink (passwordless auth / potential shadow creds)."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(msDS-KeyCredentialLink=*)',
                search_base=self.base_dn,
                attributes=['sAMAccountName', 'msDS-KeyCredentialLink', 'objectClass'],
                size_limit=100
            )
            for obj in results:
                name = obj.get('sAMAccountName') or obj.get('name', 'Unknown')
                obj_classes = str(obj.get('objectClass', [])).lower()
                obj_type = 'user' if 'user' in obj_classes and 'computer' not in obj_classes else 'computer'
                risks.append({
                    'type': RiskTypes.KEY_CREDENTIAL_LINK_PRESENT,
                    'severity': Severity.HIGH,
                    'title': f'Key Credential Link: {name}',
                    'description': f'{name} has msDS-KeyCredentialLink set. May be legitimate (Windows Hello, FIDO2) or Shadow Credentials attack.',
                    'affected_object': name,
                    'object_type': obj_type,
                    'impact': 'Allows certificate-based auth. If attacker-added, enables persistence.',
                    'attack_scenario': 'Whisker/Shadow Credentials - add key credential to gain access.',
                    'mitigation': 'Audit who can write msDS-KeyCredentialLink. Review unexpected entries.',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
                })
        except Exception as e:
            logger.debug(f"KeyCredentialLink analysis: {e}")
        return risks

    def _analyze_sid_history(self, users: List[Dict], computers: List[Dict]) -> List[Dict]:
        """Users/computers with sIDHistory - potential privilege escalation."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(sIDHistory=*)',
                search_base=self.base_dn,
                attributes=['sAMAccountName', 'sIDHistory', 'objectClass', 'distinguishedName']
            )
            for obj in results:
                name = obj.get('sAMAccountName') or obj.get('name') or 'Unknown'
                obj_class = str(obj.get('objectClass', [])).lower()
                obj_type = 'user' if 'user' in obj_class and 'computer' not in obj_class else 'computer'
                risks.append({
                    'type': RiskTypes.SID_HISTORY_PRESENT,
                    'severity': Severity.HIGH,
                    'title': f'sIDHistory Present: {name}',
                    'description': f'{name} has sIDHistory attribute set. May indicate domain migration or privilege escalation vector.',
                    'affected_object': name,
                    'object_type': obj_type,
                    'impact': 'sIDHistory can grant extra privileges. If original domain SID had admin rights, this account may have equivalent rights.',
                    'attack_scenario': 'Golden Ticket with sIDHistory or abuse during migration.',
                    'mitigation': 'Review sIDHistory after domain migrations. Remove unnecessary SIDHistory entries.',
                    'mitre_attack': MITRETechniques.EXPLOITATION_PRIVILEGE_ESCALATION,
                })
        except Exception as e:
            logger.debug(f"sIDHistory analysis: {e}")
        return risks

    def _analyze_foreign_security_principals(self) -> List[Dict]:
        """Cross-domain group memberships (foreignSecurityPrincipal)."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(objectClass=foreignSecurityPrincipal)',
                search_base=self.base_dn,
                attributes=['name', 'objectSid', 'distinguishedName']
            )
            if results:
                def _sid_display(sid_or_name: str) -> str:
                    s = (sid_or_name or '').strip()
                    friendly = WELL_KNOWN_SIDS.get(s)
                    return f'{s} ({friendly})' if friendly else s
                fsp_raw = [r.get('name') or r.get('distinguishedName', 'Unknown')[:50] for r in results[:20]]
                fsp_list = [_sid_display(x) for x in fsp_raw]
                risks.append({
                    'type': RiskTypes.FOREIGN_SECURITY_PRINCIPAL,
                    'severity': Severity.MEDIUM,
                    'title': f'Foreign Security Principals: {len(results)} found',
                    'description': f'{len(results)} cross-domain object references (foreignSecurityPrincipal). These are SIDs, not groups; they represent well-known principals or references from trusted domains.',
                    'affected_object': ', '.join(fsp_raw[:5]) + (f' (+{len(results)-5})' if len(results) > 5 else ''),
                    'object_type': 'foreign_security_principal',
                    'impact': 'Trust abuse - members from trusted domains may have unexpected privileges.',
                    'attack_scenario': 'Compromise trusted domain, abuse cross-domain group membership.',
                    'mitigation': 'Audit groups with foreign members. Restrict trust scope.',
                    'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN,
                    'affected_objects': fsp_list,
                })
        except Exception as e:
            logger.debug(f"Foreign Security Principal analysis: {e}")
        return risks

    def _analyze_fine_grained_password_policy(self) -> List[Dict]:
        """Fine-grained password policies (PSO)."""
        risks = []
        try:
            config_dn = f"CN=Configuration,{self.base_dn}"
            results = self.ldap.search(
                search_filter='(objectClass=msDS-PasswordSettings)',
                search_base=f"CN=Password Settings Container,CN=System,{self.base_dn}",
                attributes=['name', 'msDS-PSOAppliesTo', 'msDS-MinimumPasswordLength']
            )
            if results:
                for pso in results:
                    name = pso.get('name', 'Unknown')
                    applies = pso.get('msDS-PSOAppliesTo') or []
                    if isinstance(applies, str):
                        applies = [applies]
                    risks.append({
                        'type': RiskTypes.FINE_GRAINED_PASSWORD_POLICY,
                        'severity': Severity.LOW,
                        'title': f'PSO: {name}',
                        'description': f'Fine-grained password policy {name} applies to {len(applies)} object(s).',
                        'affected_object': name,
                        'object_type': 'policy',
                        'impact': 'PSOs override default policy. Ensure policies are not weaker than domain default.',
                        'mitigation': 'Audit PSO strength. Apply to appropriate groups only.',
                        'affected_objects': applies[:10],
                    })
        except Exception as e:
            logger.debug(f"PSO analysis: {e}")
        return risks

    def _analyze_bitlocker_recovery(self) -> List[Dict]:
        """BitLocker recovery information stored in AD."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(objectClass=msFVE-RecoveryInformation)',
                search_base=self.base_dn,
                attributes=['name', 'distinguishedName', 'msFVE-RecoveryPassword'],
                size_limit=100
            )
            if results:
                count = len(results)
                risks.append({
                    'type': RiskTypes.BITLOCKER_RECOVERY_IN_AD,
                    'severity': Severity.MEDIUM,
                    'title': f'BitLocker Recovery in AD: {count} objects',
                    'description': f'{count} BitLocker recovery information objects stored in AD. Recovery keys can be extracted with appropriate permissions.',
                    'affected_object': f'{count} computers',
                    'object_type': 'computer',
                    'impact': 'Recovery keys in AD allow decryption of drives if attacker gains read access.',
                    'mitigation': 'Restrict who can read msFVE-RecoveryInformation. Consider TPM-only or escrow.',
                })
        except Exception as e:
            logger.debug(f"BitLocker analysis: {e}")
        return risks

    def _analyze_adminsdholder(self) -> List[Dict]:
        """AdminSDHolder and protected groups."""
        risks = []
        try:
            # Check if AdminSDHolder exists (single-object read; filter must use & for multiple conditions)
            results = self.ldap.search(
                search_filter='(objectClass=*)',
                search_base=f"CN=AdminSDHolder,CN=System,{self.base_dn}",
                attributes=['distinguishedName'],
                size_limit=1
            )
            if results:
                risks.append({
                    'type': RiskTypes.ADMINSDHOLDER_ANALYSIS,
                    'severity': Severity.LOW,
                    'title': 'AdminSDHolder Present',
                    'description': 'AdminSDHolder object protects privileged accounts. SDProp runs periodically to reset ACLs on protected groups.',
                    'affected_object': 'CN=AdminSDHolder,CN=System',
                    'object_type': 'configuration',
                    'impact': 'Modifying AdminSDHolder ACLs affects all protected accounts. Understand SDProp behavior.',
                    'mitigation': 'Audit AdminSDHolder permissions. Do not weaken ACLs.',
                })
        except Exception as e:
            logger.debug(f"AdminSDHolder analysis: {e}")
        return risks

    def _analyze_ou_structure(self, gpos: List[Dict]) -> List[Dict]:
        """OU structure, GPO links, blocked inheritance."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(objectClass=organizationalUnit)',
                search_base=self.base_dn,
                attributes=['ou', 'gPLink', 'gPOptions', 'distinguishedName']
            )
            for ou in results:
                ou_name = ou.get('ou') or ou.get('name', 'Unknown')
                gpo_options = ou.get('gPOptions')
                # gPOptions=1 means block inheritance
                if gpo_options and str(gpo_options) == '1':
                    risks.append({
                        'type': RiskTypes.OU_GPO_INHERITANCE_BLOCKED,
                        'severity': Severity.MEDIUM,
                        'title': f'GPO Inheritance Blocked: {ou_name}',
                        'description': f'OU {ou_name} has GPO inheritance blocked (gPOptions=1). Child OUs may not receive domain-level policies.',
                        'affected_object': ou_name,
                        'object_type': 'configuration',
                        'impact': 'Security policies may not apply to objects in this OU hierarchy.',
                        'mitigation': 'Document why inheritance is blocked. Ensure required policies are linked directly.',
                    })
        except Exception as e:
            logger.debug(f"OU structure analysis: {e}")
        return risks

    def _analyze_empty_nested_groups(self, groups: List[Dict]) -> List[Dict]:
        """Empty groups and deeply nested groups."""
        risks = []

        # Empty groups
        empty = [g for g in groups if not g.get('member') and not g.get('members')]
        if len(empty) > 10:
            risks.append({
                'type': RiskTypes.EMPTY_GROUP,
                'severity': Severity.LOW,
                'title': f'Empty Groups: {len(empty)} found',
                'description': f'{len(empty)} groups have no members. Consider cleanup.',
                'affected_object': f'{len(empty)} groups',
                'object_type': 'group',
                'impact': 'Clutter, potential for misuse if populated later without review.',
                'mitigation': 'Remove unused empty groups.',
                'affected_objects': [g.get('name') or g.get('sAMAccountName') for g in empty],
            })

        # Deeply nested - simplified check
        for g in groups:
            members = g.get('member') or g.get('members') or []
            if not isinstance(members, list):
                members = [members] if members else []
            member_of = g.get('memberOf') or []
            if not isinstance(member_of, list):
                member_of = [member_of] if member_of else []
            total_refs = len(members) + len(member_of)
            if total_refs > 50:
                risks.append({
                    'type': RiskTypes.DEEPLY_NESTED_GROUP,
                    'severity': Severity.LOW,
                    'title': f'Large Group: {g.get("name", "Unknown")}',
                    'description': f'Group has {len(members)} members and {len(member_of)} parent groups. Complex nesting.',
                    'affected_object': g.get('name') or g.get('sAMAccountName'),
                    'object_type': 'group',
                    'impact': 'Complex group nesting makes auditing difficult.',
                    'mitigation': 'Simplify group structure where possible.',
                })
        return risks

    def _analyze_computer_expiration(self, computers: List[Dict]) -> List[Dict]:
        """Computer accounts with expiration set (or expired)."""
        risks = []
        # accountExpires: 9223372036854775807 = never; 0 = different meaning
        for comp in computers:
            expires = comp.get('accountExpires')
            if expires is None:
                continue
            try:
                exp_val = int(expires)
                if exp_val > 0 and exp_val < 9223372036854775807:
                    # Has expiration - could be expired
                    name = comp.get('name', 'Unknown')
                    risks.append({
                        'type': RiskTypes.COMPUTER_ACCOUNT_EXPIRED,
                        'severity': Severity.MEDIUM,
                        'title': f'Computer Account Expiration: {name}',
                        'description': f'Computer {name} has accountExpires set. May be expired or scheduled for removal.',
                        'affected_object': name,
                        'object_type': 'computer',
                        'impact': 'Expired computer accounts cannot authenticate. May indicate decommissioned systems.',
                        'mitigation': 'Review and either extend or remove expired accounts.',
                    })
            except (ValueError, TypeError):
                pass
        return risks

    def _analyze_printer_objects(self) -> List[Dict]:
        """Printer objects - PrintNightmare / printer abuse."""
        risks = []
        try:
            results = self.ldap.search(
                search_filter='(objectClass=printQueue)',
                search_base=self.base_dn,
                attributes=['name', 'distinguishedName'],
                size_limit=50
            )
            if results:
                printer_names = [r.get('name', 'Unknown') for r in results[:10]]
                risks.append({
                    'type': RiskTypes.PRINTER_OBJECT_RISK,
                    'severity': Severity.MEDIUM,
                    'title': f'Printer Objects: {len(results)} found',
                    'description': f'{len(results)} printQueue objects in AD. Printers can be abused for coercion (PetitPotam, PrintNightmare).',
                    'affected_object': ', '.join(printer_names),
                    'object_type': 'computer',
                    'impact': 'Unpatched print spoolers enable NTLM relay and RCE.',
                    'attack_scenario': 'PetitPotam/PrintNightmare coercion to relay NTLM.',
                    'mitigation': 'Patch print spooler. Disable on non-print servers. Restrict NTLM.',
                    'mitre_attack': MITRETechniques.LATERAL_MOVEMENT,
                    'affected_objects': printer_names,
                })
        except Exception as e:
            logger.debug(f"Printer analysis: {e}")
        return risks

    def _analyze_exchange_objects(self) -> List[Dict]:
        """Exchange-related objects in AD. Uses (objectClass=*) to avoid 'invalid class' when Exchange schema is not installed."""
        risks = []
        results = []
        try:
            config_dn = f"CN=Configuration,{self.base_dn}"
            exchange_base = f"CN=Microsoft Exchange,CN=Services,{config_dn}"
            try:
                results = self.ldap.search(
                    search_filter='(objectClass=*)',
                    search_base=exchange_base,
                    attributes=['name', 'distinguishedName'],
                    size_limit=20
                )
            except Exception:
                results = []
            if not results:
                return risks
            try:
                risks.append({
                    'type': RiskTypes.EXCHANGE_OBJECTS_FOUND,
                    'severity': Severity.LOW,
                    'title': f'Exchange Servers: {len(results)} found',
                    'description': f'Exchange environment detected. {len(results)} Exchange server(s) in Configuration partition.',
                    'affected_object': f'{len(results)} servers',
                    'object_type': 'configuration',
                    'impact': 'Exchange adds attack surface (ProxyShell, etc.). Ensure patches applied.',
                    'mitigation': 'Keep Exchange patched. Monitor for CVE-2021-26855, etc.',
                })
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Exchange analysis: {e}")
        return risks

    def _analyze_dns_zones(self) -> List[Dict]:
        """AD-integrated DNS zones."""
        risks = []
        try:
            # DNS zones can be in Microsoft DNS container
            dns_base = f"CN=Microsoft DNS,CN=System,{self.base_dn}"
            results = self.ldap.search(
                search_filter='(objectClass=dnsZone)',
                search_base=dns_base,
                attributes=['name', 'dc'],
                size_limit=20
            )
            if results:
                zone_names = [r.get('dc') or r.get('name', 'Unknown') for r in results[:5]]
                risks.append({
                    'type': RiskTypes.DNS_ZONE_FOUND,
                    'severity': Severity.LOW,
                    'title': f'AD-Integrated DNS: {len(results)} zones',
                    'description': f'AD-integrated DNS detected. {len(results)} zone(s). Zone data stored in AD.',
                    'affected_object': ', '.join(zone_names),
                    'object_type': 'configuration',
                    'impact': 'DNS admins can modify zones. DnsAdmins→DC takeover if not careful.',
                    'mitigation': 'Restrict DnsAdmins membership. Monitor zone changes.',
                })
        except Exception as e:
            logger.debug(f"DNS zone analysis: {e}")
        return risks

    def _analyze_recycle_bin(self) -> List[Dict]:
        """AD Recycle Bin - deleted objects."""
        risks = []
        try:
            # Try LDAP_SERVER_SHOW_DELETED_OID - may not be supported
            results = self.ldap.search(
                search_filter='(isDeleted=TRUE)',
                search_base=self.base_dn,
                attributes=['name', 'distinguishedName', 'isDeleted'],
                size_limit=50
            )
            if results:
                risks.append({
                    'type': RiskTypes.AD_RECYCLE_BIN_DELETED_OBJECTS,
                    'severity': Severity.MEDIUM,
                    'title': f'Recycle Bin: {len(results)} deleted objects',
                    'description': f'{len(results)} deleted objects in AD Recycle Bin. Objects can be recovered or used for persistence.',
                    'affected_object': f'{len(results)} objects',
                    'object_type': 'configuration',
                    'impact': 'Deleted objects with SIDHistory can be restored. Attackers may target recently deleted admins.',
                    'mitigation': 'Audit recycle bin. Limit who can recover deleted objects.',
                })
        except Exception as e:
            # Recycle bin may not be enabled or OID not supported
            logger.debug(f"Recycle bin analysis: {e}")
        return risks
