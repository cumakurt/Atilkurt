"""
DCSync Rights Analyzer Module
Detects accounts with DCSync rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All)
"""

import logging
from typing import Any, Optional
from ldap3.utils.conv import escape_filter_chars
from core.constants import RiskTypes, Severity, MITRETechniques
from core.security_descriptor_parser import SecurityDescriptorParser, parse_security_descriptor

logger = logging.getLogger(__name__)


class DCSyncAnalyzer:
    """Analyzes DCSync rights and identifies accounts vulnerable to DCSync attacks."""

    # DCSync rights OIDs
    DS_REPLICATION_GET_CHANGES = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    DS_REPLICATION_GET_CHANGES_ALL = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    def __init__(self, ldap_connection):
        """
        Initialize DCSync analyzer.

        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection

    def analyze_dcsync_rights(self, users: list[dict[str, Any]],
                            groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Analyze DCSync rights for users and groups.

        Args:
            users: List of user dictionaries
            groups: List of group dictionaries

        Returns:
            List of risk dictionaries for DCSync rights
        """
        risks = []

        try:
            # Get domain root DN
            base_dn = self.ldap.base_dn

            processed_accounts = set()
            for account_info in self._get_explicit_dcsync_accounts(base_dn, users, groups):
                account_key = f"{account_info['account_name']}_{account_info['account_type']}_{account_info.get('target_object', base_dn)}"
                if account_key in processed_accounts:
                    continue
                processed_accounts.add(account_key)

                risks.append(self._create_dcsync_risk(account_info))

            # Also check well-known privileged groups that typically have DCSync
            # Use a set to avoid duplicate risks
            processed_users = set()
            privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Administrators']
            for group in groups:
                group_name = group.get('name') or group.get('sAMAccountName')
                if group_name and any(priv in group_name for priv in privileged_groups):
                    # Check members of these groups
                    members = group.get('member', []) or []
                    if not isinstance(members, list):
                        members = [members] if members else []

                    for member_dn in members:
                        member_name = self._extract_name_from_dn(member_dn)
                        if member_name and member_name not in processed_users:
                            # Check if this user is in the list
                            for user in users:
                                username = user.get('sAMAccountName')
                                if username == member_name:
                                    processed_users.add(username)
                                    risks.append({
                                        'type': RiskTypes.DCSYNC_RIGHTS,
                                        'severity': Severity.CRITICAL,
                                        'title': f'DCSync via Privileged Group: {username}',
                                        'description': (
                                            f"User '{username}' is member of '{group_name}' which has "
                                            "implicit DCSync rights through Domain Admin privileges."
                                        ),
                                        'affected_object': username,
                                        'object_type': 'user',
                                        'privileged_group': group_name,
                                        'impact': (
                                            'Members of Domain Admins, Enterprise Admins, or Administrators '
                                            'have implicit DCSync rights and can extract all password hashes.'
                                        ),
                                        'attack_scenario': (
                                            f"An attacker who compromises '{username}' can use DCSync "
                                            "to extract all domain password hashes."
                                        ),
                                        'mitigation': (
                                            'Apply principle of least privilege. Remove unnecessary members '
                                            'from privileged groups. Use privileged access management.'
                                        ),
                                        'cis_reference': 'CIS Benchmark requires minimal membership in privileged groups',
                                        'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_DCSYNC,
                                        'exploitation_tools': [
                                            'Mimikatz lsadump::dcsync',
                                            'Impacket secretsdump'
                                        ]
                                    })
                                    break

            logger.info(f"Found {len(risks)} DCSync rights risks")
            return risks

        except Exception as e:
            logger.error(f"Error analyzing DCSync rights: {str(e)}")
            return []

    def _get_explicit_dcsync_accounts(
        self,
        target_dn: str,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Parse the domain ACL and return principals with explicit DCSync rights."""
        accounts_with_rights = []
        sid_map = self._build_sid_map(users, groups)

        try:
            results = self.ldap.search(
                search_base=target_dn,
                search_filter=f'(distinguishedName={escape_filter_chars(target_dn)})',
                attributes=['distinguishedName', 'nTSecurityDescriptor'],
                size_limit=1,
            )
            if not results:
                return accounts_with_rights

            sd = results[0].get('nTSecurityDescriptor')
            if isinstance(sd, list) and sd:
                sd = sd[0]
            if isinstance(sd, str):
                try:
                    sd = bytes.fromhex(sd)
                except ValueError:
                    sd = sd.encode("latin-1")
            if isinstance(sd, bytearray):
                sd = bytes(sd)
            if not isinstance(sd, bytes):
                return accounts_with_rights

            parsed_sd = parse_security_descriptor(sd)
            for ace in parsed_sd.get('dacl', []):
                permissions = ace.get('permissions', {})
                rights = [
                    right for right in (
                        'DS-Replication-Get-Changes',
                        'DS-Replication-Get-Changes-All',
                        'DS-Replication-Get-Changes-In-Filtered-Set',
                        'AllExtendedRights',
                    )
                    if right in permissions
                ]
                if not rights:
                    continue

                sid = ace.get('sid')
                account = sid_map.get(sid, {
                    'account_name': sid or 'Unknown SID',
                    'account_type': 'sid',
                })
                accounts_with_rights.append({
                    'account_name': account['account_name'],
                    'account_type': account['account_type'],
                    'rights': rights,
                    'target_object': target_dn,
                    'source': 'Domain ACL',
                    'sid': sid,
                })
        except Exception as e:
            logger.debug(f"Error parsing DCSync ACL for {target_dn}: {str(e)}")

        return accounts_with_rights

    def _create_dcsync_risk(self, account_info: dict[str, Any]) -> dict[str, Any]:
        """Create a normalized DCSync risk dictionary."""
        target_object = account_info.get('target_object', self.ldap.base_dn)
        return {
            'type': RiskTypes.DCSYNC_RIGHTS,
            'severity': Severity.CRITICAL,
            'title': f'DCSync Rights: {account_info["account_name"]}',
            'description': (
                f"Account '{account_info['account_name']}' has DCSync rights "
                f"on '{target_object}'. This allows the account to replicate domain data "
                "including password hashes."
            ),
            'affected_object': account_info['account_name'],
            'object_type': account_info['account_type'],
            'target_object': target_object,
            'dcsync_rights': account_info['rights'],
            'impact': (
                'Accounts with DCSync rights can replicate all domain data including '
                'password hashes. This is equivalent to having Domain Admin privileges. '
                'An attacker with DCSync rights can extract all password hashes from '
                'the domain controller.'
            ),
            'attack_scenario': (
                f"An attacker who compromises '{account_info['account_name']}' can use "
                "tools like Mimikatz (lsadump::dcsync) or Impacket secretsdump to extract "
                "all password hashes from the domain controller without needing to be "
                "on the DC itself."
            ),
            'mitigation': (
                'Review and remove DCSync rights from non-essential accounts. Only '
                'Domain Controllers and specific service accounts should have DCSync rights. '
                'Use privileged access management (PAM) solutions. Monitor for DCSync '
                'usage attempts.'
            ),
            'cis_reference': 'CIS Benchmark requires strict control over DCSync rights',
            'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_DCSYNC,
            'exploitation_tools': [
                'Mimikatz lsadump::dcsync',
                'Impacket secretsdump',
                'DSInternals Get-ADReplAccount',
                'Rubeus',
            ],
        }

    def _build_sid_map(self, users: list[dict[str, Any]], groups: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
        """Build a SID lookup map for collected users and groups."""
        sid_map: dict[str, dict[str, str]] = {}
        for user in users:
            sid = self._sid_to_string(user.get('objectSid'))
            username = user.get('sAMAccountName')
            if sid and username:
                sid_map[sid] = {'account_name': username, 'account_type': 'user'}
        for group in groups:
            sid = self._sid_to_string(group.get('objectSid'))
            group_name = group.get('name') or group.get('sAMAccountName')
            if sid and group_name:
                sid_map[sid] = {'account_name': group_name, 'account_type': 'group'}
        return sid_map

    def _sid_to_string(self, raw_sid: Any) -> str:
        """Convert LDAP SID values to canonical SID strings."""
        if not raw_sid:
            return ''
        if isinstance(raw_sid, list) and raw_sid:
            raw_sid = raw_sid[0]
        if isinstance(raw_sid, str):
            if raw_sid.startswith('S-'):
                return raw_sid
            try:
                raw_sid = bytes.fromhex(raw_sid)
            except ValueError:
                raw_sid = raw_sid.encode('latin-1')
        if isinstance(raw_sid, bytearray):
            raw_sid = bytes(raw_sid)
        if not isinstance(raw_sid, bytes):
            return str(raw_sid)
        parser = SecurityDescriptorParser(b'')
        return parser._parse_sid_from_bytes(raw_sid) or ''

    def _extract_name_from_dn(self, dn: str) -> Optional[str]:
        """Extract name from distinguished name."""
        if not dn:
            return None
        if 'CN=' in dn:
            try:
                cn_part = dn.split('CN=')[1].split(',')[0]
                return cn_part
            except Exception:
                return None
        return dn
