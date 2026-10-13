"""
Kerberos & Delegation Analysis Module
Analyzes Kerberos and delegation-related security risks
"""

import logging

from analysis.privileged_account_status import account_is_disabled
from core.ad_identity import computer_has_unexpected_unconstrained_delegation
from core.ad_security import as_list, as_text
from core.constants import MITRETechniques, RiskTypes, Severity, UACFlags
from core.security_descriptor_parser import parse_security_descriptor

logger = logging.getLogger(__name__)


class KerberosDelegationAnalyzer:
    """Analyzes Kerberos and delegation configurations for security risks."""

    def __init__(self):
        """Initialize Kerberos delegation analyzer."""
        self.risks = []

    def analyze(self, users, computers):
        """
        Analyze users and computers for Kerberos/delegation risks.

        Args:
            users: List of user dictionaries
            computers: List of computer dictionaries

        Returns:
            list: List of risk dictionaries
        """
        risks = []

        # Check unconstrained delegation
        risks.extend(self._check_unconstrained_delegation(users, computers))

        # Check constrained delegation
        risks.extend(self._check_constrained_delegation(users, computers))

        # Check resource-based constrained delegation
        risks.extend(self._check_rbcd(users, computers))

        # Check SPN misuse
        risks.extend(self._check_spn_misuse(users, computers))

        logger.info(f"Found {len(risks)} Kerberos/Delegation risks")
        return risks

    def _check_unconstrained_delegation(self, users, computers):
        """Check for unconstrained delegation on users and computers."""
        risks = []

        # Check computers
        for computer in computers:
            if computer_has_unexpected_unconstrained_delegation(computer):
                risks.append({
                    'type': 'unconstrained_delegation',
                    'severity': 'critical',
                    'title': 'Unconstrained Delegation Enabled',
                    'description': f"Computer '{computer.get('name')}' has unconstrained delegation enabled",
                    'affected_object': computer.get('name'),
                    'object_type': 'computer',
                    'impact': 'Unconstrained delegation allows a service to impersonate users to any service in the domain, creating a significant privilege escalation risk',
                    'attack_scenario': 'If an attacker compromises a computer with unconstrained delegation, they can capture and reuse Kerberos tickets from any user who authenticates to that computer, potentially gaining domain admin access',
                    'mitigation': 'Disable unconstrained delegation. Use constrained delegation or resource-based constrained delegation instead, which limits which services can be accessed',
                    'cis_reference': 'CIS Benchmark recommends disabling unconstrained delegation',
                    'mitre_attack': 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
                })

        # Check users (less common but possible)
        for user in users:
            uac = user.get('userAccountControl', 0)
            if isinstance(uac, str):
                try:
                    uac = int(uac)
                except ValueError:
                    continue

            if account_is_disabled(user):
                continue

            if uac & 524288:  # TRUSTED_FOR_DELEGATION
                risks.append({
                    'type': 'unconstrained_delegation_user',
                    'severity': 'critical',
                    'title': 'User with Unconstrained Delegation',
                    'description': f"User '{user.get('sAMAccountName')}' has unconstrained delegation enabled",
                    'affected_object': user.get('sAMAccountName'),
                    'object_type': 'user',
                    'impact': 'Users with unconstrained delegation can impersonate other users to any service, creating a severe security risk',
                    'attack_scenario': 'An attacker who compromises a user account with unconstrained delegation can impersonate any user, including domain administrators',
                    'mitigation': 'Immediately disable unconstrained delegation for user accounts. This setting should only be used for service accounts with constrained delegation if absolutely necessary',
                    'cis_reference': 'CIS Benchmark prohibits unconstrained delegation for user accounts',
                    'mitre_attack': 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
                })

        return risks

    def _check_constrained_delegation(self, users, computers):
        """Flag accounts with an explicit msDS-AllowedToDelegateTo service list."""
        risks = []
        for object_type, objects, name_key in (
            ('computer', computers, 'name'),
            ('user', users, 'sAMAccountName'),
        ):
            for obj in objects or []:
                allowed = [as_text(item) for item in as_list(obj.get('msDS-AllowedToDelegateTo')) if as_text(item)]
                if not allowed:
                    continue
                name = as_text(obj.get(name_key) or obj.get('sAMAccountName') or obj.get('name')) or 'unknown'
                risks.append({
                    'type': RiskTypes.CONSTRAINED_DELEGATION,
                    'severity': Severity.MEDIUM,
                    'title': 'Constrained Delegation Configured',
                    'description': (
                        f"{object_type.title()} '{name}' can impersonate users to "
                        f"{len(allowed)} service(s) via msDS-AllowedToDelegateTo"
                    ),
                    'affected_object': name,
                    'object_type': object_type,
                    'allowed_services': allowed,
                    'protocol_transition': bool(self._uac_value(obj) & UACFlags.TRUSTED_TO_AUTH_FOR_DELEGATION),
                    'impact': 'Constrained delegation is narrower than unconstrained, but a compromise of this account can still reach every listed service.',
                    'attack_scenario': 'If the delegated account is compromised, an attacker can request S4U2Proxy tickets for the allowed SPNs and impersonate users to those services.',
                    'mitigation': 'Review and minimize the allowed service list. Prefer resource-based constrained delegation and remove protocol transition unless required.',
                    'cis_reference': 'CIS Benchmark recommends reviewing all delegation configurations',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
                })
        return risks

    def _check_rbcd(self, users, computers):
        """Report resource-based constrained delegation from collected security descriptors."""
        risks = []
        for object_type, objects, name_key in (
            ('computer', computers, 'name'),
            ('user', users, 'sAMAccountName'),
        ):
            for obj in objects or []:
                blob = obj.get('msDS-AllowedToActOnBehalfOfOtherIdentity')
                if blob in (None, '', [], b''):
                    continue
                principals = self._rbcd_principals(blob)
                name = as_text(obj.get(name_key) or obj.get('sAMAccountName') or obj.get('name')) or 'unknown'
                if not principals:
                    risks.append({
                        'type': 'delegation_descriptor_unreadable',
                        'severity': Severity.MEDIUM,
                        'title': f'Delegation descriptor unreadable: {name}',
                        'description': (
                            f"{object_type.title()} '{name}' has msDS-AllowedToActOnBehalfOfOtherIdentity set, "
                            'but no trustee SID could be read from it. This is not a confirmed RBCD grant.'
                        ),
                        'affected_object': name,
                        'object_type': object_type,
                        'rbcd_principals': [],
                        'evidence': {'requires_runtime_validation': True, 'parse_valid': False},
                        'impact': 'An unreadable delegation descriptor cannot be treated as a clean configuration or as a confirmed impersonation grant.',
                        'mitigation': 'Re-read the security descriptor with a security-descriptor control and review the DACL before treating the attribute as RBCD.',
                        'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
                    })
                    continue
                risks.append({
                    'type': RiskTypes.RBCD_DELEGATION,
                    'severity': Severity.HIGH,
                    'title': f'RBCD Configured: {name}',
                    'description': (
                        f"{object_type.title()} '{name}' allows "
                        f"{len(principals) or 'one or more'} principal(s) to act on its behalf "
                        'via msDS-AllowedToActOnBehalfOfOtherIdentity.'
                    ),
                    'affected_object': name,
                    'object_type': object_type,
                    'rbcd_principals': principals,
                    'impact': 'A principal listed in the RBCD descriptor can impersonate users to this account. Write access to the attribute is a common privilege-escalation primitive.',
                    'attack_scenario': 'Compromise or create a listed principal, then use S4U2Self/S4U2Proxy to impersonate a privileged user to the target.',
                    'mitigation': 'Audit and clear unexpected msDS-AllowedToActOnBehalfOfOtherIdentity values. Restrict who can write the attribute.',
                    'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
                })
        return risks

    @staticmethod
    def _uac_value(obj: dict) -> int:
        try:
            return int(obj.get('userAccountControl') or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _rbcd_principals(value) -> list[str]:
        principals: list[str] = []
        for item in as_list(value):
            raw = item
            if hasattr(raw, 'raw_values') and raw.raw_values:
                raw = raw.raw_values[0]
            if isinstance(raw, memoryview):
                raw = raw.tobytes()
            if not isinstance(raw, (bytes, bytearray)):
                continue
            parsed = parse_security_descriptor(bytes(raw))
            for ace in parsed.get('dacl') or []:
                sid = ace.get('sid')
                if sid and sid not in principals:
                    principals.append(sid)
        return principals

    def _check_spn_misuse(self, users, computers):
        """Check for SPN misuse and duplicate SPNs."""
        risks = []
        spn_map = {}

        # Collect all SPNs from users
        for user in users:
            spns = user.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            if spns:
                for spn in spns:
                    if not spn:
                        continue
                    if spn not in spn_map:
                        spn_map[spn] = []
                    spn_map[spn].append({
                        'type': 'user',
                        'name': user.get('sAMAccountName')
                    })

        # Collect all SPNs from computers
        for computer in computers:
            spns = computer.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []
            if spns:
                for spn in spns:
                    if not spn:
                        continue
                    if spn not in spn_map:
                        spn_map[spn] = []
                    spn_map[spn].append({
                        'type': 'computer',
                        'name': computer.get('name')
                    })

        # Check for duplicate SPNs
        for spn, objects in spn_map.items():
            if len(objects) > 1:
                risks.append({
                    'type': 'duplicate_spn',
                    'severity': 'high',
                    'title': 'Duplicate Service Principal Name',
                    'description': f"SPN '{spn}' is assigned to {len(objects)} objects",
                    'affected_object': spn,
                    'object_type': 'spn',
                    'conflicting_objects': objects,
                    'impact': 'Duplicate SPNs can cause authentication failures and security issues. Kerberos cannot uniquely identify which account should be used for authentication',
                    'attack_scenario': 'An attacker could potentially exploit duplicate SPNs to perform authentication attacks or cause service disruptions',
                    'mitigation': 'Ensure each SPN is unique and assigned to only one account. Review and remove duplicate SPN assignments',
                    'cis_reference': 'CIS Benchmark requires unique SPN assignments',
                    'mitre_attack': 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
                })

        return risks
