"""
Kerberoasting and AS-REP Roasting Detection Module
Detects accounts vulnerable to Kerberoasting and AS-REP roasting attacks
"""

import logging
from typing import Any
from analysis.privileged_account_status import account_is_disabled
from core.ad_identity import first_ldap_rdn, is_privileged_group_name, privileged_membership_values
from core.constants import MITRETechniques, RiskTypes, Severity, UACFlags

logger = logging.getLogger(__name__)

_MACHINE_TRUST_FLAGS = (
    UACFlags.WORKSTATION_TRUST_ACCOUNT
    | UACFlags.SERVER_TRUST_ACCOUNT
    | UACFlags.INTERDOMAIN_TRUST_ACCOUNT
)
_MANAGED_SERVICE_CLASSES = frozenset({
    "msds-groupmanagedserviceaccount",
    "msds-managedserviceaccount",
})


def _account_uac(user: dict[str, Any]) -> int | None:
    raw = user.get("userAccountControl")
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def is_kerberos_roastable_account(user: dict[str, Any]) -> bool:
    """Return True when a TGT or TGS can still be issued for this account.

    Disabled accounts, krbtgt, computer accounts, and managed service accounts
    are not practical Kerberoasting or AS-REP targets. The KDC rejects disabled
    clients, and managed/machine passwords are random.
    """
    sam = str(user.get("sAMAccountName") or "")
    if not sam or sam.casefold() == "krbtgt" or sam.endswith("$"):
        return False
    if account_is_disabled(user):
        return False
    uac = _account_uac(user)
    if uac is not None and uac & _MACHINE_TRUST_FLAGS:
        return False
    classes = user.get("objectClass") or []
    if isinstance(classes, str):
        classes = [classes]
    if {str(item).casefold() for item in classes} & _MANAGED_SERVICE_CLASSES:
        return False
    if user.get("msDS-GroupMSAMembership") or user.get("msDS-ManagedPasswordInterval"):
        return False
    return True


class KerberoastingDetector:
    """Detects accounts vulnerable to Kerberoasting and AS-REP roasting."""

    def __init__(self):
        """Initialize Kerberoasting detector."""
        pass

    def detect_kerberoasting_targets(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Detect users vulnerable to Kerberoasting attacks.

        Args:
            users: List of user dictionaries

        Returns:
            List of risk dictionaries for Kerberoasting targets
        """
        risks = []

        for user in users:
            username = user.get('sAMAccountName')
            if not username or not is_kerberos_roastable_account(user):
                continue

            spns = user.get('servicePrincipalName') or []
            if not isinstance(spns, list):
                spns = [spns] if spns else []

            # User must have SPN to be vulnerable to Kerberoasting
            if not spns or len(spns) == 0:
                continue

            privileged_groups = [
                first_ldap_rdn(group_dn)
                for group_dn in privileged_membership_values(user.get('memberOf'))
                if is_privileged_group_name(first_ldap_rdn(group_dn))
            ]
            is_privileged = bool(privileged_groups)
            severity = Severity.CRITICAL if is_privileged else Severity.HIGH

            risks.append({
                'type': RiskTypes.KERBEROASTING_TARGET,
                'severity': severity,
                'title': f'Kerberoasting Target: {username}',
                'description': f"User '{username}' has {len(spns)} Service Principal Name(s) and is vulnerable to Kerberoasting attacks",
                'affected_object': username,
                'object_type': 'user',
                'spns': spns,
                'is_privileged': is_privileged,
                'privileged_groups': privileged_groups,
                'impact': 'This account can be targeted for Kerberoasting attacks. If the password is cracked, attackers gain access to the account and its associated permissions.',
                'attack_scenario': (
                    f"An attacker can request Kerberos service tickets for the SPNs associated with '{username}' "
                    "using tools like Impacket GetUserSPNs or Rubeus. The encrypted ticket can then be cracked "
                    "offline to obtain the account password without triggering account lockout."
                ),
                'mitigation': (
                    'Use strong, complex passwords for service accounts. Consider using managed service accounts '
                    '(MSAs) or group managed service accounts (gMSAs) instead of regular user accounts for services. '
                    'Implement monitoring for Kerberoasting attempts.'
                ),
                'cis_reference': 'CIS Benchmark recommends using managed service accounts for services',
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                'exploitation_tools': [
                    'Impacket GetUserSPNs',
                    'Rubeus kerberoast',
                    'CrackMapExec',
                    'hashcat (for password cracking)'
                ],
                'export_format': self._generate_export_format(username, spns, 'kerberoasting')
            })

        logger.info(f"Found {len(risks)} Kerberoasting targets")
        return risks

    def detect_asrep_roasting_targets(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Detect users vulnerable to AS-REP roasting attacks.

        Args:
            users: List of user dictionaries

        Returns:
            List of risk dictionaries for AS-REP roasting targets
        """
        risks = []

        for user in users:
            username = user.get('sAMAccountName')
            if not username or not is_kerberos_roastable_account(user):
                continue

            uac = user.get('userAccountControl', 0)
            if isinstance(uac, str):
                try:
                    uac = int(uac)
                except ValueError:
                    continue

            # Check if preauthentication is disabled
            # DONT_REQUIRE_PREAUTH = 4194304 (0x400000)
            if not (uac & 4194304):
                continue

            privileged_groups = [
                first_ldap_rdn(group_dn)
                for group_dn in privileged_membership_values(user.get('memberOf'))
            ]
            is_privileged = bool(privileged_groups)
            severity = Severity.CRITICAL if is_privileged else Severity.HIGH

            risks.append({
                'type': RiskTypes.ASREP_ROASTING_TARGET,
                'severity': severity,
                'title': f'AS-REP Roasting Target: {username}',
                'description': f"User '{username}' has Kerberos preauthentication disabled and is vulnerable to AS-REP roasting attacks",
                'affected_object': username,
                'object_type': 'user',
                'is_privileged': is_privileged,
                'privileged_groups': privileged_groups,
                'impact': 'This account can be targeted for AS-REP roasting attacks. Attackers can request Kerberos tickets without knowing the password and crack them offline without triggering account lockout.',
                'attack_scenario': (
                    f"An attacker can request a Kerberos ticket for '{username}' without preauthentication "
                    "using tools like Impacket GetNPUsers or Rubeus asreproast. The encrypted ticket can then "
                    "be cracked offline to obtain the account password without triggering account lockout policies."
                ),
                'mitigation': (
                    'IMMEDIATELY enable Kerberos preauthentication for this account. This is a critical security '
                    'setting that should never be disabled. Review why preauthentication was disabled and ensure '
                    'it is not needed for legitimate purposes.'
                ),
                'cis_reference': 'CIS Benchmark requires Kerberos preauthentication for all accounts',
                'mitre_attack': MITRETechniques.STEAL_FORGE_KERBEROS_KERBEROASTING,
                'exploitation_tools': [
                    'Impacket GetNPUsers',
                    'Rubeus asreproast',
                    'CrackMapExec',
                    'hashcat (for password cracking)'
                ],
                'export_format': self._generate_export_format(username, [], 'asrep')
            })

        logger.info(f"Found {len(risks)} AS-REP roasting targets")
        return risks

    def _extract_group_name(self, group_dn: str) -> str:
        """Extract the first RDN from a group DN or return the bare name."""
        return first_ldap_rdn(group_dn)

    def _generate_export_format(self, username: str, spns: list[str], attack_type: str) -> dict[str, Any]:
        """
        Generate export format for exploitation tools.

        Args:
            username: Username
            spns: List of SPNs (for Kerberoasting)
            attack_type: 'kerberoasting' or 'asrep'

        Returns:
            Dictionary with export formats
        """
        export = {
            'username': username,
            'attack_type': attack_type
        }

        if attack_type == 'kerberoasting':
            # Impacket format
            export['impacket_command'] = f"GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/{username}"

            # Rubeus format
            export['rubeus_command'] = f"Rubeus.exe kerberoast /user:{username}"

            # CrackMapExec format
            export['cme_command'] = f"crackmapexec ldap <DC_IP> -u {username} -p <PASSWORD> --kerberoasting"

            # SPN list for manual testing
            export['spns'] = spns

        elif attack_type == 'asrep':
            # Impacket format
            export['impacket_command'] = f"GetNPUsers.py -dc-ip <DC_IP> <DOMAIN>/{username} -no-pass"

            # Rubeus format
            export['rubeus_command'] = f"Rubeus.exe asreproast /user:{username}"

            # CrackMapExec format
            export['cme_command'] = f"crackmapexec ldap <DC_IP> -u {username} --asreproast"

        return export
