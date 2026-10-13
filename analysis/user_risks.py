"""
User Risk Analysis Module
Analyzes user data for security risks
"""

import logging
from typing import Any
from datetime import datetime, timezone
from core.ad_identity import first_ldap_rdn, nested_privileged_groups, privileged_membership_values
from core.ad_security import as_list
from core.constants import UACFlags, RiskTypes, Severity, MITRETechniques, TimeThresholds
from core.base_analyzer import BaseAnalyzer
from core.types import UserDict, RiskDict
from analysis.privileged_account_status import (
    account_is_disabled,
    privileged_admin_roles,
    risks_for_disabled_privileged_admin,
)

logger = logging.getLogger(__name__)


def _elapsed_days(value: Any) -> int | None:
    """Return whole UTC days since an LDAP timestamp, or None when unreadable."""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            value = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - value.astimezone(timezone.utc)).days


def _within_past_days(days: int | None, window: int) -> bool:
    return days is not None and 0 <= days <= window


class UserRiskAnalyzer(BaseAnalyzer):
    """Analyzes user objects for security risks."""

    def __init__(self):
        """Initialize user risk analyzer."""
        super().__init__()

    def analyze(self, users: list[UserDict], groups: list[dict[str, Any]] | None = None) -> list[RiskDict]:
        """
        Analyze users for security risks.

        Args:
            users: List of user dictionaries
            groups: Collected groups, used to expand nested privileged membership

        Returns:
            list: List of risk dictionaries
        """
        risks = []
        self._directory_groups = list(groups or [])

        for user in users:
            self._enrich_user_data(user)
            risks.extend(self._check_admin_count(user))
            if account_is_disabled(user):
                # A disabled account cannot authenticate. Report the disablement
                # itself only when privilege or a dangerous flag would return
                # with a re-enable.
                risks.extend(risks_for_disabled_privileged_admin(user))
                risks.extend(self._check_disabled_sensitive_configuration(user))
                continue

            risks.extend(self._check_password_never_expires(user))
            risks.extend(self._check_password_not_required(user))
            risks.extend(self._check_kerberos_preauth_disabled(user))
            risks.extend(self._check_spn_users(user))
            risks.extend(self._check_inactive_privileged(user))
            risks.extend(self._check_locked_account(user))
            risks.extend(self._check_service_account_password_never_expires(user))
            risks.extend(self._check_recently_created_account(user))
            risks.extend(self._check_recently_changed_privileged_account(user))

        logger.info(f"Found {len(risks)} user-related risks")
        return risks

    def _enrich_user_data(self, user: dict[str, Any]):
        """
        Enrich user data with additional metadata for reporting.

        Args:
            user: User dictionary to enrich
        """
        account_age_days = _elapsed_days(user.get('whenCreated'))
        if account_age_days is not None:
            user['accountAgeDays'] = account_age_days

        # Extract admin group memberships from the first RDN only.
        domain_admin_groups = []
        enterprise_admin_groups = []
        schema_admin_groups = []
        admin_groups = list(privileged_membership_values(user.get('memberOf')))
        seen_admin_names = {first_ldap_rdn(item).casefold() for item in admin_groups}
        for name in nested_privileged_groups(user, getattr(self, '_directory_groups', None)):
            if name.casefold() not in seen_admin_names:
                seen_admin_names.add(name.casefold())
                admin_groups.append(name)

        for group_dn in admin_groups:
            folded = first_ldap_rdn(group_dn).casefold()
            if folded == 'domain admins':
                domain_admin_groups.append(group_dn)
            elif folded == 'enterprise admins':
                enterprise_admin_groups.append(group_dn)
            elif folded == 'schema admins':
                schema_admin_groups.append(group_dn)

        user['domainAdminGroups'] = domain_admin_groups
        user['enterpriseAdminGroups'] = enterprise_admin_groups
        user['schemaAdminGroups'] = schema_admin_groups
        user['adminGroups'] = admin_groups

        # Calculate admin privilege age (when adminCount was set or when joined admin group)
        # This is approximate - we use whenChanged as proxy for when admin privileges were granted
        when_changed = user.get('whenChanged')
        if user.get('adminCount') in (1, '1') or admin_groups:
            admin_privilege_age_days = _elapsed_days(when_changed)
            if admin_privilege_age_days is not None:
                user['adminPrivilegeAgeDays'] = admin_privilege_age_days

        # Check if service account (has SPN or name starts with service account patterns)
        spns = user.get('servicePrincipalName', []) or []
        if not isinstance(spns, list):
            spns = [spns] if spns else []

        username = str(user.get('sAMAccountName') or '')
        username_folded = username.casefold()
        # Name and description substrings such as "ServiceDesk" are not evidence
        # that the account is a service principal.
        is_service_account = bool(spns) or username_folded.startswith(('svc_', 'srv_', 'service_'))
        user['isServiceAccount'] = is_service_account

        days_since_logon = _elapsed_days(user.get('lastLogonTimestamp'))
        if days_since_logon is not None:
            user['daysSinceLastLogon'] = days_since_logon

        user['createdInLast10Days'] = _within_past_days(account_age_days, 10)
        user['createdInLast30Days'] = _within_past_days(account_age_days, 30)
        user['createdInLast60Days'] = _within_past_days(account_age_days, 60)
        user['createdInLast90Days'] = _within_past_days(account_age_days, 90)

        # whenChanged updates for any attribute write, not only group membership.
        changed_days = _elapsed_days(when_changed)
        user['groupChangedInLast10Days'] = _within_past_days(changed_days, 10)
        user['groupChangedInLast30Days'] = _within_past_days(changed_days, 30)
        user['groupChangedInLast60Days'] = _within_past_days(changed_days, 60)
        user['groupChangedInLast90Days'] = _within_past_days(changed_days, 90)

    def _check_password_never_expires(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if user has password never expires flag.

        Service accounts are reported by the service-account check so the same
        flag is not scored twice.
        """
        risks = []
        if user.get('isServiceAccount'):
            return risks
        uac = user.get('userAccountControl', 0)

        if isinstance(uac, str):
            try:
                uac = int(uac)
            except ValueError:
                return risks

        if self._check_uac_flag(uac, UACFlags.DONT_EXPIRE_PASSWORD):
            risks.append(self._create_user_risk(
                risk_type=RiskTypes.USER_PASSWORD_NEVER_EXPIRES,
                title='Password Never Expires',
                description="User '{username}' has password that never expires",
                user=user,
                severity=Severity.HIGH,
                impact='Passwords that never expire increase the risk of compromised credentials remaining valid indefinitely',
                attack_scenario='An attacker who compromises a password that never expires maintains persistent access without needing to periodically update credentials',
                mitigation='Enable password expiration policy and ensure all user accounts have expiring passwords. Review and update passwords for accounts with this flag',
                cis_reference='CIS Benchmark recommends password expiration policies',
                mitre_attack=MITRETechniques.VALID_ACCOUNTS
            ))

        return risks

    def _check_password_not_required(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if user has password not required flag (CRITICAL)."""
        risks = []
        uac = user.get('userAccountControl', 0)

        if isinstance(uac, str):
            try:
                uac = int(uac)
            except ValueError:
                return risks

        if self._check_uac_flag(uac, UACFlags.PASSWD_NOTREQD):
            risks.append(self._create_user_risk(
                risk_type=RiskTypes.PASSWORD_NOT_REQUIRED,
                title='Password Not Required (CRITICAL)',
                description="User '{username}' has password not required flag set - this is extremely dangerous",
                user=user,
                severity=Severity.CRITICAL,
                impact='Accounts with password not required can be accessed without authentication, creating a severe security vulnerability',
                attack_scenario='An attacker can authenticate to this account without knowing any password, gaining immediate access to the account and its associated permissions',
                mitigation='IMMEDIATELY remove the password not required flag. Set a strong password for the account. This flag should never be used in production environments',
                cis_reference='CIS Benchmark prohibits password not required flag',
                mitre_attack=MITRETechniques.VALID_ACCOUNTS
            ))

        return risks

    def _check_kerberos_preauth_disabled(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if Kerberos preauthentication is disabled."""
        risks = []
        uac = user.get('userAccountControl', 0)

        if isinstance(uac, str):
            try:
                uac = int(uac)
            except ValueError:
                return risks

        if uac & UACFlags.DONT_REQUIRE_PREAUTH:
            privileged_groups = [
                first_ldap_rdn(group_dn)
                for group_dn in privileged_membership_values(user.get('memberOf'))
            ]
            is_privileged = bool(privileged_groups)
            risks.append({
                'type': RiskTypes.KERBEROS_PREAUTH_DISABLED,
                'severity': Severity.CRITICAL if is_privileged else Severity.HIGH,
                'title': 'Kerberos Preauthentication Disabled',
                'description': f"User '{user.get('sAMAccountName')}' has Kerberos preauthentication disabled",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'is_privileged': is_privileged,
                'privileged_groups': privileged_groups,
                'impact': 'Disabling preauthentication allows attackers to request Kerberos tickets without knowing the password, enabling offline brute-force attacks',
                'attack_scenario': 'An attacker can perform AS-REP roasting attacks, attempting to crack passwords offline without triggering account lockout policies',
                'mitigation': 'Enable Kerberos preauthentication for all user accounts. This is a critical security setting that should never be disabled',
                'cis_reference': 'CIS Benchmark requires Kerberos preauthentication for all accounts',
                'mitre_attack': 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
            })

        return risks

    def _check_spn_users(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if user has Service Principal Names defined."""
        risks = []
        spns = user.get('servicePrincipalName') or []
        if not isinstance(spns, list):
            spns = [spns] if spns else []

        if spns and len(spns) > 0:
            risks.append({
                'type': RiskTypes.USER_WITH_SPN,
                'severity': Severity.MEDIUM,
                'title': 'User with Service Principal Name',
                'description': f"User '{user.get('sAMAccountName')}' has {len(spns)} Service Principal Name(s) defined",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'spns': spns,
                'impact': 'Users with SPNs can be targeted for Kerberoasting attacks, where attackers request service tickets and attempt to crack the password offline',
                'attack_scenario': 'An attacker can request Kerberos service tickets for the SPN and attempt to crack the password hash offline, potentially gaining access to the account',
                'mitigation': 'Review if SPNs are necessary for user accounts. Consider using managed service accounts (MSAs) or group managed service accounts (gMSAs) instead of regular user accounts for services',
                'cis_reference': 'CIS Benchmark recommends using managed service accounts for services',
                'mitre_attack': 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
            })

        return risks

    def _check_admin_count(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Report adminCount only when it no longer matches a privileged group.

        adminCount stays set after an account leaves a protected group, and
        AdminSDHolder keeps rewriting the ACL. Current privileged members are
        already covered by membership findings.
        """
        if user.get('adminCount') not in (1, '1'):
            return []
        groups = as_list(user.get('memberOf'))
        privileged_groups = privileged_membership_values(groups)
        if privileged_groups or privileged_admin_roles(user):
            return []
        username = user.get('sAMAccountName')
        return [{
            'type': RiskTypes.ADMIN_COUNT_SET,
            'severity': Severity.MEDIUM,
            'title': 'Stale adminCount without privileged membership',
            'description': (
                f"User '{username}' still has adminCount=1 but is not a member of a "
                "well-known privileged group"
            ),
            'affected_object': username,
            'object_type': 'user',
            'member_of': groups,
            'privileged_groups': [],
            'impact': (
                'AdminSDHolder continues to protect this account as if it were privileged. '
                'The flag is not evidence that the account currently holds Domain Admin rights.'
            ),
            'attack_scenario': (
                'A previously privileged account can keep a protected ACL after removal from '
                'admin groups, hiding later permission changes and preserving an unexpected security descriptor.'
            ),
            'mitigation': (
                'Confirm the account should not be privileged, move it out of any protected container, '
                'and clear adminCount so AdminSDHolder stops owning the ACL.'
            ),
            'cis_reference': 'CIS Benchmark recommends regular review of administrative accounts',
            'mitre_attack': 'T1078 - Valid Accounts'
        }]

    def _check_inactive_privileged(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check for inactive privileged accounts."""
        risks = []

        privileged_groups = list(user.get('adminGroups') or [])
        roles = privileged_admin_roles(user)
        if not privileged_groups and not roles:
            return risks

        # Check last logon
        last_logon = user.get('lastLogonTimestamp')
        if not last_logon:
            return risks

        # Check if last logon is more than threshold days ago
        if isinstance(last_logon, str):
            try:
                last_logon = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
            except Exception:
                return risks

        if isinstance(last_logon, datetime) or isinstance(last_logon, str):
            days_inactive = _elapsed_days(last_logon)
            if days_inactive is not None and days_inactive > TimeThresholds.INACTIVE_ACCOUNT_THRESHOLD:
                risks.append({
                    'type': RiskTypes.INACTIVE_PRIVILEGED_ACCOUNT,
                    'severity': Severity.MEDIUM,
                    'title': 'Inactive Privileged Account',
                    'description': f"Privileged user '{user.get('sAMAccountName')}' has not logged in for {days_inactive} days",
                    'affected_object': user.get('sAMAccountName'),
                    'object_type': 'user',
                    'days_inactive': days_inactive,
                    'privileged_groups': privileged_groups or roles,
                    'impact': 'Inactive privileged accounts pose a security risk as they may be forgotten and not properly secured, or may have been compromised without detection',
                    'attack_scenario': 'An attacker who compromises an inactive privileged account may go undetected for extended periods, as the account owner is not actively monitoring it',
                    'mitigation': 'Review inactive privileged accounts regularly. Disable or remove accounts that are no longer needed. Ensure all active privileged accounts have strong passwords and MFA enabled',
                    'cis_reference': 'CIS Benchmark recommends disabling inactive accounts',
                    'mitre_attack': 'T1078 - Valid Accounts'
                })

        return risks

    def _check_disabled_sensitive_configuration(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Report a disabled account that would become dangerous if re-enabled."""
        uac = user.get('userAccountControl', 0)
        if isinstance(uac, (list, tuple)):
            uac = uac[0] if uac else 0
        try:
            uac = int(uac or 0)
        except (TypeError, ValueError):
            uac = 0
        spns = user.get('servicePrincipalName') or []
        if not isinstance(spns, list):
            spns = [spns] if spns else []
        reasons = []
        if spns:
            reasons.append("service principal names")
        if uac & UACFlags.DONT_REQUIRE_PREAUTH:
            reasons.append("Kerberos preauthentication disabled")
        if uac & UACFlags.PASSWD_NOTREQD:
            reasons.append("password not required")
        if uac & UACFlags.TRUSTED_FOR_DELEGATION:
            reasons.append("unconstrained delegation")
        if as_list(user.get('msDS-AllowedToDelegateTo')):
            reasons.append("constrained delegation targets")
        if not reasons:
            return []
        username = user.get('sAMAccountName')
        joined = ", ".join(reasons)
        return [{
            'type': RiskTypes.DISABLED_ACCOUNT_SENSITIVE_CONFIGURATION,
            'severity': Severity.MEDIUM,
            'title': 'Disabled account retains sensitive configuration',
            'description': f"Disabled user '{username}' still has {joined}",
            'affected_object': username,
            'object_type': 'user',
            'sensitive_configuration': reasons,
            'impact': 'The account cannot authenticate while disabled, but re-enabling it restores the listed attack surface.',
            'attack_scenario': 'An operator re-enables the account without clearing the old flags, and the account becomes Kerberoastable, delegatable, or passwordless.',
            'mitigation': 'Remove the sensitive flags before any re-enable, or delete the account if it is no longer required.',
            'cis_reference': 'CIS Benchmark recommends removing unused accounts',
            'mitre_attack': 'T1078 - Valid Accounts',
        }]

    def _check_locked_account(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if user account is locked."""
        risks = []

        if user.get('isLocked'):
            risks.append({
                'type': RiskTypes.LOCKED_USER_ACCOUNT,
                'severity': Severity.MEDIUM,
                'title': 'Locked User Account',
                'description': f"User account '{user.get('sAMAccountName')}' is locked",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'impact': 'Locked accounts may indicate brute-force attack attempts or legitimate user issues',
                'attack_scenario': 'Multiple locked accounts could indicate a coordinated attack attempt',
                'mitigation': 'Investigate locked accounts to determine cause. Review account lockout policies. Consider implementing account lockout alerts',
                'cis_reference': 'CIS Benchmark recommends monitoring account lockouts',
                'mitre_attack': 'T1110 - Brute Force'
            })

        return risks

    def _check_service_account_password_never_expires(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if service account has password never expires flag."""
        risks = []

        # Check if this is a service account
        if not user.get('isServiceAccount'):
            return risks

        uac = user.get('userAccountControl', 0)
        if isinstance(uac, str):
            try:
                uac = int(uac)
            except ValueError:
                return risks

        if uac & UACFlags.DONT_EXPIRE_PASSWORD:
            risks.append({
                'type': RiskTypes.SERVICE_ACCOUNT_PASSWORD_NEVER_EXPIRES,
                'severity': Severity.HIGH,
                'title': 'Service Account Password Never Expires',
                'description': f"Service account '{user.get('sAMAccountName')}' has password that never expires",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'spns': user.get('servicePrincipalName', []),
                'impact': 'Service accounts with passwords that never expire pose a security risk as compromised credentials remain valid indefinitely',
                'attack_scenario': 'An attacker who compromises a service account password maintains persistent access without password rotation',
                'mitigation': 'Consider using Group Managed Service Accounts (gMSAs) or Managed Service Accounts (MSAs) instead of regular accounts for services. If regular accounts must be used, implement regular password rotation',
                'cis_reference': 'CIS Benchmark recommends using managed service accounts',
                'mitre_attack': 'T1078 - Valid Accounts'
            })

        return risks

    def _check_recently_created_account(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Check if account was created recently (potential security concern)."""
        risks = []

        # Only flag if account was created in last threshold days and has admin privileges
        if user.get('createdInLast30Days') and (user.get('adminGroups') or privileged_admin_roles(user)):
            risks.append({
                'type': RiskTypes.RECENTLY_CREATED_ACCOUNT,
                'severity': Severity.MEDIUM,
                'title': 'Recently Created Privileged Account',
                'description': f"Privileged account '{user.get('sAMAccountName')}' was created recently",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'accountAgeDays': user.get('accountAgeDays'),
                'adminGroups': user.get('adminGroups', []),
                'impact': 'Recently created privileged accounts should be reviewed to ensure they are legitimate and properly secured',
                'attack_scenario': 'An attacker who gains domain admin access might create new privileged accounts for persistence',
                'mitigation': 'Review recently created privileged accounts. Verify they are legitimate and properly secured. Monitor for unauthorized account creation',
                'cis_reference': 'CIS Benchmark recommends monitoring account creation',
                'mitre_attack': 'T1136 - Create Account'
            })

        return risks

    def _check_recently_changed_privileged_account(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        """Report a recent whenChanged write on a currently privileged account.

        whenChanged is not a group-membership timestamp. The finding says the
        object changed, which is the only fact LDAP exposes here.
        """
        if not user.get('groupChangedInLast30Days'):
            return []
        if not (user.get('adminGroups') or privileged_admin_roles(user)):
            return []
        if user.get('groupChangedInLast10Days'):
            days_ago = 'last 10 days'
        else:
            days_ago = 'last 30 days'
        username = user.get('sAMAccountName')
        return [{
            'type': RiskTypes.RECENTLY_MODIFIED_GROUP_MEMBERSHIP,
            'severity': Severity.MEDIUM,
            'title': 'Privileged account recently changed',
            'description': (
                f"Privileged account '{username}' was modified in the {days_ago}. "
                "whenChanged does not prove that group membership changed."
            ),
            'affected_object': username,
            'object_type': 'user',
            'adminGroups': user.get('adminGroups', []),
            'impact': 'A recent write to a privileged account can be a legitimate change or an unexpected persistence edit.',
            'attack_scenario': 'An attacker with write access changes a privileged account attribute. Review the directory change, rather than assuming the group list changed.',
            'mitigation': 'Review the recent attribute changes on this account and confirm they were authorized.',
            'cis_reference': 'CIS Benchmark recommends monitoring privileged account changes',
            'mitre_attack': 'T1098 - Account Manipulation',
        }]
