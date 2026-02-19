"""
User Risk Analysis Module
Analyzes user data for security risks
"""

import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
from core.constants import UACFlags, RiskTypes, Severity, MITRETechniques, TimeThresholds
from core.base_analyzer import BaseAnalyzer
from core.types import UserDict, RiskDict

logger = logging.getLogger(__name__)


class UserRiskAnalyzer(BaseAnalyzer):
    """Analyzes user objects for security risks."""
    
    def __init__(self):
        """Initialize user risk analyzer."""
        super().__init__()
    
    def analyze(self, users: List[UserDict]) -> List[RiskDict]:
        """
        Analyze users for security risks.
        
        Args:
            users: List of user dictionaries
        
        Returns:
            list: List of risk dictionaries
        """
        risks = []
        
        for user in users:
            # Enrich user data with additional metadata
            self._enrich_user_data(user)
            
            # Check password never expires
            risks.extend(self._check_password_never_expires(user))
            
            # Check password not required
            risks.extend(self._check_password_not_required(user))
            
            # Check Kerberos preauth disabled
            risks.extend(self._check_kerberos_preauth_disabled(user))
            
            # Check SPN defined users
            risks.extend(self._check_spn_users(user))
            
            # Check adminCount users
            risks.extend(self._check_admin_count(user))
            
            # Check inactive privileged accounts
            risks.extend(self._check_inactive_privileged(user))
            
            # Check disabled accounts
            risks.extend(self._check_disabled_account(user))
            
            # Check locked accounts
            risks.extend(self._check_locked_account(user))
            
            # Check service accounts with password never expires
            risks.extend(self._check_service_account_password_never_expires(user))
            
            # Check recently created accounts
            risks.extend(self._check_recently_created_account(user))
            
            # Check recently modified group membership
            risks.extend(self._check_recently_modified_group_membership(user))
        
        logger.info(f"Found {len(risks)} user-related risks")
        return risks
    
    def _enrich_user_data(self, user: Dict[str, Any]):
        """
        Enrich user data with additional metadata for reporting.
        
        Args:
            user: User dictionary to enrich
        """
        # Calculate account age
        when_created = user.get('whenCreated')
        if when_created:
            try:
                if isinstance(when_created, str):
                    when_created = datetime.fromisoformat(when_created.replace('Z', '+00:00'))
                if isinstance(when_created, datetime):
                    account_age_days = (datetime.now() - when_created.replace(tzinfo=None)).days
                    user['accountAgeDays'] = account_age_days
            except Exception:
                pass
        
        # Extract admin group memberships
        member_of = user.get('memberOf', []) or []
        if not isinstance(member_of, list):
            member_of = [member_of] if member_of else []
        
        domain_admin_groups = []
        enterprise_admin_groups = []
        schema_admin_groups = []
        admin_groups = []
        
        for group_dn in member_of:
            group_str = str(group_dn).upper()
            if 'DOMAIN ADMINS' in group_str:
                domain_admin_groups.append(group_dn)
            if 'ENTERPRISE ADMINS' in group_str:
                enterprise_admin_groups.append(group_dn)
            if 'SCHEMA ADMINS' in group_str:
                schema_admin_groups.append(group_dn)
            if any(priv in group_str for priv in ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'SCHEMA ADMINS', 'ADMINISTRATORS']):
                admin_groups.append(group_dn)
        
        user['domainAdminGroups'] = domain_admin_groups
        user['enterpriseAdminGroups'] = enterprise_admin_groups
        user['schemaAdminGroups'] = schema_admin_groups
        user['adminGroups'] = admin_groups
        
        # Calculate admin privilege age (when adminCount was set or when joined admin group)
        # This is approximate - we use whenChanged as proxy for when admin privileges were granted
        when_changed = user.get('whenChanged')
        admin_privilege_age_days = None
        if (user.get('adminCount') == 1 or user.get('adminCount') == '1' or admin_groups) and when_changed:
            try:
                if isinstance(when_changed, str):
                    when_changed = datetime.fromisoformat(when_changed.replace('Z', '+00:00'))
                if isinstance(when_changed, datetime):
                    admin_privilege_age_days = (datetime.now() - when_changed.replace(tzinfo=None)).days
                    user['adminPrivilegeAgeDays'] = admin_privilege_age_days
            except Exception:
                pass
        
        # Check if service account (has SPN or name starts with service account patterns)
        spns = user.get('servicePrincipalName', []) or []
        if not isinstance(spns, list):
            spns = [spns] if spns else []
        
        username = user.get('sAMAccountName', '') or ''
        username_upper = username.upper() if username else ''
        description = user.get('description') or ''
        description_upper = description.upper() if description else ''
        
        is_service_account = (
            len(spns) > 0 or
            username_upper.startswith('SVC_') or
            username_upper.startswith('SRV_') or
            username_upper.startswith('SERVICE_') or
            'SERVICE' in username_upper or
            (description_upper and 'SERVICE' in description_upper)
        )
        user['isServiceAccount'] = is_service_account
        
        # Calculate days since last logon
        last_logon = user.get('lastLogonTimestamp')
        if last_logon:
            try:
                if isinstance(last_logon, str):
                    last_logon = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
                if isinstance(last_logon, datetime):
                    days_since_logon = (datetime.now() - last_logon.replace(tzinfo=None)).days
                    user['daysSinceLastLogon'] = days_since_logon
            except Exception:
                pass
        
        # Check if account was created recently (10/30/60/90 days)
        if when_created:
            try:
                if isinstance(when_created, str):
                    when_created = datetime.fromisoformat(when_created.replace('Z', '+00:00'))
                if isinstance(when_created, datetime):
                    days_ago = (datetime.now() - when_created.replace(tzinfo=None)).days
                    user['createdInLast10Days'] = days_ago <= 10
                    user['createdInLast30Days'] = days_ago <= 30
                    user['createdInLast60Days'] = days_ago <= 60
                    user['createdInLast90Days'] = days_ago <= 90
            except Exception:
                pass
        
        # Check if group membership was changed recently
        if when_changed:
            try:
                if isinstance(when_changed, str):
                    when_changed = datetime.fromisoformat(when_changed.replace('Z', '+00:00'))
                if isinstance(when_changed, datetime):
                    days_ago = (datetime.now() - when_changed.replace(tzinfo=None)).days
                    user['groupChangedInLast10Days'] = days_ago <= 10
                    user['groupChangedInLast30Days'] = days_ago <= 30
                    user['groupChangedInLast60Days'] = days_ago <= 60
                    user['groupChangedInLast90Days'] = days_ago <= 90
            except Exception:
                pass
    
    def _check_password_never_expires(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if user has password never expires flag."""
        risks = []
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
    
    def _check_password_not_required(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    
    def _check_kerberos_preauth_disabled(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if Kerberos preauthentication is disabled."""
        risks = []
        uac = user.get('userAccountControl', 0)
        
        if isinstance(uac, str):
            try:
                uac = int(uac)
            except ValueError:
                return risks
        
        if uac & UACFlags.DONT_REQUIRE_PREAUTH:
            risks.append({
                'type': RiskTypes.KERBEROS_PREAUTH_DISABLED,
                'severity': Severity.CRITICAL,
                'title': 'Kerberos Preauthentication Disabled',
                'description': f"User '{user.get('sAMAccountName')}' has Kerberos preauthentication disabled",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'impact': 'Disabling preauthentication allows attackers to request Kerberos tickets without knowing the password, enabling offline brute-force attacks',
                'attack_scenario': 'An attacker can perform AS-REP roasting attacks, attempting to crack passwords offline without triggering account lockout policies',
                'mitigation': 'Enable Kerberos preauthentication for all user accounts. This is a critical security setting that should never be disabled',
                'cis_reference': 'CIS Benchmark requires Kerberos preauthentication for all accounts',
                'mitre_attack': 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting'
            })
        
        return risks
    
    def _check_spn_users(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    
    def _check_admin_count(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if user has adminCount flag set."""
        risks = []
        admin_count = user.get('adminCount')
        
        if admin_count == 1 or admin_count == '1':
            groups = user.get('memberOf') or []
            if not isinstance(groups, list):
                groups = [groups] if groups else []
            privileged_groups = [g for g in groups if g and any(priv in str(g) for priv in 
                ['Domain Admins', 'Enterprise Admins', 'Administrators', 'Account Operators'])]
            
            risks.append({
                'type': RiskTypes.ADMIN_COUNT_SET,
                'severity': Severity.HIGH,
                'title': 'AdminCount Flag Set',
                'description': f"User '{user.get('sAMAccountName')}' has adminCount=1, indicating administrative privileges",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'member_of': groups,
                'privileged_groups': privileged_groups,
                'impact': 'Users with adminCount=1 are protected by AdminSDHolder, indicating they have or had administrative privileges. This should be reviewed regularly',
                'attack_scenario': 'If an attacker compromises an account with adminCount=1, they gain administrative privileges with potential domain-wide impact',
                'mitigation': 'Regularly review accounts with adminCount=1. Ensure these accounts are necessary and properly secured with strong passwords and MFA. Remove adminCount if the account no longer requires administrative privileges',
                'cis_reference': 'CIS Benchmark recommends regular review of administrative accounts',
                'mitre_attack': 'T1078 - Valid Accounts'
            })
        
        return risks
    
    def _check_inactive_privileged(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for inactive privileged accounts."""
        risks = []
        
        # Check if user has privileged group membership
        groups = user.get('memberOf') or []
        if not isinstance(groups, list):
            groups = [groups] if groups else []
        privileged_groups = [g for g in groups if g and any(priv in str(g) for priv in 
            ['Domain Admins', 'Enterprise Admins', 'Administrators', 'Account Operators', 
             'Backup Operators', 'Server Operators'])]
        
        if not privileged_groups:
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
        
        if isinstance(last_logon, datetime):
            days_inactive = (datetime.now() - last_logon.replace(tzinfo=None)).days
            if days_inactive > TimeThresholds.INACTIVE_ACCOUNT_THRESHOLD:
                risks.append({
                    'type': RiskTypes.INACTIVE_PRIVILEGED_ACCOUNT,
                    'severity': Severity.MEDIUM,
                    'title': 'Inactive Privileged Account',
                    'description': f"Privileged user '{user.get('sAMAccountName')}' has not logged in for {days_inactive} days",
                    'affected_object': user.get('sAMAccountName'),
                    'object_type': 'user',
                    'days_inactive': days_inactive,
                    'privileged_groups': privileged_groups,
                    'impact': 'Inactive privileged accounts pose a security risk as they may be forgotten and not properly secured, or may have been compromised without detection',
                    'attack_scenario': 'An attacker who compromises an inactive privileged account may go undetected for extended periods, as the account owner is not actively monitoring it',
                    'mitigation': 'Review inactive privileged accounts regularly. Disable or remove accounts that are no longer needed. Ensure all active privileged accounts have strong passwords and MFA enabled',
                    'cis_reference': 'CIS Benchmark recommends disabling inactive accounts',
                    'mitre_attack': 'T1078 - Valid Accounts'
                })
        
        return risks
    
    def _check_disabled_account(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if user account is disabled."""
        risks = []
        
        if user.get('isDisabled'):
            risks.append({
                'type': RiskTypes.DISABLED_USER_ACCOUNT,
                'severity': Severity.LOW,
                'title': 'Disabled User Account',
                'description': f"User account '{user.get('sAMAccountName')}' is disabled",
                'affected_object': user.get('sAMAccountName'),
                'object_type': 'user',
                'impact': 'Disabled accounts should be reviewed to ensure they are not needed or should be removed',
                'attack_scenario': 'Disabled accounts that are re-enabled without proper review could pose security risks',
                'mitigation': 'Review disabled accounts regularly. Remove accounts that are no longer needed. Ensure proper approval process before re-enabling accounts',
                'cis_reference': 'CIS Benchmark recommends removing unused accounts',
                'mitre_attack': 'T1078 - Valid Accounts'
            })
        
        return risks
    
    def _check_locked_account(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    
    def _check_service_account_password_never_expires(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
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
    
    def _check_recently_created_account(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if account was created recently (potential security concern)."""
        risks = []
        
        # Only flag if account was created in last threshold days and has admin privileges
        if user.get('createdInLast30Days') and (user.get('adminCount') == 1 or user.get('adminCount') == '1' or user.get('adminGroups')):
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
    
    def _check_recently_modified_group_membership(self, user: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check if group membership was modified recently (potential security concern)."""
        risks = []
        
        # Only flag if group membership was changed in last 30 days and user has admin privileges
        if user.get('groupChangedInLast30Days') and (user.get('adminCount') == 1 or user.get('adminCount') == '1' or user.get('adminGroups')):
            days_ago = None
            if user.get('groupChangedInLast10Days'):
                days_ago = 'last 10 days'
            elif user.get('groupChangedInLast30Days'):
                days_ago = 'last 30 days'
            elif user.get('groupChangedInLast60Days'):
                days_ago = 'last 60 days'
            elif user.get('groupChangedInLast90Days'):
                days_ago = 'last 90 days'
            
            if days_ago:
                risks.append({
                    'type': RiskTypes.RECENTLY_MODIFIED_GROUP_MEMBERSHIP,
                    'severity': Severity.MEDIUM,
                    'title': 'Recently Modified Group Membership',
                    'description': f"Privileged account '{user.get('sAMAccountName')}' had group membership modified in the {days_ago}",
                    'affected_object': user.get('sAMAccountName'),
                    'object_type': 'user',
                    'adminGroups': user.get('adminGroups', []),
                    'impact': 'Recent group membership changes on privileged accounts should be reviewed to ensure they are legitimate and authorized',
                    'attack_scenario': 'An attacker who gains access to a privileged account might modify group memberships to maintain persistence or escalate privileges',
                    'mitigation': 'Review recent group membership changes on privileged accounts. Verify they are legitimate and authorized. Monitor for unauthorized group membership modifications',
                    'cis_reference': 'CIS Benchmark recommends monitoring group membership changes',
                    'mitre_attack': 'T1078 - Valid Accounts'
                })
        
        return risks
