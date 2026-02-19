"""
Advanced Compliance Analyzer Module
Performs LDAP-based compliance checks for CIS Benchmark, NIST CSF, ISO 27001, and GDPR
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class ComplianceAnalyzer:
    """
    Advanced compliance analyzer that performs LDAP queries to check compliance.
    """
    
    def __init__(self, ldap_connection):
        """
        Initialize compliance analyzer.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
        self.base_dn = ldap_connection.base_dn
    
    def analyze_cis_benchmark(self, users: List[Dict[str, Any]], 
                              groups: List[Dict[str, Any]], 
                              computers: List[Dict[str, Any]],
                              password_policy_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform CIS Benchmark compliance checks using LDAP queries.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            password_policy_data: Optional password policy data
            
        Returns:
            Dict with CIS Benchmark compliance analysis
        """
        controls = []
        
        # CIS 2.3.1.1 - Ensure 'Password never expires' is set to 'False' for all users
        password_never_expires_count = sum(1 for u in users if u.get('userAccountControl', 0) & 0x10000)
        controls.append({
            'control_id': 'CIS 2.3.1.1',
            'control_name': 'Password never expires',
            'status': 'passed' if password_never_expires_count == 0 else 'failed',
            'details': {
                'count': password_never_expires_count,
                'affected_users': [u.get('sAMAccountName') for u in users if u.get('userAccountControl', 0) & 0x10000][:10]
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
            'recommendation': 'Set password expiration for all user accounts'
        })
        
        # CIS 2.3.1.2 - Ensure 'Password not required' is set to 'False' for all users
        password_not_required_count = sum(1 for u in users if u.get('userAccountControl', 0) & 0x20)
        controls.append({
            'control_id': 'CIS 2.3.1.2',
            'control_name': 'Password not required',
            'status': 'passed' if password_not_required_count == 0 else 'failed',
            'details': {
                'count': password_not_required_count,
                'affected_users': [u.get('sAMAccountName') for u in users if u.get('userAccountControl', 0) & 0x20][:10]
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))',
            'recommendation': 'Require passwords for all user accounts'
        })
        
        # CIS 2.3.1.3 - Ensure 'Kerberos preauthentication' is enabled for all users
        preauth_disabled_count = sum(1 for u in users if u.get('userAccountControl', 0) & 0x400000)
        controls.append({
            'control_id': 'CIS 2.3.1.3',
            'control_name': 'Kerberos preauthentication',
            'status': 'passed' if preauth_disabled_count == 0 else 'failed',
            'details': {
                'count': preauth_disabled_count,
                'affected_users': [u.get('sAMAccountName') for u in users if u.get('userAccountControl', 0) & 0x400000][:10]
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
            'recommendation': 'Enable Kerberos preauthentication for all user accounts'
        })
        
        # CIS 2.3.1.4 - Ensure unconstrained delegation is disabled
        unconstrained_delegation_count = sum(1 for c in computers if c.get('userAccountControl', 0) & 0x80000)
        controls.append({
            'control_id': 'CIS 2.3.1.4',
            'control_name': 'Unconstrained delegation',
            'status': 'passed' if unconstrained_delegation_count == 0 else 'failed',
            'details': {
                'count': unconstrained_delegation_count,
                'affected_computers': [c.get('name') for c in computers if c.get('userAccountControl', 0) & 0x80000][:10]
            },
            'ldap_query': '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
            'recommendation': 'Disable unconstrained delegation on all computer accounts'
        })
        
        # CIS 2.3.1.5 - Ensure Domain Admins group has minimal members
        domain_admins = next((g for g in groups if 'DOMAIN ADMINS' in (g.get('name', '') or '').upper()), None)
        domain_admin_count = len(domain_admins.get('member', [])) if domain_admins and domain_admins.get('member') else 0
        controls.append({
            'control_id': 'CIS 2.3.1.5',
            'control_name': 'Domain Admins membership',
            'status': 'passed' if domain_admin_count <= 2 else 'failed',
            'details': {
                'count': domain_admin_count,
                'members': domain_admins.get('member', [])[:10] if domain_admins else []
            },
            'ldap_query': '(&(objectClass=group)(name=Domain Admins))',
            'recommendation': 'Limit Domain Admins group to 2 or fewer members'
        })
        
        # CIS 2.3.2.1 - Password policy checks
        if password_policy_data:
            min_length = password_policy_data.get('minPwdLength', 0)
            max_age_raw = password_policy_data.get('maxPwdAge', 0)
            pwd_properties = password_policy_data.get('pwdProperties', 0)
            complexity_enabled = bool(pwd_properties & 1)
            
            # Convert maxPwdAge from Windows timestamp (100-nanosecond intervals) to days
            # Use same conversion logic as password_policy_analyzer
            max_age_days = 0
            if max_age_raw:
                try:
                    if isinstance(max_age_raw, (int, str)):
                        max_age_raw = int(max_age_raw)
                        # Convert from 100-nanosecond intervals to days
                        # Note: password_policy_analyzer uses division by 864000000000
                        # Negative value means password expires, 0 means never expires
                        if max_age_raw < 0:
                            # Use same conversion as password_policy_analyzer._convert_timespan_to_days
                            max_age_days = int(abs(max_age_raw) / 864000000000)
                        elif max_age_raw == 0:
                            max_age_days = 999999  # Never expires (bad)
                except (ValueError, TypeError):
                    max_age_days = 0
            
            controls.append({
                'control_id': 'CIS 2.3.2.1',
                'control_name': 'Password policy strength',
                'status': 'passed' if min_length >= 14 and max_age_days <= 90 and complexity_enabled else 'failed',
                'details': {
                    'min_length': min_length,
                    'max_age_days': max_age_days,
                    'complexity_enabled': complexity_enabled,
                    'pwd_history_length': password_policy_data.get('pwdHistoryLength', 0)
                },
                'ldap_query': '(objectClass=domainDNS)',
                'recommendation': 'Set minimum password length to 14+, maximum age to 90 days or less, enable complexity'
            })
        
        # CIS 2.3.2.2 - Account lockout policy
        if password_policy_data:
            lockout_threshold = password_policy_data.get('lockoutThreshold', 0)
            lockout_duration_raw = password_policy_data.get('lockoutDuration', 0)
            lockout_observation_window_raw = password_policy_data.get('lockoutObservationWindow', 0)
            
            # Convert lockout duration and observation window from Windows timestamp to minutes
            # Using same conversion logic: divide by 864000000000 to get days, then convert to minutes
            lockout_duration_minutes = 0
            lockout_observation_window_minutes = 0
            
            if lockout_duration_raw:
                try:
                    if isinstance(lockout_duration_raw, (int, str)):
                        lockout_duration_raw = int(lockout_duration_raw)
                        if lockout_duration_raw < 0:
                            # Convert to days first, then to minutes
                            days = abs(lockout_duration_raw) / 864000000000
                            lockout_duration_minutes = int(days * 24 * 60)
                except (ValueError, TypeError):
                    pass
            
            if lockout_observation_window_raw:
                try:
                    if isinstance(lockout_observation_window_raw, (int, str)):
                        lockout_observation_window_raw = int(lockout_observation_window_raw)
                        if lockout_observation_window_raw < 0:
                            # Convert to days first, then to minutes
                            days = abs(lockout_observation_window_raw) / 864000000000
                            lockout_observation_window_minutes = int(days * 24 * 60)
                except (ValueError, TypeError):
                    pass
            
            controls.append({
                'control_id': 'CIS 2.3.2.2',
                'control_name': 'Account lockout policy',
                'status': 'passed' if lockout_threshold > 0 and lockout_threshold <= 10 else 'failed',
                'details': {
                    'lockout_threshold': lockout_threshold,
                    'lockout_duration_minutes': lockout_duration_minutes,
                    'lockout_observation_window_minutes': lockout_observation_window_minutes
                },
                'ldap_query': '(objectClass=domainDNS)',
                'recommendation': 'Enable account lockout with threshold of 5-10 failed attempts'
            })
        
        # CIS 2.3.3.1 - EOL operating systems
        eol_count = sum(1 for c in computers if c.get('operatingSystem') and 
                       any(eol in (c.get('operatingSystem', '') or '').upper() 
                           for eol in ['WINDOWS SERVER 2008', 'WINDOWS SERVER 2012', 'WINDOWS XP', 'WINDOWS VISTA']))
        controls.append({
            'control_id': 'CIS 2.3.3.1',
            'control_name': 'EOL operating systems',
            'status': 'passed' if eol_count == 0 else 'failed',
            'details': {
                'count': eol_count,
                'affected_computers': [c.get('name') for c in computers if c.get('operatingSystem') and 
                                      any(eol in (c.get('operatingSystem', '') or '').upper() 
                                          for eol in ['WINDOWS SERVER 2008', 'WINDOWS SERVER 2012', 'WINDOWS XP', 'WINDOWS VISTA'])][:10]
            },
            'ldap_query': '(&(objectClass=computer)(operatingSystem=*))',
            'recommendation': 'Upgrade or remove End-of-Life operating systems'
        })
        
        # CIS 2.3.4.1 - LAPS configuration
        # Check LAPS by examining existing computer objects for LAPS attributes
        # Instead of querying ms-Mcs-AdmPwd directly (which may not exist), check computers we already have
        try:
            laps_configured_count = 0
            total_computers = len(computers)
            
            # Check if any computers have LAPS-related attributes
            # LAPS attributes: ms-Mcs-AdmPwdExpirationTime, msMcs-AdmPwdExpirationTime
            laps_attribute_names = ['ms-Mcs-AdmPwdExpirationTime', 'msMcs-AdmPwdExpirationTime', 'msMcsAdmPwdExpirationTime']
            
            for computer in computers:
                # Check if computer has any LAPS expiration time attribute
                for attr_name in laps_attribute_names:
                    if computer.get(attr_name):
                        laps_configured_count += 1
                        break
            
            # Alternative: Try a safe LDAP query if attribute might exist
            # Only query if we have no computers with LAPS attributes from our existing data
            if laps_configured_count == 0 and total_computers > 0:
                try:
                    # Try querying for computers with LAPS expiration time (safer than password attribute)
                    laps_results = self.ldap.search(
                        search_base=self.base_dn,
                        search_filter='(&(objectClass=computer)(|(ms-Mcs-AdmPwdExpirationTime=*)(msMcs-AdmPwdExpirationTime=*)))',
                        attributes=['name']
                    )
                    if laps_results:
                        laps_configured_count = len(laps_results)
                except Exception:
                    # If query fails, continue with count from existing data
                    pass
            
            laps_percentage = (laps_configured_count / total_computers * 100) if total_computers > 0 else 0
            
            controls.append({
                'control_id': 'CIS 2.3.4.1',
                'control_name': 'LAPS configuration',
                'status': 'passed' if laps_percentage >= 90 else 'failed',
                'details': {
                    'configured_count': laps_configured_count,
                    'total_computers': total_computers,
                    'percentage': round(laps_percentage, 2)
                },
                'ldap_query': '(&(objectClass=computer)(|(ms-Mcs-AdmPwdExpirationTime=*)(msMcs-AdmPwdExpirationTime=*)))',
                'recommendation': 'Install and configure LAPS on at least 90% of computers'
            })
        except Exception as e:
            logger.debug(f"Error checking LAPS: {e}")
            controls.append({
                'control_id': 'CIS 2.3.4.1',
                'control_name': 'LAPS configuration',
                'status': 'unknown',
                'details': {
                    'error': str(e),
                    'total_computers': len(computers)
                },
                'ldap_query': '(&(objectClass=computer)(|(ms-Mcs-AdmPwdExpirationTime=*)(msMcs-AdmPwdExpirationTime=*)))',
                'recommendation': 'Check LAPS installation status'
            })
        
        # CIS 2.3.5.1 - GPP passwords
        try:
            gpp_results = self.ldap.search(
                search_base=self.base_dn,
                search_filter='(objectClass=groupPolicyContainer)',
                attributes=['gPCFileSysPath', 'name']
            )
            gpp_count = len(gpp_results) if gpp_results else 0
            # Note: Actual GPP password extraction requires SYSVOL access
            controls.append({
                'control_id': 'CIS 2.3.5.1',
                'control_name': 'GPP passwords',
                'status': 'warning',
                'details': {
                    'gpo_count': gpp_count,
                    'note': 'GPP password detection requires SYSVOL access'
                },
                'ldap_query': '(objectClass=groupPolicyContainer)',
                'recommendation': 'Audit SYSVOL for GPP files containing passwords'
            })
        except Exception as e:
            logger.debug(f"Error checking GPP: {e}")
        
        # CIS 2.3.6.1 - DCSync rights
        try:
            # Check for DCSync rights by examining ACLs on domain root
            domain_root = self.ldap.search(
                search_base=self.base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['distinguishedName']
            )
            if domain_root:
                # DCSync requires Replicating Directory Changes and Replicating Directory Changes All
                # This is complex to check via LDAP, so we mark as warning
                controls.append({
                    'control_id': 'CIS 2.3.6.1',
                    'control_name': 'DCSync rights',
                    'status': 'warning',
                    'details': {
                        'note': 'DCSync rights check requires ACL analysis'
                    },
                    'ldap_query': '(objectClass=domainDNS)',
                    'recommendation': 'Audit ACLs for Replicating Directory Changes rights'
                })
        except Exception as e:
            logger.debug(f"Error checking DCSync: {e}")
        
        # CIS 2.3.7.1 - Trust SID filtering
        try:
            trusts = self.ldap.search(
                search_base=self.base_dn,
                search_filter='(objectClass=trustedDomain)',
                attributes=['trustAttributes', 'name', 'trustDirection']
            )
            sid_filtering_disabled = []
            if trusts:
                for trust in trusts:
                    trust_attrs = trust.get('trustAttributes', 0)
                    # Trust attribute: SID filtering is enabled when bit 0x4 is NOT set
                    # trustAttributes value meanings:
                    # - 0x1 = Non-transitive
                    # - 0x4 = SID filtering disabled (bad)
                    # - 0x8 = Quarantined domain
                    # - 0x40 = Forest trust
                    if isinstance(trust_attrs, (int, str)):
                        try:
                            trust_attrs = int(trust_attrs) if isinstance(trust_attrs, str) else trust_attrs
                            # Check if SID filtering is disabled (bit 0x4 is set)
                            if trust_attrs & 0x4:  # SID filtering disabled
                                sid_filtering_disabled.append(trust.get('name', 'Unknown'))
                        except (ValueError, TypeError):
                            logger.debug(f"Could not parse trustAttributes: {trust_attrs}")
            
            controls.append({
                'control_id': 'CIS 2.3.7.1',
                'control_name': 'Trust SID filtering',
                'status': 'passed' if len(sid_filtering_disabled) == 0 else 'failed',
                'details': {
                    'total_trusts': len(trusts) if trusts else 0,
                    'sid_filtering_disabled_count': len(sid_filtering_disabled),
                    'affected_trusts': sid_filtering_disabled[:10]
                },
                'ldap_query': '(objectClass=trustedDomain)',
                'recommendation': 'Enable SID filtering on all trust relationships'
            })
        except Exception as e:
            logger.debug(f"Error checking trusts: {e}")
        
        # Calculate compliance score
        passed = sum(1 for c in controls if c.get('status') == 'passed')
        failed = sum(1 for c in controls if c.get('status') == 'failed')
        total = len(controls)
        compliance_score = (passed / total * 100) if total > 0 else 0.0
        
        return {
            'framework': 'CIS Benchmark',
            'total_controls': total,
            'passed_controls': passed,
            'failed_controls': failed,
            'warning_controls': sum(1 for c in controls if c.get('status') == 'warning'),
            'compliance_score': compliance_score,
            'controls': controls,
            'timestamp': datetime.now().isoformat()
        }
    
    def analyze_nist_csf(self, users: List[Dict[str, Any]], 
                        groups: List[Dict[str, Any]], 
                        computers: List[Dict[str, Any]],
                        password_policy_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform NIST Cybersecurity Framework compliance checks using LDAP queries.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            password_policy_data: Optional password policy data
            
        Returns:
            Dict with NIST CSF compliance analysis
        """
        functions = {
            'PR': {'name': 'Protect', 'controls': [], 'status': 'partial'},
            'DE': {'name': 'Detect', 'controls': [], 'status': 'partial'},
            'RS': {'name': 'Respond', 'controls': [], 'status': 'partial'},
            'RC': {'name': 'Recover', 'controls': [], 'status': 'partial'},
            'ID': {'name': 'Identify', 'controls': [], 'status': 'partial'}
        }
        
        # PR.AC-1: Identity and access management
        # Check for accounts with password never expires
        password_never_expires = sum(1 for u in users if u.get('userAccountControl', 0) & 0x10000)
        functions['PR']['controls'].append({
            'control_id': 'PR.AC-1',
            'control_name': 'Identity and access management',
            'status': 'passed' if password_never_expires == 0 else 'failed',
            'details': {
                'password_never_expires_count': password_never_expires,
                'total_users': len(users)
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))'
        })
        
        # PR.AC-1: Check for accounts without passwords
        password_not_required = sum(1 for u in users if u.get('userAccountControl', 0) & 0x20)
        functions['PR']['controls'].append({
            'control_id': 'PR.AC-1',
            'control_name': 'Password requirements',
            'status': 'passed' if password_not_required == 0 else 'failed',
            'details': {
                'password_not_required_count': password_not_required
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))'
        })
        
        # PR.AC-7: Unsuccessful logon attempts
        if password_policy_data:
            lockout_threshold = password_policy_data.get('lockoutThreshold', 0)
            functions['PR']['controls'].append({
                'control_id': 'PR.AC-7',
                'control_name': 'Unsuccessful logon attempts',
                'status': 'passed' if lockout_threshold > 0 else 'failed',
                'details': {
                    'lockout_threshold': lockout_threshold
                },
                'ldap_query': '(objectClass=domainDNS)'
            })
        
        # PR.DS-2: Data-at-rest protection
        # Check for EOL systems
        eol_count = sum(1 for c in computers if c.get('operatingSystem') and 
                       any(eol in (c.get('operatingSystem', '') or '').upper() 
                           for eol in ['WINDOWS SERVER 2008', 'WINDOWS SERVER 2012']))
        functions['PR']['controls'].append({
            'control_id': 'PR.DS-2',
            'control_name': 'Data-at-rest protection',
            'status': 'passed' if eol_count == 0 else 'failed',
            'details': {
                'eol_systems_count': eol_count,
                'total_computers': len(computers)
            },
            'ldap_query': '(&(objectClass=computer)(operatingSystem=*))'
        })
        
        # DE.AE: Anomalies and events
        # Check for inactive accounts (potential security risk)
        inactive_threshold = datetime.now() - timedelta(days=90)
        inactive_count = 0
        for u in users:
            last_logon = u.get('lastLogonTimestamp')
            if last_logon:
                # Handle both datetime objects and timestamp strings
                logon_dt = None
                if isinstance(last_logon, datetime):
                    logon_dt = last_logon
                elif isinstance(last_logon, str):
                    try:
                        # Try ISO format
                        logon_dt = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
                    except (ValueError, AttributeError):
                        # If parsing fails, skip this user
                        continue
                
                if logon_dt and isinstance(logon_dt, datetime):
                    # Compare datetime objects
                    try:
                        if logon_dt < inactive_threshold and not (u.get('userAccountControl', 0) & 0x2):
                            inactive_count += 1
                    except (TypeError, ValueError):
                        # Skip if comparison fails
                        continue
        functions['DE']['controls'].append({
            'control_id': 'DE.AE-1',
            'control_name': 'Anomalies and events detection',
            'status': 'warning' if inactive_count > len(users) * 0.1 else 'passed',
            'details': {
                'inactive_accounts_count': inactive_count,
                'threshold_days': 90
            },
            'ldap_query': '(&(objectClass=user)(lastLogonTimestamp<=*))'
        })
        
        # Calculate scores per function
        for func_id, func_data in functions.items():
            if func_data['controls']:
                passed = sum(1 for c in func_data['controls'] if c.get('status') == 'passed')
                total = len(func_data['controls'])
                func_data['score'] = (passed / total * 100) if total > 0 else 0.0
                func_data['status'] = 'passed' if func_data['score'] >= 80 else 'partial' if func_data['score'] >= 50 else 'failed'
        
        # Calculate overall compliance score
        total_score = sum(f.get('score', 0) for f in functions.values() if f.get('controls'))
        compliance_score = total_score / len([f for f in functions.values() if f.get('controls')]) if functions else 0.0
        
        return {
            'framework': 'NIST Cybersecurity Framework',
            'compliance_score': compliance_score,
            'functions': functions,
            'timestamp': datetime.now().isoformat()
        }
    
    def analyze_iso_27001(self, users: List[Dict[str, Any]], 
                          groups: List[Dict[str, Any]], 
                          computers: List[Dict[str, Any]],
                          password_policy_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform ISO 27001 compliance checks using LDAP queries.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            password_policy_data: Optional password policy data
            
        Returns:
            Dict with ISO 27001 compliance analysis
        """
        domains = defaultdict(list)
        
        # A.9.2.1: User registration and de-registration
        # Check for disabled accounts that should be removed
        disabled_accounts = [u for u in users if u.get('userAccountControl', 0) & 0x2]
        domains['A.9.2'].append({
            'control_id': 'A.9.2.1',
            'control_name': 'User registration and de-registration',
            'status': 'warning' if len(disabled_accounts) > len(users) * 0.1 else 'passed',
            'details': {
                'disabled_accounts_count': len(disabled_accounts),
                'total_users': len(users)
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
        })
        
        # A.9.4.2: Secure log-on procedures
        preauth_disabled = sum(1 for u in users if u.get('userAccountControl', 0) & 0x400000)
        domains['A.9.4'].append({
            'control_id': 'A.9.4.2',
            'control_name': 'Secure log-on procedures',
            'status': 'passed' if preauth_disabled == 0 else 'failed',
            'details': {
                'preauth_disabled_count': preauth_disabled
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        })
        
        # A.9.4.3: Password management system
        if password_policy_data:
            min_length = password_policy_data.get('minPwdLength', 0)
            max_age_raw = password_policy_data.get('maxPwdAge', 0)
            pwd_properties = password_policy_data.get('pwdProperties', 0)
            complexity_enabled = bool(pwd_properties & 1)
            
            # Convert maxPwdAge to days
            # Use same conversion logic as password_policy_analyzer
            max_age_days = 0
            if max_age_raw:
                try:
                    if isinstance(max_age_raw, (int, str)):
                        max_age_raw = int(max_age_raw)
                        if max_age_raw < 0:
                            max_age_days = int(abs(max_age_raw) / 864000000000)
                        elif max_age_raw == 0:
                            max_age_days = 999999  # Never expires
                except (ValueError, TypeError):
                    max_age_days = 0
            
            domains['A.9.4'].append({
                'control_id': 'A.9.4.3',
                'control_name': 'Password management system',
                'status': 'passed' if min_length >= 8 and max_age_days <= 90 and complexity_enabled else 'failed',
                'details': {
                    'min_length': min_length,
                    'max_age_days': max_age_days,
                    'complexity_enabled': complexity_enabled
                },
                'ldap_query': '(objectClass=domainDNS)'
            })
        
        # A.12.6.1: Management of technical vulnerabilities
        eol_count = sum(1 for c in computers if c.get('operatingSystem') and 
                       any(eol in (c.get('operatingSystem', '') or '').upper() 
                           for eol in ['WINDOWS SERVER 2008', 'WINDOWS SERVER 2012']))
        domains['A.12.6'].append({
            'control_id': 'A.12.6.1',
            'control_name': 'Management of technical vulnerabilities',
            'status': 'passed' if eol_count == 0 else 'failed',
            'details': {
                'eol_systems_count': eol_count
            },
            'ldap_query': '(&(objectClass=computer)(operatingSystem=*))'
        })
        
        # Calculate scores per domain
        domain_scores = {}
        for domain, controls in domains.items():
            if controls:
                passed = sum(1 for c in controls if c.get('status') == 'passed')
                total = len(controls)
                domain_scores[domain] = (passed / total * 100) if total > 0 else 0.0
        
        overall_score = sum(domain_scores.values()) / len(domain_scores) if domain_scores else 0.0
        
        return {
            'framework': 'ISO 27001',
            'compliance_score': overall_score,
            'domains': dict(domains),
            'domain_scores': domain_scores,
            'timestamp': datetime.now().isoformat()
        }
    
    def analyze_gdpr(self, users: List[Dict[str, Any]], 
                    groups: List[Dict[str, Any]], 
                    computers: List[Dict[str, Any]],
                    password_policy_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform GDPR compliance checks using LDAP queries.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            password_policy_data: Optional password policy data
            
        Returns:
            Dict with GDPR compliance analysis
        """
        articles = defaultdict(list)
        
        # Article 32: Security of processing
        # Check password policy strength
        if password_policy_data:
            min_length = password_policy_data.get('minPwdLength', 0)
            complexity_enabled = bool(password_policy_data.get('pwdProperties', 0) & 1)
            
            articles['Article 32'].append({
                'control_id': 'Article 32',
                'control_name': 'Security of processing - Password strength',
                'status': 'passed' if min_length >= 8 and complexity_enabled else 'failed',
                'details': {
                    'min_length': min_length,
                    'complexity_enabled': complexity_enabled
                },
                'ldap_query': '(objectClass=domainDNS)',
                'description': 'Ensure strong password policies to protect personal data'
            })
        
        # Article 32: Account lockout
        if password_policy_data:
            lockout_threshold = password_policy_data.get('lockoutThreshold', 0)
            articles['Article 32'].append({
                'control_id': 'Article 32',
                'control_name': 'Security of processing - Account protection',
                'status': 'passed' if lockout_threshold > 0 else 'failed',
                'details': {
                    'lockout_threshold': lockout_threshold
                },
                'ldap_query': '(objectClass=domainDNS)',
                'description': 'Enable account lockout to prevent unauthorized access to personal data'
            })
        
        # Article 32: Check for accounts without passwords
        password_not_required = sum(1 for u in users if u.get('userAccountControl', 0) & 0x20)
        articles['Article 32'].append({
            'control_id': 'Article 32',
            'control_name': 'Security of processing - Access control',
            'status': 'passed' if password_not_required == 0 else 'failed',
            'details': {
                'password_not_required_count': password_not_required
            },
            'ldap_query': '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))',
            'description': 'Ensure all accounts require passwords to protect personal data'
        })
        
        # Article 32: Check for excessive privileges
        domain_admins = next((g for g in groups if 'DOMAIN ADMINS' in (g.get('name', '') or '').upper()), None)
        domain_admin_count = len(domain_admins.get('member', [])) if domain_admins and domain_admins.get('member') else 0
        articles['Article 32'].append({
            'control_id': 'Article 32',
            'control_name': 'Security of processing - Privilege management',
            'status': 'passed' if domain_admin_count <= 5 else 'warning',
            'details': {
                'domain_admin_count': domain_admin_count
            },
            'ldap_query': '(&(objectClass=group)(name=Domain Admins))',
            'description': 'Limit privileged access to personal data'
        })
        
        # Calculate scores per article
        article_scores = {}
        for article, controls in articles.items():
            if controls:
                passed = sum(1 for c in controls if c.get('status') == 'passed')
                total = len(controls)
                article_scores[article] = (passed / total * 100) if total > 0 else 0.0
        
        overall_score = sum(article_scores.values()) / len(article_scores) if article_scores else 0.0
        
        return {
            'framework': 'GDPR',
            'compliance_score': overall_score,
            'articles': dict(articles),
            'article_scores': article_scores,
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_comprehensive_compliance_report(self, users: List[Dict[str, Any]], 
                                                groups: List[Dict[str, Any]], 
                                                computers: List[Dict[str, Any]],
                                                password_policy_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report for all frameworks using LDAP queries.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            password_policy_data: Optional password policy data
            
        Returns:
            Dict with all compliance analyses
        """
        cis_result = self.analyze_cis_benchmark(users, groups, computers, password_policy_data)
        nist_result = self.analyze_nist_csf(users, groups, computers, password_policy_data)
        iso_result = self.analyze_iso_27001(users, groups, computers, password_policy_data)
        gdpr_result = self.analyze_gdpr(users, groups, computers, password_policy_data)
        cis_v8_result = self._analyze_cis_controls_v8_from_data(users, groups, computers, password_policy_data)

        overall_score = (
            cis_result['compliance_score'] +
            nist_result['compliance_score'] +
            iso_result['compliance_score'] +
            gdpr_result['compliance_score'] +
            cis_v8_result['compliance_score']
        ) / 5

        return {
            'cis_benchmark': cis_result,
            'nist_csf': nist_result,
            'iso_27001': iso_result,
            'gdpr': gdpr_result,
            'cis_controls_v8': cis_v8_result,
            'overall_compliance_score': overall_score,
            'timestamp': datetime.now().isoformat()
        }

    def _analyze_cis_controls_v8_from_data(
        self,
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]],
        computers: List[Dict[str, Any]],
        password_policy_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Derive CIS Controls v8 compliance from LDAP data."""
        failed = []
        # Map CIS controls to checks (simplified)
        if any(u.get('userAccountControl', 0) & 0x10000 for u in users):
            failed.append('4.3')
        if any(u.get('userAccountControl', 0) & 0x20 for u in users):
            failed.append('5.2')
        if any(u.get('userAccountControl', 0) & 0x400000 for u in users):
            failed.append('5.2')
        if any(c.get('userAccountControl', 0) & 0x80000 for c in computers):
            failed.append('5.2')
        admin_groups = [g for g in groups if 'DOMAIN ADMINS' in str(g.get('name', '')).upper()]
        if admin_groups:
            members = admin_groups[0].get('member', []) or admin_groups[0].get('members', [])
            if not isinstance(members, list):
                members = [members] if members else []
            if len(members) > 5:
                failed.append('5.1')
        total_safeguards = 20
        passed = total_safeguards - len(failed)
        return {
            'framework': 'CIS Controls v8',
            'compliance_score': max(0, passed / total_safeguards * 100),
            'failed_safeguards': failed,
            'passed_safeguards': total_safeguards - len(failed),
        }
