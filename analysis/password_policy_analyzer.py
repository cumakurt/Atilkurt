"""
Password Policy Analyzer Module
Analyzes domain password policy and account lockout policy
"""

import logging
from typing import List, Dict, Any, Optional
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class PasswordPolicyAnalyzer:
    """Analyzes password policy and account lockout policy."""
    
    def __init__(self, ldap_connection):
        """
        Initialize password policy analyzer.
        
        Args:
            ldap_connection: LDAPConnection instance
        """
        self.ldap = ldap_connection
    
    def analyze_password_policy(self) -> List[Dict[str, Any]]:
        """
        Analyze domain password policy.
        
        Returns:
            List of risk dictionaries for weak password policies
        """
        risks = []
        
        try:
            # Get domain root DN
            base_dn = self.ldap.base_dn
            
            # Try multiple approaches to get password policy
            domain_info = None
            
            # Approach 1: Query domain root object directly
            try:
                results = self.ldap.search(
                    search_base=base_dn,
                    search_filter='(objectClass=domainDNS)',
                    attributes=['minPwdLength', 'maxPwdAge', 'minPwdAge', 
                              'pwdHistoryLength', 'pwdProperties', 
                              'lockoutThreshold', 'lockoutDuration', 
                              'lockoutObservationWindow', 'distinguishedName']
                )
                
                if results and len(results) > 0:
                    domain_info = results[0]
                    logger.debug(f"Found domain object at: {domain_info.get('distinguishedName', base_dn)}")
            except Exception as e:
                logger.debug(f"Error querying domain root: {e}")
            
            # Approach 2: If not found, try searching from root
            if not domain_info:
                try:
                    # Try to find domain object
                    results = self.ldap.search(
                        search_filter='(objectClass=domainDNS)',
                        attributes=['minPwdLength', 'maxPwdAge', 'minPwdAge', 
                                  'pwdHistoryLength', 'pwdProperties', 
                                  'lockoutThreshold', 'lockoutDuration', 
                                  'lockoutObservationWindow', 'distinguishedName']
                    )
                    
                    if results and len(results) > 0:
                        domain_info = results[0]
                        logger.debug(f"Found domain object via search: {domain_info.get('distinguishedName', 'Unknown')}")
                except Exception as e:
                    logger.debug(f"Error searching for domain object: {e}")
            
            # Approach 3: Try Default Domain Policy container
            if not domain_info:
                try:
                    policy_dn = f"CN=Default Domain Policy,CN=System,{base_dn}"
                    results = self.ldap.search(
                        search_base=policy_dn,
                        search_filter='(objectClass=*)',
                        attributes=['minPwdLength', 'maxPwdAge', 'minPwdAge', 
                                  'pwdHistoryLength', 'pwdProperties', 
                                  'lockoutThreshold', 'lockoutDuration', 
                                  'lockoutObservationWindow']
                    )
                    
                    if results and len(results) > 0:
                        domain_info = results[0]
                        logger.debug(f"Found policy at: {policy_dn}")
                except Exception as e:
                    logger.debug(f"Error querying Default Domain Policy: {e}")
            
            if domain_info:
                    
                    # Analyze password policy
                    min_length = domain_info.get('minPwdLength')
                    max_age = domain_info.get('maxPwdAge')
                    min_age = domain_info.get('minPwdAge')
                    history_length = domain_info.get('pwdHistoryLength')
                    pwd_properties = domain_info.get('pwdProperties', 0)
                    
                    # Analyze lockout policy
                    lockout_threshold = domain_info.get('lockoutThreshold')
                    lockout_duration = domain_info.get('lockoutDuration')
                    lockout_window = domain_info.get('lockoutObservationWindow')
                    
                    policy_issues = []
                    
                    # Initialize variables for policy details
                    min_length_val = None
                    max_age_days_val = None
                    history_length_val = None
                    complexity_enabled_val = None
                    lockout_threshold_val = None
                    
                    # Check minimum password length
                    if min_length is not None:
                        try:
                            min_length_val = int(min_length) if isinstance(min_length, (int, str)) else 0
                            if min_length_val < 14:
                                policy_issues.append({
                                    'issue': f'Minimum password length is {min_length_val} (recommended: 14+)',
                                    'severity': Severity.HIGH if min_length_val < 8 else Severity.MEDIUM,
                                    'recommendation': 'Increase minimum password length to at least 14 characters'
                                })
                        except (ValueError, TypeError) as e:
                            logger.debug(f"Error parsing minPwdLength: {e}")
                    
                    # Check password age
                    if max_age is not None:
                        try:
                            max_age_days_val = self._convert_timespan_to_days(max_age)
                            if max_age_days_val > 90:
                                policy_issues.append({
                                    'issue': f'Maximum password age is {max_age_days_val} days (recommended: 90 or less)',
                                    'severity': Severity.MEDIUM,
                                    'recommendation': 'Set maximum password age to 90 days or less'
                                })
                            elif max_age_days_val == 0:
                                policy_issues.append({
                                    'issue': 'Passwords never expire (maximum age is 0)',
                                    'severity': Severity.HIGH,
                                    'recommendation': 'Set maximum password age to 90 days or less'
                                })
                        except Exception as e:
                            logger.debug(f"Error parsing maxPwdAge: {e}")
                    
                    # Check password history
                    if history_length is not None:
                        try:
                            history_length_val = int(history_length) if isinstance(history_length, (int, str)) else 0
                            if history_length_val < 12:
                                policy_issues.append({
                                    'issue': f'Password history length is {history_length_val} (recommended: 12+)',
                                    'severity': Severity.MEDIUM,
                                    'recommendation': 'Increase password history length to at least 12'
                                })
                        except (ValueError, TypeError) as e:
                            logger.debug(f"Error parsing pwdHistoryLength: {e}")
                    
                    # Check password complexity
                    if pwd_properties is not None:
                        try:
                            pwd_properties_int = int(pwd_properties) if isinstance(pwd_properties, (int, str)) else 0
                            complexity_enabled_val = bool(pwd_properties_int & 1)  # PASSWORD_COMPLEXITY flag
                            if not complexity_enabled_val:
                                policy_issues.append({
                                    'issue': 'Password complexity is disabled',
                                    'severity': Severity.HIGH,
                                    'recommendation': 'Enable password complexity requirements'
                                })
                        except (ValueError, TypeError) as e:
                            logger.debug(f"Error parsing pwdProperties: {e}")
                    
                    # Check lockout policy
                    if lockout_threshold is not None:
                        try:
                            lockout_threshold_val = int(lockout_threshold) if isinstance(lockout_threshold, (int, str)) else 0
                            if lockout_threshold_val == 0:
                                policy_issues.append({
                                    'issue': 'Account lockout is disabled (threshold is 0)',
                                    'severity': Severity.CRITICAL,
                                    'recommendation': 'Enable account lockout with threshold of 5-10 failed attempts'
                                })
                            elif lockout_threshold_val > 10:
                                policy_issues.append({
                                    'issue': f'Account lockout threshold is {lockout_threshold_val} (recommended: 5-10)',
                                    'severity': Severity.MEDIUM,
                                    'recommendation': 'Set account lockout threshold to 5-10 failed attempts'
                                })
                        except (ValueError, TypeError) as e:
                            logger.debug(f"Error parsing lockoutThreshold: {e}")
                    
                    # Create risks for each policy issue
                    for issue in policy_issues:
                        risks.append({
                            'type': RiskTypes.PASSWORD_POLICY_WEAK,
                            'severity': issue['severity'],
                            'title': f'Weak Password Policy: {issue["issue"]}',
                            'description': issue['issue'],
                            'affected_object': 'Domain Password Policy',
                            'object_type': 'policy',
                            'policy_detail': {
                                'min_length': min_length_val,
                                'max_age_days': max_age_days_val,
                                'history_length': history_length_val,
                                'complexity_enabled': complexity_enabled_val,
                                'lockout_threshold': lockout_threshold_val
                            },
                            'impact': (
                                'Weak password policies make it easier for attackers to guess or crack passwords. '
                                'This increases the risk of account compromise.'
                            ),
                            'attack_scenario': (
                                'Attackers can use brute-force or dictionary attacks to compromise accounts '
                                'with weak password policies. Disabled lockout allows unlimited attempts.'
                            ),
                            'mitigation': issue['recommendation'],
                            'cis_reference': 'CIS Benchmark provides specific password policy recommendations',
                            'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN
                        })
            else:
                # If no domain info found, create a warning risk
                logger.warning("Could not retrieve domain password policy information. Trying alternative methods...")
                
                # Try one more approach: query rootDSE for defaultNamingContext
                try:
                    # Try to get rootDSE
                    root_results = self.ldap.search(
                        search_base='',
                        search_filter='(objectClass=*)',
                        attributes=['defaultNamingContext']
                    )
                    
                    if root_results:
                        default_naming_context = root_results[0].get('defaultNamingContext')
                        if default_naming_context:
                            # Try querying with the naming context
                            results = self.ldap.search(
                                search_base=default_naming_context,
                                search_filter='(objectClass=domainDNS)',
                                attributes=['minPwdLength', 'maxPwdAge', 'minPwdAge', 
                                          'pwdHistoryLength', 'pwdProperties', 
                                          'lockoutThreshold', 'lockoutDuration', 
                                          'lockoutObservationWindow']
                            )
                            
                            if results and len(results) > 0:
                                domain_info = results[0]
                                logger.info("Successfully retrieved password policy using defaultNamingContext")
                                logger.info(f"Password policy attributes found: {list(domain_info.keys())}")
                                
                                # Re-analyze with found domain_info
                                # Extract policy values
                                min_length = domain_info.get('minPwdLength')
                                max_age = domain_info.get('maxPwdAge')
                                history_length = domain_info.get('pwdHistoryLength')
                                pwd_properties = domain_info.get('pwdProperties', 0)
                                lockout_threshold = domain_info.get('lockoutThreshold')
                                
                                # Analyze and create risks (reuse the same logic)
                                policy_issues = []
                                min_length_val = None
                                max_age_days_val = None
                                history_length_val = None
                                complexity_enabled_val = None
                                lockout_threshold_val = None
                                
                                # Check minimum password length
                                if min_length is not None:
                                    try:
                                        min_length_val = int(min_length) if isinstance(min_length, (int, str)) else 0
                                        if min_length_val < 14:
                                            policy_issues.append({
                                                'issue': f'Minimum password length is {min_length_val} (recommended: 14+)',
                                                'severity': Severity.HIGH if min_length_val < 8 else Severity.MEDIUM,
                                                'recommendation': 'Increase minimum password length to at least 14 characters'
                                            })
                                    except (ValueError, TypeError):
                                        pass
                                
                                # Check password age
                                if max_age is not None:
                                    try:
                                        max_age_days_val = self._convert_timespan_to_days(max_age)
                                        if max_age_days_val > 90:
                                            policy_issues.append({
                                                'issue': f'Maximum password age is {max_age_days_val} days (recommended: 90 or less)',
                                                'severity': Severity.MEDIUM,
                                                'recommendation': 'Set maximum password age to 90 days or less'
                                            })
                                        elif max_age_days_val == 0:
                                            policy_issues.append({
                                                'issue': 'Passwords never expire (maximum age is 0)',
                                                'severity': Severity.HIGH,
                                                'recommendation': 'Set maximum password age to 90 days or less'
                                            })
                                    except Exception:
                                        pass
                                
                                # Check password history
                                if history_length is not None:
                                    try:
                                        history_length_val = int(history_length) if isinstance(history_length, (int, str)) else 0
                                        if history_length_val < 12:
                                            policy_issues.append({
                                                'issue': f'Password history length is {history_length_val} (recommended: 12+)',
                                                'severity': Severity.MEDIUM,
                                                'recommendation': 'Increase password history length to at least 12'
                                            })
                                    except (ValueError, TypeError):
                                        pass
                                
                                # Check password complexity
                                if pwd_properties is not None:
                                    try:
                                        pwd_properties_int = int(pwd_properties) if isinstance(pwd_properties, (int, str)) else 0
                                        complexity_enabled_val = bool(pwd_properties_int & 1)
                                        if not complexity_enabled_val:
                                            policy_issues.append({
                                                'issue': 'Password complexity is disabled',
                                                'severity': Severity.HIGH,
                                                'recommendation': 'Enable password complexity requirements'
                                            })
                                    except (ValueError, TypeError):
                                        pass
                                
                                # Check lockout policy
                                if lockout_threshold is not None:
                                    try:
                                        lockout_threshold_val = int(lockout_threshold) if isinstance(lockout_threshold, (int, str)) else 0
                                        if lockout_threshold_val == 0:
                                            policy_issues.append({
                                                'issue': 'Account lockout is disabled (threshold is 0)',
                                                'severity': Severity.CRITICAL,
                                                'recommendation': 'Enable account lockout with threshold of 5-10 failed attempts'
                                            })
                                        elif lockout_threshold_val > 10:
                                            policy_issues.append({
                                                'issue': f'Account lockout threshold is {lockout_threshold_val} (recommended: 5-10)',
                                                'severity': Severity.MEDIUM,
                                                'recommendation': 'Set account lockout threshold to 5-10 failed attempts'
                                            })
                                    except (ValueError, TypeError):
                                        pass
                                
                                # Create risks for each policy issue
                                for issue in policy_issues:
                                    risks.append({
                                        'type': RiskTypes.PASSWORD_POLICY_WEAK,
                                        'severity': issue['severity'],
                                        'title': f'Weak Password Policy: {issue["issue"]}',
                                        'description': issue['issue'],
                                        'affected_object': 'Domain Password Policy',
                                        'object_type': 'policy',
                                        'policy_detail': {
                                            'min_length': min_length_val,
                                            'max_age_days': max_age_days_val,
                                            'history_length': history_length_val,
                                            'complexity_enabled': complexity_enabled_val,
                                            'lockout_threshold': lockout_threshold_val
                                        },
                                        'impact': (
                                            'Weak password policies make it easier for attackers to guess or crack passwords. '
                                            'This increases the risk of account compromise.'
                                        ),
                                        'attack_scenario': (
                                            'Attackers can use brute-force or dictionary attacks to compromise accounts '
                                            'with weak password policies. Disabled lockout allows unlimited attempts.'
                                        ),
                                        'mitigation': issue['recommendation'],
                                        'cis_reference': 'CIS Benchmark provides specific password policy recommendations',
                                        'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN
                                    })
                except Exception as e:
                    logger.debug(f"Error trying alternative method: {e}")
                
                # Create warning risk if still no data
                if not domain_info:
                    risks.append({
                        'type': RiskTypes.PASSWORD_POLICY_WEAK,
                        'severity': Severity.MEDIUM,
                        'title': 'Password Policy Information Unavailable',
                        'description': 'Could not retrieve domain password policy information. This may indicate insufficient permissions or the policy may be configured at a different location.',
                        'affected_object': 'Domain Password Policy',
                        'object_type': 'policy',
                        'impact': 'Unable to verify password policy strength. Policy may be weak or misconfigured.',
                        'attack_scenario': 'Without visibility into password policy, weak policies may go undetected.',
                        'mitigation': 'Ensure LDAP read permissions for domain password policy attributes. Verify policy configuration manually using: Get-ADDefaultDomainPasswordPolicy (PowerShell) or dsquery (command line).',
                        'cis_reference': 'CIS Benchmark requires password policy review',
                        'mitre_attack': MITRETechniques.VALID_ACCOUNTS_DOMAIN
                    })
            
            if len(risks) == 0 and domain_info:
                # If policy was retrieved but no issues found, log success
                logger.info("Password policy retrieved successfully - no issues found (policy appears to be strong)")
            
            logger.info(f"Found {len(risks)} password policy issues")
            return risks
            
        except Exception as e:
            logger.error(f"Error in password policy analysis: {str(e)}")
            return []
    
    def _convert_timespan_to_days(self, timespan) -> int:
        """
        Convert Windows timespan (100-nanosecond intervals) to days.
        
        Args:
            timespan: Windows timespan value
        
        Returns:
            Number of days
        """
        try:
            if timespan is None:
                return 0
            if isinstance(timespan, str):
                timespan = int(timespan)
            if timespan == 0:
                return 0
            # Convert to days: timespan / (100ns * 1000 * 1000 * 1000 * 60 * 60 * 24)
            days = timespan / 864000000000
            return int(days)
        except (ValueError, TypeError, ZeroDivisionError):
            return 0
