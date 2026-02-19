"""
Misconfiguration Checklist Module
CIS Benchmark and Microsoft best practices based checklist
"""

import logging

logger = logging.getLogger(__name__)


class MisconfigurationChecker:
    """Checks for common AD misconfigurations based on CIS and Microsoft best practices."""
    
    def __init__(self):
        """Initialize misconfiguration checker."""
        pass
    
    def check(self, users, groups, computers, gpos):
        """
        Perform comprehensive misconfiguration checks.
        
        Args:
            users: List of user dictionaries
            groups: List of group dictionaries
            computers: List of computer dictionaries
            gpos: List of GPO dictionaries
        
        Returns:
            list: List of misconfiguration findings
        """
        findings = []
        
        # Password policy checks
        findings.extend(self._check_password_policy(users))
        
        # Admin account hygiene
        findings.extend(self._check_admin_hygiene(users, groups))
        
        # Delegation misconfigurations
        findings.extend(self._check_delegation_misconfig(users, computers))
        
        # ACL issues
        findings.extend(self._check_acl_issues(users, groups))
        
        # Trust risks (placeholder - would need trust data)
        findings.extend(self._check_trust_risks())
        
        # Tiering issues
        findings.extend(self._check_tiering_issues(users, groups))
        
        logger.info(f"Found {len(findings)} misconfiguration issues")
        return findings
    
    def _check_password_policy(self, users):
        """Check password policy weaknesses."""
        findings = []
        
        # Count users with password never expires
        never_expires_count = 0
        for user in users:
            uac = user.get('userAccountControl', 0)
            if isinstance(uac, (int, str)):
                try:
                    uac = int(uac)
                    if uac & 65536:  # DONT_EXPIRE_PASSWORD
                        never_expires_count += 1
                except (ValueError, TypeError):
                    pass
        
        if never_expires_count > 0:
            findings.append({
                'type': 'password_policy_weakness',
                'severity': 'high',
                'title': 'Password Policy Weakness',
                'description': f'{never_expires_count} user(s) have passwords that never expire',
                'category': 'Password Policy',
                'recommendation': 'Implement domain-wide password expiration policy. Review and remove DONT_EXPIRE_PASSWORD flag from user accounts',
                'cis_reference': 'CIS Benchmark 1.1.1 - Enforce password history',
                'microsoft_reference': 'Microsoft Security Baseline - Password Policy'
            })
        
        return findings
    
    def _check_admin_hygiene(self, users, groups):
        """Check admin account hygiene issues."""
        findings = []
        
        # Count admin accounts
        admin_accounts = []
        for user in users:
            if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                admin_accounts.append(user.get('sAMAccountName'))
        
        if len(admin_accounts) > 10:
            findings.append({
                'type': 'excessive_admin_accounts',
                'severity': 'medium',
                'title': 'Excessive Admin Accounts',
                'description': f'{len(admin_accounts)} accounts have adminCount=1 flag',
                'category': 'Admin Account Hygiene',
                'recommendation': 'Review admin accounts regularly. Remove adminCount flag from accounts that no longer need administrative privileges',
                'cis_reference': 'CIS Benchmark 2.3 - Limit administrative accounts',
                'microsoft_reference': 'Microsoft Security Baseline - Administrative Accounts'
            })
        
        return findings
    
    def _check_delegation_misconfig(self, users, computers):
        """Check delegation misconfigurations."""
        findings = []
        
        # Count unconstrained delegation
        unconstrained_count = 0
        for computer in computers:
            if computer.get('unconstrainedDelegation'):
                unconstrained_count += 1
        
        if unconstrained_count > 0:
            findings.append({
                'type': 'unconstrained_delegation_present',
                'severity': 'critical',
                'title': 'Unconstrained Delegation Detected',
                'description': f'{unconstrained_count} computer(s) have unconstrained delegation enabled',
                'category': 'Delegation',
                'recommendation': 'Disable unconstrained delegation. Use constrained or resource-based constrained delegation instead',
                'cis_reference': 'CIS Benchmark 2.2.1 - Disable unconstrained delegation',
                'microsoft_reference': 'Microsoft Security Baseline - Kerberos Delegation'
            })
        
        return findings
    
    def _check_acl_issues(self, users, groups):
        """Check ACL-related issues."""
        findings = []
        
        # This is a placeholder - full ACL analysis would require SD parsing
        findings.append({
            'type': 'acl_review_needed',
            'severity': 'medium',
            'title': 'ACL Review Recommended',
            'description': 'Regular ACL review is recommended to identify excessive permissions on critical objects',
            'category': 'Access Control',
            'recommendation': 'Review ACLs on Domain Admins, Enterprise Admins, and other privileged groups. Ensure principle of least privilege',
            'cis_reference': 'CIS Benchmark 2.4 - Review ACLs on privileged groups',
            'microsoft_reference': 'Microsoft Security Baseline - Access Control'
        })
        
        return findings
    
    def _check_trust_risks(self):
        """Check trust-related risks."""
        findings = []
        
        # Placeholder - would need trust data from AD
        findings.append({
            'type': 'trust_review_needed',
            'severity': 'medium',
            'title': 'Trust Relationship Review',
            'description': 'Review all trust relationships regularly to ensure they are necessary and secure',
            'category': 'Trust Relationships',
            'recommendation': 'Audit all domain trusts. Remove unnecessary trusts. Ensure external trusts use selective authentication',
            'cis_reference': 'CIS Benchmark 2.5 - Review trust relationships',
            'microsoft_reference': 'Microsoft Security Baseline - Trust Relationships'
        })
        
        return findings
    
    def _check_tiering_issues(self, users, groups):
        """Check tiering/separation issues."""
        findings = []
        
        # Check if admin accounts are used for regular operations
        admin_with_spn = 0
        for user in users:
            if user.get('adminCount') == 1 or user.get('adminCount') == '1':
                spns = user.get('servicePrincipalName') or []
                if spns and len(spns) > 0:
                    admin_with_spn += 1
        
        if admin_with_spn > 0:
            findings.append({
                'type': 'tiering_violation',
                'severity': 'high',
                'title': 'Tiering Violation - Admin Accounts with SPNs',
                'description': f'{admin_with_spn} administrative account(s) have Service Principal Names, violating tiering principles',
                'category': 'Tiering',
                'recommendation': 'Separate administrative accounts from service accounts. Use managed service accounts (MSAs) or gMSAs for services',
                'cis_reference': 'CIS Benchmark 2.6 - Implement tiering model',
                'microsoft_reference': 'Microsoft Security Baseline - Tiering Model'
            })
        
        return findings
