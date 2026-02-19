"""
Kerberos & Delegation Analysis Module
Analyzes Kerberos and delegation-related security risks
"""

import logging

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
            if computer.get('unconstrainedDelegation'):
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
        """Check for constrained delegation configurations."""
        risks = []
        
        # Note: Constrained delegation requires checking msDS-AllowedToDelegateTo attribute
        # This is a simplified check - full implementation would need to query this attribute
        # For now, we'll flag computers/users with delegation flags but note this is a limitation
        
        for computer in computers:
            uac = computer.get('userAccountControl', 0)
            # TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216 (0x1000000)
            if uac & 16777216:
                risks.append({
                    'type': 'constrained_delegation',
                    'severity': 'medium',
                    'title': 'Constrained Delegation Configured',
                    'description': f"Computer '{computer.get('name')}' has constrained delegation configured",
                    'affected_object': computer.get('name'),
                    'object_type': 'computer',
                    'impact': 'Constrained delegation is more secure than unconstrained, but still requires careful review to ensure only necessary services are allowed',
                    'attack_scenario': 'If misconfigured, constrained delegation could allow an attacker to access more services than intended if they compromise the delegated account',
                    'mitigation': 'Review constrained delegation settings regularly. Ensure only necessary services are in the allowed list. Consider using resource-based constrained delegation instead',
                    'cis_reference': 'CIS Benchmark recommends reviewing all delegation configurations',
                    'mitre_attack': 'T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket'
                })
        
        return risks
    
    def _check_rbcd(self, users, computers):
        """Check for resource-based constrained delegation risks."""
        risks = []
        
        # Note: Full RBCD analysis requires checking msDS-AllowedToActOnBehalfOfOtherIdentity
        # This is a placeholder - in a full implementation, you would query this attribute
        # and analyze the relationships
        
        # For now, we'll provide a general risk note
        # In production, this would analyze actual RBCD configurations
        
        return risks
    
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
