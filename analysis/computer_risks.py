"""
Computer Risk Analysis Module
Analyzes computer objects for security risks including EOL OS detection
"""

import logging
from datetime import datetime, timedelta
from core.constants import RiskTypes, Severity

logger = logging.getLogger(__name__)


class ComputerRiskAnalyzer:
    """Analyzes computer objects for security risks."""
    
    # End of Life operating systems (simplified list)
    EOL_OPERATING_SYSTEMS = {
        'Windows Server 2008': datetime(2020, 1, 14),
        'Windows Server 2008 R2': datetime(2020, 1, 14),
        'Windows Server 2012': datetime(2023, 10, 10),
        'Windows Server 2012 R2': datetime(2023, 10, 10),
        'Windows 7': datetime(2020, 1, 14),
        'Windows 8': datetime(2016, 1, 12),
        'Windows 8.1': datetime(2023, 1, 10),
        'Windows XP': datetime(2014, 4, 8),
        'Windows Vista': datetime(2017, 4, 11),
        'Windows Server 2003': datetime(2015, 7, 14)
    }
    
    def __init__(self):
        """Initialize computer risk analyzer."""
        pass
    
    def analyze(self, computers):
        """
        Analyze computers for security risks.
        
        Args:
            computers: List of computer dictionaries
        
        Returns:
            list: List of risk dictionaries
        """
        risks = []
        
        for computer in computers:
            # Enrich computer data with additional metadata
            self._enrich_computer_data(computer)
            
            # Check EOL operating systems
            risks.extend(self._check_eol_os(computer))
            
            # Check unconstrained delegation
            risks.extend(self._check_unconstrained_delegation(computer))
            
            # Check constrained delegation
            risks.extend(self._check_constrained_delegation(computer))
            
            # Check inactive computers
            risks.extend(self._check_inactive_computer(computer))
            
            # Check never used computers
            risks.extend(self._check_never_used_computer(computer))
        
        logger.info(f"Found {len(risks)} computer-related risks")
        return risks
    
    def _enrich_computer_data(self, computer):
        """
        Enrich computer data with additional metadata for reporting.
        
        Args:
            computer: Computer dictionary to enrich
        """
        # Calculate days since last logon
        last_logon = computer.get('lastLogonTimestamp')
        if last_logon:
            try:
                if isinstance(last_logon, str):
                    last_logon = datetime.fromisoformat(last_logon.replace('Z', '+00:00'))
                if isinstance(last_logon, datetime):
                    days_since_logon = (datetime.now() - last_logon.replace(tzinfo=None)).days
                    computer['daysSinceLastLogon'] = days_since_logon
                    
                    # Check if inactive for specific periods
                    computer['inactiveFor10Days'] = days_since_logon >= 10
                    computer['inactiveFor30Days'] = days_since_logon >= 30
                    computer['inactiveFor60Days'] = days_since_logon >= 60
                    computer['inactiveFor90Days'] = days_since_logon >= 90
            except Exception:
                pass
        
        # Check if computer was never used (no lastLogonTimestamp or very old whenCreated)
        when_created = computer.get('whenCreated')
        if when_created and not last_logon:
            try:
                if isinstance(when_created, str):
                    when_created = datetime.fromisoformat(when_created.replace('Z', '+00:00'))
                if isinstance(when_created, datetime):
                    days_since_created = (datetime.now() - when_created.replace(tzinfo=None)).days
                    # Consider never used if created more than 30 days ago and no logon
                    computer['neverUsed'] = days_since_created > 30
            except Exception:
                pass
    
    def _check_eol_os(self, computer):
        """Check for End of Life operating systems."""
        risks = []
        os_name = computer.get('operatingSystem')
        
        if not os_name:
            return risks
        
        # Check if OS is in EOL list
        for eol_os, eol_date in self.EOL_OPERATING_SYSTEMS.items():
            if eol_os.lower() in os_name.lower():
                days_since_eol = (datetime.now() - eol_date).days
                
                risks.append({
                    'type': RiskTypes.EOL_OPERATING_SYSTEM,
                    'severity': Severity.CRITICAL,
                    'title': 'End of Life Operating System',
                    'description': f"Computer '{computer.get('name')}' is running {os_name} which reached end of life on {eol_date.strftime('%Y-%m-%d')} ({days_since_eol} days ago)",
                    'affected_object': computer.get('name'),
                    'object_type': 'computer',
                    'operating_system': os_name,
                    'eol_date': eol_date.strftime('%Y-%m-%d'),
                    'days_since_eol': days_since_eol,
                    'impact': 'End of life operating systems no longer receive security updates, making them vulnerable to known exploits and attacks',
                    'attack_scenario': 'Attackers can exploit unpatched vulnerabilities in EOL operating systems to gain unauthorized access or escalate privileges',
                    'mitigation': 'Immediately upgrade to a supported operating system. If upgrade is not possible, isolate the system and implement additional security controls',
                    'cis_reference': 'CIS Benchmark requires supported operating systems',
                    'mitre_attack': 'T1068 - Exploitation for Privilege Escalation'
                })
                break
        
        return risks
    
    def _check_unconstrained_delegation(self, computer):
        """Check for unconstrained delegation on computers."""
        risks = []
        
        if computer.get('unconstrainedDelegation'):
            risks.append({
                'type': RiskTypes.COMPUTER_UNCONSTRAINED_DELEGATION,
                'severity': Severity.CRITICAL,
                'title': 'Computer with Unconstrained Delegation',
                'description': f"Computer '{computer.get('name')}' has unconstrained delegation enabled",
                'affected_object': computer.get('name'),
                'object_type': 'computer',
                'impact': 'Unconstrained delegation allows a service to impersonate users to any service in the domain, creating a significant privilege escalation risk',
                'attack_scenario': 'If an attacker compromises a computer with unconstrained delegation, they can capture and reuse Kerberos tickets from any user who authenticates to that computer, potentially gaining domain admin access',
                'mitigation': 'Disable unconstrained delegation. Use constrained delegation or resource-based constrained delegation instead, which limits which services can be accessed',
                'cis_reference': 'CIS Benchmark recommends disabling unconstrained delegation',
                'mitre_attack': 'T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket'
            })
        
        return risks
    
    def _check_constrained_delegation(self, computer):
        """Check for constrained delegation configurations."""
        risks = []
        
        allowed_to_delegate = computer.get('msDS-AllowedToDelegateTo', [])
        if not allowed_to_delegate:
            allowed_to_delegate = []
        
        if len(allowed_to_delegate) > 0:
            # Check if delegation list is too broad
            if len(allowed_to_delegate) > 10:
                risks.append({
                    'type': RiskTypes.COMPUTER_BROAD_CONSTRAINED_DELEGATION,
                    'severity': Severity.HIGH,
                    'title': 'Broad Constrained Delegation Configuration',
                    'description': f"Computer '{computer.get('name')}' has constrained delegation configured with {len(allowed_to_delegate)} allowed services",
                    'affected_object': computer.get('name'),
                    'object_type': 'computer',
                    'allowed_services': allowed_to_delegate,
                    'impact': 'Broad constrained delegation configurations increase the attack surface. If the delegated account is compromised, attackers can access many services',
                    'attack_scenario': 'If an attacker compromises a computer with broad constrained delegation, they can access multiple services through delegation, potentially escalating privileges',
                    'mitigation': 'Review and minimize the list of allowed services. Only include services that are absolutely necessary. Consider using resource-based constrained delegation',
                    'cis_reference': 'CIS Benchmark recommends minimizing delegation configurations',
                    'mitre_attack': 'T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket'
                })
        
        return risks
    
    def _check_inactive_computer(self, computer):
        """Check for inactive computers (not logged on for extended periods)."""
        risks = []
        
        days_since_logon = computer.get('daysSinceLastLogon')
        if days_since_logon is None:
            return risks
        
        # Flag computers inactive for 90+ days
        if days_since_logon >= 90:
            risks.append({
                'type': RiskTypes.INACTIVE_COMPUTER,
                'severity': Severity.MEDIUM,
                'title': 'Inactive Computer',
                'description': f"Computer '{computer.get('name')}' has not logged on for {days_since_logon} days",
                'affected_object': computer.get('name'),
                'object_type': 'computer',
                'days_inactive': days_since_logon,
                'impact': 'Inactive computers may be decommissioned systems that should be removed from the domain, or systems that are not being properly monitored',
                'attack_scenario': 'Inactive computers that are not properly secured could be compromised without detection',
                'mitigation': 'Review inactive computers. Remove decommissioned systems from the domain. Ensure all active systems are properly secured and monitored',
                'cis_reference': 'CIS Benchmark recommends removing unused computer accounts',
                'mitre_attack': 'T1078 - Valid Accounts'
            })
        
        return risks
    
    def _check_never_used_computer(self, computer):
        """Check for computers that were joined to domain but never used."""
        risks = []
        
        if computer.get('neverUsed'):
            risks.append({
                'type': RiskTypes.NEVER_USED_COMPUTER,
                'severity': Severity.LOW,
                'title': 'Never Used Computer',
                'description': f"Computer '{computer.get('name')}' was joined to the domain but has never logged on",
                'affected_object': computer.get('name'),
                'object_type': 'computer',
                'impact': 'Computers that are joined but never used may be test systems, abandoned systems, or systems that were never properly configured',
                'attack_scenario': 'Unused computer accounts could be compromised and used for lateral movement if not properly secured',
                'mitigation': 'Review never-used computer accounts. Remove test or abandoned systems. Ensure all computer accounts are properly secured',
                'cis_reference': 'CIS Benchmark recommends removing unused accounts',
                'mitre_attack': 'T1078 - Valid Accounts'
            })
        
        return risks
