"""
Legacy Operating System Analyzer Module
Detects and analyzes computers with old/legacy operating systems
"""

import logging
from datetime import datetime
from typing import List, Dict, Any
from core.constants import RiskTypes, Severity

logger = logging.getLogger(__name__)


class LegacyOSAnalyzer:
    """Analyzes computers for legacy/old operating systems."""
    
    # Legacy operating systems with their end-of-life dates
    LEGACY_OS_EOL_DATES = {
        'Windows Server 2003': datetime(2015, 7, 14),
        'Windows Server 2008': datetime(2020, 1, 14),
        'Windows Server 2008 R2': datetime(2020, 1, 14),
        'Windows Server 2012': datetime(2023, 10, 10),
        'Windows Server 2012 R2': datetime(2023, 10, 10),
        'Windows XP': datetime(2014, 4, 8),
        'Windows Vista': datetime(2017, 4, 11),
        'Windows 7': datetime(2020, 1, 14),
        'Windows 8': datetime(2016, 1, 12),
        'Windows 8.1': datetime(2023, 1, 10),
        'Windows Server 2016': None,  # Still supported but old
        'Windows Server 2019': None,  # Still supported but old
    }
    
    # Operating systems considered legacy (older than 5 years)
    LEGACY_OS_PATTERNS = [
        'Windows Server 2003',
        'Windows Server 2008',
        'Windows Server 2012',
        'Windows XP',
        'Windows Vista',
        'Windows 7',
        'Windows 8',
    ]
    
    def __init__(self):
        """Initialize legacy OS analyzer."""
        pass
    
    def analyze(self, computers: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze computers for legacy operating systems.
        
        Args:
            computers: List of computer dictionaries
            
        Returns:
            dict: Analysis results with legacy computers and risks
        """
        legacy_computers = []
        risks = []
        
        for computer in computers:
            os_name = computer.get('operatingSystem')
            os_version = computer.get('operatingSystemVersion', '')
            
            if not os_name:
                # Check if operatingSystemVersion contains OS info
                if os_version:
                    os_name = self._extract_os_from_version(os_version)
                
                if not os_name:
                    continue
            
            # Check if OS is legacy
            is_legacy, legacy_info = self._check_legacy_os(os_name, os_version)
            
            if is_legacy:
                computer_copy = computer.copy()
                computer_copy['legacyOSInfo'] = legacy_info
                legacy_computers.append(computer_copy)
                
                # Generate risk entry
                risk = self._create_legacy_os_risk(computer, legacy_info)
                risks.append(risk)
        
        logger.info(f"Found {len(legacy_computers)} computers with legacy operating systems")
        
        return {
            'legacy_computers': legacy_computers,
            'risks': risks,
            'total_count': len(legacy_computers),
            'eol_count': sum(1 for c in legacy_computers if c.get('legacyOSInfo', {}).get('is_eol', False)),
            'old_but_supported_count': sum(1 for c in legacy_computers if not c.get('legacyOSInfo', {}).get('is_eol', False))
        }
    
    def _check_legacy_os(self, os_name: str, os_version: str = '') -> tuple:
        """
        Check if operating system is legacy.
        
        Args:
            os_name: Operating system name
            os_version: Operating system version
            
        Returns:
            tuple: (is_legacy, legacy_info_dict)
        """
        os_name_lower = os_name.lower()
        legacy_info = {
            'os_name': os_name,
            'os_version': os_version,
            'is_eol': False,
            'eol_date': None,
            'days_since_eol': None,
            'legacy_reason': None
        }
        
        # Check exact matches in EOL dates
        for eol_os, eol_date in self.LEGACY_OS_EOL_DATES.items():
            if eol_os.lower() in os_name_lower:
                legacy_info['is_eol'] = eol_date is not None
                legacy_info['eol_date'] = eol_date.strftime('%Y-%m-%d') if eol_date else None
                
                if eol_date:
                    days_since_eol = (datetime.now() - eol_date).days
                    legacy_info['days_since_eol'] = days_since_eol
                    legacy_info['legacy_reason'] = f"End of Life ({days_since_eol} days ago)"
                
                return True, legacy_info
        
        # Check for legacy patterns
        for pattern in self.LEGACY_OS_PATTERNS:
            if pattern.lower() in os_name_lower:
                legacy_info['legacy_reason'] = "Legacy operating system pattern detected"
                return True, legacy_info
        
        # Check Windows Server 2016/2019 (old but still supported)
        if 'Windows Server 2016' in os_name or 'Windows Server 2019' in os_name:
            legacy_info['legacy_reason'] = "Older Windows Server version (consider upgrading)"
            return True, legacy_info
        
        return False, None
    
    def _extract_os_from_version(self, os_version: str) -> str:
        """
        Extract OS name from version string.
        
        Args:
            os_version: Operating system version string
            
        Returns:
            str: Extracted OS name or empty string
        """
        # Common version patterns
        version_patterns = {
            '6.0': 'Windows Vista / Server 2008',
            '6.1': 'Windows 7 / Server 2008 R2',
            '6.2': 'Windows 8 / Server 2012',
            '6.3': 'Windows 8.1 / Server 2012 R2',
            '10.0': 'Windows 10 / Server 2016',
        }
        
        for version, os_name in version_patterns.items():
            if version in os_version:
                return os_name
        
        return ''
    
    def _create_legacy_os_risk(self, computer: Dict[str, Any], legacy_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create risk entry for legacy OS computer.
        
        Args:
            computer: Computer dictionary
            legacy_info: Legacy OS information dictionary
            
        Returns:
            dict: Risk dictionary
        """
        os_name = legacy_info.get('os_name', 'Unknown')
        is_eol = legacy_info.get('is_eol', False)
        eol_date = legacy_info.get('eol_date')
        days_since_eol = legacy_info.get('days_since_eol')
        
        # Determine severity
        if is_eol and days_since_eol and days_since_eol > 365:
            severity = Severity.CRITICAL
        elif is_eol:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM
        
        # Create description
        if is_eol and eol_date:
            description = f"Computer '{computer.get('name')}' is running {os_name} which reached end of life on {eol_date}"
            if days_since_eol:
                description += f" ({days_since_eol} days ago)"
        else:
            description = f"Computer '{computer.get('name')}' is running legacy operating system: {os_name}"
        
        return {
            'type': RiskTypes.EOL_OPERATING_SYSTEM,
            'severity': severity,
            'title': 'Legacy Operating System Detected',
            'description': description,
            'affected_object': computer.get('name'),
            'object_type': 'computer',
            'operating_system': os_name,
            'operating_system_version': legacy_info.get('os_version', ''),
            'eol_date': eol_date,
            'days_since_eol': days_since_eol,
            'is_eol': is_eol,
            'legacy_reason': legacy_info.get('legacy_reason'),
            'dns_hostname': computer.get('dNSHostName'),
            'distinguished_name': computer.get('distinguishedName'),
            'last_logon': computer.get('lastLogonTimestamp'),
            'impact': 'Legacy operating systems may not receive security updates, making them vulnerable to known exploits. EOL systems pose critical security risks.',
            'attack_scenario': 'Attackers can exploit unpatched vulnerabilities in legacy/EOL operating systems to gain unauthorized access, escalate privileges, or perform lateral movement.',
            'mitigation': 'Immediately upgrade to a supported operating system. If upgrade is not immediately possible, isolate the system from the network, implement additional security controls, and plan for migration.',
            'cis_reference': 'CIS Benchmark requires supported operating systems with active security updates',
            'mitre_attack': 'T1068 - Exploitation for Privilege Escalation, T1078 - Valid Accounts'
        }
