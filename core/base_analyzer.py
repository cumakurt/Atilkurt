"""
Base Analyzer Module
Base class for all analyzers to reduce code duplication
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from core.types import RiskDict
from core.constants import RiskTypes, Severity, MITRETechniques

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Base class for all risk analyzers."""
    
    def __init__(self):
        """Initialize base analyzer."""
        self.risks: List[RiskDict] = []
    
    @abstractmethod
    def analyze(self, *args, **kwargs) -> List[RiskDict]:
        """
        Analyze data for security risks.
        
        Returns:
            List of risk dictionaries
        """
        pass
    
    def _create_risk(
        self,
        risk_type: str,
        title: str,
        description: str,
        affected_object: str,
        object_type: str,
        severity: str = Severity.MEDIUM,
        impact: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        mitigation: Optional[str] = None,
        cis_reference: Optional[str] = None,
        mitre_attack: Optional[str] = None,
        **additional_fields
    ) -> RiskDict:
        """
        Create a standardized risk dictionary.
        
        Args:
            risk_type: Risk type identifier
            title: Risk title
            description: Risk description
            affected_object: Affected object identifier
            object_type: Type of object (user, computer, group, etc.)
            severity: Risk severity level
            impact: Impact description
            attack_scenario: Attack scenario description
            mitigation: Mitigation recommendations
            cis_reference: CIS Benchmark reference
            mitre_attack: MITRE ATT&CK technique ID
            **additional_fields: Additional fields to include in risk
        
        Returns:
            Risk dictionary
        """
        risk: RiskDict = {
            'type': risk_type,
            'severity': severity,
            'title': title,
            'description': description,
            'affected_object': affected_object,
            'object_type': object_type,
        }
        
        # Add optional fields if provided
        if impact:
            risk['impact'] = impact
        if attack_scenario:
            risk['attack_scenario'] = attack_scenario
        if mitigation:
            risk['mitigation'] = mitigation
        if cis_reference:
            risk['cis_reference'] = cis_reference
        if mitre_attack:
            risk['mitre_attack'] = mitre_attack
        
        # Add any additional fields
        risk.update(additional_fields)
        
        return risk
    
    def _create_user_risk(
        self,
        risk_type: str,
        title: str,
        description: str,
        user: Dict[str, Any],
        severity: str = Severity.MEDIUM,
        impact: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        mitigation: Optional[str] = None,
        cis_reference: Optional[str] = None,
        mitre_attack: Optional[str] = None,
        **additional_fields
    ) -> RiskDict:
        """
        Create a user-related risk.
        
        Args:
            risk_type: Risk type identifier
            title: Risk title
            description: Risk description
            user: User dictionary
            severity: Risk severity level
            impact: Impact description
            attack_scenario: Attack scenario description
            mitigation: Mitigation recommendations
            cis_reference: CIS Benchmark reference
            mitre_attack: MITRE ATT&CK technique ID
            **additional_fields: Additional fields to include in risk
        
        Returns:
            Risk dictionary
        """
        username = user.get('sAMAccountName', 'Unknown')
        return self._create_risk(
            risk_type=risk_type,
            title=title,
            description=description.format(username=username) if '{username}' in description else description,
            affected_object=username,
            object_type='user',
            severity=severity,
            impact=impact,
            attack_scenario=attack_scenario,
            mitigation=mitigation,
            cis_reference=cis_reference,
            mitre_attack=mitre_attack,
            **additional_fields
        )
    
    def _create_computer_risk(
        self,
        risk_type: str,
        title: str,
        description: str,
        computer: Dict[str, Any],
        severity: str = Severity.MEDIUM,
        impact: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        mitigation: Optional[str] = None,
        cis_reference: Optional[str] = None,
        mitre_attack: Optional[str] = None,
        **additional_fields
    ) -> RiskDict:
        """
        Create a computer-related risk.
        
        Args:
            risk_type: Risk type identifier
            title: Risk title
            description: Risk description
            computer: Computer dictionary
            severity: Risk severity level
            impact: Impact description
            attack_scenario: Attack scenario description
            mitigation: Mitigation recommendations
            cis_reference: CIS Benchmark reference
            mitre_attack: MITRE ATT&CK technique ID
            **additional_fields: Additional fields to include in risk
        
        Returns:
            Risk dictionary
        """
        computer_name = computer.get('name', 'Unknown')
        return self._create_risk(
            risk_type=risk_type,
            title=title,
            description=description.format(computer_name=computer_name) if '{computer_name}' in description else description,
            affected_object=computer_name,
            object_type='computer',
            severity=severity,
            impact=impact,
            attack_scenario=attack_scenario,
            mitigation=mitigation,
            cis_reference=cis_reference,
            mitre_attack=mitre_attack,
            **additional_fields
        )
    
    def _create_group_risk(
        self,
        risk_type: str,
        title: str,
        description: str,
        group: Dict[str, Any],
        severity: str = Severity.MEDIUM,
        impact: Optional[str] = None,
        attack_scenario: Optional[str] = None,
        mitigation: Optional[str] = None,
        cis_reference: Optional[str] = None,
        mitre_attack: Optional[str] = None,
        **additional_fields
    ) -> RiskDict:
        """
        Create a group-related risk.
        
        Args:
            risk_type: Risk type identifier
            title: Risk title
            description: Risk description
            group: Group dictionary
            severity: Risk severity level
            impact: Impact description
            attack_scenario: Attack scenario description
            mitigation: Mitigation recommendations
            cis_reference: CIS Benchmark reference
            mitre_attack: MITRE ATT&CK technique ID
            **additional_fields: Additional fields to include in risk
        
        Returns:
            Risk dictionary
        """
        group_name = group.get('name') or group.get('sAMAccountName', 'Unknown')
        return self._create_risk(
            risk_type=risk_type,
            title=title,
            description=description.format(group_name=group_name) if '{group_name}' in description else description,
            affected_object=group_name,
            object_type='group',
            severity=severity,
            impact=impact,
            attack_scenario=attack_scenario,
            mitigation=mitigation,
            cis_reference=cis_reference,
            mitre_attack=mitre_attack,
            **additional_fields
        )
    
    def _check_uac_flag(self, uac: Any, flag: int) -> bool:
        """
        Check if a UAC flag is set.
        
        Args:
            uac: User Account Control value
            flag: Flag to check
        
        Returns:
            True if flag is set, False otherwise
        """
        if isinstance(uac, str):
            try:
                uac = int(uac)
            except ValueError:
                return False
        
        if not isinstance(uac, int):
            return False
        
        return bool(uac & flag)
