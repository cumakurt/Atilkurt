"""
Factory Pattern Module
Factory classes for creating analyzers and other components
"""

from typing import Dict, Type, Optional
from core.base_analyzer import BaseAnalyzer
from analysis.user_risks import UserRiskAnalyzer
from analysis.computer_risks import ComputerRiskAnalyzer
from analysis.group_risks import GroupRiskAnalyzer
from analysis.kerberos_delegation import KerberosDelegationAnalyzer
from analysis.privilege_escalation import PrivilegeEscalationAnalyzer
from analysis.misconfiguration_checklist import MisconfigurationChecker
from analysis.kerberoasting_detector import KerberoastingDetector
from analysis.service_account_analyzer import ServiceAccountAnalyzer
from analysis.gpo_abuse_analyzer import GPOAbuseAnalyzer
from analysis.attack_path_analyzer import AttackPathAnalyzer
from analysis.exploitability_scorer import ExploitabilityScorer
from analysis.privilege_calculator import PrivilegeCalculator
from analysis.dcsync_analyzer import DCSyncAnalyzer
from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
from analysis.trust_analyzer import TrustAnalyzer
from analysis.certificate_analyzer import CertificateAnalyzer
from analysis.gpp_password_extractor import GPPPasswordExtractor
from analysis.laps_analyzer import LAPSAnalyzer
from analysis.vulnerability_scanner import VulnerabilityScanner
from scoring.risk_scorer import RiskScorer
from core.config import AppConfig, get_config


class AnalyzerFactory:
    """Factory for creating analyzer instances."""
    
    _analyzer_registry: Dict[str, Type[BaseAnalyzer]] = {
        'user': UserRiskAnalyzer,
        'computer': ComputerRiskAnalyzer,
        'group': GroupRiskAnalyzer,
        'kerberos': KerberosDelegationAnalyzer,
        'privilege_escalation': PrivilegeEscalationAnalyzer,
        'misconfiguration': MisconfigurationChecker,
        'kerberoasting': KerberoastingDetector,
        'service_account': ServiceAccountAnalyzer,
        'gpo_abuse': GPOAbuseAnalyzer,
        'attack_path': AttackPathAnalyzer,
        'exploitability': ExploitabilityScorer,
        'privilege_calculator': PrivilegeCalculator,
        'dcsync': DCSyncAnalyzer,
        'password_policy': PasswordPolicyAnalyzer,
        'trust': TrustAnalyzer,
        'certificate': CertificateAnalyzer,
        'gpp': GPPPasswordExtractor,
        'laps': LAPSAnalyzer,
        'vulnerability': VulnerabilityScanner,
    }
    
    @classmethod
    def create_analyzer(cls, analyzer_type: str, **kwargs) -> BaseAnalyzer:
        """
        Create an analyzer instance.
        
        Args:
            analyzer_type: Type of analyzer to create
            **kwargs: Additional arguments for analyzer initialization
        
        Returns:
            Analyzer instance
        
        Raises:
            ValueError: If analyzer type is not registered
        """
        analyzer_class = cls._analyzer_registry.get(analyzer_type.lower())
        if analyzer_class is None:
            raise ValueError(f"Unknown analyzer type: {analyzer_type}")
        
        return analyzer_class(**kwargs)
    
    @classmethod
    def register_analyzer(cls, analyzer_type: str, analyzer_class: Type[BaseAnalyzer]) -> None:
        """
        Register a new analyzer type.
        
        Args:
            analyzer_type: Type identifier for the analyzer
            analyzer_class: Analyzer class to register
        """
        cls._analyzer_registry[analyzer_type.lower()] = analyzer_class
    
    @classmethod
    def list_analyzers(cls) -> list:
        """
        List all registered analyzer types.
        
        Returns:
            List of analyzer type names
        """
        return list(cls._analyzer_registry.keys())


class RiskScorerFactory:
    """Factory for creating risk scorer instances."""
    
    @staticmethod
    def create_scorer(config: Optional[AppConfig] = None) -> RiskScorer:
        """
        Create a risk scorer instance.
        
        Args:
            config: Application configuration (optional)
        
        Returns:
            RiskScorer instance
        """
        if config is None:
            config = get_config()
        
        scorer = RiskScorer()
        # Update base scores from config if needed
        if config and config.risk_scoring:
            scorer.BASE_RISK_SCORES.update(config.risk_scoring.base_scores)
        
        return scorer
