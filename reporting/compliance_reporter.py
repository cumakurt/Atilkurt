"""
Compliance Reporting Module
CIS Benchmark, NIST CSF, ISO 27001, GDPR compliance checking
Uses advanced LDAP-based compliance analyzer for detailed checks
"""

import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class ComplianceReporter:
    """
    Generates compliance reports for various frameworks.
    """
    
    # CIS Benchmark mappings
    CIS_BENCHMARK_MAPPINGS = {
        'user_password_never_expires': 'CIS 2.3.1.1',
        'password_not_required': 'CIS 2.3.1.2',
        'kerberos_preauth_disabled': 'CIS 2.3.1.3',
        'unconstrained_delegation': 'CIS 2.3.1.4',
        'too_many_domain_admins': 'CIS 2.3.1.5',
        'weak_password_policy': 'CIS 2.3.2.1',
        'account_lockout_disabled': 'CIS 2.3.2.2',
        'eol_operating_system': 'CIS 2.3.3.1',
        'laps_not_configured': 'CIS 2.3.4.1',
        'gpp_passwords': 'CIS 2.3.5.1',
        'dcsync_rights': 'CIS 2.3.6.1',
        'trust_sid_filtering_disabled': 'CIS 2.3.7.1'
    }
    
    # NIST CSF mappings
    NIST_CSF_MAPPINGS = {
        'user_password_never_expires': 'PR.AC-1',
        'password_not_required': 'PR.AC-1',
        'kerberos_preauth_disabled': 'PR.AC-1',
        'unconstrained_delegation': 'PR.AC-1',
        'weak_password_policy': 'PR.AC-1',
        'account_lockout_disabled': 'PR.AC-7',
        'eol_operating_system': 'PR.DS-2',
        'laps_not_configured': 'PR.DS-2',
        'gpp_passwords': 'PR.DS-2',
        'dcsync_rights': 'PR.AC-1',
        'trust_sid_filtering_disabled': 'PR.AC-1',
        'privilege_escalation_path': 'PR.AC-1',
        'shadow_admin': 'PR.AC-1'
    }
    
    # ISO 27001 mappings
    ISO_27001_MAPPINGS = {
        'user_password_never_expires': 'A.9.4.2',
        'password_not_required': 'A.9.4.2',
        'kerberos_preauth_disabled': 'A.9.4.2',
        'weak_password_policy': 'A.9.4.3',
        'account_lockout_disabled': 'A.9.4.2',
        'eol_operating_system': 'A.12.6.1',
        'laps_not_configured': 'A.9.2.1',
        'gpp_passwords': 'A.9.4.2',
        'dcsync_rights': 'A.9.2.1',
        'trust_sid_filtering_disabled': 'A.9.4.2',
        'privilege_escalation_path': 'A.9.2.1',
        'shadow_admin': 'A.9.2.1'
    }
    
    # CIS Controls v8 mappings (Critical Security Controls)
    CIS_CONTROLS_V8_MAPPINGS = {
        'user_password_never_expires': '4.3 (Unused/Unauthorized Account Disabled)',
        'password_not_required': '5.2 (Privileged Access Management)',
        'kerberos_preauth_disabled': '5.2 (Privileged Access Management)',
        'unconstrained_delegation': '5.2 (Privileged Access Management)',
        'too_many_domain_admins': '5.1 (Privileged Account Inventory)',
        'weak_password_policy': '5.2 (Privileged Access Management)',
        'account_lockout_disabled': '5.2 (Privileged Access Management)',
        'eol_operating_system': '7.1 (Vulnerability Management)',
        'laps_not_configured': '4.6 (Removable Media)',
        'gpp_passwords': '5.2 (Privileged Access Management)',
        'dcsync_rights': '5.2 (Privileged Access Management)',
        'trust_sid_filtering_disabled': '13.2 (Network Security)',
        'privilege_escalation_path': '5.2 (Privileged Access Management)',
        'shadow_admin': '5.1 (Privileged Account Inventory)',
        'nopac_vulnerable': '7.1 (Vulnerability Management)',
        'ldap_signing_disabled': '13.2 (Network Security)',
        'ntlm_restriction_weak': '13.2 (Network Security)',
        'smb_signing_disabled': '13.2 (Network Security)',
        'zerologon_vulnerable': '7.1 (Vulnerability Management)',
        'printnightmare_vulnerable': '7.1 (Vulnerability Management)',
        'petitpotam_vulnerable': '13.2 (Network Security)',
    }

    # GDPR mappings
    GDPR_MAPPINGS = {
        'user_password_never_expires': 'Article 32',
        'password_not_required': 'Article 32',
        'weak_password_policy': 'Article 32',
        'account_lockout_disabled': 'Article 32',
        'gpp_passwords': 'Article 32',
        'dcsync_rights': 'Article 32',
        'privilege_escalation_path': 'Article 32',
        'shadow_admin': 'Article 32'
    }
    
    def __init__(self, ldap_connection=None):
        """
        Initialize compliance reporter.
        
        Args:
            ldap_connection: Optional LDAPConnection instance for advanced analysis
        """
        self.ldap = ldap_connection
        if ldap_connection:
            from analysis.compliance_analyzer import ComplianceAnalyzer
            self.analyzer = ComplianceAnalyzer(ldap_connection)
        else:
            self.analyzer = None
    
    def analyze_cis_benchmark(self, risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze compliance with CIS Benchmark.
        
        Args:
            risks: List of risk dictionaries
            
        Returns:
            Dict with CIS compliance analysis
        """
        compliance_results = {
            'framework': 'CIS Benchmark',
            'total_controls': len(self.CIS_BENCHMARK_MAPPINGS),
            'failed_controls': [],
            'passed_controls': [],
            'compliance_score': 0.0,
            'details': {}
        }
        
        risk_types = {risk.get('type', '') for risk in risks}
        mapped_controls = set()
        
        for risk_type, cis_control in self.CIS_BENCHMARK_MAPPINGS.items():
            if risk_type in risk_types:
                compliance_results['failed_controls'].append({
                    'control': cis_control,
                    'risk_type': risk_type,
                    'count': sum(1 for r in risks if r.get('type') == risk_type)
                })
                mapped_controls.add(cis_control)
            else:
                compliance_results['passed_controls'].append(cis_control)
        
        # Calculate compliance score
        total_controls = len(self.CIS_BENCHMARK_MAPPINGS)
        failed_count = len(compliance_results['failed_controls'])
        compliance_results['compliance_score'] = max(0.0, (total_controls - failed_count) / total_controls * 100)
        
        return compliance_results
    
    def analyze_nist_csf(self, risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze compliance with NIST Cybersecurity Framework.
        
        Args:
            risks: List of risk dictionaries
            
        Returns:
            Dict with NIST CSF compliance analysis
        """
        compliance_results = {
            'framework': 'NIST CSF',
            'functions': {
                'PR': {'name': 'Protect', 'controls': [], 'status': 'partial'},
                'DE': {'name': 'Detect', 'controls': [], 'status': 'partial'},
                'RS': {'name': 'Respond', 'controls': [], 'status': 'partial'},
                'RC': {'name': 'Recover', 'controls': [], 'status': 'partial'},
                'ID': {'name': 'Identify', 'controls': [], 'status': 'partial'}
            },
            'compliance_score': 0.0,
            'details': {}
        }
        
        risk_types = {risk.get('type', '') for risk in risks}
        function_scores = {}
        
        for risk_type, nist_control in self.NIST_CSF_MAPPINGS.items():
            function_id = nist_control.split('-')[0]
            if risk_type in risk_types:
                if function_id not in function_scores:
                    function_scores[function_id] = {'total': 0, 'failed': 0}
                function_scores[function_id]['total'] += 1
                function_scores[function_id]['failed'] += 1
                
                if function_id in compliance_results['functions']:
                    compliance_results['functions'][function_id]['controls'].append({
                        'control': nist_control,
                        'risk_type': risk_type,
                        'status': 'failed'
                    })
        
        # Calculate scores per function
        total_score = 0.0
        for function_id, scores in function_scores.items():
            if scores['total'] > 0:
                function_score = (scores['total'] - scores['failed']) / scores['total'] * 100
                total_score += function_score
                if function_id in compliance_results['functions']:
                    compliance_results['functions'][function_id]['score'] = function_score
                    compliance_results['functions'][function_id]['status'] = 'passed' if function_score >= 80 else 'partial'
        
        compliance_results['compliance_score'] = total_score / len(function_scores) if function_scores else 0.0
        
        return compliance_results
    
    def analyze_iso_27001(self, risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze compliance with ISO 27001.
        
        Args:
            risks: List of risk dictionaries
            
        Returns:
            Dict with ISO 27001 compliance analysis
        """
        compliance_results = {
            'framework': 'ISO 27001',
            'domains': defaultdict(list),
            'compliance_score': 0.0,
            'details': {}
        }
        
        risk_types = {risk.get('type', '') for risk in risks}
        domain_scores = defaultdict(lambda: {'total': 0, 'failed': 0})
        
        for risk_type, iso_control in self.ISO_27001_MAPPINGS.items():
            domain = iso_control.split('.')[0]
            if risk_type in risk_types:
                domain_scores[domain]['total'] += 1
                domain_scores[domain]['failed'] += 1
                compliance_results['domains'][domain].append({
                    'control': iso_control,
                    'risk_type': risk_type,
                    'status': 'failed'
                })
            else:
                domain_scores[domain]['total'] += 1
        
        # Calculate scores per domain
        total_score = 0.0
        for domain, scores in domain_scores.items():
            if scores['total'] > 0:
                domain_score = (scores['total'] - scores['failed']) / scores['total'] * 100
                total_score += domain_score
                compliance_results['domains'][domain].append({
                    'score': domain_score,
                    'status': 'passed' if domain_score >= 80 else 'partial'
                })
        
        compliance_results['compliance_score'] = total_score / len(domain_scores) if domain_scores else 0.0
        
        return compliance_results
    
    def analyze_gdpr(self, risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze compliance with GDPR.
        
        Args:
            risks: List of risk dictionaries
            
        Returns:
            Dict with GDPR compliance analysis
        """
        compliance_results = {
            'framework': 'GDPR',
            'articles': defaultdict(list),
            'compliance_score': 0.0,
            'details': {}
        }
        
        risk_types = {risk.get('type', '') for risk in risks}
        article_scores = defaultdict(lambda: {'total': 0, 'failed': 0})
        
        for risk_type, gdpr_article in self.GDPR_MAPPINGS.items():
            if risk_type in risk_types:
                article_scores[gdpr_article]['total'] += 1
                article_scores[gdpr_article]['failed'] += 1
                compliance_results['articles'][gdpr_article].append({
                    'risk_type': risk_type,
                    'status': 'failed',
                    'description': f"Risk violates {gdpr_article} - Data protection by design and by default"
                })
            else:
                article_scores[gdpr_article]['total'] += 1
        
        # Calculate scores per article
        total_score = 0.0
        for article, scores in article_scores.items():
            if scores['total'] > 0:
                article_score = (scores['total'] - scores['failed']) / scores['total'] * 100
                total_score += article_score
                compliance_results['articles'][article].append({
                    'score': article_score,
                    'status': 'passed' if article_score >= 80 else 'partial'
                })
        
        compliance_results['compliance_score'] = total_score / len(article_scores) if article_scores else 0.0
        
        return compliance_results

    def analyze_cis_controls_v8(self, risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze compliance with CIS Controls v8 (Critical Security Controls).
        """
        compliance_results = {
            'framework': 'CIS Controls v8',
            'safeguards': [],
            'failed_safeguards': [],
            'passed_safeguards': [],
            'compliance_score': 0.0,
        }
        risk_types = {risk.get('type', '') for risk in risks}
        for risk_type, safeguard in self.CIS_CONTROLS_V8_MAPPINGS.items():
            if risk_type in risk_types:
                compliance_results['failed_safeguards'].append({
                    'safeguard': safeguard,
                    'risk_type': risk_type,
                    'count': sum(1 for r in risks if r.get('type') == risk_type)
                })
            else:
                compliance_results['passed_safeguards'].append(safeguard)
        total = len(self.CIS_CONTROLS_V8_MAPPINGS)
        failed = len(compliance_results['failed_safeguards'])
        compliance_results['compliance_score'] = max(0.0, (total - failed) / total * 100)
        return compliance_results
    
    def generate_compliance_report(self, risks: List[Dict[str, Any]], 
                                  users: Optional[List[Dict[str, Any]]] = None,
                                  groups: Optional[List[Dict[str, Any]]] = None,
                                  computers: Optional[List[Dict[str, Any]]] = None,
                                  password_policy_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report for all frameworks.
        Uses advanced LDAP-based analysis if available, falls back to risk-based analysis.
        
        Args:
            risks: List of risk dictionaries
            users: Optional list of user dictionaries for advanced analysis
            groups: Optional list of group dictionaries for advanced analysis
            computers: Optional list of computer dictionaries for advanced analysis
            password_policy_data: Optional password policy data for advanced analysis
            
        Returns:
            Dict with all compliance analyses
        """
        # Use advanced LDAP-based analysis if available
        if self.analyzer and users is not None and groups is not None and computers is not None:
            logger.info("Using advanced LDAP-based compliance analysis")
            return self.analyzer.generate_comprehensive_compliance_report(
                users, groups, computers, password_policy_data
            )
        
        # Fallback to risk-based analysis
        logger.info("Using risk-based compliance analysis")
        cis_result = self.analyze_cis_benchmark(risks)
        nist_result = self.analyze_nist_csf(risks)
        iso_result = self.analyze_iso_27001(risks)
        gdpr_result = self.analyze_gdpr(risks)
        cis_v8_result = self.analyze_cis_controls_v8(risks)

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
            'overall_compliance_score': overall_score
        }
