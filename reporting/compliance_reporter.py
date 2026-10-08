"""
Compliance Reporting Module
CIS Benchmark, NIST CSF, ISO 27001, GDPR compliance checking
Uses advanced LDAP-based compliance analyzer for detailed checks
"""

import logging
from typing import Any, Optional
from core.finding_evidence import is_disproved, requires_validation
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
        'disabled_domain_admin': 'CIS 2.3.1.5',
        'disabled_enterprise_admin': 'CIS 2.3.1.5',
        'password_policy_weak': 'CIS 2.3.2.1',
        'account_lockout_disabled': 'CIS 2.3.2.2',
        'eol_operating_system': 'CIS 2.3.3.1',
        'laps_not_configured': 'CIS 2.3.4.1',
        'gpp_password_found': 'CIS 2.3.5.1',
        'dcsync_rights': 'CIS 2.3.6.1',
        'trust_relationship_risk': 'CIS 2.3.7.1'
    }

    # NIST CSF mappings
    NIST_CSF_MAPPINGS = {
        'user_password_never_expires': 'PR.AC-1',
        'password_not_required': 'PR.AC-1',
        'kerberos_preauth_disabled': 'PR.AC-1',
        'unconstrained_delegation': 'PR.AC-1',
        'password_policy_weak': 'PR.AC-1',
        'account_lockout_disabled': 'PR.AC-7',
        'eol_operating_system': 'PR.DS-2',
        'laps_not_configured': 'PR.DS-2',
        'gpp_password_found': 'PR.DS-2',
        'dcsync_rights': 'PR.AC-1',
        'trust_relationship_risk': 'PR.AC-1',
        'privilege_escalation_path': 'PR.AC-1',
        'shadow_admin': 'PR.AC-1',
        'disabled_domain_admin': 'PR.AC-1',
        'disabled_enterprise_admin': 'PR.AC-1',
    }

    # ISO 27001 mappings
    ISO_27001_MAPPINGS = {
        'user_password_never_expires': 'A.9.4.2',
        'password_not_required': 'A.9.4.2',
        'kerberos_preauth_disabled': 'A.9.4.2',
        'password_policy_weak': 'A.9.4.3',
        'account_lockout_disabled': 'A.9.4.2',
        'eol_operating_system': 'A.12.6.1',
        'laps_not_configured': 'A.9.2.1',
        'gpp_password_found': 'A.9.4.2',
        'dcsync_rights': 'A.9.2.1',
        'trust_relationship_risk': 'A.9.4.2',
        'privilege_escalation_path': 'A.9.2.1',
        'shadow_admin': 'A.9.2.1',
        'disabled_domain_admin': 'A.9.2.1',
        'disabled_enterprise_admin': 'A.9.2.1',
    }

    # CIS Controls v8 mappings (Critical Security Controls)
    CIS_CONTROLS_V8_MAPPINGS = {
        'user_password_never_expires': '4.3 (Unused/Unauthorized Account Disabled)',
        'password_not_required': '5.2 (Privileged Access Management)',
        'kerberos_preauth_disabled': '5.2 (Privileged Access Management)',
        'unconstrained_delegation': '5.2 (Privileged Access Management)',
        'too_many_domain_admins': '5.1 (Privileged Account Inventory)',
        'disabled_domain_admin': '5.1 (Privileged Account Inventory)',
        'disabled_enterprise_admin': '5.1 (Privileged Account Inventory)',
        'password_policy_weak': '5.2 (Privileged Access Management)',
        'account_lockout_disabled': '5.2 (Privileged Access Management)',
        'eol_operating_system': '7.1 (Vulnerability Management)',
        'laps_not_configured': '4.6 (Removable Media)',
        'gpp_password_found': '5.2 (Privileged Access Management)',
        'dcsync_rights': '5.2 (Privileged Access Management)',
        'trust_relationship_risk': '13.2 (Network Security)',
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
        'password_policy_weak': 'Article 32',
        'account_lockout_disabled': 'Article 32',
        'gpp_password_found': 'Article 32',
        'dcsync_rights': 'Article 32',
        'privilege_escalation_path': 'Article 32',
        'shadow_admin': 'Article 32',
        'disabled_domain_admin': 'Article 32',
        'disabled_enterprise_admin': 'Article 32',
    }

    RISK_TYPE_ALIASES = {
        'weak_password_policy': 'password_policy_weak',
        'gpp_passwords': 'gpp_password_found',
        'trust_sid_filtering_disabled': 'trust_relationship_risk',
    }

    @classmethod
    def _risk_type_counts(cls, risks: list[dict[str, Any]]) -> dict[str, int]:
        """Count current risk identifiers while accepting legacy aliases."""
        counts: dict[str, int] = defaultdict(int)
        for risk in risks:
            if requires_validation(risk) or is_disproved(risk):
                continue
            risk_type = risk.get('type', '')
            canonical_type = cls.RISK_TYPE_ALIASES.get(risk_type, risk_type)
            counts[canonical_type] += 1
        return counts

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

    def _mapped_checks(self, risks, mapping):
        """Findings prove failures; their absence cannot prove a control passed."""
        counts = self._risk_type_counts(risks)
        return [
            {'control': control, 'control_id': control, 'control_name': risk_type,
             'risk_type': risk_type, 'count': counts[risk_type],
             'status': 'failed' if counts[risk_type] else 'unknown'}
            for risk_type, control in mapping.items()
        ]

    @staticmethod
    def _finding_summary(framework, checks):
        return {
            'framework': framework,
            'assessment_basis': 'findings_only',
            'assessment_status': 'partial' if any(row['status'] == 'failed' for row in checks) else 'not_assessed',
            'compliance_score': 0.0,
            'total_controls': len({row['control'] for row in checks}),
            'total_checks': len(checks),
            'unknown_checks': sum(row['status'] == 'unknown' for row in checks),
            'limitation': 'Findings establish mapped failures only. Absence of a finding does not verify compliance.',
        }

    def analyze_cis_benchmark(self, risks: list[dict[str, Any]]) -> dict[str, Any]:
        """Map observed failures without treating unassessed controls as passed."""
        checks = self._mapped_checks(risks, self.CIS_BENCHMARK_MAPPINGS)
        result = self._finding_summary('CIS Benchmark', checks)
        result.update(controls=checks, passed_controls=[],
                      failed_controls=[row for row in checks if row['status'] == 'failed'],
                      unknown_controls=sorted({row['control'] for row in checks if row['status'] == 'unknown'}))
        return result

    def analyze_nist_csf(self, risks: list[dict[str, Any]]) -> dict[str, Any]:
        """Group mapped failures by NIST function with explicit unknown checks."""
        checks = self._mapped_checks(risks, self.NIST_CSF_MAPPINGS)
        result = self._finding_summary('NIST CSF', checks)
        functions = {}
        for key, name in (('PR', 'Protect'), ('DE', 'Detect'), ('RS', 'Respond'), ('RC', 'Recover'), ('ID', 'Identify')):
            rows = [row for row in checks if row['control'].split('.', 1)[0] == key]
            failed = any(row['status'] == 'failed' for row in rows)
            functions[key] = {'name': name, 'controls': rows, 'status': 'partial' if failed else 'not_assessed',
                              'score': 0.0 if rows else None}
        result['functions'] = functions
        return result

    def analyze_iso_27001(self, risks: list[dict[str, Any]]) -> dict[str, Any]:
        """Keep mapped findings and unknown checks visible in each ISO domain."""
        checks = self._mapped_checks(risks, self.ISO_27001_MAPPINGS)
        result = self._finding_summary('ISO 27001', checks)
        domains = defaultdict(list)
        for row in checks:
            domains['.'.join(row['control'].split('.')[:2])].append(row)
        result.update(domains=dict(domains), domain_scores={key: 0.0 for key in domains})
        return result

    def analyze_gdpr(self, risks: list[dict[str, Any]]) -> dict[str, Any]:
        """Expose mapped findings without inferring regulatory compliance."""
        checks = self._mapped_checks(risks, self.GDPR_MAPPINGS)
        result = self._finding_summary('GDPR', checks)
        articles = defaultdict(list)
        for row in checks:
            articles[row['control']].append(row)
        result.update(articles=dict(articles), article_scores={key: 0.0 for key in articles})
        return result

    def analyze_cis_controls_v8(self, risks: list[dict[str, Any]]) -> dict[str, Any]:
        """Expose observed safeguard failures and the remaining unknown checks."""
        checks = self._mapped_checks(risks, self.CIS_CONTROLS_V8_MAPPINGS)
        result = self._finding_summary('CIS Controls v8', checks)
        result.update(safeguards=checks, passed_safeguards=[],
                      failed_safeguards=[{'safeguard': row['control'], **row} for row in checks if row['status'] == 'failed'],
                      unknown_safeguards=sorted({row['control'] for row in checks if row['status'] == 'unknown'}))
        return result

    def generate_compliance_report(self, risks: list[dict[str, Any]],
                                  users: Optional[list[dict[str, Any]]] = None,
                                  groups: Optional[list[dict[str, Any]]] = None,
                                  computers: Optional[list[dict[str, Any]]] = None,
                                  password_policy_data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
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
            'overall_compliance_score': overall_score,
            'assessment_basis': 'findings_only',
            'assessment_status': 'partial' if any(result['assessment_status'] == 'partial' for result in
                (cis_result, nist_result, iso_result, gdpr_result, cis_v8_result)) else 'not_assessed',
            'limitation': cis_result['limitation'],
        }
