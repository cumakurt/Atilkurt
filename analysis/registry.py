"""
Analysis Registry Module
Single source of truth for analysis steps and risk keys.
Enables adding new analyzers without editing the main entry point.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Risk keys: single source for consolidation and export
# ---------------------------------------------------------------------------

# Keys in analysis results that are lists of risks (for consolidated risk list).
# Order matters for consistency; shadow_admin_risks and acl_escalation_risks
# are built in score_and_consolidate from shadow_admins and acl_escalation_paths.
CONSOLIDATION_RISK_KEYS: Tuple[str, ...] = (
    "user_risks",
    "computer_risks",
    "group_risks",
    "kerberos_risks",
    "escalation_paths",
    "acl_risks",
    "comprehensive_acl_risks",
    "legacy_os_risks",
    "kerberoasting_targets",
    "asrep_targets",
    "service_risks",
    "gpo_abuse_risks",
    "dcsync_risks",
    "password_policy_risks",
    "trust_risks",
    "certificate_risks",
    "gpp_risks",
    "laps_risks",
    "zerologon_risks",
    "printnightmare_risks",
    "petitpotam_risks",
    "shadow_cred_risks",
    "nopac_risks",
    "domain_security_risks",
    "extended_ldap_risks",
    "password_spray_risks",
    "golden_gmsa_risks",
    "honeypot_risks",
    "stale_objects_risks",
    "adcs_extended_risks",
    "audit_policy_risks",
    "backup_operator_risks",
    "coercion_risks",
    "gmsa_risks",
    "krbtgt_risks",
    "lateral_movement_risks",
    "machine_quota_risks",
    "replication_risks",
)

# Mapping: export_data key -> analysis key (for JSON export).
# Covers all analysis-derived keys in the JSON export; renames use different export key.
EXPORT_KEY_TO_ANALYSIS_KEY: Dict[str, str] = {
    "misconfig_findings": "misconfig_findings",
    "kerberoasting_targets": "kerberoasting_targets",
    "asrep_targets": "asrep_targets",
    "service_risks": "service_risks",
    "gpo_abuse_risks": "gpo_abuse_risks",
    "dcsync_risks": "dcsync_risks",
    "password_policy_risks": "password_policy_risks",
    "trust_risks": "trust_risks",
    "certificate_risks": "certificate_risks",
    "gpp_risks": "gpp_risks",
    "laps_risks": "laps_risks",
    "zerologon_risks": "zerologon_risks",
    "printnightmare_risks": "printnightmare_risks",
    "petitpotam_risks": "petitpotam_risks",
    "shadow_credentials_risks": "shadow_cred_risks",
    "legacy_os_data": "legacy_os_results",
    "acl_security_data": "acl_security_results",
    "shadow_admins": "shadow_admins",
    "acl_escalation_paths": "acl_escalation_paths",
    "tier_data": "tier_data",
    "password_spray_risks": "password_spray_risks",
    "golden_gmsa_risks": "golden_gmsa_risks",
    "honeypot_risks": "honeypot_risks",
    "stale_objects_risks": "stale_objects_risks",
    "adcs_extended_risks": "adcs_extended_risks",
    "audit_policy_risks": "audit_policy_risks",
    "backup_operator_risks": "backup_operator_risks",
    "coercion_risks": "coercion_risks",
    "gmsa_risks": "gmsa_risks",
    "krbtgt_risks": "krbtgt_risks",
    "lateral_movement_risks": "lateral_movement_risks",
    "machine_quota_risks": "machine_quota_risks",
    "replication_risks": "replication_risks",
}


def get_consolidated_risk_lists(analysis: Dict[str, Any]) -> List[Any]:
    """Return risk lists from analysis in registry order for consolidation."""
    return [analysis.get(k, []) for k in CONSOLIDATION_RISK_KEYS]


def build_export_analysis_slice(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Build the analysis portion of JSON export from analysis dict."""
    out: Dict[str, Any] = {}
    dict_only_keys = {"legacy_os_data", "acl_security_data", "tier_data"}
    for export_key, analysis_key in EXPORT_KEY_TO_ANALYSIS_KEY.items():
        default: Any = None if export_key in dict_only_keys else []
        out[export_key] = analysis.get(analysis_key, default)
    return out


# ---------------------------------------------------------------------------
# Analysis step: (description, runner)
# Runner: (ldap_conn, data) -> dict to merge into results
# ---------------------------------------------------------------------------

def _run_user_risks(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.user_risks import UserRiskAnalyzer
    users = data["users"]
    analyzer = UserRiskAnalyzer()
    return {"user_risks": analyzer.analyze(users)}


def _run_computer_risks(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.computer_risks import ComputerRiskAnalyzer
    analyzer = ComputerRiskAnalyzer()
    return {"computer_risks": analyzer.analyze(data["computers"])}


def _run_legacy_os(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.legacy_os_analyzer import LegacyOSAnalyzer
    analyzer = LegacyOSAnalyzer()
    res = analyzer.analyze(data["computers"])
    return {"legacy_os_results": res, "legacy_os_risks": res.get("risks", [])}


def _run_group_risks(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.group_risks import GroupRiskAnalyzer
    analyzer = GroupRiskAnalyzer()
    return {"group_risks": analyzer.analyze(data["groups"], data["users"])}


def _run_kerberos(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.kerberos_delegation import KerberosDelegationAnalyzer
    analyzer = KerberosDelegationAnalyzer()
    risks = analyzer.analyze(data["users"], data["computers"])
    return {"kerberos_risks": risks}


def _run_escalation(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.privilege_escalation import PrivilegeEscalationAnalyzer
    analyzer = PrivilegeEscalationAnalyzer()
    return {"escalation_paths": analyzer.analyze(data["users"], data["groups"], data["computers"])}


def _run_acl_legacy(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from core.collectors.acl_collector import ACLCollector
    collector = ACLCollector(ldap_conn)
    risks = collector.collect_acl_risks(data["users"], data["groups"], data["computers"])
    return {"acl_risks": risks}


def _run_acl_security(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.acl_security_analyzer import ACLSecurityAnalyzer
    analyzer = ACLSecurityAnalyzer(ldap_conn)
    res = analyzer.analyze(data["users"], data["groups"], data["computers"])
    return {
        "acl_security_results": res,
        "comprehensive_acl_risks": res.get("acl_risks", []),
        "shadow_admins": res.get("shadow_admins", []),
        "acl_escalation_paths": res.get("privilege_escalation_paths", []),
        "inheritance_risks": res.get("inheritance_risks", []),
    }


def _run_misconfig(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.misconfiguration_checklist import MisconfigurationChecker
    checker = MisconfigurationChecker()
    return {"misconfig_findings": checker.check(
        data["users"], data["groups"], data["computers"], data["gpos"]
    )}


def _run_kerberoasting(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.kerberoasting_detector import KerberoastingDetector
    detector = KerberoastingDetector()
    return {
        "kerberoasting_targets": detector.detect_kerberoasting_targets(data["users"]),
        "asrep_targets": detector.detect_asrep_roasting_targets(data["users"]),
    }


def _run_service_accounts(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.service_account_analyzer import ServiceAccountAnalyzer
    analyzer = ServiceAccountAnalyzer()
    return {"service_risks": analyzer.analyze_service_accounts(data["users"])}


def _run_gpo_abuse(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.gpo_abuse_analyzer import GPOAbuseAnalyzer
    analyzer = GPOAbuseAnalyzer()
    return {"gpo_abuse_risks": analyzer.analyze_gpo_risks(data["gpos"], data["users"], data["groups"])}


def _run_dcsync(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.dcsync_analyzer import DCSyncAnalyzer
    analyzer = DCSyncAnalyzer(ldap_conn)
    return {"dcsync_risks": analyzer.analyze_dcsync_rights(data["users"], data["groups"])}


def _run_password_policy(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
    analyzer = PasswordPolicyAnalyzer(ldap_conn)
    return {"password_policy_risks": analyzer.analyze_password_policy()}


def _run_trust(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.trust_analyzer import TrustAnalyzer
    analyzer = TrustAnalyzer(ldap_conn)
    return {"trust_risks": analyzer.analyze_trusts()}


def _run_certificate(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.certificate_analyzer import CertificateAnalyzer
    analyzer = CertificateAnalyzer(ldap_conn)
    return {"certificate_risks": analyzer.analyze_certificate_services()}


def _run_gpp(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.gpp_password_extractor import GPPPasswordExtractor
    extractor = GPPPasswordExtractor(ldap_conn)
    return {"gpp_risks": extractor.analyze_gpp_passwords(data["gpos"])}


def _run_laps(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.laps_analyzer import LAPSAnalyzer
    analyzer = LAPSAnalyzer(ldap_conn)
    return {"laps_risks": analyzer.analyze_laps(data["computers"], data["users"], data["groups"])}


def _run_vulnerability(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.vulnerability_scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner(ldap_conn)
    return {
        "zerologon_risks": scanner.scan_zerologon(data["computers"]),
        "printnightmare_risks": scanner.scan_printnightmare(data["computers"]),
        "petitpotam_risks": scanner.scan_petitpotam(data["computers"]),
        "shadow_cred_risks": scanner.scan_shadow_credentials(data["users"]),
        "nopac_risks": scanner.scan_nopac(data["computers"]),
    }


def _run_domain_security(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.domain_security_analyzer import DomainSecurityAnalyzer
    analyzer = DomainSecurityAnalyzer(ldap_conn)
    return {"domain_security_risks": analyzer.analyze_domain_security(gpos=data["gpos"])}


def _run_extended_ldap(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.extended_ldap_analyzer import ExtendedLDAPAnalyzer
    analyzer = ExtendedLDAPAnalyzer(ldap_conn)
    return {"extended_ldap_risks": analyzer.analyze_all(
        data["users"], data["computers"], data["groups"], data["gpos"]
    )}


def _run_tier(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.tier_analyzer import TierAnalyzer
    analyzer = TierAnalyzer()
    return {"tier_data": analyzer.analyze_tiers(data["users"], data["computers"], data["groups"])}


def _run_password_spray(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.password_spray_risk_analyzer import PasswordSprayRiskAnalyzer
    analyzer = PasswordSprayRiskAnalyzer(ldap_conn)
    return {"password_spray_risks": analyzer.analyze(data["users"])}


def _run_golden_gmsa(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.golden_gmsa_analyzer import GoldenGMSAAnalyzer
    analyzer = GoldenGMSAAnalyzer(ldap_conn)
    return {"golden_gmsa_risks": analyzer.analyze()}


def _run_honeypot(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.honeypot_detector import HoneypotDetector
    detector = HoneypotDetector()
    return {"honeypot_risks": detector.analyze(data["users"], data["groups"])}


def _run_stale_objects(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.stale_objects_analyzer import StaleObjectsAnalyzer
    analyzer = StaleObjectsAnalyzer(ldap_conn)
    return {"stale_objects_risks": analyzer.analyze(data["users"], data["computers"], data["groups"])}


def _run_adcs_extended(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.ad_cs_extended_analyzer import ADCSExtendedAnalyzer
    analyzer = ADCSExtendedAnalyzer(ldap_conn)
    return {"adcs_extended_risks": analyzer.analyze()}


def _run_audit_policy(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.audit_policy_analyzer import AuditPolicyAnalyzer
    analyzer = AuditPolicyAnalyzer(ldap_conn)
    return {"audit_policy_risks": analyzer.analyze(data["groups"])}


def _run_backup_operator(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.backup_operator_analyzer import BackupOperatorAnalyzer
    analyzer = BackupOperatorAnalyzer()
    return {"backup_operator_risks": analyzer.analyze(data["users"], data["groups"])}


def _run_coerce(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.coerce_attack_analyzer import CoerceAttackAnalyzer
    analyzer = CoerceAttackAnalyzer(ldap_conn)
    return {"coercion_risks": analyzer.analyze(data["computers"])}


def _run_gmsa(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.gmsa_analyzer import GMSAAnalyzer
    analyzer = GMSAAnalyzer(ldap_conn)
    return {"gmsa_risks": analyzer.analyze(data["users"])}


def _run_krbtgt(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.krbtgt_health_analyzer import KRBTGTHealthAnalyzer
    analyzer = KRBTGTHealthAnalyzer(ldap_conn)
    return {"krbtgt_risks": analyzer.analyze()}


def _run_lateral_movement(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.lateral_movement_analyzer import LateralMovementAnalyzer
    analyzer = LateralMovementAnalyzer()
    return {"lateral_movement_risks": analyzer.analyze(data["users"], data["computers"], data["groups"])}


def _run_machine_quota(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.machine_quota_analyzer import MachineQuotaAnalyzer
    analyzer = MachineQuotaAnalyzer(ldap_conn)
    return {"machine_quota_risks": analyzer.analyze()}


def _run_replication(ldap_conn: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    from analysis.replication_metadata_analyzer import ReplicationMetadataAnalyzer
    analyzer = ReplicationMetadataAnalyzer(ldap_conn)
    return {"replication_risks": analyzer.analyze(data["users"], data["groups"])}


# (description, runner) for each analysis step
ANALYSIS_STEPS: List[Tuple[str, Callable[[Any, Dict[str, Any]], Dict[str, Any]]]] = [
    ("User risk analysis", _run_user_risks),
    ("Computer risk analysis", _run_computer_risks),
    ("Legacy OS analysis", _run_legacy_os),
    ("Group risk analysis", _run_group_risks),
    ("Kerberos delegation analysis", _run_kerberos),
    ("Privilege escalation analysis", _run_escalation),
    ("ACL analysis (legacy)", _run_acl_legacy),
    ("Comprehensive ACL security analysis", _run_acl_security),
    ("Misconfiguration checklist", _run_misconfig),
    ("Kerberoasting and AS-REP roasting detection", _run_kerberoasting),
    ("Service account analysis", _run_service_accounts),
    ("GPO abuse analysis", _run_gpo_abuse),
    ("DCSync rights analysis", _run_dcsync),
    ("Password policy analysis", _run_password_policy),
    ("Trust relationship analysis", _run_trust),
    ("AD Certificate Services analysis", _run_certificate),
    ("GPP password extraction", _run_gpp),
    ("LAPS analysis", _run_laps),
    ("Vulnerability scanning", _run_vulnerability),
    ("Domain security analysis", _run_domain_security),
    ("Extended LDAP analysis", _run_extended_ldap),
    ("TIER model assessment", _run_tier),
    ("Password spray risk analysis", _run_password_spray),
    ("Golden gMSA analysis", _run_golden_gmsa),
    ("Honeypot/deception detection", _run_honeypot),
    ("Stale objects analysis", _run_stale_objects),
    ("Extended AD CS analysis (ESC5-14)", _run_adcs_extended),
    ("Audit policy analysis", _run_audit_policy),
    ("Backup Operators and sensitive groups", _run_backup_operator),
    ("Coercion attack surface analysis", _run_coerce),
    ("gMSA configuration analysis", _run_gmsa),
    ("KRBTGT health analysis", _run_krbtgt),
    ("Lateral movement analysis", _run_lateral_movement),
    ("Machine account quota analysis", _run_machine_quota),
    ("Replication metadata analysis", _run_replication),
]


def run_all_analyses(
    ldap_conn: Any,
    data: Dict[str, Any],
    *,
    progress_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """
    Run all registered analysis steps and return merged results.
    Optionally call progress_callback(description, step_result) after each step.
    """
    results: Dict[str, Any] = {}
    for description, runner in ANALYSIS_STEPS:
        step_result = runner(ldap_conn, data)
        results.update(step_result)
        if progress_callback:
            progress_callback(description, step_result)
    return results
