"""
Analysis Registry Module
Single source of truth for analysis steps and risk keys.
Enables adding new analyzers without editing the main entry point.
"""

import json
import time
from typing import Any, Callable, Optional

from core.exceptions import AnalysisError, LDAPConnectionError, LDAPSearchError

# ---------------------------------------------------------------------------
# Risk keys: single source for consolidation and export
# ---------------------------------------------------------------------------

# Keys in analysis results that are lists of risks (for consolidated risk list).
# Order matters for consistency; shadow_admin_risks and acl_escalation_risks
# are built in score_and_consolidate from shadow_admins and acl_escalation_paths.
CONSOLIDATION_RISK_KEYS: tuple[str, ...] = (
    "user_risks",
    "computer_risks",
    "group_risks",
    "identity_protection_risks",
    "kerberos_risks",
    "kerberos_account_security_risks",
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
    "fine_grained_password_policy_risks",
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
    "ldap_directory_exposure_risks",
    "hidden_privilege_risks",
    "hybrid_identity_risks",
    "rodc_attack_surface_risks",
    "delegated_msa_risks",
    "sccm_attack_surface_risks",
)

# Mapping: export_data key -> analysis key (for JSON export).
# Covers all analysis-derived keys in the JSON export; renames use different export key.
EXPORT_KEY_TO_ANALYSIS_KEY: dict[str, str] = {
    "user_risks": "user_risks",
    "computer_risks": "computer_risks",
    "group_risks": "group_risks",
    "kerberos_risks": "kerberos_risks",
    "escalation_paths": "escalation_paths",
    "acl_risks": "acl_risks",
    "comprehensive_acl_risks": "comprehensive_acl_risks",
    "misconfig_findings": "misconfig_findings",
    "kerberoasting_targets": "kerberoasting_targets",
    "asrep_targets": "asrep_targets",
    "service_risks": "service_risks",
    "gpo_abuse_risks": "gpo_abuse_risks",
    "dcsync_risks": "dcsync_risks",
    "password_policy_risks": "password_policy_risks",
    "identity_protection_risks": "identity_protection_risks",
    "kerberos_account_security_risks": "kerberos_account_security_risks",
    "fine_grained_password_policy_risks": "fine_grained_password_policy_risks",
    "trust_risks": "trust_risks",
    "certificate_risks": "certificate_risks",
    "gpp_risks": "gpp_risks",
    "laps_risks": "laps_risks",
    "zerologon_risks": "zerologon_risks",
    "printnightmare_risks": "printnightmare_risks",
    "petitpotam_risks": "petitpotam_risks",
    "shadow_credentials_risks": "shadow_cred_risks",
    "nopac_risks": "nopac_risks",
    "domain_security_risks": "domain_security_risks",
    "extended_ldap_risks": "extended_ldap_risks",
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
    "ldap_directory_exposure_risks": "ldap_directory_exposure_risks",
    "hidden_privilege_risks": "hidden_privilege_risks",
    "hybrid_identity_risks": "hybrid_identity_risks",
    "rodc_attack_surface_risks": "rodc_attack_surface_risks",
    "delegated_msa_risks": "delegated_msa_risks",
    "sccm_attack_surface_risks": "sccm_attack_surface_risks",
    "domain_admin_takeover": "domain_admin_takeover",
}


def get_consolidated_risk_lists(analysis: dict[str, Any]) -> list[Any]:
    """Return risk lists from analysis in registry order for consolidation."""
    return [analysis.get(k, []) for k in CONSOLIDATION_RISK_KEYS]


def deduplicate_risks(risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove exact duplicates and duplicate EOL findings for the same object."""
    unique_risks: list[dict[str, Any]] = []
    exact_fingerprints: set[str] = set()
    eol_objects: set[tuple[Any, Any]] = set()

    for risk in risks:
        fingerprint = json.dumps(risk, sort_keys=True, default=str, separators=(",", ":"))
        if fingerprint in exact_fingerprints:
            continue

        if risk.get("type") == "eol_operating_system":
            eol_key = (risk.get("object_type"), risk.get("affected_object"))
            if eol_key in eol_objects:
                continue
            eol_objects.add(eol_key)

        exact_fingerprints.add(fingerprint)
        unique_risks.append(risk)

    return unique_risks


def build_export_analysis_slice(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build the analysis portion of JSON export from analysis dict."""
    out: dict[str, Any] = {}
    dict_only_keys = {"legacy_os_data", "acl_security_data", "tier_data", "domain_admin_takeover"}
    for export_key, analysis_key in EXPORT_KEY_TO_ANALYSIS_KEY.items():
        default: Any = None if export_key in dict_only_keys else []
        out[export_key] = analysis.get(analysis_key, default)
    return out


# ---------------------------------------------------------------------------
# Analysis step: (description, runner)
# Runner: (ldap_conn, data) -> dict to merge into results
# ---------------------------------------------------------------------------

def _run_user_risks(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.user_risks import UserRiskAnalyzer
    users = data["users"]
    analyzer = UserRiskAnalyzer()
    return {"user_risks": analyzer.analyze(users)}


def _run_computer_risks(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.computer_risks import ComputerRiskAnalyzer
    analyzer = ComputerRiskAnalyzer()
    return {"computer_risks": analyzer.analyze(data["computers"])}


def _run_legacy_os(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.legacy_os_analyzer import LegacyOSAnalyzer
    analyzer = LegacyOSAnalyzer()
    res = analyzer.analyze(data["computers"])
    return {"legacy_os_results": res, "legacy_os_risks": res.get("risks", [])}


def _run_group_risks(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.group_risks import GroupRiskAnalyzer
    analyzer = GroupRiskAnalyzer()
    return {"group_risks": analyzer.analyze(data["groups"], data["users"])}


def _run_identity_protection(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.identity_protection_analyzer import IdentityProtectionAnalyzer
    analyzer = IdentityProtectionAnalyzer()
    return {"identity_protection_risks": analyzer.analyze(data["users"])}


def _run_kerberos(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.kerberos_delegation import KerberosDelegationAnalyzer
    analyzer = KerberosDelegationAnalyzer()
    risks = analyzer.analyze(data["users"], data["computers"])
    return {"kerberos_risks": risks}


def _run_kerberos_account_security(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.kerberos_account_security_analyzer import KerberosAccountSecurityAnalyzer
    analyzer = KerberosAccountSecurityAnalyzer()
    return {
        "kerberos_account_security_risks": analyzer.analyze(
            data["users"], data["computers"]
        )
    }


def _run_escalation(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.privilege_escalation import PrivilegeEscalationAnalyzer
    analyzer = PrivilegeEscalationAnalyzer()
    return {"escalation_paths": analyzer.analyze(data["users"], data["groups"], data["computers"])}


def _run_acl_legacy(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from core.collectors.acl_collector import ACLCollector
    collector = ACLCollector(ldap_conn)
    risks = collector.collect_acl_risks(data["users"], data["groups"], data["computers"])
    return {"acl_risks": risks}


def _run_acl_security(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
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


def _run_misconfig(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.misconfiguration_checklist import MisconfigurationChecker
    checker = MisconfigurationChecker()
    return {"misconfig_findings": checker.check(
        data["users"], data["groups"], data["computers"], data["gpos"]
    )}


def _run_kerberoasting(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.kerberoasting_detector import KerberoastingDetector
    detector = KerberoastingDetector()
    return {
        "kerberoasting_targets": detector.detect_kerberoasting_targets(data["users"]),
        "asrep_targets": detector.detect_asrep_roasting_targets(data["users"]),
    }


def _run_service_accounts(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.service_account_analyzer import ServiceAccountAnalyzer
    analyzer = ServiceAccountAnalyzer()
    return {"service_risks": analyzer.analyze_service_accounts(data["users"])}


def _run_gpo_abuse(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.gpo_abuse_analyzer import GPOAbuseAnalyzer
    analyzer = GPOAbuseAnalyzer()
    return {"gpo_abuse_risks": analyzer.analyze_gpo_risks(data["gpos"], data["users"], data["groups"])}


def _run_dcsync(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.dcsync_analyzer import DCSyncAnalyzer
    analyzer = DCSyncAnalyzer(ldap_conn)
    return {"dcsync_risks": analyzer.analyze_dcsync_rights(data["users"], data["groups"])}


def _run_password_policy(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
    analyzer = PasswordPolicyAnalyzer(ldap_conn)
    return {"password_policy_risks": analyzer.analyze_password_policy()}


def _run_fine_grained_password_policy(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.fine_grained_password_policy_analyzer import FineGrainedPasswordPolicyAnalyzer
    analyzer = FineGrainedPasswordPolicyAnalyzer(ldap_conn)
    return {"fine_grained_password_policy_risks": analyzer.analyze()}


def _run_trust(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.trust_analyzer import TrustAnalyzer
    analyzer = TrustAnalyzer(ldap_conn)
    return {"trust_risks": analyzer.analyze_trusts()}


def _run_certificate(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.certificate_analyzer import CertificateAnalyzer
    analyzer = CertificateAnalyzer(ldap_conn)
    return {"certificate_risks": analyzer.analyze_certificate_services()}


def _run_gpp(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.gpp_password_extractor import GPPPasswordExtractor
    extractor = GPPPasswordExtractor(ldap_conn)
    return {"gpp_risks": extractor.analyze_gpp_passwords(data["gpos"])}


def _run_laps(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.laps_analyzer import LAPSAnalyzer
    analyzer = LAPSAnalyzer(ldap_conn)
    return {"laps_risks": analyzer.analyze_laps(data["computers"], data["users"], data["groups"])}


def _run_vulnerability(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.vulnerability_scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner(ldap_conn)
    return {
        "zerologon_risks": scanner.scan_zerologon(data["computers"]),
        "printnightmare_risks": scanner.scan_printnightmare(data["computers"]),
        "petitpotam_risks": scanner.scan_petitpotam(data["computers"]),
        "shadow_cred_risks": scanner.scan_shadow_credentials(data["users"]),
        "nopac_risks": scanner.scan_nopac(data["computers"]),
    }


def _run_domain_security(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.domain_security_analyzer import DomainSecurityAnalyzer
    analyzer = DomainSecurityAnalyzer(ldap_conn)
    return {"domain_security_risks": analyzer.analyze_domain_security(gpos=data["gpos"])}


def _run_extended_ldap(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.extended_ldap_analyzer import ExtendedLDAPAnalyzer
    analyzer = ExtendedLDAPAnalyzer(ldap_conn)
    return {"extended_ldap_risks": analyzer.analyze_all(
        data["users"], data["computers"], data["groups"], data["gpos"]
    )}


def _run_tier(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.tier_analyzer import TierAnalyzer
    analyzer = TierAnalyzer()
    return {"tier_data": analyzer.analyze_tiers(data["users"], data["computers"], data["groups"])}


def _run_password_spray(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.password_spray_risk_analyzer import PasswordSprayRiskAnalyzer
    analyzer = PasswordSprayRiskAnalyzer(ldap_conn)
    return {"password_spray_risks": analyzer.analyze(data["users"])}


def _run_golden_gmsa(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.golden_gmsa_analyzer import GoldenGMSAAnalyzer
    analyzer = GoldenGMSAAnalyzer(ldap_conn)
    return {"golden_gmsa_risks": analyzer.analyze()}


def _run_honeypot(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.honeypot_detector import HoneypotDetector
    detector = HoneypotDetector()
    return {"honeypot_risks": detector.analyze(data["users"], data["groups"])}


def _run_stale_objects(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.stale_objects_analyzer import StaleObjectsAnalyzer
    analyzer = StaleObjectsAnalyzer(ldap_conn)
    return {"stale_objects_risks": analyzer.analyze(data["users"], data["computers"], data["groups"])}


def _run_adcs_extended(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.ad_cs_extended_analyzer import ADCSExtendedAnalyzer
    analyzer = ADCSExtendedAnalyzer(ldap_conn)
    return {"adcs_extended_risks": analyzer.analyze()}


def _run_audit_policy(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.audit_policy_analyzer import AuditPolicyAnalyzer
    analyzer = AuditPolicyAnalyzer(ldap_conn)
    return {"audit_policy_risks": analyzer.analyze(data["groups"])}


def _run_backup_operator(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.backup_operator_analyzer import BackupOperatorAnalyzer
    analyzer = BackupOperatorAnalyzer()
    return {"backup_operator_risks": analyzer.analyze(data["users"], data["groups"])}


def _run_coerce(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.coerce_attack_analyzer import CoerceAttackAnalyzer
    analyzer = CoerceAttackAnalyzer(ldap_conn)
    return {"coercion_risks": analyzer.analyze(data["computers"])}


def _run_gmsa(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.gmsa_analyzer import GMSAAnalyzer
    analyzer = GMSAAnalyzer(ldap_conn)
    return {"gmsa_risks": analyzer.analyze(data["users"])}


def _run_krbtgt(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.krbtgt_health_analyzer import KRBTGTHealthAnalyzer
    analyzer = KRBTGTHealthAnalyzer(ldap_conn)
    return {"krbtgt_risks": analyzer.analyze()}


def _run_lateral_movement(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.lateral_movement_analyzer import LateralMovementAnalyzer
    analyzer = LateralMovementAnalyzer()
    return {"lateral_movement_risks": analyzer.analyze(data["users"], data["computers"], data["groups"])}


def _run_machine_quota(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.machine_quota_analyzer import MachineQuotaAnalyzer
    analyzer = MachineQuotaAnalyzer(ldap_conn)
    return {"machine_quota_risks": analyzer.analyze()}


def _run_replication(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.replication_metadata_analyzer import ReplicationMetadataAnalyzer
    analyzer = ReplicationMetadataAnalyzer(ldap_conn)
    return {"replication_risks": analyzer.analyze(data["users"], data["groups"])}


def _run_ldap_directory_exposure(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.ldap_directory_exposure_analyzer import LDAPDirectoryExposureAnalyzer
    analyzer = LDAPDirectoryExposureAnalyzer(ldap_conn)
    return {"ldap_directory_exposure_risks": analyzer.analyze(data.get("users") or [])}


def _run_hidden_privilege(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.hidden_privilege_analyzer import HiddenPrivilegeAnalyzer
    analyzer = HiddenPrivilegeAnalyzer()
    return {
        "hidden_privilege_risks": analyzer.analyze(data["users"], data["computers"], data["groups"])
    }


def _run_hybrid_identity(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.hybrid_identity_analyzer import HybridIdentityAnalyzer
    analyzer = HybridIdentityAnalyzer(ldap_conn)
    return {"hybrid_identity_risks": analyzer.analyze(data["users"], data["computers"])}


def _run_rodc_attack_surface(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.rodc_attack_surface_analyzer import RODCAttackSurfaceAnalyzer
    analyzer = RODCAttackSurfaceAnalyzer(ldap_conn)
    return {"rodc_attack_surface_risks": analyzer.analyze(data["computers"], data["groups"])}


def _run_delegated_msa(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.delegated_msa_analyzer import DelegatedMSAAnalyzer
    analyzer = DelegatedMSAAnalyzer(ldap_conn)
    return {"delegated_msa_risks": analyzer.analyze()}


def _run_sccm_attack_surface(ldap_conn: Any, data: dict[str, Any]) -> dict[str, Any]:
    from analysis.sccm_attack_surface_analyzer import SCCMAttackSurfaceAnalyzer
    analyzer = SCCMAttackSurfaceAnalyzer(ldap_conn)
    return {"sccm_attack_surface_risks": analyzer.analyze()}


# (key, description, runner) for each analysis step.
ANALYSIS_STEP_REGISTRY: list[tuple[str, str, Callable[[Any, dict[str, Any]], dict[str, Any]]]] = [
    ("user_risks", "User risk analysis", _run_user_risks),
    ("computer_risks", "Computer risk analysis", _run_computer_risks),
    ("legacy_os", "Legacy OS analysis", _run_legacy_os),
    ("group_risks", "Group risk analysis", _run_group_risks),
    ("identity_protection", "Privileged identity protection analysis", _run_identity_protection),
    ("kerberos_delegation", "Kerberos delegation analysis", _run_kerberos),
    (
        "kerberos_account_security",
        "Kerberos account encryption and delegation protection analysis",
        _run_kerberos_account_security,
    ),
    ("privilege_escalation", "Privilege escalation analysis", _run_escalation),
    ("acl_legacy", "ACL analysis (legacy)", _run_acl_legacy),
    ("acl_security", "Comprehensive ACL security analysis", _run_acl_security),
    ("misconfiguration", "Misconfiguration checklist", _run_misconfig),
    ("kerberoasting", "Kerberoasting and AS-REP roasting detection", _run_kerberoasting),
    ("service_accounts", "Service account analysis", _run_service_accounts),
    ("gpo_abuse", "GPO abuse analysis", _run_gpo_abuse),
    ("dcsync", "DCSync rights analysis", _run_dcsync),
    ("password_policy", "Password policy analysis", _run_password_policy),
    (
        "fine_grained_password_policy",
        "Fine-grained password policy override analysis",
        _run_fine_grained_password_policy,
    ),
    ("trusts", "Trust relationship analysis", _run_trust),
    ("certificate_services", "AD Certificate Services analysis", _run_certificate),
    ("gpp_passwords", "GPP password extraction", _run_gpp),
    ("laps", "LAPS analysis", _run_laps),
    ("vulnerability_scan", "Vulnerability scanning", _run_vulnerability),
    ("domain_security", "Domain security analysis", _run_domain_security),
    ("extended_ldap", "Extended LDAP analysis", _run_extended_ldap),
    ("tier_model", "TIER model assessment", _run_tier),
    ("password_spray", "Password spray risk analysis", _run_password_spray),
    ("golden_gmsa", "Golden gMSA analysis", _run_golden_gmsa),
    ("honeypot", "Honeypot/deception detection", _run_honeypot),
    ("stale_objects", "Stale objects analysis", _run_stale_objects),
    ("adcs_extended", "Extended AD CS analysis (ESC5-14)", _run_adcs_extended),
    ("audit_policy", "Audit policy analysis", _run_audit_policy),
    ("backup_operators", "Backup Operators and sensitive groups", _run_backup_operator),
    ("coercion", "Coercion attack surface analysis", _run_coerce),
    ("gmsa", "gMSA configuration analysis", _run_gmsa),
    ("krbtgt", "KRBTGT health analysis", _run_krbtgt),
    ("lateral_movement", "Lateral movement analysis", _run_lateral_movement),
    ("machine_quota", "Machine account quota analysis", _run_machine_quota),
    ("replication_metadata", "Replication metadata analysis", _run_replication),
    ("ldap_directory_exposure", "LDAP directory exposure and anonymous enumeration", _run_ldap_directory_exposure),
    ("hidden_privilege", "Hidden privilege and primary-group analysis", _run_hidden_privilege),
    ("hybrid_identity", "Hybrid identity (Entra Connect, Seamless SSO, ADFS)", _run_hybrid_identity),
    ("rodc_attack_surface", "RODC password-replication attack surface", _run_rodc_attack_surface),
    ("delegated_msa", "Delegated MSA / BadSuccessor analysis", _run_delegated_msa),
    ("sccm_attack_surface", "SCCM System Management attack surface", _run_sccm_attack_surface),
]

# Backward-compatible view used by existing tests and external imports.
ANALYSIS_STEPS: list[tuple[str, Callable[[Any, dict[str, Any]], dict[str, Any]]]] = [
    (description, runner) for _, description, runner in ANALYSIS_STEP_REGISTRY
]

ANALYSIS_STEP_DEFAULTS: dict[str, dict[str, Any]] = {
    "user_risks": {"user_risks": []},
    "computer_risks": {"computer_risks": []},
    "legacy_os": {
        "legacy_os_results": {"total_count": 0, "eol_count": 0, "risks": []},
        "legacy_os_risks": [],
    },
    "group_risks": {"group_risks": []},
    "identity_protection": {"identity_protection_risks": []},
    "kerberos_delegation": {"kerberos_risks": []},
    "kerberos_account_security": {"kerberos_account_security_risks": []},
    "privilege_escalation": {"escalation_paths": []},
    "acl_legacy": {"acl_risks": []},
    "acl_security": {
        "acl_security_results": {
            "acl_risks": [],
            "shadow_admins": [],
            "privilege_escalation_paths": [],
            "inheritance_risks": [],
            "total_risks": 0,
            "critical_risks": 0,
            "high_risks": 0,
        },
        "comprehensive_acl_risks": [],
        "shadow_admins": [],
        "acl_escalation_paths": [],
        "inheritance_risks": [],
    },
    "misconfiguration": {"misconfig_findings": []},
    "kerberoasting": {"kerberoasting_targets": [], "asrep_targets": []},
    "service_accounts": {"service_risks": []},
    "gpo_abuse": {"gpo_abuse_risks": []},
    "dcsync": {"dcsync_risks": []},
    "password_policy": {"password_policy_risks": []},
    "fine_grained_password_policy": {"fine_grained_password_policy_risks": []},
    "trusts": {"trust_risks": []},
    "certificate_services": {"certificate_risks": []},
    "gpp_passwords": {"gpp_risks": []},
    "laps": {"laps_risks": []},
    "vulnerability_scan": {
        "zerologon_risks": [],
        "printnightmare_risks": [],
        "petitpotam_risks": [],
        "shadow_cred_risks": [],
        "nopac_risks": [],
    },
    "domain_security": {"domain_security_risks": []},
    "extended_ldap": {"extended_ldap_risks": []},
    "tier_model": {"tier_data": {}},
    "password_spray": {"password_spray_risks": []},
    "golden_gmsa": {"golden_gmsa_risks": []},
    "honeypot": {"honeypot_risks": []},
    "stale_objects": {"stale_objects_risks": []},
    "adcs_extended": {"adcs_extended_risks": []},
    "audit_policy": {"audit_policy_risks": []},
    "backup_operators": {"backup_operator_risks": []},
    "coercion": {"coercion_risks": []},
    "gmsa": {"gmsa_risks": []},
    "krbtgt": {"krbtgt_risks": []},
    "lateral_movement": {"lateral_movement_risks": []},
    "machine_quota": {"machine_quota_risks": []},
    "replication_metadata": {"replication_risks": []},
    "ldap_directory_exposure": {"ldap_directory_exposure_risks": []},
    "hidden_privilege": {"hidden_privilege_risks": []},
    "hybrid_identity": {"hybrid_identity_risks": []},
    "rodc_attack_surface": {"rodc_attack_surface_risks": []},
    "delegated_msa": {"delegated_msa_risks": []},
    "sccm_attack_surface": {"sccm_attack_surface_risks": []},
}

FAST_PROFILE_EXCLUDED: set[str] = {
    "acl_security",
    "extended_ldap",
    "adcs_extended",
    "coercion",
    "replication_metadata",
}


def get_analysis_step_keys() -> tuple[str, ...]:
    """Return valid analysis step keys for CLI validation."""
    return tuple(key for key, _, _ in ANALYSIS_STEP_REGISTRY)


def _selected_analysis_steps(
    profile: str,
    skip_keys: Optional[list[str]],
) -> list[tuple[str, str, Callable[[Any, dict[str, Any]], dict[str, Any]]]]:
    """Return analysis steps selected by profile and explicit skip keys."""
    skip_set = set(skip_keys or [])
    if profile == "fast":
        skip_set.update(FAST_PROFILE_EXCLUDED)
    return [
        (key, description, runner)
        for key, description, runner in ANALYSIS_STEP_REGISTRY
        if key not in skip_set
    ]


def _defaults_for_skipped_steps(
    selected_keys: set[str],
) -> dict[str, Any]:
    """Return empty result values for skipped analysis steps."""
    defaults: dict[str, Any] = {}
    for key, _, _ in ANALYSIS_STEP_REGISTRY:
        if key not in selected_keys:
            defaults.update(ANALYSIS_STEP_DEFAULTS.get(key, {}))
    return defaults


def run_all_analyses(
    ldap_conn: Any,
    data: dict[str, Any],
    *,
    progress_callback: Optional[Callable[[str, dict[str, Any], Optional[float]], None]] = None,
    status_callback: Optional[Callable[[str], None]] = None,
    profile: str = "full",
    skip_keys: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Run all registered analysis steps and return merged results.
    Optionally call progress_callback(description, step_result) after each step.
    """
    selected_steps = _selected_analysis_steps(profile, skip_keys)
    selected_keys = {key for key, _, _ in selected_steps}
    results: dict[str, Any] = _defaults_for_skipped_steps(selected_keys)

    for key, description, runner in selected_steps:
        if status_callback:
            status_callback(description)
        start_time = time.perf_counter()
        try:
            step_result = runner(ldap_conn, data)
        except (KeyboardInterrupt, SystemExit):
            raise
        except (AnalysisError, LDAPSearchError, LDAPConnectionError):
            raise
        except Exception as exc:
            raise AnalysisError(
                f"Unexpected failure in analysis step {key!r} ({description}): {exc}"
            ) from exc
        duration = time.perf_counter() - start_time
        results.update(step_result)
        if progress_callback:
            progress_callback(description, step_result, duration)
    return results
