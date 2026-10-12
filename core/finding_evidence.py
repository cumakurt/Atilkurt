"""Shared evidence boundaries for scoring, reporting, and attack-path claims."""

from typing import Any


def invalidate_finding_evidence(original: dict[str, Any], state: str) -> dict[str, Any]:
    """Retain finding identity when prior evidence no longer proves its condition."""
    from copy import deepcopy

    risk = deepcopy(original)
    basis = risk.pop('review_basis', None)
    if isinstance(basis, dict):
        risk.update(basis)
    risk.update(requires_validation=True, finding_status='needs_validation', score_excluded=True)
    evidence = risk.get('evidence')
    evidence = evidence if isinstance(evidence, dict) else {}
    evidence.pop('vulnerability_confirmed', None)
    evidence.pop('validation_review', None)
    evidence.update(requires_runtime_validation=True, control_state=state)
    risk['evidence'] = evidence
    return risk


# These LDAP rules identify a component, an absent observation, or a prerequisite.
# Their output alone does not establish an exploitable configuration.
VALIDATION_REQUIRED_TYPES = frozenset({
    'zerologon_vulnerable', 'printnightmare_vulnerable', 'petitpotam_vulnerable', 'nopac_vulnerable',
    'coercion_spoolsample', 'coercion_dfscoerce', 'coercion_webclient',
    'shadow_credentials', 'key_credential_link_present', 'key_credential_privileged',
    'hybrid_azure_sso_account', 'hybrid_entra_connect_account', 'hybrid_adfs_service',
    'hybrid_join_not_observed', 'dmsa_schema_enabled', 'dmsa_object_present',
    'sccm_system_management_present', 'sccm_management_point',
    'laps_not_configured', 'windows_laps_not_deployed', 'windows_laps_encryption_gap',
    'windows_laps_history_disabled', 'windows_laps_dsrm_not_backed_up',
    'posture_evidence_incomplete', 'password_spray_risk',
    'golden_gmsa_root_key', 'gpo_linked_to_privileged_ou', 'gpo_modification_rights',
    'lateral_movement_unrestricted', 'lateral_movement_tier_violation',
    'bitlocker_recovery_in_ad', 'certificate_services_detected', 'adminsdholder_analysis',
    'fine_grained_password_policy', 'foreign_security_principal', 'dns_zone_found',
    'exchange_objects_found', 'ad_recycle_bin_enabled', 'builtin_admin_renamed',
    'honeypot_candidate', 'honeypot_recommendation', 'trust_stale_configuration',
})


def requires_validation(risk: dict[str, Any]) -> bool:
    """Return whether a finding still needs evidence before it can be scored.

    A positive validation result must be explicit; a nonempty probe string (for
    example, "not vulnerable") is not proof. Existing checkpoint findings use
    the same evidence boundary as newly collected findings.
    """
    evidence = risk.get('evidence')
    evidence = evidence if isinstance(evidence, dict) else {}
    if risk.get('finding_status') == 'false_positive':
        return False
    if risk.get('requires_validation') is True or evidence.get('requires_runtime_validation') or risk.get('finding_status') == 'needs_validation':
        return True
    if evidence.get('vulnerability_confirmed') is True:
        return False
    risk_type = str(risk.get('type') or '').casefold()
    return bool(
        risk_type in VALIDATION_REQUIRED_TYPES
        or risk_type.startswith('certificate_esc')
        or risk.get('cve')
    )


def is_score_excluded(risk: dict[str, Any]) -> bool:
    """Review decisions and accepted risks do not inflate remediation scores."""
    return (requires_validation(risk) or risk.get('finding_status') == 'false_positive'
            or risk.get('exception_status') == 'active')


def is_disproved(risk: dict[str, Any]) -> bool:
    return risk.get('finding_status') == 'false_positive'


def annotate_validation(risk: dict[str, Any]) -> None:
    """Preserve the potential impact while marking unverified findings for review."""
    if requires_validation(risk):
        risk.setdefault('potential_severity', risk.get('severity', 'low'))
        risk['finding_status'] = 'needs_validation'
        risk['score_excluded'] = True
        risk['severity'] = 'low'
        risk['severity_level'] = 'Low'
