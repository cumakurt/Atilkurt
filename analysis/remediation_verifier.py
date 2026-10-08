"""Compare selected findings against a fresh, sufficiently covered assessment."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from core.exceptions import ValidationError
from core.finding_evidence import is_disproved, requires_validation
from core.finding_review import FindingReviewManager, RULE_VERSION, parse_time
from analysis.registry import get_analysis_step_keys


def verify_remediation(
    previous: dict[str, Any],
    risks: list[dict[str, Any]],
    data: dict[str, Any],
    coverage: dict[str, Any],
    domain: str,
    selected_ids: list[str] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if str(previous.get("domain") or "").casefold().strip(".") != domain.casefold().strip("."):
        raise ValidationError("Retest snapshot belongs to a different domain")
    older = deepcopy(previous.get("risks") or [])
    if not isinstance(older, list) or any(not isinstance(risk, dict) for risk in older):
        raise ValidationError("Retest snapshot has invalid findings")
    for old in older:
        if old.get('review_basis') is not None and not isinstance(old['review_basis'], dict):
            raise ValidationError('Retest finding review_basis must be an object')
        old["_saved_rule_version"] = old.get("rule_version")
        old["_saved_disproved"] = is_disproved(old)
        old["_saved_pending"] = requires_validation(old)
        old["_requires_independent_retest"] = bool((old.get("review_basis") or {}).get("requires_validation"))
    old_data = {key: previous.get(key) or [] for key in ("users", "groups", "computers", "gpos")}
    FindingReviewManager().apply(older, old_data, domain)
    requested = set(selected_ids or [risk["finding_id"] for risk in older])
    known = {risk["finding_id"] for risk in older}
    if requested - known:
        raise ValidationError("Retest selection contains an unknown finding ID")
    current = {risk["finding_id"]: risk for risk in risks}
    context = data.get("scan_context") or {}
    health = data.get("collection_health") or {}
    now = now or datetime.now(timezone.utc)
    try:
        collected = parse_time(context.get("collected_at"))
        fresh = now - timedelta(hours=24) <= collected <= now + timedelta(minutes=5)
    except ValidationError:
        fresh = False
    steps = coverage.get("analysis_steps") or []
    full = {step.get("key") for step in steps} == set(get_analysis_step_keys()) and all(
        step.get("status") == "completed" for step in steps
    )
    sufficient = (context.get("fresh_ldap") is True and fresh and health.get("status") == "completed" and full
                  and (data.get('engagement_scope') or {}).get('coverage', 'domain') == 'domain')
    descriptor_gap = any(
        "ntsecuritydescriptor" in {str(name).casefold() for name in query.get("unobserved_attributes", [])}
        or any(
            str(name).casefold() == "ntsecuritydescriptor" and count > 0
            for name, count in query.get("unobserved_attribute_counts", {}).items()
        )
        for query in health.get("queries", [])
    )
    results = []
    for old in older:
        identifier = old["finding_id"]
        if identifier not in requested:
            continue
        present = current.get(identifier)
        old_rule = old.get("_saved_rule_version")
        # Binding restores current IDs; the saved rule version is checked below
        # using the original snapshot metadata rather than overwritten values.
        saved_version = (previous.get("review_center") or {}).get("rule_version")
        status, reason = "insufficient_evidence", "Fresh full collection and analysis are required"
        if saved_version and saved_version != RULE_VERSION or old_rule != RULE_VERSION:
            reason = "Rule version changed; an absence cannot prove remediation"
        elif old["_saved_disproved"]:
            reason = "A disproved finding is not a remediation baseline"
        elif present and not requires_validation(present) and not is_disproved(present):
            status, reason = "still_present", "The current assessment contains this finding"
        elif sufficient and present is None:
            kind = str(old.get("type") or "").casefold()
            if (old["_saved_pending"] or old["_requires_independent_retest"]
                    or kind.startswith(('protocol_', 'sysvol_'))
                    or old.get('source') in {'protocol_verification', 'sysvol_read_only'}):
                reason = "This condition needs independent validation; LDAP absence cannot prove remediation"
            elif descriptor_gap and any(word in kind for word in ("acl", "dcsync", "replication", "path", "gpo")):
                reason = "Security descriptor visibility is incomplete; absence cannot prove remediation"
            elif "password_policy" in kind and any(
                any(
                    str(name).casefold()
                    in {"minpwdlength", "maxpwdage", "pwdhistorylength", "pwdproperties", "lockoutthreshold"}
                    for name in query.get("unobserved_attributes", [])
                )
                for query in health.get("queries", [])
            ):
                reason = "Password policy visibility is incomplete; absence cannot prove remediation"
            else:
                status, reason = "resolved", "The finding is absent after fresh collection and full analysis"
        elif present:
            reason = "Current finding requires validation or has a review decision"
        results.append(
            {
                "finding_id": identifier,
                "title": old.get("title"),
                "affected_object": old.get("affected_object"),
                "status": status,
                "reason": reason,
                "current_fingerprint": present.get("evidence_fingerprint") if present else None,
            }
        )
    return {
        "schema_version": 1,
        "findings": results,
        "summary": {
            status: sum(row["status"] == status for row in results)
            for status in ("resolved", "still_present", "insufficient_evidence")
        },
        "limitation": "LDAP-backed absence is accepted only with fresh full collection and complete analysis. Runtime or ownership conditions need independent retesting. Offline rebuilding, skipped checks and read failures cannot close a finding.",
    }
