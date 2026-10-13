"""Separate analysis execution from independently verified endpoint controls."""

from __future__ import annotations

from typing import Any

from analysis.registry import ANALYSIS_STEP_REGISTRY
from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer
from core.finding_evidence import requires_validation


def build_scan_coverage(
    analysis: dict[str, Any],
    risks: list[dict[str, Any]],
    review_center: dict[str, Any],
    collection_health: dict[str, Any] | None = None,
) -> dict[str, Any]:
    execution = analysis.get("analysis_execution") or {}
    known = {key for key, _, _ in ANALYSIS_STEP_REGISTRY}
    ran = set(execution.get("completed_steps") or []) & known
    skipped = execution.get("skipped_steps") or {}
    partial = set(execution.get("partial_steps") or {}) & ran
    completed = ran - partial
    steps = [
        {
            "key": key,
            "description": description,
            "status": "partial" if key in partial else "completed" if key in ran else "skipped" if key in skipped else "unknown",
            "reason": "ldap_query_failed" if key in partial else skipped.get(key, "execution_not_recorded" if key not in ran else ""),
        }
        for key, description, _ in ANALYSIS_STEP_REGISTRY
    ]
    total = len(steps)
    observations = (review_center.get("document") or {}).get("observations") or []
    posture = (analysis.get("posture_evidence") or {}).get("summary") or {}
    controls = []
    for control in PostureEvidenceAnalyzer.CONTROL_ALIASES:
        evidence = (analysis.get("posture_evidence") or {}).get("evidence", {}).get(control) or []
        controls.append(
            {
                "control": control,
                "status": "evidence_imported" if evidence else "not_verified",
                "source_count": len(evidence),
            }
        )
    pending = sum(requires_validation(risk) for risk in risks)
    target_controls = list((analysis.get('posture_evidence') or {}).get('checks') or [])
    target_controls.extend(((analysis.get('engagement') or {}).get('security_controls') or {}).get('checks') or [])
    return {
        "analysis_steps": steps,
        "controls": controls,
        "target_controls": target_controls,
        "summary": {
            "completed_steps": len(completed),
            "partial_steps": len(partial),
            "total_steps": total,
            "execution_percent": round(100 * len(completed) / total, 1) if total and execution else None,
            "skipped_steps": sum(step["status"] == "skipped" for step in steps),
            "unknown_steps": sum(step["status"] == "unknown" for step in steps),
            "verified_findings": sum(risk.get("review_status") == "confirmed" for risk in risks),
            "validation_required": pending,
            "endpoint_observations": len(observations),
            "posture_controls_with_evidence": len(posture.get("covered_controls") or []),
            "total_posture_controls": len(controls),
            "target_control_states": {state: sum(row.get('status') == state for row in target_controls)
                                      for state in ('secure', 'insecure', 'unknown', 'conflicting', 'not_applicable')},
            "assurance_status": 'incomplete' if not target_controls or any(row.get('status') in ('unknown', 'conflicting') for row in target_controls) else 'measured_targets_only',
            "collection_status": (collection_health or {}).get("status") or "unknown",
        },
        "score_scope": "The security score describes supported findings. Completed analysis does not prove that every control or host was verified.",
    }
