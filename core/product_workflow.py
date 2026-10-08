"""Connect accuracy, verification, history and task workflows to each report."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from functools import lru_cache
import hashlib
from typing import Any

from analysis.remediation_verifier import verify_remediation
from analysis.root_cause_analyzer import group_root_causes
from analysis.rule_quality import evaluate_quality
from core.assessment_history import AssessmentHistory
from core.evidence_signing import canonical_json, read_json, unwrap_document, write_document


@lru_cache(maxsize=1)
def _builtin_quality():
    return evaluate_quality()


def load_workflow_document(path: str, args) -> dict[str, Any]:
    document, verification = unwrap_document(
        read_json(path), getattr(args, "trusted_key", None), getattr(args, "require_signed_evidence", False)
    )
    records = getattr(args, "_signature_verifications", None)
    if records is None:
        args._signature_verifications = records = []
    record = {"source": path, **verification}
    if record not in records:
        records.append(record)
    return document


def prepare_product_workspace(
    args, data: dict[str, Any], analysis: dict[str, Any], scoring: dict[str, Any], *, history=None
) -> dict[str, Any]:
    risks = scoring["scored_risks"]
    quality_path = getattr(args, "quality_dataset", None)
    if quality_path:
        dataset = read_json(quality_path)
        if dataset.get("schema_version") != 1 or not isinstance(dataset.get("cases"), list):
            from core.exceptions import ValidationError

            raise ValidationError("Quality dataset requires schema_version 1 and labelled cases")
        quality = evaluate_quality(dataset["cases"])
    else:
        quality = deepcopy(_builtin_quality())
    verification = {"findings": [], "summary": {}, "requested": False}
    if getattr(args, "retest", None):
        verification = verify_remediation(
            load_workflow_document(args.retest, args),
            risks,
            data,
            scoring["scan_coverage"],
            args.domain,
            getattr(args, "retest_finding", None),
        )
        verification["requested"] = True
    workspace = {
        "schema_version": 1,
        "quality": quality,
        "collection_health": data.get("collection_health") or {"status": "unknown", "queries": []},
        "effective_access": analysis.get("effective_access") or {"principals": [], "collected": 0, "requested": 0},
        "verification": verification,
        "root_causes": group_root_causes(risks, analysis.get("attack_graph_v2") or {}),
        "history": {"enabled": False, "runs": [], "changed_finding_ids": [], "notifications": []},
        "tickets": [],
        "audit": {"status": "disabled"},
        "signatures": getattr(args, "_signature_verifications", []),
        "engagement": {"scope": data.get('engagement_scope') or {}, **(analysis.get('engagement') or {})},
    }
    database = getattr(args, "history_db", None)
    if database:
        with ExitStack() as stack:
            if history is None:
                history = stack.enter_context(AssessmentHistory(database))
            stack.enter_context(history.transaction())
            history.audit_document()
            context = dict(data.get("scan_context") or {})
            review_document = scoring["review_center"]["document"]
            context["review_digest"] = hashlib.sha256(canonical_json(review_document)).hexdigest()
            for field, destination, actor in (
                ("reviews", "review_decisions", "reviewer"),
                ("exceptions", "risk_exceptions", "owner"),
            ):
                context[destination] = [
                    {key: row.get(key) for key in ("finding_id", "status", actor, "reviewed_at", "expires_at")}
                    for row in review_document.get(field, [])
                ]
            workspace["history"] = history.record_scan(
                args.domain, risks, scoring["domain_score"], scoring["scan_coverage"], context, verification
            )
            if getattr(args, "ticket_file", None):
                resolved = {row["finding_id"] for row in verification["findings"] if row["status"] == "resolved"}
                history.apply_tasks(load_workflow_document(args.ticket_file, args), args.domain, resolved)
            workspace["tickets"] = history.tasks(args.domain)
            audit = history.audit_document()
            workspace["audit"] = {
                "status": "verified",
                "entries": len(audit["entries"]),
                "chain_head": audit["chain_head"],
            }
            if getattr(args, "audit_export", None):
                write_document(args.audit_export, audit, getattr(args, "signing_key", None))
    return workspace


@contextmanager
def product_workspace_transaction(args, data, analysis, scoring):
    """Roll back findings, tasks and alert deduplication if publication fails."""
    with ExitStack() as stack:
        history = None
        if getattr(args, "history_db", None):
            history = stack.enter_context(AssessmentHistory(args.history_db))
            stack.enter_context(history.transaction())
        yield prepare_product_workspace(args, data, analysis, scoring, history=history)


def export_product_workspace(args, workspace: dict[str, Any], risks: list[dict[str, Any]]) -> None:
    from reporting.export_formats import ExportFormats

    selected = risks
    if getattr(args, "export_changes_only", False):
        changed = set(workspace["history"]["changed_finding_ids"])
        selected = [risk for risk in risks if risk.get("finding_id") in changed]
        current = {risk.get("finding_id") for risk in selected}
        selected.extend(
            row for row in workspace["history"].get("changed_findings", []) if row["finding_id"] not in current
        )
    for field, exporter in (
        ("csv_export", ExportFormats.export_csv),
        ("siem_export", ExportFormats.export_siem_json),
        ("cef_export", ExportFormats.export_cef),
    ):
        path = getattr(args, field, None)
        if path:
            if field == "csv_export":
                exporter(selected, path)
            else:
                exporter(selected, path, args.domain)
            print(f"[+] Integration export saved: {path} ({len(selected)} findings)")
    for field, content in (
        ("quality_export", workspace["quality"]),
        ("retest_export", workspace["verification"]),
        (
            "notifications_export",
            {"schema_version": 1, "domain": args.domain, "notifications": workspace["history"]["notifications"]},
        ),
        ("tickets_export", {"schema_version": 1, "domain": args.domain, "tickets": workspace["tickets"]}),
    ):
        path = getattr(args, field, None)
        if path:
            write_document(path, content, getattr(args, "signing_key", None))
            print(f"[+] Workflow export saved: {path}")
    if workspace["history"]["notifications"]:
        print(f"[+] Important changes: {len(workspace['history']['notifications'])}")
