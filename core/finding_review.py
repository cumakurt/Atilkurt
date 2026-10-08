"""Persistent, configuration-bound finding reviews and expiring risk exceptions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any

from core.ad_security import as_text
from core.exceptions import ValidationError
from core.finding_evidence import requires_validation

RULE_VERSION = "2026.10.1"
MAX_REVIEW_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10000
REVIEW_STATUSES = {"confirmed", "false_positive", "insufficient_evidence"}
CONFIG_FIELDS = (
    "userAccountControl",
    "memberOf",
    "member",
    "primaryGroupID",
    "objectSid",
    "tokenGroups",
    "sIDHistory",
    "nTSecurityDescriptor",
    "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink",
    "operatingSystem",
    "operatingSystemVersion",
    "gPLink",
    "gPOptions",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> datetime:
    """Require an explicit timezone so expiration is independent of the host."""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("Timezone is required")
        return moment.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Review timestamps must use ISO 8601 with a timezone") from exc


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, ensure_ascii=True).encode()).hexdigest()


def required_checks(risk: dict[str, Any]) -> list[str]:
    """Name the prerequisites a reviewer must independently substantiate."""
    kind = str(risk.get("type") or "").casefold()
    if kind.startswith("certificate_esc"):
        return ["template_configuration", "enrollment_permissions", "ca_publication", "ca_policy"]
    if risk.get("cve"):
        return ["affected_version_or_configuration", "service_exposure", "effective_policy"]
    if "laps" in kind:
        return ["effective_laps_policy", "attribute_read_visibility", "target_configuration"]
    if "key_credential" in kind or kind == "shadow_credentials":
        return ["key_ownership", "unauthorized_key_or_write_access"]
    if "replication" in kind or "dcsync" in kind:
        return ["domain_root_scope", "get_changes", "get_changes_all", "principal_token"]
    if kind.startswith("event_"):
        return ["event_identity", "activity_context", "unauthorized_activity"]
    return ["condition_verified", "security_impact_verified"]


def _stable_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _stable_evidence(item)
            for key, item in value.items()
            if key
            not in {
                "source",
                "source_files",
                "collected_at",
                "requires_runtime_validation",
                "vulnerability_confirmed",
                "validation_review",
            }
        }
    if isinstance(value, (list, tuple)):
        return [_stable_evidence(item) for item in value]
    if isinstance(value, set):
        return sorted(
            (_stable_evidence(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True, default=str)
        )
    if isinstance(value, bytes):
        return str(value)
    return value


def bind_finding(risk: dict[str, Any], domain: str, objects: dict[str, list[dict[str, Any]]]) -> None:
    """Attach an immutable identity and a fingerprint of observed configuration."""
    evidence = risk.get("evidence")
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    original = risk.setdefault(
        "review_basis",
        {
            "evidence": evidence,
            "severity": risk.get("potential_severity", risk.get("severity", "low")),
            "requires_validation": requires_validation(risk),
            "title": risk.get("title", ""),
        },
    )
    if not isinstance(original, dict) or not {'evidence', 'severity', 'requires_validation'} <= original.keys():
        raise ValidationError('Finding review_basis requires evidence, severity and requires_validation')
    original.setdefault("title", risk.get("title", ""))
    # Several analyzers use one type for distinct conditions on one object.
    # Keep those decisions separate while treating numeric changes as evidence
    # changes rather than changes to the underlying rule's identity.
    condition = re.sub(r"\b\d+(?:\.\d+)?\b", "#", str(original["title"]).casefold())
    identity = {
        "domain": domain.casefold().strip("."),
        "type": risk.get("type"),
        "object_type": risk.get("object_type"),
        "affected_object": str(risk.get("affected_object") or "").casefold(),
        "target": str(risk.get("target_object") or evidence_dict.get("target_dn") or "").casefold(),
        "trustee": risk.get("trustee") or evidence_dict.get("trustee_sid"),
        "permission": risk.get("permission") or evidence_dict.get("permission"),
        "condition": condition,
    }
    risk["finding_id"] = _hash(identity)[:24]
    risk["rule_version"] = RULE_VERSION
    labels = {str(identity["affected_object"]), str(identity["target"])}
    context = []
    for name in labels:
        for obj in objects.get(name, []):
            context.append({key: _stable_evidence(obj[key]) for key in CONFIG_FIELDS if key in obj})
    configuration = {
        "identity": identity,
        "evidence": _stable_evidence(original["evidence"]),
        "context": sorted(context, key=lambda item: json.dumps(item, sort_keys=True, default=str)),
        "rights": risk.get("dcsync_rights"),
        "path": risk.get("path"),
        "cve": risk.get("cve"),
        "condition_details": original["title"],
    }
    risk["evidence_fingerprint"] = _hash(configuration)


def empty_review_document(domain: str) -> dict[str, Any]:
    return {"schema_version": 1, "domain": domain, "reviews": [], "exceptions": [], "observations": []}


def load_review_document(path: str, domain: str, *, trusted_keys: list[str] | None = None,
                        require_signed: bool = False) -> dict[str, Any]:
    """Read a bounded document; malformed input is never silently ignored."""
    try:
        from core.evidence_signing import canonical_json, read_json, unwrap_document
        wrapped = read_json(path, MAX_REVIEW_BYTES * 2)
        document, signature = unwrap_document(wrapped, trusted_keys, require_signed)
        if len(canonical_json(document)) > MAX_REVIEW_BYTES:
            raise ValidationError("Review document exceeds the 16 MiB limit")
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValidationError(f"Cannot read review document: {path}") from exc
    validate_review_document(document, domain)
    document["signature_verification"] = signature
    return document


def validate_review_document(document: Any, domain: str) -> None:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValidationError("Review document requires schema_version 1")
    if str(document.get("domain") or "").casefold().strip(".") != domain.casefold().strip("."):
        raise ValidationError("Review document belongs to a different domain")
    for field in ("reviews", "exceptions", "observations"):
        rows = document.get(field, [])
        if not isinstance(rows, list) or len(rows) > MAX_RECORDS or any(not isinstance(row, dict) for row in rows):
            raise ValidationError(f"Review document {field} must be a bounded list of records")
    for review in document.get("reviews", []):
        if not isinstance(review.get("status"), str) or review.get("status") not in REVIEW_STATUSES:
            raise ValidationError("Unknown finding review status")
        if not isinstance(review.get("checks", []), list) or len(review.get("checks", [])) > 100:
            raise ValidationError("Review checks must be a list")


def _record_problem(
    record: dict[str, Any], risk: dict[str, Any], now: datetime, max_age_days: int, *, exception: bool = False
) -> str | None:
    if record.get("evidence_fingerprint") != risk["evidence_fingerprint"]:
        return "configuration_changed"
    if record.get("rule_version") != RULE_VERSION:
        return "rule_changed"
    if (
        not str(record.get("reason") or "").strip()
        or not str(record.get("owner" if exception else "reviewer") or "").strip()
    ):
        return "missing_reason_or_owner"
    try:
        created = parse_time(record.get("created_at" if exception else "reviewed_at"))
        expires = parse_time(record.get("expires_at"))
    except ValidationError:
        return "invalid_timestamp"
    if created > now + timedelta(minutes=5) or expires <= created:
        return "invalid_timestamp"
    if expires <= now:
        return "expired"
    if not exception and created < now - timedelta(days=max_age_days):
        return "stale_evidence"
    return None


def _check_problem(review: dict[str, Any], risk: dict[str, Any], now: datetime, max_age_days: int) -> str | None:
    checks = review.get("checks", [])
    valid: dict[str, str] = {}
    for check in checks:
        if (
            not isinstance(check, dict)
            or not isinstance(check.get("result"), str)
            or check.get("result") not in {"pass", "fail", "unknown"}
        ):
            return "invalid_checks"
        name = check.get("name")
        if not isinstance(name, str):
            return "invalid_checks"
        if name in valid:
            return "conflicting_checks"
        target = str(check.get("target") or "").casefold()
        expected = {str(risk.get("affected_object") or "").casefold(), str(risk.get("target_object") or "").casefold()}
        if not target or target not in expected or not str(check.get("source") or "").strip():
            return "unbound_evidence"
        try:
            collected = parse_time(check.get("collected_at"))
        except ValidationError:
            return "invalid_timestamp"
        if collected > now + timedelta(minutes=5) or collected < now - timedelta(days=max_age_days):
            return "stale_evidence"
        valid[name] = check["result"]
    required = risk["required_checks"]
    if review["status"] == "confirmed" and any(valid.get(name) != "pass" for name in required):
        return "missing_prerequisites"
    if review["status"] == "false_positive" and not any(valid.get(name) == "fail" for name in required):
        return "missing_disproof"
    return None


class FindingReviewManager:
    """Apply review decisions without converting accepted risks into secure controls."""

    def apply(
        self,
        risks: list[dict[str, Any]],
        data: dict[str, Any],
        domain: str,
        document: dict[str, Any] | None = None,
        *,
        now: datetime | None = None,
        max_age_days: int = 30,
    ) -> dict[str, Any]:
        now = now or utc_now()
        document = document or empty_review_document(domain)
        validate_review_document(document, domain)
        objects: dict[str, list[dict[str, Any]]] = {}
        for key in ("users", "computers", "groups", "gpos"):
            for obj in data.get(key, []):
                for field in ("sAMAccountName", "name", "cn", "distinguishedName", "dn"):
                    label = as_text(obj.get(field)).casefold()
                    if label:
                        bucket = objects.setdefault(label, [])
                        if obj not in bucket:
                            bucket.append(obj)
        reviews: dict[str, list[dict[str, Any]]] = {}
        exceptions: dict[str, list[dict[str, Any]]] = {}
        for field, index in (("reviews", reviews), ("exceptions", exceptions)):
            for record in document.get(field, []):
                index.setdefault(str(record.get("finding_id") or ""), []).append(record)
        findings = []
        for risk in risks:
            bind_finding(risk, domain, objects)
            risk["required_checks"] = required_checks(risk)
            # Resume always re-evaluates expiry and changed evidence.
            original = risk["review_basis"]
            risk["evidence"] = original["evidence"]
            risk["severity"] = original["severity"]
            risk["finding_status"] = "needs_validation" if original["requires_validation"] else "detected"
            risk.pop("score_excluded", None)
            risk.pop("exception_status", None)
            risk.pop("risk_exception", None)
            review_rows = reviews.get(risk["finding_id"], [])
            risk["review_status"] = "not_reviewed"
            if len(review_rows) > 1:
                risk["review_status"] = "conflicting_reviews"
            elif review_rows:
                review = review_rows[0]
                problem = _record_problem(review, risk, now, max_age_days)
                if not problem and review["status"] != "insufficient_evidence":
                    problem = _check_problem(review, risk, now, max_age_days)
                risk["review_status"] = problem or review["status"]
                if not problem:
                    status = review["status"]
                    risk["finding_status"] = status if status != "insufficient_evidence" else "needs_validation"
                    if status == "confirmed":
                        evidence = dict(original["evidence"]) if isinstance(original["evidence"], dict) else {}
                        evidence.pop("requires_runtime_validation", None)
                        evidence["vulnerability_confirmed"] = True
                        evidence["validation_review"] = review
                        risk["evidence"] = evidence
                    elif status == "false_positive":
                        risk["score_excluded"] = True
                        risk["potential_severity"] = original["severity"]
                        risk["severity"] = "low"
            if risk["review_status"] == "conflicting_reviews":
                risk["finding_status"] = "needs_validation"
            exception_rows = exceptions.get(risk["finding_id"], [])
            if exception_rows:
                problem = (
                    "conflicting_exceptions"
                    if len(exception_rows) > 1
                    else _record_problem(exception_rows[0], risk, now, max_age_days, exception=True)
                )
                risk["exception_status"] = problem or "active"
                if not problem:
                    risk["risk_exception"] = exception_rows[0]
                    risk["score_excluded"] = True
            findings.append(
                {
                    key: risk.get(key)
                    for key in (
                        "finding_id",
                        "evidence_fingerprint",
                        "rule_version",
                        "type",
                        "title",
                        "affected_object",
                        "object_type",
                        "severity",
                        "finding_status",
                        "review_status",
                        "exception_status",
                        "required_checks",
                    )
                }
            )
        matched = {risk["finding_id"] for risk in risks}
        unmatched = [
            row.get("finding_id")
            for row in document.get("reviews", []) + document.get("exceptions", [])
            if row.get("finding_id") not in matched
        ]
        observation_index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        observation_states = []
        for observation in document.get("observations", []):
            state = "available"
            try:
                collected = parse_time(observation.get("collected_at"))
                if collected > now + timedelta(minutes=5):
                    state = "invalid_timestamp"
                elif collected < now - timedelta(days=max_age_days):
                    state = "stale_evidence"
            except ValidationError:
                state = "invalid_timestamp"
            if not observation.get("target") or not observation.get("source"):
                state = "unbound_evidence"
            row = {**observation, "status": state}
            observation_states.append(row)
            if state == "available":
                name = str(observation.get("name")).casefold()
                value = observation.get("value")
                # A host has several services; their distinct states are not
                # conflicting observations of the same service.
                subject = (
                    str(value.get("name") or "").casefold() if name == "service" and isinstance(value, dict) else ""
                )
                key = (str(observation.get("target")).casefold(), name, subject)
                observation_index.setdefault(key, []).append(row)
        for rows in observation_index.values():
            if len({_hash(_stable_evidence(row.get("value"))) for row in rows}) > 1:
                for row in rows:
                    row["status"] = "conflicting_evidence"
        return {
            "schema_version": 1,
            "domain": domain,
            "generated_at": now.isoformat(),
            "rule_version": RULE_VERSION,
            "max_age_days": max_age_days,
            "findings": findings,
            "document": document,
            "unmatched_records": unmatched,
            "observations": observation_states,
            "summary": {
                "total": len(risks),
                "confirmed": sum(r.get("review_status") == "confirmed" for r in risks),
                "false_positive": sum(r.get("finding_status") == "false_positive" for r in risks),
                "needs_validation": sum(requires_validation(r) for r in risks),
                "active_exceptions": sum(r.get("exception_status") == "active" for r in risks),
            },
        }
