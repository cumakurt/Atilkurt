"""Transactional local history, deduplicated alerts, tasks and chained audit records."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

from core.evidence_signing import canonical_json
from core.exceptions import ValidationError
from core.finding_evidence import is_disproved, requires_validation
from core.finding_review import parse_time

MAX_AUDIT_ROWS = 100000


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _state(risk):
    if is_disproved(risk):
        return "false_positive"
    if requires_validation(risk):
        return "needs_validation"
    if risk.get("exception_status") == "active":
        return "accepted"
    return "supported"


class AssessmentHistory:
    """One local database; no external delivery or directory changes."""

    def __init__(self, path: str):
        target = Path(path)
        if target.is_symlink():
            raise ValidationError("History database must not be a symbolic link")
        if not target.parent.is_dir():
            target.parent.mkdir(parents=True, mode=0o700)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        self.connection = sqlite3.connect(target, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.close()
            raise ValidationError("Unsupported history database schema")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, domain TEXT NOT NULL, created_at TEXT NOT NULL,
                score REAL, fresh INTEGER NOT NULL, coverage REAL, summary TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (
                domain TEXT NOT NULL, finding_id TEXT NOT NULL, state TEXT NOT NULL,
                ever_supported INTEGER NOT NULL, last_run TEXT NOT NULL, fingerprint TEXT,
                severity TEXT, exception_state TEXT, details TEXT NOT NULL,
                PRIMARY KEY(domain, finding_id));
            CREATE TABLE IF NOT EXISTS alerts (
                event_id TEXT PRIMARY KEY, domain TEXT NOT NULL, run_id TEXT NOT NULL,
                kind TEXT NOT NULL, finding_id TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks (
                domain TEXT NOT NULL, finding_id TEXT NOT NULL, details TEXT NOT NULL,
                PRIMARY KEY(domain, finding_id));
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
                body TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS runs_domain_time ON runs(domain, created_at);
            PRAGMA user_version=1;
        """)

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def transaction(self):
        """Commit a workflow only after its outputs succeed; support nested callers."""
        nested = self.connection.in_transaction
        savepoint = "atilkurt_" + uuid4().hex
        self.connection.execute(f"SAVEPOINT {savepoint}" if nested else "BEGIN IMMEDIATE")
        try:
            yield self
            if nested:
                self.connection.execute(f"RELEASE {savepoint}")
            else:
                self.connection.commit()
        except BaseException:
            if nested:
                self.connection.execute(f"ROLLBACK TO {savepoint}")
                self.connection.execute(f"RELEASE {savepoint}")
            else:
                self.connection.rollback()
            raise

    def _audit(self, domain, action, details, actor=None):
        previous = self.connection.execute("SELECT entry_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        previous_hash = previous[0] if previous else "0" * 64
        body = {
            "domain": domain,
            "action": action,
            "actor": actor or getpass.getuser(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "details": details,
        }
        entry_hash = _digest({"previous_hash": previous_hash, "body": body})
        self.connection.execute(
            "INSERT INTO audit(domain,body,previous_hash,entry_hash) VALUES(?,?,?,?)",
            (domain, canonical_json(body).decode(), previous_hash, entry_hash),
        )

    def record_scan(
        self,
        domain: str,
        risks: list[dict[str, Any]],
        score: float,
        coverage: dict[str, Any],
        context: dict[str, Any],
        verification: dict[str, Any],
    ) -> dict[str, Any]:
        domain = domain.casefold().strip(".")
        run_id = uuid4().hex
        created = datetime.now(timezone.utc).isoformat()
        fresh = context.get("fresh_ldap") is True
        current_ids = set()
        alerts, changed = [], []
        resolved = {row["finding_id"] for row in verification.get("findings", []) if row["status"] == "resolved"}
        with self.transaction():
            old = {
                row["finding_id"]: dict(row)
                for row in self.connection.execute("SELECT * FROM findings WHERE domain=?", (domain,))
            }
            old_tasks = {
                row["finding_id"]: row["details"]
                for row in self.connection.execute("SELECT finding_id,details FROM tasks WHERE domain=?", (domain,))
            }
            for risk in risks:
                identifier = risk.get("finding_id")
                if not isinstance(identifier, str) or not identifier:
                    raise ValidationError("History findings require a stable finding ID")
                current_ids.add(identifier)
                state = _state(risk)
                previous = old.get(identifier)
                fingerprint = risk.get("evidence_fingerprint")
                details = {
                    "finding_id": identifier,
                    "title": risk.get("title"),
                    "type": risk.get("type"),
                    "object_type": risk.get("object_type"),
                    "affected_object": risk.get("affected_object"),
                    "state": state,
                    "severity": risk.get("severity"),
                    "evidence_fingerprint": fingerprint,
                    "rule_version": risk.get("rule_version"),
                }
                if (
                    previous is None
                    or previous["state"] != state
                    or previous["fingerprint"] != fingerprint
                    or previous["severity"] != risk.get("severity")
                    or previous["exception_state"] != risk.get("exception_status")
                ):
                    changed.append(identifier)
                    self._audit(domain, "finding.changed", {"finding_id": identifier, "state": state, "run_id": run_id})
                kinds = []
                if (
                    fresh
                    and state == "supported"
                    and risk.get("severity") == "critical"
                    and (
                        previous is None
                        or not previous["ever_supported"]
                        or previous["state"] == "supported"
                        and previous["severity"] != "critical"
                    )
                ):
                    kinds.append("new_critical")
                if fresh and state == "supported" and previous and previous["state"] in ("resolved", "false_positive"):
                    kinds.append("reopened")
                if previous and previous["exception_state"] == "active" and risk.get("exception_status") == "expired":
                    kinds.append("exception_expired")
                for kind in kinds:
                    event_id = _digest(
                        {
                            "domain": domain,
                            "finding_id": identifier,
                            "kind": kind,
                            "transition_from": previous["last_run"] if previous else "initial",
                            "fingerprint": fingerprint,
                        }
                    )[:32]
                    event = {**details, "event_id": event_id, "kind": kind, "run_id": run_id, "created_at": created}
                    inserted = self.connection.execute(
                        "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?)",
                        (event_id, domain, run_id, kind, identifier, canonical_json(event).decode()),
                    )
                    if inserted.rowcount:
                        alerts.append(event)
                ever = bool(previous and previous["ever_supported"]) or state in ("supported", "accepted")
                self.connection.execute(
                    "INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        domain,
                        identifier,
                        state,
                        int(ever),
                        run_id,
                        fingerprint,
                        risk.get("severity"),
                        risk.get("exception_status"),
                        canonical_json(details).decode(),
                    ),
                )
                task = old_tasks.get(identifier)
                if task or state in ("supported", "needs_validation"):
                    task_details = (
                        json.loads(task)
                        if task
                        else {
                            "finding_id": identifier,
                            "external_id": "AK-" + identifier,
                            "owner": "unassigned",
                            "status": "awaiting_verification" if state == "needs_validation" else "open",
                            "due_at": None,
                            "notes": "",
                        }
                    )
                    if task_details.get("status") == "resolved" and state in (
                        "supported",
                        "needs_validation",
                        "accepted",
                    ):
                        task_details["status"] = "awaiting_verification" if state == "needs_validation" else "open"
                        task_details.pop("verified_run_id", None)
                        self._audit(domain, "task.reopened", {"finding_id": identifier, "run_id": run_id})
                    task_details.update(
                        title=risk.get("title"),
                        affected_object=risk.get("affected_object"),
                        severity=risk.get("severity"),
                        finding_status=state,
                    )
                    self.connection.execute(
                        "INSERT OR REPLACE INTO tasks VALUES(?,?,?)",
                        (domain, identifier, canonical_json(task_details).decode()),
                    )
            for identifier, previous in old.items():
                if identifier in current_ids:
                    continue
                state = "resolved" if identifier in resolved else "unassessed"
                if not fresh or previous["state"] == "resolved":
                    continue
                if state != previous["state"]:
                    changed.append(identifier)
                    self.connection.execute(
                        "UPDATE findings SET state=?,last_run=? WHERE domain=? AND finding_id=?",
                        (state, run_id, domain, identifier),
                    )
                    self._audit(domain, "finding." + state, {"finding_id": identifier, "run_id": run_id})
                if state == "resolved":
                    task = old_tasks.get(identifier)
                    if task:
                        task_details = json.loads(task)
                        task_details.update(status="resolved", finding_status="resolved", verified_run_id=run_id)
                        self.connection.execute(
                            "UPDATE tasks SET details=? WHERE domain=? AND finding_id=?",
                            (canonical_json(task_details).decode(), domain, identifier),
                        )
                        self._audit(domain, "task.verified", {"finding_id": identifier, "run_id": run_id})
            summary = {
                "supported": sum(_state(risk) == "supported" for risk in risks),
                "pending": sum(requires_validation(risk) for risk in risks),
                "alerts": len(alerts),
                "critical": sum(
                    _state(risk) == "supported" and str(risk.get("severity") or "").lower() == "critical"
                    for risk in risks
                ),
                "high": sum(
                    _state(risk) == "supported" and str(risk.get("severity") or "").lower() == "high"
                    for risk in risks
                ),
            }
            self.connection.execute(
                "INSERT INTO runs VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    domain,
                    created,
                    score,
                    int(fresh),
                    coverage.get("summary", {}).get("execution_percent"),
                    canonical_json(summary).decode(),
                ),
            )
            self._audit(
                domain,
                "scan.recorded",
                {
                    "run_id": run_id,
                    "fresh_ldap": fresh,
                    "changed_findings": changed,
                    "review_digest": context.get("review_digest"),
                    "review_decisions": context.get("review_decisions", []),
                    "risk_exceptions": context.get("risk_exceptions", []),
                },
            )
            changed_ids = set(changed)
            changed_findings = [
                {
                    **json.loads(row["details"]),
                    "state": row["state"],
                    "finding_status": row["state"],
                    "score_excluded": row["state"] != "supported",
                }
                for row in self.connection.execute(
                    "SELECT details,state,finding_id FROM findings WHERE domain=?", (domain,)
                )
                if row["finding_id"] in changed_ids
            ]
        return {
            "run_id": run_id,
            "changed_finding_ids": changed,
            "changed_findings": changed_findings,
            "notifications": alerts,
            "runs": self.runs(domain),
            "enabled": True,
        }

    def runs(self, domain: str, limit: int = 30) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM runs WHERE domain=? ORDER BY created_at DESC,rowid DESC LIMIT ?",
            (domain.casefold().strip("."), max(1, min(limit, 1000))),
        )
        return [{**dict(row), "summary": json.loads(row["summary"])} for row in rows]

    def apply_tasks(self, document: dict[str, Any], domain: str, resolved_ids: set[str] | None = None):
        domain = domain.casefold().strip(".")
        rows = document.get("tickets")
        if (
            document.get("schema_version") != 1
            or str(document.get("domain") or "").casefold().strip(".") != domain
            or not isinstance(rows, list)
            or len(rows) > 10000
        ):
            raise ValidationError("Task file requires the same domain and a bounded ticket list")
        known = {
            row[0]: row[1]
            for row in self.connection.execute("SELECT finding_id,state FROM findings WHERE domain=?", (domain,))
        }
        records, seen = [], set()
        for row in rows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("finding_id"), str)
                or row["finding_id"] not in known
                or row["finding_id"] in seen
            ):
                raise ValidationError("Task has an unknown or duplicate finding ID")
            identifier = row["finding_id"]
            seen.add(identifier)
            owner, notes = row.get("owner"), row.get("notes", "")
            status = row.get("status", "open")
            if (
                not isinstance(owner, str)
                or not owner.strip()
                or len(owner) > 200
                or not isinstance(notes, str)
                or len(notes) > 8000
                or status not in ("open", "in_progress", "awaiting_verification", "resolved")
            ):
                raise ValidationError("Task owner, notes or status is invalid")
            if (
                status == "resolved"
                and identifier not in (resolved_ids or set())
                and known.get(identifier) != "resolved"
            ):
                raise ValidationError("Task closure requires fresh remediation verification")
            due = parse_time(row.get("due_at")).isoformat() if row.get("due_at") else None
            record = {
                "finding_id": identifier,
                "external_id": "AK-" + identifier,
                "owner": owner.strip(),
                "notes": notes,
                "status": status,
                "due_at": due,
            }
            records.append(record)
        with self.transaction():
            current_states = {
                row["finding_id"]: row["state"]
                for row in self.connection.execute("SELECT finding_id,state FROM findings WHERE domain=?", (domain,))
            }
            old_tasks = {
                row["finding_id"]: row["details"]
                for row in self.connection.execute("SELECT finding_id,details FROM tasks WHERE domain=?", (domain,))
            }
            for record in records:
                if record["status"] == "resolved" and current_states.get(record["finding_id"]) != "resolved":
                    raise ValidationError("Task closure requires a currently verified resolved finding")
                old = json.loads(old_tasks.get(record["finding_id"], "{}"))
                if old and all(old.get(key) == value for key, value in record.items()):
                    continue
                self.connection.execute(
                    "INSERT OR REPLACE INTO tasks VALUES(?,?,?)",
                    (
                        domain,
                        record["finding_id"],
                        canonical_json({**old, **record}).decode(),
                    ),
                )
                self._audit(
                    domain,
                    "task.updated",
                    {
                        "finding_id": record["finding_id"],
                        "task_digest": _digest(record),
                        "owner": record["owner"],
                        "status": record["status"],
                        "due_at": record["due_at"],
                    },
                )

    def tasks(self, domain: str) -> list[dict[str, Any]]:
        return [
            json.loads(row[0])
            for row in self.connection.execute(
                "SELECT details FROM tasks WHERE domain=? ORDER BY finding_id", (domain.casefold().strip("."),)
            )
        ]

    def finding_kpi_snapshot(self, domain: str) -> dict[str, Any] | None:
        """Return immutable KPI totals recorded by the last fresh scan."""
        domain = domain.casefold().strip(".")
        run = self.connection.execute(
            "SELECT run_id, score, summary FROM runs WHERE domain=? AND fresh=1 "
            "ORDER BY created_at DESC,rowid DESC LIMIT 1",
            (domain,),
        ).fetchone()
        if not run:
            return None
        # Offline reviews can update findings without changing the last live
        # run. Counts must come from the same run as its score and timestamp.
        summary = json.loads(run['summary'])
        return {
            "run_id": run["run_id"],
            "score": run["score"],
            "critical": summary.get('critical'),
            "high": summary.get('high'),
            "supported": summary.get('supported'),
        }

    def audit_document(self) -> dict[str, Any]:
        rows = list(self.connection.execute("SELECT * FROM audit ORDER BY seq LIMIT ?", (MAX_AUDIT_ROWS + 1,)))
        if len(rows) > MAX_AUDIT_ROWS:
            raise ValidationError("Audit export limit exceeded; archive the history database")
        previous = "0" * 64
        entries = []
        for row in rows:
            body = json.loads(row["body"])
            expected = _digest({"previous_hash": previous, "body": body})
            if row["previous_hash"] != previous or row["entry_hash"] != expected:
                raise ValidationError("Audit chain integrity check failed")
            entries.append({"sequence": row["seq"], "body": body, "previous_hash": previous, "entry_hash": expected})
            previous = expected
        return {
            "schema_version": 1,
            "entries": entries,
            "chain_head": previous,
            "limitation": "The chain detects local edits. Export and sign its head to detect a complete database rewrite.",
        }
