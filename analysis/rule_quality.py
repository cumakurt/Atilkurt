"""Labelled, offline rule evaluation; fixture results are not production rates."""

from __future__ import annotations

from copy import deepcopy
from collections import defaultdict
import hashlib
import struct
from typing import Any
from uuid import UUID

from core.evidence_signing import canonical_json
from core.exceptions import ValidationError
from core.finding_evidence import requires_validation
from core.finding_review import RULE_VERSION

SID = "S-1-5-21-100-200-300-1100"
CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


def _descriptor(grants):
    entries = []
    for grant in grants:
        sid = grant.get("sid", SID)
        parts = [int(part) for part in sid.split("-")[1:]]
        binary = bytes([parts[0], len(parts) - 2]) + parts[1].to_bytes(6, "big")
        binary += b"".join(part.to_bytes(4, "little") for part in parts[2:])
        guid = grant.get("guid")
        denied = grant.get("denied", False)
        kind = (6 if denied else 5) if guid else (1 if denied else 0)
        payload = struct.pack("<I", grant["mask"])
        if guid:
            payload += struct.pack("<I", 1) + UUID(guid).bytes_le
        payload += binary
        entries.append(struct.pack("<BBH", kind, grant.get("flags", 0), len(payload) + 4) + payload)
    body = b"".join(entries)
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(body), len(entries), 0) + body
    return struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20) + acl


class FixtureDirectory:
    """Explicit fixture responses; no connection or network operation exists."""

    base_dn = "DC=example,DC=com"
    connection = None

    def __init__(self, rows=None, queries=None):
        self.rows = rows or []
        self.queries = queries or []
        self.query_count = 0
        self.unavailable_queries = 0

    def search(self, **kwargs):
        self.query_count += 1
        if self.query_count > 10000:
            raise ValidationError("Fixture exceeded its query budget")
        for query in self.queries:
            if query.get("filter") == kwargs.get("search_filter") and query.get("base", self.base_dn) == (
                kwargs.get("search_base") or self.base_dn
            ):
                if query.get("error"):
                    self.unavailable_queries += 1
                    raise ValidationError("Fixture query is unavailable")
                return deepcopy(query.get("rows") or [])
        return deepcopy(self.rows)


def builtin_cases() -> list[dict[str, Any]]:
    cases = []
    grant = {"mask": 0x100}
    for name, expected, grants in (
        ("complete_replication", "positive", [grant]),
        ("changes_only", "negative", [{"mask": 0x100, "guid": CHANGES}]),
        (
            "different_principals",
            "negative",
            [{"mask": 0x100, "guid": CHANGES}, {"mask": 0x100, "guid": CHANGES_ALL, "sid": SID + "1"}],
        ),
        ("deny_before_allow", "negative", [{"mask": 0x100, "denied": True}, grant]),
        ("allow_before_deny", "positive", [grant, {"mask": 0x100, "denied": True}]),
        ("inherit_only", "negative", [{"mask": 0x100, "flags": 8}]),
        ("nested_token", "positive", [{"mask": 0x100, "sid": SID + "1"}]),
    ):
        inputs = {"grants": grants}
        if name == "nested_token":
            inputs["groups"] = [
                {
                    "name": "delegates",
                    "objectSid": SID + "1",
                    "distinguishedName": "CN=delegates,DC=example,DC=com",
                    "member": ["CN=delegate,DC=example,DC=com"],
                }
            ]
        cases.append({"id": name, "rule": "dcsync", "expected": expected, "input": inputs})
    for name, value, expected in (
        ("strong_length", 16, "negative"),
        ("weak_length", 6, "positive"),
        ("missing_length", None, "unknown"),
    ):
        cases.append(
            {
                "id": name,
                "rule": "password_policy",
                "expected": expected,
                "input": {"attributes": {} if value is None else {"minPwdLength": value}},
            }
        )
    for name, uac, os_name, expected in (
        ("legacy_dc_unverified", 8192, "Windows Server 2016", "unknown"),
        ("member_server", 4096, "Windows Server 2016", "negative"),
        ("disabled_dc", 8194, "Windows Server 2016", "negative"),
    ):
        cases.append(
            {
                "id": name,
                "rule": "zerologon",
                "expected": expected,
                "input": {"computers": [{"name": "host01", "userAccountControl": uac, "operatingSystem": os_name}]},
            }
        )
    for name, expected, grants in (
        ("broad_write", "positive", [{"mask": 0x40000000, "sid": "S-1-1-0"}]),
        (
            "broad_write_denied",
            "negative",
            [{"mask": 0x40000000, "sid": "S-1-1-0", "denied": True}, {"mask": 0x40000000, "sid": "S-1-1-0"}],
        ),
        (
            "scoped_reset",
            "negative",
            [{"mask": 0x100, "guid": "00299570-246d-11d0-a768-00aa006e0529", "sid": "S-1-1-0"}],
        ),
    ):
        cases.append({"id": name, "rule": "broad_acl", "expected": expected, "input": {"grants": grants}})
    from analysis.quality_families import family_cases
    return cases + family_cases()


def _evaluate(case):
    inputs = deepcopy(case["input"])
    rule = case["rule"]
    observable = True
    if rule == "dcsync":
        from analysis.dcsync_analyzer import DCSyncAnalyzer

        ldap = FixtureDirectory([{"nTSecurityDescriptor": _descriptor(inputs.get("grants") or [])}])
        users = inputs.get("users") or [
            {
                "sAMAccountName": "delegate",
                "objectSid": SID,
                "userAccountControl": 512,
                "distinguishedName": "CN=delegate,DC=example,DC=com",
            }
        ]
        risks = DCSyncAnalyzer(ldap).analyze_dcsync_rights(users, inputs.get("groups") or [])
    elif rule == "password_policy":
        from analysis.password_policy_analyzer import PasswordPolicyAnalyzer

        attributes = inputs.get("attributes") or {}
        risks = PasswordPolicyAnalyzer(
            FixtureDirectory([{"distinguishedName": FixtureDirectory.base_dn, **attributes}])
        ).analyze_password_policy()
        observable = bool(attributes)
    elif rule == "zerologon":
        from analysis.vulnerability_scanner import VulnerabilityScanner

        risks = VulnerabilityScanner(FixtureDirectory()).scan_zerologon(inputs.get("computers") or [])
    elif rule == "broad_acl":
        from core.ad_security import dangerous_broad_aces
        from core.security_descriptor_parser import parse_security_descriptor

        risks = [
            {"type": "broad_acl"}
            for _ in dangerous_broad_aces(parse_security_descriptor(_descriptor(inputs.get("grants") or [])))
        ]
    elif rule == "registry":
        from analysis.registry import get_analysis_step_keys, get_consolidated_risk_lists, run_all_analyses

        steps = inputs.get("steps") or []
        known = set(get_analysis_step_keys())
        if (
            not steps
            or not isinstance(steps, list)
            or any(not isinstance(step, str) or step not in known for step in steps)
        ):
            raise ValidationError("Registry fixtures require known analysis steps")
        directory = {key: inputs.get("data", {}).get(key, []) for key in ("users", "groups", "computers", "gpos")}
        ldap = FixtureDirectory(inputs.get("ldap_rows"), inputs.get("queries"))
        analysis = run_all_analyses(
            ldap,
            directory,
            skip_keys=sorted(known - set(steps)),
        )
        risks = [risk for rows in get_consolidated_risk_lists(analysis) for risk in rows]
        observable = not ldap.unavailable_queries and set(steps) <= set(
            analysis.get("analysis_execution", {}).get("completed_steps", [])
        )
    elif rule in {'adcs', 'delegation', 'gpo', 'trust', 'laps'}:
        from analysis.quality_families import evaluate_family
        risks, observable = evaluate_family(rule, inputs, _descriptor)
    else:
        raise ValidationError("Unknown quality fixture adapter")
    if case.get("risk_types"):
        risks = [risk for risk in risks if risk.get("type") in case["risk_types"]]
    if any(not requires_validation(risk) for risk in risks):
        return "positive"
    return "unknown" if risks or not observable else "negative"


def evaluate_quality(cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cases = builtin_cases() if cases is None else cases
    if not isinstance(cases, list) or not 1 <= len(cases) <= 1000:
        raise ValidationError("Quality evaluation requires 1 to 1000 labelled cases")
    identities = set()
    results = []
    grouped = defaultdict(list)
    for case in cases:
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("id"), str)
            or not case["id"]
            or case["id"] in identities
            or case.get("expected") not in ("positive", "negative", "unknown")
            or case.get("rule") not in ("dcsync", "password_policy", "zerologon", "broad_acl", "registry", "adcs", "delegation", "gpo", "trust", "laps")
            or not isinstance(case.get("input"), dict)
        ):
            raise ValidationError("Invalid or duplicate quality case")
        identities.add(case["id"])
        try:
            prediction = _evaluate(case)
        except (ValueError, TypeError, KeyError, OverflowError, struct.error) as exc:
            raise ValidationError(f"Invalid quality fixture input: {case['id']}") from exc
        result = {
            "id": case["id"],
            "rule": case["rule"],
            "expected": case["expected"],
            "predicted": prediction,
            "passed": prediction == case["expected"],
        }
        results.append(result)
        grouped[case["rule"]].append(result)
    metrics = []
    for rule, rows in sorted(grouped.items()):
        tp = sum(row["expected"] == row["predicted"] == "positive" for row in rows)
        fp = sum(row["expected"] != "positive" and row["predicted"] == "positive" for row in rows)
        fn = sum(row["expected"] == "positive" and row["predicted"] != "positive" for row in rows)
        tn = sum(row["expected"] == row["predicted"] == "negative" for row in rows)
        metrics.append(
            {
                "rule": rule,
                "cases": len(rows),
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "true_negative": tn,
                "abstained": sum(row["predicted"] == "unknown" for row in rows),
                "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            }
        )
    return {
        "schema_version": 1,
        "rule_version": RULE_VERSION,
        "dataset_fingerprint": hashlib.sha256(canonical_json(cases)).hexdigest(),
        "summary": {
            "cases": len(results),
            "passed": sum(row["passed"] for row in results),
            "failed": sum(not row["passed"] for row in results),
            "evaluated_families": len(metrics),
        },
        "rules": metrics,
        "cases": results,
        "limitation": "Rates describe these labelled fixtures only. Unrepresented rules and production environments are not measured.",
    }
