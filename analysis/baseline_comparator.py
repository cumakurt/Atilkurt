"""
Baseline Comparator Module
Compares current scan results with previous baseline to detect drift
"""

import json
import logging
from typing import Any, Optional
from datetime import datetime
from pathlib import Path

from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class BaselineComparator:
    """Compares current scan with baseline for drift detection."""

    def load_baseline(self, baseline_path: str) -> Optional[dict[str, Any]]:
        """
        Load baseline from JSON file (from --json-export or checkpoint).
        """
        path = Path(baseline_path)
        if not path.exists():
            logger.error(f"Baseline file not found: {baseline_path}")
            return None
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            return data
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return None

    def compare(
        self,
        current_risks: list[dict[str, Any]],
        baseline_risks: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Compare current risks with baseline.
        Returns new risks, resolved risks, and summary.
        """
        def _risk_key(r: dict) -> str:
            return f"{r.get('type', '')}|{r.get('affected_object', '')}"

        baseline_keys = {_risk_key(r) for r in baseline_risks}
        current_keys = {_risk_key(r) for r in current_risks}

        new_risks = [r for r in current_risks if _risk_key(r) not in baseline_keys]
        resolved_risks = [r for r in baseline_risks if _risk_key(r) not in current_keys]
        unchanged_risks = [r for r in current_risks if _risk_key(r) in baseline_keys]

        return {
            'new_risks': new_risks,
            'resolved_risks': resolved_risks,
            'unchanged_risks': unchanged_risks,
            'summary': {
                'baseline_count': len(baseline_risks),
                'current_count': len(current_risks),
                'new_count': len(new_risks),
                'resolved_count': len(resolved_risks),
                'unchanged_count': len(unchanged_risks),
                'drift': len(current_risks) - len(baseline_risks),
            },
            'timestamp': datetime.now().isoformat(),
        }

    def compare_full(
        self,
        current_data: dict[str, Any],
        baseline_path: str
    ) -> dict[str, Any]:
        """
        Full comparison using baseline file.
        current_data should have 'risks' key from main scan.
        """
        baseline = self.load_baseline(baseline_path)
        if not baseline:
            return {'error': 'Baseline not loaded', 'comparison': None}

        baseline_risks = baseline.get('risks', []) or baseline.get('data', {}).get('risks', [])
        current_risks = current_data.get('risks', [])

        comparison = self.compare(current_risks, baseline_risks)
        comparison['baseline_file'] = baseline_path
        comparison['baseline_timestamp'] = baseline.get('timestamp') or baseline.get('data', {}).get('timestamp')
        return comparison

    def compare_snapshot(
        self,
        current_data: dict[str, Any],
        current_analysis: dict[str, Any],
        current_risks: list[dict[str, Any]],
        baseline_path: str,
    ) -> dict[str, Any]:
        """Compare security-relevant objects, risks, and graph edges."""
        baseline = self.load_baseline(baseline_path)
        if not baseline:
            return {"error": "Baseline not loaded", "risks": [], "summary": {}}
        if isinstance(baseline.get("data"), dict) and any(
            key in baseline["data"] for key in ("users", "analysis", "scoring")
        ):
            baseline = baseline["data"]

        object_specs = {
            "users": ("sAMAccountName", (
                "memberOf", "adminCount", "userAccountControl", "servicePrincipalName",
                "msDS-SupportedEncryptionTypes", "hasKeyCredentialLink",
            )),
            "computers": ("name", (
                "userAccountControl", "servicePrincipalName", "msDS-SupportedEncryptionTypes",
                "msDS-AllowedToDelegateTo", "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-PasswordExpirationTime", "managedBy",
            )),
            "groups": ("name", ("member", "memberOf", "managedBy")),
            "gpos": ("name", ("displayName", "gPCFileSysPath", "gPLink", "whenChanged")),
        }
        collections: dict[str, Any] = {}
        changed_fields: list[dict[str, Any]] = []
        for collection, (identity_key, fields) in object_specs.items():
            current_items = current_data.get(collection, []) or []
            baseline_items = baseline.get(collection, []) or []
            current_map = self._object_map(current_items, identity_key)
            baseline_map = self._object_map(baseline_items, identity_key)
            added = sorted(set(current_map) - set(baseline_map))
            removed = sorted(set(baseline_map) - set(current_map))
            modified: list[dict[str, Any]] = []
            for identity in sorted(set(current_map).intersection(baseline_map)):
                field_changes = {}
                for field in fields:
                    before = self._canonical(baseline_map[identity].get(field))
                    after = self._canonical(current_map[identity].get(field))
                    if before != after:
                        field_changes[field] = {"before": before, "after": after}
                        changed_fields.append({
                            "collection": collection, "identity": identity, "field": field,
                            "before": before, "after": after,
                        })
                if field_changes:
                    modified.append({"identity": identity, "changes": field_changes})
            collections[collection] = {"added": added, "removed": removed, "modified": modified}

        baseline_risks = baseline.get("risks", []) or (baseline.get("scoring") or {}).get("scored_risks", [])
        risk_comparison = self.compare(current_risks, baseline_risks)
        severity_changes = self._severity_changes(current_risks, baseline_risks)
        current_graph = current_analysis.get("attack_graph_v2") or {}
        baseline_graph = baseline.get("attack_graph_v2") or (baseline.get("analysis") or {}).get("attack_graph_v2") or {}
        current_edges = self._edge_keys(current_graph.get("edges") or [])
        baseline_edges = self._edge_keys(baseline_graph.get("edges") or [])
        added_edges = sorted(current_edges - baseline_edges)
        removed_edges = sorted(baseline_edges - current_edges)

        risks: list[dict[str, Any]] = []
        new_high = [
            risk for risk in risk_comparison["new_risks"]
            if str(risk.get("severity") or risk.get("severity_level")).casefold() in {"critical", "high"}
        ]
        if new_high:
            risks.append(self._delta_risk(
                RiskTypes.SNAPSHOT_NEW_CRITICAL_RISK,
                Severity.CRITICAL if any(str(r.get("severity")).casefold() == "critical" for r in new_high) else Severity.HIGH,
                f"{len(new_high)} new high-impact risks appeared since the baseline",
                "The current snapshot contains high or critical findings that were not present in the baseline.",
                ", ".join(str(r.get("affected_object") or r.get("type")) for r in new_high[:15]),
                {"new_risk_count": len(new_high), "risk_types": sorted({str(r.get("type")) for r in new_high})},
            ))
        privilege_changes = [
            change for change in changed_fields
            if change["field"] in {"member", "memberOf", "adminCount", "userAccountControl", "managedBy"}
        ]
        if privilege_changes:
            risks.append(self._delta_risk(
                RiskTypes.SNAPSHOT_PRIVILEGE_CHANGE, Severity.HIGH,
                f"{len(privilege_changes)} privilege-relevant directory fields changed",
                "Group membership, protection, account-control, or ownership fields changed since the baseline.",
                ", ".join(sorted({change["identity"] for change in privilege_changes})[:15]),
                {"change_count": len(privilege_changes), "changes": privilege_changes[:100]},
            ))
        control_changes = [
            change for change in changed_fields
            if change["collection"] == "gpos" or change["field"] in {
                "servicePrincipalName", "msDS-SupportedEncryptionTypes", "msDS-AllowedToDelegateTo",
                "hasKeyCredentialLink", "msLAPS-PasswordExpirationTime",
            }
        ]
        if control_changes:
            risks.append(self._delta_risk(
                RiskTypes.SNAPSHOT_SECURITY_CONTROL_CHANGE, Severity.MEDIUM,
                f"{len(control_changes)} security-control fields changed",
                "Kerberos, delegation, key credential, LAPS, SPN, or GPO state differs from the baseline.",
                ", ".join(sorted({change["identity"] for change in control_changes})[:15]),
                {"change_count": len(control_changes), "changes": control_changes[:100]},
            ))
        if added_edges:
            risks.append(self._delta_risk(
                RiskTypes.SNAPSHOT_ATTACK_EDGE_ADDED, Severity.HIGH,
                f"{len(added_edges)} attack-graph edges were added",
                "New membership, control, trust, PKI, gMSA, DNS, or hybrid graph relationships exist.",
                "Attack graph",
                {"added_edge_count": len(added_edges), "added_edges": added_edges[:100]},
            ))

        return {
            "baseline_file": baseline_path,
            "timestamp": datetime.now().isoformat(),
            "collections": collections,
            "risk_comparison": risk_comparison,
            "severity_changes": severity_changes,
            "attack_graph": {"added_edges": added_edges, "removed_edges": removed_edges},
            "risks": risks,
            "summary": {
                "new_risks": risk_comparison["summary"]["new_count"],
                "resolved_risks": risk_comparison["summary"]["resolved_count"],
                "severity_changes": len(severity_changes),
                "object_field_changes": len(changed_fields),
                "added_attack_edges": len(added_edges),
                "removed_attack_edges": len(removed_edges),
                "finding_count": len(risks),
            },
        }

    @staticmethod
    def _object_map(items: list[dict[str, Any]], identity_key: str) -> dict[str, dict[str, Any]]:
        mapped = {}
        for item in items:
            identity = str(item.get(identity_key) or item.get("distinguishedName") or "").strip()
            if identity:
                mapped[identity.casefold()] = item
        return mapped

    @staticmethod
    def _canonical(value: Any) -> Any:
        if isinstance(value, (list, tuple, set)):
            return sorted((str(item) for item in value), key=str.casefold)
        if isinstance(value, dict):
            return {str(key): BaselineComparator._canonical(child) for key, child in sorted(value.items())}
        if isinstance(value, datetime):
            return value.isoformat()
        return value

    @staticmethod
    def _severity_changes(current: list[dict[str, Any]], baseline: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def key(risk: dict[str, Any]) -> tuple[str, str]:
            return str(risk.get("type") or ""), str(risk.get("affected_object") or "")
        baseline_map = {key(risk): risk for risk in baseline}
        changes = []
        for risk in current:
            prior = baseline_map.get(key(risk))
            if prior and str(prior.get("severity")) != str(risk.get("severity")):
                changes.append({
                    "type": risk.get("type"), "affected_object": risk.get("affected_object"),
                    "before": prior.get("severity"), "after": risk.get("severity"),
                })
        return changes

    @staticmethod
    def _edge_keys(edges: list[dict[str, Any]]) -> set[str]:
        return {
            f"{edge.get('source', '')}|{edge.get('type', '')}|{edge.get('target', '')}"
            for edge in edges if isinstance(edge, dict)
        }

    @staticmethod
    def _delta_risk(risk_type: str, severity: str, title: str, description: str,
                    affected: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": risk_type, "severity": severity, "title": title, "description": description,
            "affected_object": affected, "object_type": "configuration",
            "impact": "A newly introduced security-relevant change can open an attack path that was absent from the approved baseline.",
            "attack_scenario": "An unauthorized or mistaken change adds privilege, weakens a control, or creates a new Tier-0 route.",
            "mitigation": "Validate the change ticket and owner, revert unauthorized changes, and establish an approved new baseline after remediation.",
            "mitre_attack": MITRETechniques.PRIVILEGE_ESCALATION,
            "evidence": evidence,
        }
