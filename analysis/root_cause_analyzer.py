"""Group findings by explicit shared grants without changing scores or hiding paths."""

from __future__ import annotations

from collections import defaultdict
import hashlib
from typing import Any

from analysis.remediation_simulator import edge_id
from core.evidence_signing import canonical_json


def group_root_causes(risks: list[dict[str, Any]], graph: dict[str, Any]) -> dict[str, Any]:
    nodes = {node["id"]: node for node in graph.get("nodes") or []}
    groups = {}
    grants = defaultdict(list)
    direct_grants = defaultdict(set)
    for edge in graph.get("edges") or []:
        if edge.get("type") != "Controls" or not edge.get("permission"):
            continue
        source, target = nodes.get(edge["source"], {}), nodes.get(edge["target"], {})
        identifier = edge_id(edge)
        groups[identifier] = {
            "root_cause_id": identifier,
            "title": f"{source.get('label', edge['source'])} → {target.get('label', edge['target'])}: {edge['permission']}",
            "source": edge["source"],
            "target": edge["target"],
            "permission": edge["permission"],
            "finding_ids": set(),
            "affected_objects": set(),
            "edge_ids": [identifier],
            "action": "Review this exact grant and simulate its removal, including alternate paths.",
        }
        grants[(edge["source"], edge["target"])].append(identifier)
        for target_name in (target.get("label"), target.get("dn")):
            if source.get("sid") and target_name:
                direct_grants[(source["sid"], str(target_name).casefold(), edge["permission"])].add(identifier)
    for risk in risks:
        finding_id = risk.get("finding_id")
        if not finding_id:
            continue
        evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
        matched = set()
        path = evidence.get("path") or risk.get("path") or []
        if isinstance(path, list) and all(isinstance(node, str) for node in path):
            for source, target in zip(path, path[1:]):
                matched.update(grants.get((source, target), []))
        trustee = str(risk.get("trustee") or evidence.get("trustee_sid") or "")
        target_name = str(risk.get("affected_object") or "").casefold()
        if trustee:
            matched.update(direct_grants.get((trustee, target_name, risk.get("permission")), set()))
        if not matched:
            identifier = hashlib.sha256(canonical_json({"finding": finding_id})).hexdigest()[:24]
            groups[identifier] = {
                "root_cause_id": identifier,
                "title": risk.get("title"),
                "finding_ids": set(),
                "affected_objects": set(),
                "edge_ids": [],
                "action": risk.get("mitigation") or "Validate the finding and its prerequisites.",
            }
            matched.add(identifier)
        for identifier in matched:
            group = groups[identifier]
            group["finding_ids"].add(finding_id)
            group["affected_objects"].add(str(risk.get("affected_object") or ""))
    rows = []
    for group in groups.values():
        if not group["finding_ids"]:
            continue
        rows.append(
            {
                **group,
                "finding_ids": sorted(group["finding_ids"]),
                "affected_objects": sorted(group["affected_objects"]),
                "finding_count": len(group["finding_ids"]),
            }
        )
    rows.sort(key=lambda group: (-group["finding_count"], group["root_cause_id"]))
    return {
        "groups": rows,
        "summary": {"root_causes": len(rows), "shared_causes": sum(group["finding_count"] > 1 for group in rows)},
        "limitation": "Only explicit grants shared by collected paths are grouped. Original findings, scores and alternate paths remain available.",
    }
