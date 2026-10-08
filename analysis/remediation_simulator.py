"""Bounded, immutable what-if analysis over collected attack-graph edges."""

from __future__ import annotations

from collections import defaultdict, deque
import hashlib
import json
from typing import Any

from core.exceptions import ValidationError

NON_CONTROL_EDGES = {"InboundTrust", "OutboundTrust", "RelatedTo"}
MAX_NODES = 20000
MAX_EDGES = 100000
MAX_DEPTH = 6
MAX_TRAVERSAL_WORK = 20_000_000


def edge_id(edge: dict[str, Any]) -> str:
    key = [str(edge.get(name) or "") for name in ("source", "target", "type", "permission")]
    return hashlib.sha256(json.dumps(key, ensure_ascii=True).encode()).hexdigest()[:24]


def graph_snapshot(graph: dict[str, Any]) -> dict[str, Any]:
    """Only retain graph fields required by the interactive simulator."""
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    if len(nodes) > MAX_NODES or len(edges) > MAX_EDGES:
        raise ValidationError("Attack graph exceeds remediation simulation limits")
    targets = sum(bool(node.get("privileged")) for node in nodes)
    if targets * (len(nodes) + len(edges)) > MAX_TRAVERSAL_WORK:
        raise ValidationError("Attack graph exceeds remediation traversal limits")
    ids = {str(node["id"]) for node in nodes}
    return {
        "nodes": [{key: node.get(key) for key in ("id", "label", "kind", "privileged")} for node in nodes],
        "edges": [
            {**{key: edge.get(key) for key in ("source", "target", "type", "permission")}, "id": edge_id(edge)}
            for edge in edges
            if edge.get("source") in ids and edge.get("target") in ids and edge.get("type") not in NON_CONTROL_EDGES
        ],
        "max_depth": MAX_DEPTH,
    }


def _reachability(snapshot: dict[str, Any], removed: set[str]) -> dict[str, dict[str, Any]]:
    # Traverse backwards once per Tier-0 target, rather than once per foothold.
    reverse: dict[str, set[str]] = defaultdict(set)
    for edge in snapshot["edges"]:
        if edge["id"] not in removed:
            reverse[edge["target"]].add(edge["source"])
    targets = {node["id"] for node in snapshot["nodes"] if node.get("privileged")}
    sources = {
        node["id"]
        for node in snapshot["nodes"]
        if node.get("kind") in {"user", "computer", "principal"} and node["id"] not in targets
    }
    results: dict[str, dict[str, Any]] = {}
    for target in sorted(targets):
        queue = deque([(target, 0)])
        visited = {target}
        while queue:
            current, depth = queue.popleft()
            if current in sources:
                item = results.setdefault(current, {"targets": set(), "shortest_hops": depth})
                item["targets"].add(target)
                item["shortest_hops"] = min(item["shortest_hops"], depth)
            if depth >= MAX_DEPTH:
                continue
            for previous in sorted(reverse.get(current, set())):
                if previous not in visited:
                    visited.add(previous)
                    queue.append((previous, depth + 1))
    return results


def simulate_remediation(graph: dict[str, Any], removed_edge_ids: list[str] | None = None) -> dict[str, Any]:
    """Recompute alternate paths as well as the currently displayed shortest path."""
    try:
        snapshot = graph_snapshot(graph)
    except ValidationError:
        if removed_edge_ids:
            raise
        # Simulation is optional; a large graph must not turn a successful
        # assessment into a failed scan or display zero exposure as a result.
        return {
            "schema_version": 1,
            "available": False,
            "max_depth": MAX_DEPTH,
            "removed_edge_ids": [],
            "before": {"exposed_sources": None, "source_target_pairs": None},
            "after": {"exposed_sources": None, "source_target_pairs": None},
            "closed_sources": [],
            "changed_sources": [],
            "graph": {"nodes": [], "edges": [], "max_depth": MAX_DEPTH},
            "limitations": "Simulation limits exceeded. The assessment remains available; exposure was not computed.",
        }
    removed = set(removed_edge_ids or [])
    known = {edge["id"] for edge in snapshot["edges"]}
    if removed - known:
        raise ValidationError("Remediation scenario refers to an unknown or non-control edge")
    before = _reachability(snapshot, set())
    after = _reachability(snapshot, removed)
    labels = {node["id"]: node.get("label") or node["id"] for node in snapshot["nodes"]}
    changed = []
    for source in sorted(before):
        old = before[source]
        new = after.get(source, {"targets": set(), "shortest_hops": None})
        if old != new:
            changed.append(
                {
                    "source": source,
                    "label": labels[source],
                    "before_targets": sorted(old["targets"]),
                    "after_targets": sorted(new["targets"]),
                    "before_hops": old["shortest_hops"],
                    "after_hops": new["shortest_hops"],
                    "closed": not new["targets"],
                }
            )
    return {
        "schema_version": 1,
        "available": True,
        "max_depth": MAX_DEPTH,
        "removed_edge_ids": sorted(removed),
        "before": {
            "exposed_sources": len(before),
            "source_target_pairs": sum(len(item["targets"]) for item in before.values()),
        },
        "after": {
            "exposed_sources": len(after),
            "source_target_pairs": sum(len(item["targets"]) for item in after.values()),
        },
        "closed_sources": sorted(set(before) - set(after)),
        "changed_sources": changed,
        "graph": snapshot,
        "limitations": "Prediction within the collected graph and six hops. Uncollected relationships and operational dependencies are not modeled.",
    }
