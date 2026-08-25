"""Evidence graph, shortest Tier-0 paths, chokepoints, and blast radius."""

from __future__ import annotations

from collections import defaultdict, deque
import logging
import re
from typing import Any

from core.ad_identity import account_has_privileged_evidence, is_privileged_group_record
from core.ad_security import as_list, as_text, sid_text
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)


class AttackGraphV2Analyzer:
    """Build a deterministic graph from memberships, ACL findings, and Package B graphs."""

    MAX_DEPTH = 6
    MAX_REPORTED_PATHS = 50

    def analyze(
        self,
        users: list[dict[str, Any]],
        groups: list[dict[str, Any]],
        computers: list[dict[str, Any]],
        analysis_results: dict[str, Any],
    ) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        sid_to_id: dict[str, str] = {}
        dn_to_id: dict[str, str] = {}

        for kind, objects in (("user", users), ("group", groups), ("computer", computers)):
            for obj in objects:
                label = as_text(obj.get("sAMAccountName") or obj.get("name") or obj.get("cn"))
                if not label:
                    continue
                node_id = self._node_id(kind, label)
                privileged = account_has_privileged_evidence(obj) or (
                    kind == "group" and is_privileged_group_record(obj)
                )
                nodes[node_id] = {
                    "id": node_id, "label": label, "kind": kind,
                    "privileged": privileged,
                }
                sid = sid_text(obj.get("objectSid"))
                dn = as_text(obj.get("distinguishedName") or obj.get("dn"))
                if sid:
                    sid_to_id[sid] = node_id
                    nodes[node_id]["sid"] = sid
                if dn:
                    dn_to_id[dn.casefold()] = node_id
                    nodes[node_id]["dn"] = dn

        for kind, objects in (("user", users), ("group", groups), ("computer", computers)):
            for obj in objects:
                source = self._lookup_object(obj, kind, nodes)
                if not source:
                    continue
                for parent_dn in as_list(obj.get("memberOf")):
                    target = dn_to_id.get(as_text(parent_dn).casefold())
                    if target:
                        self._edge(edges, source, target, "MemberOf", {"evidence": "memberOf"})

        for finding in analysis_results.get("comprehensive_acl_risks") or []:
            trustee_sid = as_text(finding.get("trustee"))
            source = sid_to_id.get(trustee_sid)
            target = self._find_by_label(nodes, as_text(finding.get("affected_object")))
            if source and target:
                self._edge(edges, source, target, "Controls", {
                    "permission": finding.get("permission"), "risk_type": finding.get("type"),
                })

        self._merge_component_graphs(nodes, edges, analysis_results)
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in edges.values():
            adjacency[edge["source"]].add(edge["target"])
        targets = {node_id for node_id, node in nodes.items() if node.get("privileged")}

        paths: list[dict[str, Any]] = []
        source_nodes = [
            node_id for node_id, node in nodes.items()
            if node.get("kind") in {"user", "computer", "principal"} and node_id not in targets
        ]
        for source in source_nodes:
            path = self._shortest_path(source, targets, adjacency)
            if not path:
                continue
            paths.append({
                "source": source, "target": path[-1], "path": path,
                "hop_count": len(path) - 1,
                "labels": [nodes.get(node_id, {}).get("label", node_id) for node_id in path],
            })
        paths.sort(key=lambda item: (item["hop_count"], item["source"], item["target"]))

        centrality: dict[str, int] = defaultdict(int)
        for path in paths:
            for node_id in path["path"][1:-1]:
                centrality[node_id] += 1
        chokepoints = [
            {"node": node_id, "label": nodes.get(node_id, {}).get("label", node_id), "path_count": count}
            for node_id, count in centrality.items() if count >= 3
        ]
        chokepoints.sort(key=lambda item: (-item["path_count"], item["node"]))
        blast_radius = {
            node_id: len(self._reachable_targets(node_id, targets, adjacency))
            for node_id in nodes
        }
        for node_id, count in blast_radius.items():
            nodes[node_id]["tier0_blast_radius"] = count

        risks = [self._path_risk(path, nodes) for path in paths[:self.MAX_REPORTED_PATHS]]
        for choke in chokepoints[:10]:
            risks.append({
                "type": RiskTypes.ATTACK_GRAPH_CHOKEPOINT,
                "severity": Severity.HIGH,
                "title": f'Attack-path chokepoint "{choke["label"]}" appears in {choke["path_count"]} Tier-0 paths',
                "description": "Multiple independently sourced shortest paths converge on the same intermediary node.",
                "affected_object": choke["label"],
                "object_type": "configuration",
                "impact": "Compromise of a high-centrality node provides disproportionate reach into Tier-0 assets.",
                "attack_scenario": "An attacker selects the shared intermediary to convert several low-privilege footholds into privileged access.",
                "mitigation": "Remove unnecessary incoming control edges, isolate the node, and monitor every administrative change involving it.",
                "mitre_attack": MITRETechniques.PRIVILEGE_ESCALATION,
                "evidence": choke,
            })

        graph_nodes = sorted(nodes.values(), key=lambda item: item["id"])
        graph_edges = sorted(edges.values(), key=lambda item: (item["source"], item["target"], item["type"]))
        graph = {
            "schema_version": "2.0",
            "nodes": graph_nodes,
            "edges": graph_edges,
            "shortest_paths": paths,
            "chokepoints": chokepoints,
            "summary": {
                "node_count": len(graph_nodes), "edge_count": len(graph_edges),
                "tier0_target_count": len(targets), "open_path_count": len(paths),
                "chokepoint_count": len(chokepoints),
            },
        }
        graph["opengraph"] = self._opengraph(graph_nodes, graph_edges)
        return {"risks": risks, "graph": graph}

    def _merge_component_graphs(
        self, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]],
        results: dict[str, Any],
    ) -> None:
        for key in (
            "gmsa_reader_graph", "adcs_control_plane_graph", "trust_security_v2_graph",
            "ad_dns_security_graph", "hybrid_identity_v2_graph",
        ):
            graph = results.get(key) or {}
            for node in graph.get("nodes") or []:
                if not isinstance(node, dict) or not node.get("id"):
                    continue
                node_id = str(node["id"])
                existing = nodes.setdefault(node_id, dict(node))
                existing.update({k: v for k, v in node.items() if v not in (None, "")})
            for edge in graph.get("edges") or []:
                if not isinstance(edge, dict):
                    continue
                source, target = str(edge.get("source") or ""), str(edge.get("target") or "")
                if source and target:
                    self._edge(edges, source, target, str(edge.get("type") or "RelatedTo"), {
                        key: value for key, value in edge.items() if key not in {"source", "target", "type"}
                    })

    @classmethod
    def _shortest_path(
        cls, source: str, targets: set[str], adjacency: dict[str, set[str]],
    ) -> list[str] | None:
        queue = deque([(source, [source])])
        visited = {source}
        while queue:
            current, path = queue.popleft()
            if current in targets and current != source:
                return path
            if len(path) - 1 >= cls.MAX_DEPTH:
                continue
            for neighbor in sorted(adjacency.get(current, set())):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, [*path, neighbor]))
        return None

    @classmethod
    def _reachable_targets(
        cls, source: str, targets: set[str], adjacency: dict[str, set[str]],
    ) -> set[str]:
        reached: set[str] = set()
        queue = deque([(source, 0)])
        visited = {source}
        while queue:
            current, depth = queue.popleft()
            if current in targets and current != source:
                reached.add(current)
            if depth >= cls.MAX_DEPTH:
                continue
            for neighbor in adjacency.get(current, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, depth + 1))
        return reached

    @staticmethod
    def _edge(edges: dict[tuple[str, str, str], dict[str, Any]], source: str, target: str,
              kind: str, properties: dict[str, Any]) -> None:
        key = (source, target, kind)
        edge = edges.setdefault(key, {"source": source, "target": target, "type": kind})
        edge.update({k: v for k, v in properties.items() if v not in (None, "", [], {})})

    @staticmethod
    def _lookup_object(obj: dict[str, Any], kind: str, nodes: dict[str, dict[str, Any]]) -> str | None:
        label = as_text(obj.get("sAMAccountName") or obj.get("name") or obj.get("cn"))
        node_id = AttackGraphV2Analyzer._node_id(kind, label) if label else None
        return node_id if node_id in nodes else None

    @staticmethod
    def _find_by_label(nodes: dict[str, dict[str, Any]], label: str) -> str | None:
        target = label.casefold()
        return next((node_id for node_id, node in nodes.items() if str(node.get("label", "")).casefold() == target), None)

    @staticmethod
    def _node_id(kind: str, label: str) -> str:
        normalized = re.sub(r"[^a-z0-9._$@-]+", "_", label.casefold()).strip("_")
        return f"{kind}:{normalized or 'unknown'}"

    @staticmethod
    def _path_risk(path: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> dict[str, Any]:
        labels = path["labels"]
        hops = path["hop_count"]
        return {
            "type": RiskTypes.ATTACK_GRAPH_TIER0_PATH,
            "severity": Severity.CRITICAL if hops <= 2 else Severity.HIGH,
            "title": f'Tier-0 attack path from "{labels[0]}" in {hops} hops',
            "description": " -> ".join(labels),
            "affected_object": labels[0],
            "object_type": nodes.get(path["source"], {}).get("kind", "user"),
            "impact": "The evidence graph contains a traversable relationship from a non-privileged source to a Tier-0 identity or group.",
            "attack_scenario": "An attacker follows membership, ACL, service-account, PKI, trust, or hybrid-control edges to reach Tier 0.",
            "mitigation": "Break the shortest edge first, then remove shared chokepoints and re-run the graph to verify path closure.",
            "mitre_attack": MITRETechniques.PRIVILEGE_ESCALATION,
            "evidence": path,
        }

    @staticmethod
    def _opengraph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
        """Build BloodHound OpenGraph-shaped custom-node import data."""
        return {
            "graph": {
                "nodes": [
                    {
                        "id": node["id"],
                        "kinds": ["AtilKurt", str(node.get("kind") or "Entity").title().replace("_", "")],
                        "properties": {key: value for key, value in node.items() if key != "id"},
                    }
                    for node in nodes
                ],
                "edges": [
                    {
                        "kind": edge["type"],
                        "start": {"value": edge["source"], "match_by": "id"},
                        "end": {"value": edge["target"], "match_by": "id"},
                        "properties": {
                            key: value for key, value in edge.items()
                            if key not in {"source", "target", "type"}
                        },
                    }
                    for edge in edges
                ],
            }
        }
