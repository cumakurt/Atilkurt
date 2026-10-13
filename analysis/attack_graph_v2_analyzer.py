"""Evidence graph, shortest Tier-0 paths, chokepoints, and blast radius."""

from __future__ import annotations

from collections import defaultdict, deque
import hashlib
import logging
import re
from typing import Any

from core.ad_identity import account_has_current_privileged_membership, is_privileged_group_record, is_security_group, is_tier0_group_record
from core.ad_security import as_list, as_text, sid_text
from core.constants import MITRETechniques, RiskTypes, Severity
from core.finding_evidence import is_disproved, requires_validation

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
        edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        sid_to_id: dict[str, str] = {}
        dn_to_id: dict[str, str] = {}
        label_to_id: dict[str, str] = {}

        # Keep established IDs for unique labels, but never collapse distinct
        # directory identities after punctuation/Unicode normalization.
        object_ids: dict[int, str] = {}
        candidates: dict[str, list[tuple[int, str]]] = defaultdict(list)
        for kind, objects in (("user", users), ("group", groups), ("computer", computers)):
            for obj in objects:
                label = as_text(obj.get("sAMAccountName") or obj.get("name") or obj.get("cn"))
                if label:
                    identity = sid_text(obj.get("objectSid")) or as_text(
                        obj.get("distinguishedName") or obj.get("dn") or label
                    ).casefold()
                    candidates[self._node_id(kind, label)].append((id(obj), identity))
        for base_id, entries in candidates.items():
            ambiguous = len({identity for _, identity in entries}) > 1
            for object_id, identity in entries:
                suffix = ':' + hashlib.sha256(identity.encode()).hexdigest() if ambiguous else ''
                object_ids[object_id] = base_id + suffix

        for kind, objects in (("user", users), ("group", groups), ("computer", computers)):
            for obj in objects:
                label = as_text(obj.get("sAMAccountName") or obj.get("name") or obj.get("cn"))
                if not label:
                    continue
                node_id = object_ids[id(obj)]
                sensitive = account_has_current_privileged_membership(obj) or (
                    kind == "group" and is_privileged_group_record(obj)
                )
                nodes[node_id] = {
                    "id": node_id, "label": label, "kind": kind,
                    "privileged": kind == "group" and is_tier0_group_record(obj),
                    "sensitive_access": sensitive and (kind != "group" or is_security_group(obj)),
                    "security_enabled": kind != "group" or is_security_group(obj),
                }
                label_to_id[label.casefold()] = node_id
                sid = sid_text(obj.get("objectSid"))
                dn = as_text(obj.get("distinguishedName") or obj.get("dn"))
                if sid:
                    sid_to_id[sid] = node_id
                    nodes[node_id]["sid"] = sid
                if dn:
                    dn_to_id[dn.casefold()] = node_id
                    nodes[node_id]["dn"] = dn

        for objects in (users, groups, computers):
            for obj in objects:
                source = object_ids.get(id(obj))
                if not source:
                    continue
                for parent_dn in as_list(obj.get("memberOf")):
                    target = dn_to_id.get(as_text(parent_dn).casefold())
                    if target and nodes[target].get("security_enabled") and nodes[source].get("security_enabled"):
                        self._edge(edges, source, target, "MemberOf", {"evidence": "memberOf"})

        # Primary groups and member backlinks are omitted from memberOf in some snapshots.
        for obj in [*users, *groups, *computers]:
            source = sid_to_id.get(sid_text(obj.get("objectSid")))
            primary = obj.get("primaryGroupID")
            sid = sid_text(obj.get("objectSid"))
            target = sid_to_id.get(sid.rsplit("-", 1)[0] + "-" + str(primary)) if sid and primary else None
            if source and target and nodes[target].get("security_enabled"):
                self._edge(edges, source, target, "MemberOf", {"evidence": "primaryGroupID"})
        for group in groups:
            target = object_ids.get(id(group))
            if not target or not nodes[target].get("security_enabled"):
                continue
            for member in as_list(group.get("member")):
                source = dn_to_id.get(as_text(member).casefold())
                if source and nodes[source].get("security_enabled"):
                    self._edge(edges, source, target, "MemberOf", {"evidence": "member"})

        # Token membership is existing access, not a new control grant.
        membership_children: dict[str, set[str]] = defaultdict(set)
        for edge in edges.values():
            if edge["type"] == "MemberOf":
                membership_children[edge["target"]].add(edge["source"])
        for flag in ("privileged", "sensitive_access"):
            membership_queue = deque(node_id for node_id, node in nodes.items() if node.get(flag))
            expanded: set[str] = set()
            while membership_queue:
                parent = membership_queue.popleft()
                if parent in expanded:
                    continue
                expanded.add(parent)
                for child in membership_children.get(parent, ()):
                    nodes[child][flag] = True
                    nodes[child]["privilege_basis"] = "existing_nested_membership"
                    membership_queue.append(child)

        self._merge_component_graphs(nodes, edges, analysis_results)
        # The domain naming context is created by the trust graph, after the
        # inventory nodes. ACL findings name it "Domain" and carry object_dn,
        # so control edges must be resolved only once that node exists.
        self._mark_assessed_domain(nodes)
        label_candidates: dict[str, set[str]] = defaultdict(set)
        for node_id, node in nodes.items():
            dn = as_text(node.get("dn"))
            if dn:
                dn_to_id[dn.casefold()] = node_id
            label = as_text(node.get("label"))
            label_candidates[label.casefold()].add(node_id)
        label_to_id = {label: next(iter(ids)) for label, ids in label_candidates.items() if len(ids) == 1}
        self._add_control_edges(
            nodes, edges, analysis_results.get("comprehensive_acl_risks") or [],
            sid_to_id, dn_to_id, label_to_id,
        )
        adjacency: dict[str, set[str]] = defaultdict(set)
        for edge in edges.values():
            # A trust is an authentication relationship, not an object-control
            # grant. Keep it visible without asserting a traversable takeover.
            if edge['type'] in {'InboundTrust', 'OutboundTrust', 'RelatedTo'}:
                continue
            adjacency[edge["source"]].add(edge["target"])
        targets = {node_id for node_id, node in nodes.items() if node.get("privileged")}

        reverse_adj: dict[str, set[str]] = defaultdict(set)
        for source, destinations in adjacency.items():
            for destination in destinations:
                reverse_adj[destination].add(source)

        predecessor: dict[str, str] = {}
        distance: dict[str, int] = {}
        queue = deque()
        for target in sorted(targets):
            queue.append(target)
            distance[target] = 0
        while queue:
            current = queue.popleft()
            if distance[current] >= self.MAX_DEPTH:
                continue
            for parent in sorted(reverse_adj.get(current, set())):
                if parent in distance:
                    continue
                distance[parent] = distance[current] + 1
                predecessor[parent] = current
                queue.append(parent)

        paths: list[dict[str, Any]] = []
        source_nodes = [
            node_id for node_id, node in nodes.items()
            if node.get("kind") in {"user", "computer", "principal"} and node_id not in targets
        ]
        for source in source_nodes:
            if source not in predecessor:
                continue
            path = [source]
            node_id = source
            while node_id not in targets:
                node_id = predecessor[node_id]
                path.append(node_id)
            paths.append({
                "source": source, "target": path[-1], "path": path,
                "hop_count": len(path) - 1,
                "labels": [nodes.get(item, {}).get("label", item) for item in path],
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
        blast_radius = self._blast_radius_from_targets(targets, reverse_adj, nodes)
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
                "reported_path_count": min(len(paths), self.MAX_REPORTED_PATHS),
                "report_truncated": len(paths) > self.MAX_REPORTED_PATHS,
                "max_depth": self.MAX_DEPTH,
            },
            "limitation": "Paths are bounded by max_depth and findings by reported_path_count. Absence of a reported path does not establish absence of attack paths.",
        }
        graph["opengraph"] = self._opengraph(graph_nodes, graph_edges)
        return {"risks": risks, "graph": graph}

    @staticmethod
    def _mark_assessed_domain(nodes: dict[str, dict[str, Any]]) -> None:
        """Control of the assessed domain naming context is Tier-0."""
        for node_id, node in nodes.items():
            if node.get("kind") != "domain":
                continue
            node["privileged"] = True
            if not node.get("dn") and str(node_id).startswith("domain:"):
                node["dn"] = str(node_id).split(":", 1)[1]

    def _add_control_edges(
        self, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str, str], dict[str, Any]],
        findings: list[dict[str, Any]], sid_to_id: dict[str, str], dn_to_id: dict[str, str],
        label_to_id: dict[str, str],
    ) -> None:
        replication: dict[tuple[str, str], set[str]] = defaultdict(set)
        required = {'DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All'}
        for finding in findings:
            if requires_validation(finding) or is_disproved(finding):
                continue
            source = sid_to_id.get(as_text(finding.get("trustee")))
            target = self._control_target(finding, dn_to_id, label_to_id)
            if source in nodes and target in nodes:
                permission = str(finding.get('permission') or '')
                if permission.startswith('DS-Replication-'):
                    if nodes[target].get('kind') == 'domain':
                        replication[(source, target)].add(permission)
                    continue
                if nodes[target].get('kind') == 'domain' and permission not in {
                    'GenericAll', 'WriteDACL', 'WriteOwner', 'AllExtendedRights',
                }:
                    # Writing an arbitrary domain attribute does not grant
                    # replication or administrative control of the domain.
                    continue
                self._edge(edges, source, target, "Controls", {
                    "permission": finding.get("permission"), "risk_type": finding.get("type"),
                })
        for (source, target), permissions in replication.items():
            if required <= permissions:
                # Model the conjunction as one capability; two parallel edges
                # would incorrectly model either replication right as enough.
                self._edge(edges, source, target, 'Controls', {
                    'permission': 'DS-Replication-Get-Changes + DS-Replication-Get-Changes-All',
                    'required_permissions': sorted(required), 'risk_type': 'acl_dcsync',
                })

    @staticmethod
    def _control_target(finding: dict[str, Any], dn_to_id: dict[str, str], label_to_id: dict[str, str]) -> str | None:
        explicit_dn = False
        for key in ("object_dn", "distinguishedName", "target_dn"):
            dn = as_text(finding.get(key)).casefold()
            explicit_dn = explicit_dn or bool(dn)
            if dn and dn in dn_to_id:
                return dn_to_id[dn]
        if explicit_dn:
            return None
        return label_to_id.get(as_text(finding.get("affected_object")).casefold())

    def _merge_component_graphs(
        self, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str, str], dict[str, Any]],
        results: dict[str, Any],
    ) -> None:
        for key in (
            "gmsa_reader_graph", "adcs_control_plane_graph", "trust_security_v2_graph",
            "ad_dns_security_graph", "hybrid_identity_v2_graph",
        ):
            graph = results.get(key) or {}
            by_sid = {str(node["sid"]): node_id for node_id, node in nodes.items() if node.get("sid")}
            by_dn = {str(node["dn"]).casefold(): node_id for node_id, node in nodes.items() if node.get("dn")}
            aliases: dict[str, str] = {}
            for node in graph.get("nodes") or []:
                if not isinstance(node, dict) or not node.get("id"):
                    continue
                node_id = str(node["id"])
                sid, dn = str(node.get("sid") or ""), str(node.get("dn") or "").casefold()
                canonical = by_sid.get(sid) if sid else by_dn.get(dn)
                canonical = canonical or node_id
                aliases[node_id] = canonical
                if canonical in nodes:
                    # Component evidence cannot revoke known membership or rename inventory identities.
                    nodes[canonical]["privileged"] = bool(nodes[canonical].get("privileged") or node.get("privileged"))
                else:
                    nodes[canonical] = dict(node, id=canonical)
                if sid:
                    by_sid[sid] = canonical
                if dn:
                    by_dn[dn] = canonical
            for edge in graph.get("edges") or []:
                if not isinstance(edge, dict):
                    continue
                source = aliases.get(str(edge.get("source")), str(edge.get("source") or ""))
                target = aliases.get(str(edge.get("target")), str(edge.get("target") or ""))
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
    def _blast_radius_from_targets(
        cls,
        targets: set[str],
        reverse_adj: dict[str, set[str]],
        nodes: dict[str, dict[str, Any]],
    ) -> dict[str, int]:
        blast = {node_id: 0 for node_id in nodes}
        for target in targets:
            seen = {target}
            queue = deque([(target, 0)])
            while queue:
                current, depth = queue.popleft()
                if current != target:
                    blast[current] = blast.get(current, 0) + 1
                if depth >= cls.MAX_DEPTH:
                    continue
                for parent in reverse_adj.get(current, set()):
                    if parent not in seen:
                        seen.add(parent)
                        queue.append((parent, depth + 1))
        return blast

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
    def _edge(edges: dict[tuple[str, str, str, str], dict[str, Any]], source: str, target: str,
              kind: str, properties: dict[str, Any]) -> None:
        key = (source, target, kind, str(properties.get('permission') or ''))
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
