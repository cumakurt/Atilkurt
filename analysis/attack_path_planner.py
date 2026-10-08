"""Bounded, evidence-aware alternative routes between selected identities."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone

from core.exceptions import ValidationError
from core.graph_import import validate_graph

CONTROL = {'MemberOf', 'Controls', 'ControlADCSObject', 'ControlADFSDKM', 'ReplicationRight', 'ACLControls', 'AdminTo', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
           'ForceChangePassword', 'AddMember', 'Owns', 'ReadGMSAPassword', 'ReadLAPSPassword', 'DCSync'}
CONDITIONAL = {'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AllowedToDelegate', 'AllowedToAct', 'Enroll',
               'ManageCA', 'ManageCertificates', 'WriteGPLink', 'GPLink', 'GPOAppliesTo'}


def plan_attack_paths(graph, start, goal, *, max_hops=8, max_paths=20, max_expansions=20000, now=None):
    if not 1 <= max_hops <= 16 or not 1 <= max_paths <= 100 or not 1 <= max_expansions <= 100000:
        raise ValidationError('Attack planner limits are invalid')
    validate_graph(graph)
    nodes = {node['id']: node for node in graph.get('nodes', [])}

    def resolve(value):
        matches = [identifier for identifier, node in nodes.items()
                   if value.casefold() in {identifier.casefold(), str(node.get('label', '')).casefold(), str(node.get('sid', '')).casefold()}
                   or value.casefold() in {alias.casefold() for alias in node.get('aliases', [])}]
        if len(matches) != 1:
            raise ValidationError('Attack planner start/goal must resolve to exactly one graph identity')
        return matches[0]

    start_id, goal_id = resolve(start), resolve(goal)
    now = now or datetime.now(timezone.utc)
    adjacency = {}
    excluded = 0
    for edge in graph.get('edges', []):
        relationship, props = edge.get('type'), {**edge, **(edge.get('properties') or {})}
        if (relationship not in CONTROL | CONDITIONAL
                or props.get('status') in {'disproved', 'expired', 'excluded', 'false_positive'}
                or props.get('finding_status') == 'false_positive'):
            excluded += 1
            continue
        if edge.get('source') not in nodes or edge.get('target') not in nodes:
            continue
        prerequisites = list(props.get('prerequisites') or [])
        conditional = (relationship in CONDITIONAL or props.get('status') in {'conditional', 'pending', 'unknown', 'needs_validation'}
                       or props.get('requires_validation') is True or props.get('requires_runtime_validation') is True)
        provenance = props.get('provenance') or edge.get('snapshot_provenance') or {}
        fresh = provenance.get('fresh') is True
        if provenance.get('collected_at'):
            try:
                stamp = datetime.fromisoformat(str(provenance['collected_at']).replace('Z', '+00:00'))
                fresh = fresh and stamp.tzinfo is not None and now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5)
            except ValueError:
                fresh = False
        if provenance and not fresh:
            conditional = True
            prerequisites.append('Confirm source freshness')
        expires = props.get('expires_at')
        if expires:
            try:
                stamp = datetime.fromisoformat(str(expires).replace('Z', '+00:00'))
                if stamp.tzinfo is None or stamp <= now:
                    conditional = True
                    prerequisites.append('Revalidate expired evidence')
            except ValueError:
                conditional = True
                prerequisites.append('Correct invalid evidence expiry')
        if nodes[edge['source']].get('reference_only') or nodes[edge['target']].get('reference_only'):
            conditional = True
            prerequisites.append('Resolve referenced identity')
        adjacency.setdefault(edge['source'], []).append((edge, conditional or bool(prerequisites), prerequisites))
    queue = deque([(start_id, [start_id], [], [])])
    paths, expansions, budget_pruned = [], 0, False
    while queue and len(paths) < max_paths and expansions < max_expansions:
        current, route, route_edges, missing = queue.popleft()
        expansions += 1
        if current == goal_id:
            paths.append({'nodes': route, 'edge_ids': [edge.get('id') for edge in route_edges],
                          'labels': [str(nodes[identifier].get('label') or identifier) for identifier in route],
                          'relationships': [edge['type'] for edge in route_edges],
                          'status': 'conditional' if missing else 'supported', 'prerequisites': list(dict.fromkeys(missing))})
            continue
        if len(route_edges) >= max_hops:
            continue
        for edge, conditional, prerequisites in adjacency.get(current, []):
            if edge['target'] in route:
                continue
            if len(queue) + expansions >= max_expansions:
                budget_pruned = True
                break
            required = prerequisites or (['Verify effective permission and runtime prerequisite'] if conditional else [])
            queue.append((edge['target'], route + [edge['target']], route_edges + [edge], missing + required))
    return {'schema_version': 1, 'start': start_id, 'goal': goal_id,
            'start_label': nodes[start_id].get('label') or start_id, 'goal_label': nodes[goal_id].get('label') or goal_id,
            'paths': paths,
            'expansions': expansions, 'excluded_relationships': excluded, 'truncated': bool(queue) or budget_pruned,
            'limitation': 'Routes describe evidence-backed capabilities. Successful exploitation is not asserted.'}
