"""Enumerate Domain Admin / Tier-0 options reachable from the assessment account."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from core.ad_identity import is_tier0_group_record
from core.ad_security import BROAD_PRINCIPAL_SIDS, as_text, sid_text
from core.finding_evidence import is_disproved, requires_takeover_validation as requires_validation

SKIP_EDGE_TYPES = frozenset({"InboundTrust", "OutboundTrust", "RelatedTo"})
MAX_ROUTES = 50
MAX_DEPTH = 6
TIER0_EXTRA_LABELS = frozenset({"krbtgt", "administrator"})
# Techniques any authenticated bind can start when the domain finding is open.
AUTHENTICATED_STARTERS = frozenset({
    "kerberoasting",
    "gpp_passwords",
    "machine_quota",
    "password_spray",
    "ldap_recon",
    "nopac",
    "relay_coerce",
    "laps",
})
UNAUTHENTICATED_STARTERS = frozenset({"asrep", "ldap_recon"})
MAX_STARTERS = 40
MAX_STARTER_ROUTES = 8
MAX_STARTER_EVIDENCE = 8
STARTER_KINDS = frozenset({"user", "computer", "principal", "gmsa", "msa"})
BROAD_STARTER_NAMES = frozenset({
    "everyone",
    "authenticated users",
    "users",
    "domain users",
    "domain computers",
    "guests",
    "anonymous logon",
    "pre-windows 2000 compatible access",
    "enterprise domain controllers",
    "domain controllers",
})
USE_AFFECTED_AS_FOOTHOLD_PREFIXES = (
    "dcsync",
    "shadow_admin",
    "attack_graph",
    "privilege_escalat",
    "unconstrained",
    "constrained",
    "rbcd",
    "hidden_primary",
    "privileged_computer",
    "backup_operator",
    "sensitive_operator",
    "gmsa_broad",
    "gmsa_privileged",
    "acl_privilege",
    "key_credential_privileged",
)


def identity_token_sids(identity: dict[str, Any] | None) -> set[str]:
    """Return the bind SID plus collected tokenGroups SIDs."""
    identity = identity or {}
    sids = {
        str(value)
        for value in (identity.get("token_groups") or {}).get("sids") or []
        if value
    }
    if identity.get("sid"):
        sids.add(str(identity["sid"]))
    return sids


def identity_source_ids(graph: dict[str, Any], identity: dict[str, Any]) -> list[str]:
    """Return graph node IDs for the bind account and its token groups."""
    if not identity:
        return []
    sam = str(identity.get("sam") or "").casefold()
    dn = str(identity.get("dn") or "").casefold()
    token_sids = identity_token_sids(identity)
    found: list[str] = []
    seen: set[str] = set()
    for node in graph.get("nodes") or []:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        node_id = str(node["id"])
        node_sid = str(node.get("sid") or "")
        label = str(node.get("label") or "").casefold()
        node_dn = str(node.get("dn") or "").casefold()
        if node_sid and token_sids:
            matched = node_sid in token_sids
        elif dn and node_dn:
            matched = node_dn == dn
        else:
            matched = bool(sam and label == sam)
        if matched and node_id not in seen:
            seen.add(node_id)
            found.append(node_id)
    return found


def is_tier0_node(node: dict[str, Any] | None) -> bool:
    """Return True when a graph node is Domain Admin / Tier-0 equivalent."""
    if not isinstance(node, dict):
        return False
    if node.get("privileged"):
        return True
    label = str(node.get("label") or "").strip()
    if node.get("sid"):
        return is_tier0_group_record({"objectSid": node["sid"]})
    return is_tier0_group_record({"name": label}) or label.casefold() in TIER0_EXTRA_LABELS


def enumerate_tier0_routes(
    graph: dict[str, Any],
    source_ids: list[str],
    *,
    max_depth: int = MAX_DEPTH,
    max_routes: int = MAX_ROUTES,
) -> list[dict[str, Any]]:
    """Return distinct simple paths from the sources to privileged nodes."""
    nodes = {
        str(node["id"]): node
        for node in graph.get("nodes") or []
        if isinstance(node, dict) and node.get("id")
    }
    adjacency: dict[str, set[str]] = defaultdict(set)
    edge_type: dict[tuple[str, str], str] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        kind = str(edge.get("type") or "")
        if kind in SKIP_EDGE_TYPES:
            continue
        source, target = str(edge.get("source") or ""), str(edge.get("target") or "")
        if source and target:
            adjacency[source].add(target)
            edge_type[(source, target)] = kind or "Controls"
    targets = {node_id for node_id, node in nodes.items() if is_tier0_node(node)}
    # Compute a lower bound on remaining hops once. Dense components that
    # cannot reach Tier 0 must not enumerate every simple path up to depth 6.
    reverse: dict[str, set[str]] = defaultdict(set)
    for source, neighbors in adjacency.items():
        for target in neighbors:
            reverse[target].add(source)
    distances = dict.fromkeys(targets, 0)
    pending = deque(targets)
    while pending:
        target = pending.popleft()
        if distances[target] >= max_depth:
            continue
        for source in reverse.get(target, ()):
            if source not in distances:
                distances[source] = distances[target] + 1
                pending.append(source)
    routes: list[dict[str, Any]] = []
    seen_signatures: set[tuple[str, ...]] = set()

    def record_route(path: list[str]) -> None:
        if len(routes) >= max_routes:
            return
        signature = tuple(path)
        if signature in seen_signatures:
            return
        seen_signatures.add(signature)
        labels = [str(nodes.get(item, {}).get("label") or item) for item in path]
        hops = [
            {
                "from": labels[index],
                "to": labels[index + 1],
                "type": edge_type.get((path[index], path[index + 1]), "Controls"),
            }
            for index in range(max(0, len(path) - 1))
        ]
        target_node = nodes.get(path[-1]) or {}
        routes.append(
            {
                "source": path[0],
                "target": path[-1],
                "target_label": labels[-1],
                "target_kind": str(target_node.get("kind") or ""),
                "path": list(path),
                "labels": labels,
                "hop_count": max(0, len(path) - 1),
                "hops": hops,
                "already_privileged": len(path) == 1,
            }
        )

    def walk(node_id: str, path: list[str], visited: set[str]) -> None:
        if len(routes) >= max_routes:
            return
        remaining = distances.get(node_id)
        if remaining is None or len(path) - 1 + remaining > max_depth:
            return
        if node_id in targets and len(path) > 1:
            record_route(path)
            return
        if len(path) - 1 >= max_depth:
            return
        for neighbor in sorted(adjacency.get(node_id, ())):
            if neighbor in visited:
                continue
            walk(neighbor, [*path, neighbor], visited | {neighbor})

    for source in source_ids:
        if source not in nodes or len(routes) >= max_routes:
            continue
        if is_tier0_node(nodes[source]):
            record_route([source])
        walk(source, [source], {source})
    routes.sort(key=lambda item: (item["hop_count"], item["labels"]))
    return routes[:max_routes]


def group_routes_by_target(routes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse routes that finish on the same Tier-0 object."""
    buckets: dict[str, dict[str, Any]] = {}
    for route in routes:
        key = str(route.get("target") or route.get("target_label") or "")
        bucket = buckets.setdefault(
            key,
            {
                "target": key,
                "target_label": str(route.get("target_label") or key),
                "route_count": 0,
                "shortest_hops": route.get("hop_count"),
                "routes": [],
            },
        )
        bucket["route_count"] += 1
        hops = route.get("hop_count")
        if hops is not None and (
            bucket["shortest_hops"] is None or hops < bucket["shortest_hops"]
        ):
            bucket["shortest_hops"] = hops
        bucket["routes"].append(route)
    rows = list(buckets.values())
    rows.sort(
        key=lambda item: (
            99 if item.get("shortest_hops") is None else item["shortest_hops"],
            item.get("target_label") or "",
        )
    )
    return rows


def enrollable_templates(
    risks: list[dict[str, Any]],
    identity: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return confirmed ESC templates the bound token can enroll on."""
    from core.ad_identity import is_privileged_group_record

    token_sids = identity_token_sids(identity)
    privileged_group_sids = {
        sid_text(group.get("objectSid"))
        for group in groups or []
        if is_privileged_group_record(group)
    }
    privileged_group_sids.discard(None)
    found: list[dict[str, Any]] = []
    for risk in risks:
        risk_type = str(risk.get("type") or "").casefold()
        if not risk_type.startswith("certificate_esc"):
            continue
        if requires_validation(risk) or is_disproved(risk):
            continue
        evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
        trustees = list(evidence.get("enrollment_trustees") or [])
        matched = []
        for trustee in trustees:
            if not isinstance(trustee, dict):
                continue
            sid = str(trustee.get("sid") or "")
            if sid in BROAD_PRINCIPAL_SIDS or sid in token_sids:
                if sid not in privileged_group_sids:
                    matched.append(trustee.get("name") or sid)
        if matched:
            found.append(
                {
                    "template": str(risk.get("affected_object") or ""),
                    "type": risk_type,
                    "trustees": matched,
                    "published_cas": list(evidence.get("published_cas") or []),
                }
            )
    return found


def _identity_needles(identity: dict[str, Any]) -> tuple[str, str, str, set[str]]:
    sam = str(identity.get("sam") or "").casefold()
    sid = str(identity.get("sid") or "")
    dn = str(identity.get("dn") or "").casefold()
    return sam, sid, dn, identity_token_sids(identity)


def _text_matches_identity(value: Any, sam: str, sid: str, dn: str, token_sids: set[str]) -> bool:
    text = as_text(value)
    if not text:
        return False
    folded = text.casefold()
    if sam and (
        folded == sam
        or folded.endswith("\\" + sam)
        or folded.startswith(sam + "@")
    ):
        return True
    if dn and folded == dn:
        return True
    if sid and text == sid:
        return True
    return text in token_sids


def finding_touches_identity(risk: dict[str, Any], identity: dict[str, Any]) -> bool:
    """Return True when a finding names the bind account or one of its token SIDs."""
    if not identity or not risk:
        return False
    sam, sid, dn, token_sids = _identity_needles(identity)
    if not sam and not sid and not dn:
        return False
    for key in (
        "affected_object",
        "trustee",
        "trustee_name",
        "trustee_sid",
        "sAMAccountName",
        "name",
        "source",
        "principal",
    ):
        if _text_matches_identity(risk.get(key), sam, sid, dn, token_sids):
            return True
    evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
    for key in ("trustee", "trustee_sid", "source", "principal"):
        if _text_matches_identity(evidence.get(key), sam, sid, dn, token_sids):
            return True
    for trustee in evidence.get("enrollment_trustees") or []:
        if not isinstance(trustee, dict):
            continue
        if _text_matches_identity(trustee.get("sid"), sam, sid, dn, token_sids):
            return True
        if _text_matches_identity(trustee.get("name"), sam, sid, dn, token_sids):
            return True
    path = evidence.get("path") or risk.get("path") or []
    if isinstance(path, list):
        for hop in path:
            label = hop.get("label") if isinstance(hop, dict) else hop
            if _text_matches_identity(label, sam, sid, dn, token_sids):
                return True
    return False


def account_finding_options(
    risks: list[dict[str, Any]],
    identity: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return DA-relevant findings this bind session is a trustee or object for."""
    matched = [
        risk
        for risk in risks
        if not is_disproved(risk) and finding_touches_identity(risk, identity)
    ]
    return evidence_options(matched)


def session_techniques(
    identity: dict[str, Any],
    *,
    routes: list[dict[str, Any]],
    templates: list[dict[str, Any]],
    finding_options: list[dict[str, Any]],
    open_path_ids: list[str] | None = None,
) -> list[str]:
    """Catalog technique IDs the assessment account can start in this session."""
    ids: list[str] = []
    seen: set[str] = set()

    def add(path_id: str) -> None:
        if path_id and path_id not in seen:
            seen.add(path_id)
            ids.append(path_id)

    open_ids = {str(item) for item in (open_path_ids or []) if item}
    if identity.get("resolved"):
        for path_id in sorted(AUTHENTICATED_STARTERS):
            if path_id in open_ids:
                add(path_id)
    for path_id in sorted(UNAUTHENTICATED_STARTERS):
        if path_id in open_ids:
            add(path_id)
    if routes:
        add("tier0_graph")
    if templates:
        add("adcs")
    if any(
        str(item).startswith("acl_") or str(item) == "shadow_admin"
        for option in finding_options
        for item in (option.get("types") or [])
    ):
        add("acl_generic_all")
    return ids


def build_assessment_account_view(
    identity: dict[str, Any] | None,
    graph: dict[str, Any] | None,
    risks: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    open_path_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the first-class 'from this bind account' Domain Admin block."""
    identity = identity or {}
    graph = graph or {}
    risks = list(risks or [])
    sam = str(identity.get("sam") or identity.get("bind_username") or "unresolved")
    source_ids = identity_source_ids(graph, identity)
    routes = enumerate_tier0_routes(graph, source_ids) if source_ids else []
    templates = enrollable_templates(risks, identity, groups)
    findings = account_finding_options(risks, identity)
    techniques = session_techniques(
        identity,
        routes=routes,
        templates=templates,
        finding_options=findings,
        open_path_ids=open_path_ids,
    )
    grouped = group_routes_by_target(routes)
    reaches = bool(routes) or bool(templates) or bool(findings) or bool(techniques)
    if not identity.get("resolved") and not identity.get("sam") and not identity.get("bind_username"):
        headline = (
            "The assessment account could not be identified. Domain Admin paths below "
            "describe the domain, not the bind session."
        )
    elif not identity.get("resolved"):
        headline = (
            f"The bind account '{sam}' was not found in the collected inventory, so this "
            "session's reachability is unknown. Domain-wide paths may still be open."
        )
    elif not reaches:
        headline = (
            f"The bound account '{sam}' has no evidenced path to Domain Admin or Tier-0 "
            "in this graph. That is not proof the domain is clean; other identities may still "
            "have open takeover paths."
        )
    elif any(route.get("already_privileged") for route in routes):
        names = ", ".join(
            str(route.get("target_label") or "")
            for route in routes
            if route.get("already_privileged")
        )
        extra = len(routes) - 1
        headline = (
            f"The bound account '{sam}' is already a Tier-0 identity ({names or sam})."
            + (f" {extra} additional route(s) from this token are listed below." if extra > 0 else "")
        )
    elif routes:
        shortest = min(route["hop_count"] for route in routes)
        targets = len(grouped)
        headline = (
            f"The bound account '{sam}' can reach Tier-0 in {shortest} hop(s) "
            f"({len(routes)} distinct route(s) to {targets} privileged object(s) "
            f"within {MAX_DEPTH} hops)."
        )
    elif templates:
        names = ", ".join(item["template"] for item in templates[:5]) or "a published template"
        headline = (
            f"The bound account '{sam}' can enroll on confirmed ESC template(s): {names}."
        )
    elif findings:
        headline = (
            f"The bound account '{sam}' is a trustee or object on {len(findings)} "
            "Domain Admin-relevant finding option(s)."
        )
    else:
        headline = (
            f"The bound account '{sam}' can start {len(techniques)} Domain Admin "
            f"technique(s) that any authenticated session can begin."
        )
    return {
        "sam": sam,
        "sid": identity.get("sid"),
        "dn": identity.get("dn") or "",
        "resolved": bool(identity.get("resolved")),
        "token_status": (identity.get("token_groups") or {}).get("status") or "skipped",
        "source_node_count": len(source_ids),
        "reaches_tier0": bool(routes),
        "has_assessment_options": reaches,
        "takeover_tested": False,
        "route_count": len(routes),
        "target_count": len(grouped),
        "shortest_hops": min((route["hop_count"] for route in routes), default=None),
        "routes": routes,
        "routes_by_target": grouped,
        "enrollable_templates": templates,
        "finding_options": findings,
        "session_techniques": techniques,
        "option_count": len(routes) + len(templates) + len(findings) + len(techniques),
        "headline": headline,
        "limitation": (
            "Routes use collected membership, ACL, and control-plane edges up to "
            f"{MAX_DEPTH} hops and {MAX_ROUTES} paths. Conditional ACEs, sessions, "
            "and host logons are not modeled. Authenticated-session techniques "
            "(Kerberoasting, GPP, machine quota) are listed when those findings are open."
        ),
    }


def evidence_options(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group every matched finding by object so testers see each DA option."""
    buckets: dict[str, dict[str, Any]] = {}
    for risk in evidence:
        obj = str(
            risk.get("affected_object")
            or risk.get("sAMAccountName")
            or risk.get("name")
            or "unknown"
        ).strip() or "unknown"
        bucket = buckets.setdefault(
            obj,
            {
                "object": obj,
                "finding_count": 0,
                "types": [],
                "titles": [],
                "severities": [],
                "trustees": [],
            },
        )
        bucket["finding_count"] += 1
        risk_type = str(risk.get("type") or risk.get("risk_type") or "")
        title = str(risk.get("title") or risk_type)
        severity = str(risk.get("severity") or risk.get("severity_level") or "").lower()
        trustee = str(risk.get("trustee_name") or risk.get("trustee") or "").strip()
        if risk_type and risk_type not in bucket["types"]:
            bucket["types"].append(risk_type)
        if title and title not in bucket["titles"]:
            bucket["titles"].append(title)
        if severity and severity not in bucket["severities"]:
            bucket["severities"].append(severity)
        if trustee and trustee not in bucket["trustees"]:
            bucket["trustees"].append(trustee)
    rows = list(buckets.values())
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda item: (min((rank.get(s, 9) for s in item["severities"]), default=9), item["object"]))
    return rows


def _is_broad_starter_name(name: str) -> bool:
    folded = str(name or "").strip().casefold()
    return (not folded) or folded in BROAD_STARTER_NAMES or folded in {sid.casefold() for sid in BROAD_PRINCIPAL_SIDS}


def _permission_text(risk: dict[str, Any]) -> str:
    evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
    raw = (
        risk.get("permission")
        or evidence.get("permission")
        or evidence.get("rights")
        or evidence.get("permissions")
        or ""
    )
    if isinstance(raw, (list, tuple)):
        return ", ".join(str(item) for item in raw if item)
    return str(raw).strip()


def foothold_refs(risk: dict[str, Any]) -> list[dict[str, str]]:
    """Return attacker-side principals for a finding, not the victim object."""
    if not isinstance(risk, dict) or is_disproved(risk):
        return []
    refs: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(name: Any, sid: Any = "") -> None:
        label = as_text(name)
        sid_value = as_text(sid) or (label if label.upper().startswith("S-") else "")
        if sid_value in BROAD_PRINCIPAL_SIDS:
            return
        if _is_broad_starter_name(label) or _is_broad_starter_name(sid_value):
            return
        if is_tier0_group_record({"name": label, "objectSid": sid_value}) or label.casefold() in TIER0_EXTRA_LABELS:
            return
        key = (label.casefold(), sid_value)
        if (not label and not sid_value) or key in seen:
            return
        seen.add(key)
        refs.append({"name": label or sid_value, "sid": sid_value})

    add(risk.get("trustee_display_name") or risk.get("trustee_name"), risk.get("trustee") or risk.get("trustee_sid"))
    evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
    add(evidence.get("trustee") or evidence.get("trustee_name"), evidence.get("trustee_sid") or evidence.get("trustee"))
    for trustee in evidence.get("enrollment_trustees") or []:
        if isinstance(trustee, dict):
            add(trustee.get("name"), trustee.get("sid"))
    risk_type = str(risk.get("type") or risk.get("risk_type") or "").casefold()
    if any(risk_type.startswith(prefix) for prefix in USE_AFFECTED_AS_FOOTHOLD_PREFIXES):
        add(risk.get("affected_object") or risk.get("sAMAccountName"), evidence.get("trustee_sid"))
    path = evidence.get("path") or risk.get("path")
    if isinstance(path, list) and path:
        first = path[0]
        add(first.get("label") if isinstance(first, dict) else first)
    return refs


def route_reason(route: dict[str, Any]) -> str:
    """Explain one graph route in hop order."""
    hops = route.get("hops") or []
    target = str(route.get("target_label") or route.get("target") or "Tier-0")
    if not hops:
        return f"The account is already on {target}."
    chain = " ".join(
        f"{hop.get('from')} -[{hop.get('type') or 'Controls'}]-> {hop.get('to')}"
        for hop in hops
    )
    return (
        f"Evidence graph: {chain}. Reaches {target} in {int(route.get('hop_count') or 0)} hop(s)."
    )


def finding_reason(row: dict[str, Any], sam: str) -> str:
    """Explain why a named non-admin foothold is a Domain Admin option."""
    risk = row.get("risk") if isinstance(row.get("risk"), dict) else {}
    obj = str(risk.get("affected_object") or risk.get("name") or "object").strip()
    title = str(risk.get("title") or risk.get("type") or "").strip()
    perm = _permission_text(risk)
    pending = (
        " This finding still requires validation before it is treated as exploitable."
        if row.get("pending")
        else ""
    )
    perm_bit = f" ({perm})" if perm else ""
    why = str(row.get("why_da") or "").strip()
    return (
        f"{sam} is the evidenced foothold{perm_bit} on '{obj}' "
        f"[{risk.get('type') or row.get('technique_id')} — {title}]. {why}{pending}"
    ).strip()


def _evidence_row(risk: dict[str, Any], *, pending: bool) -> dict[str, Any]:
    evidence = risk.get("evidence") if isinstance(risk.get("evidence"), dict) else {}
    detail = str(risk.get("description") or risk.get("impact") or "").strip()
    return {
        "title": str(risk.get("title") or risk.get("type") or "").strip(),
        "type": str(risk.get("type") or risk.get("risk_type") or "").strip(),
        "object": str(risk.get("affected_object") or risk.get("name") or "").strip(),
        "permission": _permission_text(risk),
        "severity": str(risk.get("severity") or risk.get("severity_level") or "").lower(),
        "trustee": str(
            risk.get("trustee_display_name")
            or risk.get("trustee_name")
            or risk.get("trustee")
            or evidence.get("trustee_sid")
            or ""
        ).strip(),
        "confirmed": not pending,
        "detail": detail[:400],
    }


def _node_index(graph: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, str]]:
    nodes = {
        str(node["id"]): node
        for node in graph.get("nodes") or []
        if isinstance(node, dict) and node.get("id")
    }
    by_sid: dict[str, str] = {}
    by_label: dict[str, str] = {}
    for node_id, node in nodes.items():
        sid = str(node.get("sid") or "")
        label = str(node.get("label") or "").casefold()
        if sid:
            by_sid[sid] = node_id
        if label:
            by_label[label] = node_id
    return nodes, by_sid, by_label


def _lookup_or_synthesize(
    name: str,
    sid: str,
    nodes: dict[str, dict[str, Any]],
    by_sid: dict[str, str],
    by_label: dict[str, str],
) -> dict[str, Any] | None:
    node_id = (sid and by_sid.get(sid)) or by_label.get(name.casefold())
    if node_id:
        return nodes[node_id]
    if not name and not sid:
        return None
    synthetic_id = f"principal:{(sid or name).casefold()}"
    return {
        "id": synthetic_id,
        "label": name or sid,
        "sid": sid or None,
        "kind": "principal",
        "privileged": False,
        "synthetic": True,
    }


def _tier0_distances(graph: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Return hop distance from each node to the nearest Tier-0 node (reverse BFS)."""
    reverse: dict[str, set[str]] = defaultdict(set)
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        if str(edge.get("type") or "") in SKIP_EDGE_TYPES:
            continue
        source, target = str(edge.get("source") or ""), str(edge.get("target") or "")
        if source and target:
            reverse[target].add(source)
    targets = {node_id for node_id, node in nodes.items() if is_tier0_node(node)}
    distance: dict[str, int] = {node_id: 0 for node_id in targets}
    queue = list(targets)
    index = 0
    while index < len(queue):
        current = queue[index]
        index += 1
        if distance[current] >= MAX_DEPTH:
            continue
        for parent in sorted(reverse.get(current, ())):
            if parent in distance:
                continue
            distance[parent] = distance[current] + 1
            queue.append(parent)
    return distance


def _is_starter_node(node: dict[str, Any]) -> bool:
    if is_tier0_node(node):
        return False
    if _is_broad_starter_name(str(node.get("label") or "")):
        return False
    kind = str(node.get("kind") or "principal").casefold()
    if kind in STARTER_KINDS:
        return True
    # Non-privileged groups that hold a control edge are footholds testers abuse.
    return kind == "group"


def build_nonadmin_starter_view(
    graph: dict[str, Any] | None,
    technique_rows: list[dict[str, Any]] | None = None,
    *,
    max_principals: int = MAX_STARTERS,
) -> dict[str, Any]:
    """List non-admin principals that can reach Domain Admin, with reasons and evidence."""
    graph = graph or {}
    technique_rows = list(technique_rows or [])
    nodes, by_sid, by_label = _node_index(graph)
    buckets: dict[str, dict[str, Any]] = {}

    def bucket_for(node: dict[str, Any]) -> dict[str, Any] | None:
        if not _is_starter_node(node):
            return None
        node_id = str(node["id"])
        return buckets.setdefault(
            node_id,
            {
                "id": node_id,
                "sam": str(node.get("label") or node_id),
                "sid": node.get("sid"),
                "kind": str(node.get("kind") or "principal"),
                "synthetic": bool(node.get("synthetic")),
                "shortest_hops": None,
                "routes": [],
                "techniques": [],
                "_technique_ids": set(),
                "_evidence_keys": set(),
            },
        )

    distances = _tier0_distances(graph, nodes)
    graph_candidates = sorted(
        (
            (dist, node_id)
            for node_id, dist in distances.items()
            if dist > 0
            and node_id in nodes
            and _is_starter_node(nodes[node_id])
            and str(nodes[node_id].get("kind") or "") in STARTER_KINDS
        ),
        key=lambda item: (item[0], item[1]),
    )
    for _dist, node_id in graph_candidates[: max_principals * 2]:
        node = nodes[node_id]
        routes = [
            route
            for route in enumerate_tier0_routes(graph, [node_id], max_routes=MAX_STARTER_ROUTES)
            if int(route.get("hop_count") or 0) > 0
        ]
        if not routes:
            continue
        bucket = bucket_for(node)
        if not bucket:
            continue
        bucket["routes"] = routes[:MAX_STARTER_ROUTES]
        bucket["shortest_hops"] = min(int(route["hop_count"]) for route in routes)
        if "tier0_graph" not in bucket["_technique_ids"]:
            bucket["_technique_ids"].add("tier0_graph")
            reasons = [route_reason(route) for route in routes[:4]]
            evidence = [
                {
                    "title": " → ".join(route.get("labels") or []),
                    "type": "attack_graph_tier0_path",
                    "object": route.get("target_label") or "",
                    "permission": ", ".join(
                        str(hop.get("type") or "") for hop in (route.get("hops") or []) if hop.get("type")
                    ),
                    "severity": "critical" if int(route.get("hop_count") or 9) <= 2 else "high",
                    "trustee": bucket["sam"],
                    "confirmed": True,
                    "detail": route_reason(route),
                }
                for route in routes[:MAX_STARTER_EVIDENCE]
            ]
            bucket["techniques"].append(
                {
                    "id": "tier0_graph",
                    "name": "Evidence-graph path into Tier-0 / Domain Admins",
                    "category": "attack_path",
                    "da_equivalent": True,
                    "pending": False,
                    "reason": " ".join(reasons),
                    "evidence": evidence,
                    "evidence_count": len(evidence),
                }
            )

    for row in technique_rows:
        risk = row.get("risk") if isinstance(row.get("risk"), dict) else {}
        if not risk:
            continue
        for ref in foothold_refs(risk):
            node = _lookup_or_synthesize(ref["name"], ref["sid"], nodes, by_sid, by_label)
            if not node:
                continue
            bucket = bucket_for(node)
            if not bucket:
                continue
            evidence_item = _evidence_row(risk, pending=bool(row.get("pending")))
            evidence_key = (evidence_item["type"], evidence_item["object"], evidence_item["title"])
            technique_id = str(row.get("technique_id") or "")
            existing = next((item for item in bucket["techniques"] if item.get("id") == technique_id), None)
            if existing is None:
                existing = {
                    "id": technique_id,
                    "name": str(row.get("technique_name") or technique_id),
                    "category": str(row.get("category") or ""),
                    "da_equivalent": bool(row.get("da_equivalent")),
                    "pending": bool(row.get("pending")),
                    "reason": finding_reason(row, bucket["sam"]),
                    "evidence": [],
                    "evidence_count": 0,
                }
                bucket["techniques"].append(existing)
                bucket["_technique_ids"].add(technique_id)
            if evidence_key not in bucket["_evidence_keys"] and len(existing["evidence"]) < MAX_STARTER_EVIDENCE:
                bucket["_evidence_keys"].add(evidence_key)
                existing["evidence"].append(evidence_item)
                existing["evidence_count"] = len(existing["evidence"])
            if row.get("pending"):
                existing["pending"] = True
            if not bucket["routes"] and not node.get("synthetic"):
                routes = [
                    route
                    for route in enumerate_tier0_routes(graph, [str(node["id"])], max_routes=MAX_STARTER_ROUTES)
                    if int(route.get("hop_count") or 0) > 0
                ]
                if routes:
                    bucket["routes"] = routes[:MAX_STARTER_ROUTES]
                    bucket["shortest_hops"] = min(int(route["hop_count"]) for route in routes)

    principals: list[dict[str, Any]] = []
    for bucket in buckets.values():
        if not bucket["techniques"] and not bucket["routes"]:
            continue
        hops = bucket["shortest_hops"]
        confirmed = sum(
            1 for item in bucket["techniques"] if not item.get("pending") and item.get("evidence")
        )
        principals.append(
            {
                "id": bucket["id"],
                "sam": bucket["sam"],
                "sid": bucket["sid"],
                "kind": bucket["kind"],
                "synthetic": bucket["synthetic"],
                "shortest_hops": hops,
                "route_count": len(bucket["routes"]),
                "routes": bucket["routes"],
                "technique_count": len(bucket["techniques"]),
                "techniques": bucket["techniques"],
                "confirmed_technique_count": confirmed,
                "evidence_count": sum(int(item.get("evidence_count") or 0) for item in bucket["techniques"]),
            }
        )
    principals.sort(
        key=lambda item: (
            99 if item.get("shortest_hops") is None else item["shortest_hops"],
            -int(item.get("confirmed_technique_count") or 0),
            -int(item.get("evidence_count") or 0),
            str(item.get("sam") or ""),
        )
    )
    truncated = len(principals) > max_principals
    principals = principals[:max_principals]
    hop_values = [item["shortest_hops"] for item in principals if item.get("shortest_hops") is not None]
    if not principals:
        headline = (
            "No named non-admin account currently has an evidenced Domain Admin foothold. "
            "Domain-wide techniques that any authenticated user can start are still listed in the catalog."
        )
    else:
        shortest = min(hop_values) if hop_values else None
        hop_bit = f" Shortest evidenced graph route: {shortest} hop(s)." if shortest is not None else ""
        headline = (
            f"{len(principals)} non-admin account(s) have an evidenced path or foothold "
            f"toward Domain Admin / Tier-0 ({sum(item['technique_count'] for item in principals)} "
            f"technique option(s), {sum(item['evidence_count'] for item in principals)} evidence row(s))."
            f"{hop_bit}"
        )
    return {
        "headline": headline,
        "principal_count": len(principals),
        "technique_option_count": sum(item["technique_count"] for item in principals),
        "evidence_count": sum(item["evidence_count"] for item in principals),
        "shortest_hops": min(hop_values) if hop_values else None,
        "truncated": truncated,
        "principals": principals,
        "limitation": (
            "Only named non-admin users, computers, and non-privileged groups are listed. "
            "Already-privileged identities and broad principals (Everyone, Authenticated Users, "
            "Domain Users) are excluded so the list stays actionable. Graph routes are bounded "
            f"to {MAX_DEPTH} hops. Confirmed findings are preferred; pending rows stay labelled."
        ),
    }
