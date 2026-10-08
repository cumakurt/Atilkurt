"""Bounded BloodHound inputs and provenance-preserving federated graphs."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import zipfile

from core.exceptions import ValidationError

MAX_BYTES = 32 * 1024 * 1024
MAX_OBJECTS = 100000
RELATIONS = {"LocalAdmins": "AdminTo", "RemoteDesktopUsers": "CanRDP", "DcomUsers": "ExecuteDCOM",
             "PSRemoteUsers": "CanPSRemote"}


def _identifier(domain, kind, identifier):
    return f"{domain.casefold().strip('.')}::{kind.casefold()}:{str(identifier).casefold()}"


def _documents(path):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise ValidationError("Graph input exceeds the compressed/file size limit")
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                if len(entries) > 100 or sum(entry.file_size for entry in entries) > MAX_BYTES:
                    raise ValidationError("Graph archive exceeds member/uncompressed limits")
                for entry in entries:
                    if entry.is_dir():
                        continue
                    if not entry.filename.lower().endswith('.json'):
                        continue
                    with archive.open(entry) as stream:
                        raw = stream.read(MAX_BYTES + 1)
                    if len(raw) > MAX_BYTES:
                        raise ValidationError("Graph archive member exceeds the size limit")
                    yield entry.filename, json.loads(raw)
        else:
            yield path.name, json.loads(path.read_bytes())
    except (ValueError, UnicodeError, zipfile.BadZipFile, RuntimeError, RecursionError) as exc:
        raise ValidationError("Invalid JSON/BloodHound graph input") from exc


def import_bloodhound(paths, *, now=None):
    now = now or datetime.now(timezone.utc)
    nodes, edges, sources = {}, [], []
    count = 0
    for path in paths:
        for member, document in _documents(path):
            if not isinstance(document, dict) or not isinstance(document.get('meta'), dict) or not isinstance(document.get('data'), list):
                raise ValidationError("BloodHound document requires meta and data")
            meta, data = document['meta'], document['data']
            kind = str(meta.get('type', '')).casefold()
            if kind not in {'users', 'groups', 'computers', 'domains'}:
                sources.append({'source': str(path), 'member': member, 'status': 'unsupported_type', 'type': kind})
                continue
            if 'count' in meta and meta['count'] != len(data):
                raise ValidationError("BloodHound metadata count does not match data")
            version = meta.get('version')
            if not isinstance(version, int) or isinstance(version, bool) or not 3 <= version <= 6:
                raise ValidationError("Supported BloodHound JSON schema versions are 3 through 6")
            observed = meta.get('collected_at') or document.get('collected_at')
            fresh = False
            if observed:
                try:
                    stamp = datetime.fromisoformat(str(observed).replace('Z', '+00:00'))
                    fresh = stamp.tzinfo is not None and now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5)
                except ValueError:
                    raise ValidationError("BloodHound collection timestamp is invalid") from None
            provenance = {'source': str(path), 'member': member, 'collector': 'SharpHound/BloodHound',
                          'schema_version': version, 'collected_at': observed, 'fresh': fresh}
            sources.append(provenance)
            for row in data:
                count += 1
                if count > MAX_OBJECTS or not isinstance(row, dict) or not isinstance(row.get('Properties'), dict):
                    raise ValidationError("BloodHound data is invalid or exceeds object limits")
                props = row['Properties']
                domain = str(props.get('domain') or '').casefold().strip('.')
                identifier = row.get('ObjectIdentifier')
                if not domain or not isinstance(identifier, str) or not identifier:
                    raise ValidationError("BloodHound objects require domain and ObjectIdentifier")
                singular = kind[:-1]
                node_id = _identifier(domain, singular, identifier)
                nodes[node_id] = {'id': node_id, 'kind': singular, 'label': props.get('name') or identifier,
                                  'domain': domain, 'sid': identifier, 'provenance': provenance,
                                  'properties': {'distinguishedName': props.get('distinguishedname')}}

                def add(principal, relationship, *, reverse=False, collected=True, domain=domain, node_id=node_id,
                        provenance=provenance, fresh=fresh):
                    if len(edges) >= MAX_OBJECTS * 5 or not isinstance(principal, dict):
                        raise ValidationError("BloodHound relationship limits exceeded or malformed relationship")
                    sid = principal.get('ObjectIdentifier') or principal.get('UserSID')
                    p_kind = str(principal.get('ObjectType') or 'user').casefold()
                    if not isinstance(sid, str) or not sid or p_kind not in {'user', 'group', 'computer', 'domain'}:
                        raise ValidationError("BloodHound relationship requires a supported principal identifier")
                    target = _identifier(domain, p_kind, sid)
                    if sid.startswith('S-1-5-32-'):
                        target = node_id + '::local:' + sid.casefold()
                    nodes.setdefault(target, {'id': target, 'kind': p_kind, 'label': sid, 'domain': domain, 'sid': sid,
                                              'reference_only': True, 'provenance': provenance})
                    source, destination = (node_id, target) if reverse else (target, node_id)
                    edges.append({'source': source, 'target': destination, 'type': relationship,
                                  'properties': {'status': 'observed' if fresh and collected else 'conditional',
                                                 'prerequisites': ([] if relationship in {'AdminTo', 'MemberOf'} else ['Service availability and effective access require verification'])
                                                 + ([] if collected else ['Collector result was unavailable or failed']),
                                                 'provenance': provenance}})

                if kind == 'groups':
                    members = row.get('Members', [])
                    if not isinstance(members, list):
                        raise ValidationError("BloodHound Members must be a list")
                    for member_row in members:
                        add(member_row, 'MemberOf')
                if kind == 'computers':
                    for field, relationship in RELATIONS.items():
                        collection = row.get(field) or {}
                        if version <= 4 and isinstance(collection, list):
                            collection = {'Results': collection}
                        if not isinstance(collection, dict) or not isinstance(collection.get('Results', []), list):
                            raise ValidationError("BloodHound local group results are invalid")
                        for principal in collection.get('Results', []):
                            add(principal, relationship, collected=collection.get('Collected') is not False and not collection.get('FailureReason'))
                    local_groups = row.get('LocalGroups', [])
                    if not isinstance(local_groups, list):
                        raise ValidationError('BloodHound LocalGroups must be a list')
                    for collection in local_groups:
                        if not isinstance(collection, dict) or not isinstance(collection.get('Results', []), list):
                            raise ValidationError('BloodHound LocalGroups results are malformed')
                        rid = str(collection.get('ObjectIdentifier') or '').split('-')[-1]
                        relationship = {'544': 'AdminTo', '555': 'CanRDP', '562': 'ExecuteDCOM', '580': 'CanPSRemote'}.get(rid)
                        if relationship:
                            for principal in collection.get('Results', []):
                                add(principal, relationship, collected=collection.get('Collected') is not False and not collection.get('FailureReason'))
                    sessions = row.get('Sessions') or {}
                    if version <= 4 and isinstance(sessions, list):
                        sessions = {'Results': sessions}
                    if not isinstance(sessions, dict) or not isinstance(sessions.get('Results', []), list):
                        raise ValidationError("BloodHound session results are invalid")
                    for principal in sessions.get('Results', []):
                        if principal.get('ComputerSID') and principal['ComputerSID'] != identifier:
                            raise ValidationError('BloodHound session belongs to another computer')
                        add(principal, 'HasSession', reverse=True, collected=sessions.get('Collected') is not False and not sessions.get('FailureReason'))
    return {'schema_version': '2.0', 'nodes': list(nodes.values()), 'edges': _deduplicate_edges(edges), 'sources': sources}


def _deduplicate_edges(edges):
    output = {}
    for edge in edges:
        edge = deepcopy(edge)
        identity = json.dumps([edge['source'], edge['target'], edge['type'], edge.get('properties', {})], sort_keys=True, default=str)
        edge['id'] = hashlib.sha256(identity.encode()).hexdigest()[:24]
        output[edge['id']] = edge
    return list(output.values())


def federate_graphs(assessments):
    """Namespace snapshots and resolve references only against unique full SIDs."""
    nodes, edges, sources, conflicts = {}, [], [], []
    sid_index = {}
    for domain, graph, provenance in assessments:
        domain = str(domain).casefold().strip('.')
        if not domain or not isinstance(graph, dict):
            raise ValidationError("Federated graph requires an explicit domain and graph")
        if len(nodes) + len(graph.get('nodes', [])) > MAX_OBJECTS:
            raise ValidationError("Federated graph exceeds node limits")
        mapping = {}
        for node in graph.get('nodes', []):
            old_id = node.get('id')
            if not isinstance(old_id, str):
                raise ValidationError("Graph nodes require string IDs")
            node_domain = str(node.get('domain') or domain).casefold().strip('.')
            domain_reference = node.get('kind') == 'trusted_domain'
            if domain_reference and isinstance(node.get('label'), str) and '.' in node['label'] and '=' not in node['label']:
                node_domain = node['label'].casefold().strip('.')
            sid = node.get('sid') or (node.get('properties') or {}).get('objectSid')
            new_id = old_id if '::' in old_id else node_domain + '::' + old_id
            if isinstance(sid, str) and sid.startswith('S-1-5-21-'):
                new_id = node_domain + '::sid:' + sid.casefold()
            elif node.get('kind') in {'domain', 'trusted_domain'}:
                new_id = node_domain + '::domain'
            mapping[old_id] = new_id
            normalized = {**deepcopy(node), 'id': new_id, 'domain': node_domain, 'snapshot_provenance': provenance}
            if domain_reference:
                normalized.update(kind='domain', reference_only=True)
            normalized['aliases'] = [old_id, node_domain + '::' + old_id]
            if new_id in nodes:
                existing = nodes[new_id]
                if existing.get('kind') != normalized.get('kind'):
                    conflicts.append({'node_id': new_id, 'reason': 'Conflicting identity kinds for one SID'})
                if existing.get('reference_only') and not normalized.get('reference_only'):
                    normalized['aliases'] += existing.get('aliases', [])
                    nodes[new_id] = normalized
                else:
                    existing.setdefault('aliases', []).extend(normalized['aliases'])
            else:
                nodes[new_id] = normalized
            if isinstance(sid, str) and sid.startswith('S-1-5-21-') and not node.get('reference_only'):
                sid_index.setdefault(sid.casefold(), set()).add(new_id)
        for edge in graph.get('edges', []):
            if len(edges) >= MAX_OBJECTS * 5:
                raise ValidationError("Federated graph exceeds edge limits")
            if edge.get('source') not in mapping or edge.get('target') not in mapping:
                conflicts.append({'reason': 'Edge endpoint missing from snapshot', 'edge_id': edge.get('id')})
                continue
            edges.append({**deepcopy(edge), 'source': mapping[edge['source']], 'target': mapping[edge['target']],
                          'snapshot_provenance': provenance})
        sources.append({'domain': domain, **provenance})
    references = {}
    for identifier, node in nodes.items():
        sid = node.get('sid') or (node.get('properties') or {}).get('objectSid')
        matches = sid_index.get(str(sid).casefold(), set())
        if node.get('reference_only') and len(matches) == 1:
            references[identifier] = next(iter(matches))
        elif node.get('reference_only') and len(matches) > 1:
            conflicts.append({'node_id': identifier, 'reason': 'SID resolves to conflicting domains/identities'})
    for edge in edges:
        edge['source'] = references.get(edge['source'], edge['source'])
        edge['target'] = references.get(edge['target'], edge['target'])
        if any(conflict.get('node_id') in (edge['source'], edge['target']) for conflict in conflicts):
            edge.setdefault('properties', {})['status'] = 'conditional'
            edge['properties'].setdefault('prerequisites', []).append('Resolve conflicting identity evidence')
    return {'schema_version': '2.0', 'nodes': list(nodes.values()), 'edges': _deduplicate_edges(edges),
            'sources': sources, 'conflicts': conflicts, 'resolved_references': references,
            'limitation': 'Trust and session edges express relationships; they do not establish takeover.'}
