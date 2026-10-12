"""Attach fresh endpoint relationships while keeping session paths conditional."""

from __future__ import annotations

from copy import deepcopy

from core.ad_security import as_text, sid_text


def attach_endpoint_graph(graph, data, observations):
    nodes = {node['id']: deepcopy(node) for node in graph.get('nodes', [])}
    aliases = {}
    for node in nodes.values():
        for value in (node['id'], node.get('sid'), node.get('label'), node.get('dn')):
            if value:
                aliases.setdefault(str(value).casefold(), set()).add(node['id'])
    for account in [*data.get('users', []), *data.get('computers', []), *data.get('groups', [])]:
        ids = aliases.get((sid_text(account.get('objectSid')) or '').casefold(), set()) or aliases.get(
            as_text(account.get('sAMAccountName') or account.get('name')).casefold(), set())
        if len(ids) == 1:
            for value in (account.get('dNSHostName'), account.get('distinguishedName'), account.get('name')):
                if value:
                    aliases.setdefault(as_text(value).casefold(), set()).update(ids)

    def resolve(value):
        found = aliases.get(str(value or '').casefold(), set())
        return next(iter(found)) if len(found) == 1 else None

    edges, gaps = [], []
    relations = {'local_administrator': 'AdminTo', 'privileged_session': 'HasSession',
                 'management_connection': 'CanPSRemote', 'controls_identity_asset': 'Controls'}
    for row in observations:
        if row.get('name') not in relations:
            continue
        value = row.get('value')
        if row.get('status') != 'available' or not isinstance(value, dict):
            gaps.append({'target': row.get('target'), 'reason': row.get('reason') or 'Endpoint relationship is unavailable'})
            continue
        if row['name'] == 'controls_identity_asset':
            source, target = resolve(row['target']), resolve(value.get('controlled_target'))
        else:
            source, target = resolve(value.get('principal_sid')), resolve(row['target'])
            if row['name'] == 'privileged_session':
                source, target = target, source
        if source is None or target is None:
            gaps.append({'target': row['target'], 'reason': 'Relationship identities are absent or ambiguous in directory inventory'})
            continue
        conditional = row['name'] in ('privileged_session', 'management_connection')
        edges.append({'source': source, 'target': target, 'type': relations[row['name']],
                      'properties': {'status': 'conditional' if conditional else 'observed',
                                     'requires_validation': conditional,
                                     'prerequisites': ['Verify effective endpoint access and credential protection'] if conditional else [],
                                     'provenance': {'fresh': True, **{key: row.get(key) for key in ('source', 'target', 'domain', 'collected_at')}}}})
    return {'nodes': list(nodes.values()), 'edges': edges, 'gaps': gaps,
            'limitation': 'A session observation does not prove credential theft. Missing or ambiguous identities are excluded; relationship freshness is checked before import.'}
