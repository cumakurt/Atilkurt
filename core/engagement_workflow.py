"""Compose opt-in pentest capabilities with existing assessment workflows."""

from __future__ import annotations

from pathlib import Path
from copy import deepcopy

from core.assessment_scope import AssessmentScope
from core.evidence_signing import read_json, write_document
from core.exceptions import ValidationError
from core.product_workflow import load_workflow_document


def prepare_engagement_inputs(args):
    documents = {}
    documents['security_evidence'] = [load_workflow_document(path, args) for path in getattr(args, 'security_evidence', [])]
    if getattr(args, 'require_signed_evidence', False):
        for path in getattr(args, 'posture_file', []):
            load_workflow_document(path, args)
        if getattr(args, 'posture_file', []):
            from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer
            PostureEvidenceAnalyzer().analyze(args.posture_file, domain=args.domain,
                                               require_signed=True, trusted_keys=args.trusted_key,
                                               max_age_days=getattr(args, 'evidence_max_age_days', 30))
    if documents['security_evidence']:
        from analysis.security_controls_analyzer import analyze_security_controls
        analyze_security_controls(documents['security_evidence'], args.domain,
                                  max_age_days=getattr(args, 'evidence_max_age_days', 30))
    for field in ('protocol_evidence', 'gpo_context'):
        path = getattr(args, field, None)
        if path:
            documents[field] = load_workflow_document(path, args)
    scope_path = getattr(args, 'scope_file', None)
    scope_document = read_json(scope_path) if scope_path else None
    args._assessment_scope = AssessmentScope(args.domain, scope_document,
                                             max_queries=getattr(args, 'max_queries', None),
                                             max_seconds=getattr(args, 'max_scan_seconds', None))
    if documents.get('protocol_evidence'):
        from core.protocol_checks import verify_protocols
        verify_protocols([], [], args._assessment_scope, local_evidence=documents['protocol_evidence'])
    from core.graph_import import import_bloodhound, validate_graph
    imports = getattr(args, 'bloodhound_import', [])
    if imports:
        if getattr(args, 'require_signed_evidence', False):
            raise ValidationError('Raw BloodHound files are unsigned; import a signed AtilKurt graph snapshot under signed-evidence policy')
        documents['bloodhound'] = import_bloodhound(imports)
    federation = []
    for path in getattr(args, 'federation_snapshot', []):
        document = load_workflow_document(path, args)
        graph = document.get('federated_graph') or document.get('attack_graph_v2')
        if not isinstance(graph, dict) or not document.get('domain'):
            raise ValidationError('Federation inputs require domain and an exported graph')
        validate_graph(graph)
        context = document.get('scan_context') or {}
        from datetime import datetime, timedelta, timezone
        try:
            stamp = datetime.fromisoformat(str(context.get('collected_at')).replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            fresh = stamp.tzinfo is not None and now - timedelta(days=30) <= stamp <= now + timedelta(minutes=5)
        except ValueError:
            fresh = False
        federation.append((document['domain'], graph, {'source': str(path), 'collected_at': context.get('collected_at'),
                                                     'fresh': fresh, 'scope': document.get('engagement_scope')}))
    documents['federation'] = federation
    if getattr(args, 'rsop_file', None):
        from analysis.effective_gpo_analyzer import parse_rsop
        documents['rsop'] = parse_rsop(args.rsop_file)
        if getattr(args, 'require_signed_evidence', False) and (documents.get('gpo_context') or {}).get('rsop_sha256') != documents['rsop']['sha256']:
            raise ValidationError('Signed-evidence policy requires the RSoP digest in the signed GPO context')
    if documents.get('gpo_context'):
        if getattr(args, 'gpo_policy_file', []):
            from core.gpo_policy_content import attach_policy_content
            documents['gpo_context'] = attach_policy_content(documents['gpo_context'], args.gpo_policy_file,
                                                           require_signed=getattr(args, 'require_signed_evidence', False))
        from analysis.effective_gpo_analyzer import analyze_effective_gpo
        analyze_effective_gpo(documents['gpo_context'], documents.get('rsop'))
    args._engagement_documents = documents
    # Fail before credentials/transport for an excluded DC or explicit service target.
    if not getattr(args, 'offline_snapshot', None):
        args._assessment_scope.check_host(args.dc_ip, 'ldaps' if args.ssl else 'ldap')
    for field, service in (('protocol_target', 'smb'), ('sysvol_host', 'smb')):
        for host in getattr(args, field, []):
            args._assessment_scope.check_host(host, service)
    from urllib.parse import urlsplit
    for endpoint in getattr(args, 'adcs_endpoint', []):
        args._assessment_scope.check_host(urlsplit(endpoint).hostname, 'adcs_http')
    return documents


def apply_engagement(args, data, analysis):
    if not hasattr(args, '_assessment_scope'):
        return
    scope = args._assessment_scope
    documents = getattr(args, '_engagement_documents', {})
    ldap = getattr(args, '_active_ldap', None)
    engagement = deepcopy(analysis.get('engagement') or {})
    if documents.get('security_evidence') or analysis.get('security_control_observations') or analysis.get('security_control_targets') or (data.get('computers') and not engagement.get('security_controls')):
        from analysis.security_controls_analyzer import analyze_security_controls, reconcile_hybrid_findings
        from analysis.tier_analyzer import TierAnalyzer
        from core.ad_identity import computer_is_domain_controller
        from core.ad_security import as_text
        targets = [as_text(row.get('dNSHostName') or row.get('name')) for row in data.get('computers', []) if computer_is_domain_controller(row)]
        inputs = documents.get('security_evidence') or []
        if not inputs and (analysis.get('security_control_observations') or analysis.get('security_control_targets')):
            inputs = [{'schema_version': 1, 'domain': args.domain,
                       'observations': analysis.get('security_control_observations') or [],
                       'targets': analysis.get('security_control_targets') or []}]
        result = analyze_security_controls(inputs, args.domain,
                                           max_age_days=getattr(args, 'evidence_max_age_days', 30), expected_targets=targets)
        engagement['security_controls'] = {key: value for key, value in result.items() if key not in ('risks', 'observations')}
        from analysis.security_controls_analyzer import refresh_security_findings
        analysis['security_control_risks'] = refresh_security_findings(analysis.get('security_control_risks') or [], result)
        analysis['security_control_observations'] = result['observations']
        analysis['security_control_targets'] = result['targets']
        reconcile_hybrid_findings(analysis.get('hybrid_identity_v2_risks', []), result['observations'])
        analysis['tier_data'] = TierAnalyzer().analyze_tiers(data.get('users', []), data.get('computers', []), data.get('groups', []), result['observations'])
        from core.endpoint_graph import attach_endpoint_graph
        endpoint_graph = attach_endpoint_graph(analysis.get('attack_graph_v2') or {}, data, result['observations'])
        if endpoint_graph['edges'] or endpoint_graph['gaps']:
            engagement['endpoint_graph'] = endpoint_graph
        else:
            engagement.pop('endpoint_graph', None)
    if getattr(args, 'protocol_target', []) or getattr(args, 'adcs_endpoint', []) or documents.get('protocol_evidence'):
        from core.protocol_checks import verify_protocols
        protocols = verify_protocols(getattr(args, 'protocol_target', []), getattr(args, 'adcs_endpoint', []), scope,
                                     timeout=min(args.timeout, 30), local_evidence=documents.get('protocol_evidence'))
        engagement['protocols'] = protocols
        analysis['protocol_verification_risks'] = protocols['risks']
    shared = []
    if getattr(args, 'sysvol_dir', []):
        from analysis.sysvol_analyzer import inspect_local_shared_files
        shared.append(inspect_local_shared_files(args.sysvol_dir))
    if getattr(args, 'sysvol_host', []):
        from analysis.sysvol_analyzer import inspect_remote_shared_files
        if ldap is None:
            raise ValidationError('Remote shared-file inspection requires a live authenticated assessment')
        if getattr(ldap, 'auth_method', 'ntlm') == 'kerberos':
            raise ValidationError('Kerberos LDAP credentials cannot be reused for password-based SYSVOL inspection; use offline shared files')
        for host in args.sysvol_host:
            shared.append(inspect_remote_shared_files(host, ldap.username, ldap.password, args.domain, scope,
                                                      timeout=min(args.timeout, 30)))
    if shared:
        engagement['shared_files'] = shared
        analysis['shared_file_risks'] = [risk for result in shared for risk in result['risks']]
    context = documents.get('gpo_context')
    if getattr(args, 'gpo_target', []):
        if ldap is None:
            raise ValidationError('Live GPO target collection requires a connected directory')
        from analysis.effective_gpo_analyzer import collect_gpo_context
        context = collect_gpo_context(ldap, args.gpo_target, data.get('gpos', []))
    if context:
        from analysis.effective_gpo_analyzer import analyze_effective_gpo
        engagement['effective_gpo'] = analyze_effective_gpo(context, documents.get('rsop'))
    elif documents.get('rsop'):
        raise ValidationError('RSoP requires --gpo-context with explicit host/user target binding')
    analysis['engagement'] = engagement
    refresh_engagement_graph(args, data, analysis)


def refresh_engagement_graph(args, data, analysis):
    """Rebuild plans from the final reviewed graph without repeating network checks."""
    if not hasattr(args, '_assessment_scope'):
        return
    scope = args._assessment_scope
    documents = getattr(args, '_engagement_documents', {})
    engagement = analysis.setdefault('engagement', {})
    local = analysis.get('attack_graph_v2') or {'nodes': [], 'edges': []}
    context = data.get('scan_context') or {}
    provenance = {'source': 'current_assessment', 'collected_at': context.get('collected_at'),
                  'fresh': context.get('fresh_ldap') is True, 'scope': scope.snapshot()}
    inputs = [(args.domain, local, provenance)] + documents.get('federation', [])
    if engagement.get('endpoint_graph'):
        inputs.append((args.domain, engagement['endpoint_graph'], {'source': 'validated_endpoint_evidence', 'fresh': True}))
    saved = getattr(args, '_saved_federated_graph', None)
    if saved and not documents.get('federation') and not documents.get('bloodhound'):
        supplemental = {**saved, 'edges': [edge for edge in saved.get('edges', [])
                        if (edge.get('snapshot_provenance') or {}).get('source') not in
                        {'current_assessment', 'validated_endpoint_evidence'}]}
        inputs.append((args.domain, supplemental, {'source': 'saved_federation', 'fresh': False}))
    if documents.get('bloodhound'):
        graph = documents['bloodhound']
        inputs.append((args.domain, graph, {'source': 'bloodhound_import', 'fresh': all(row.get('fresh') for row in graph['sources'])}))
        engagement['bloodhound'] = {'sources': graph['sources'], 'nodes': len(graph['nodes']), 'edges': len(graph['edges'])}
    if saved or documents.get('federation') or documents.get('bloodhound') or engagement.get('endpoint_graph') or getattr(args, 'plan_start', None):
        from core.graph_import import federate_graphs
        graph = federate_graphs(inputs)
        analysis['federated_graph'] = graph
        engagement['federation'] = {'sources': graph['sources'], 'conflicts': graph['conflicts'],
                                    'resolved_references': graph['resolved_references'], 'nodes': len(graph['nodes']), 'edges': len(graph['edges'])}
        if getattr(args, 'plan_start', None):
            from analysis.attack_path_planner import plan_attack_paths
            engagement['attack_plan'] = plan_attack_paths(graph, args.plan_start, args.plan_goal, max_hops=args.plan_max_hops)
    if not getattr(args, 'offline_snapshot', None) or getattr(args, 'scope_file', None) or not data.get('engagement_scope'):
        data['engagement_scope'] = scope.snapshot()
    analysis['engagement'] = engagement


def export_engagement(args, workspace, data, risks):
    if getattr(args, 'engagement_export', None):
        write_document(args.engagement_export, {'schema_version': 1, 'domain': args.domain,
                                               'scope': data.get('engagement_scope'), **workspace.get('engagement', {})},
                       getattr(args, 'signing_key', None))
    for field in ('docx_export', 'pdf_export'):
        path = getattr(args, field, None)
        if path:
            from reporting.client_report import client_document, export_client_report
            export_client_report(path, client_document(args.domain, data, risks, workspace,
                                                       masked=getattr(args, 'mask_client_report', False)), language=args.language)
            print(f'[+] Client report saved: {Path(path)}')
