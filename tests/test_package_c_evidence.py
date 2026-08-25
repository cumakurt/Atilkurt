"""Tests for Package C delta, telemetry, posture, and confidence features."""

from __future__ import annotations

import json

from AtilKurt import build_parser, validate_cli_arguments
from analysis.baseline_comparator import BaselineComparator
from analysis.confidence_scorer import ConfidenceScorer
from analysis.event_correlation_analyzer import EventCorrelationAnalyzer
from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer
from analysis.registry import CONSOLIDATION_RISK_KEYS, build_export_analysis_slice
from reporting.export_formats import ExportFormats
from reporting.localization import localize_finding_list


def _event(event_id: int, **fields):
    return {
        "EventID": event_id,
        "timestamp": "2026-08-25T09:10:00+00:00",
        "EventData": fields,
    }


def test_event_correlation_observes_rc4_roasting_changes_dcsync_and_certificate(tmp_path):
    events = [
        _event(4769, TargetUserName="scanner", ServiceName=f"HTTP/app{index}", TicketEncryptionType="0x17")
        for index in range(10)
    ]
    events.extend([
        _event(4768, TargetUserName="legacy", PreAuthType="0"),
        _event(5136, AttributeLDAPDisplayName="msDS-KeyCredentialLink"),
        _event(4662, Properties="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"),
        _event(39, CertificateSubject="CN=user"),
        _event(4887, CertificateTemplateName="UserAuth"),
    ])
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    existing = [{"type": "certificate_esc1", "affected_object": "UserAuth"}]

    result = EventCorrelationAnalyzer().analyze([str(path)], existing)
    types = {risk["type"] for risk in result["risks"]}
    assert "event_kerberos_rc4_observed" in types
    assert "event_kerberoasting_burst" in types
    assert "event_asrep_activity" in types
    assert "event_sensitive_directory_change" in types
    assert "event_dcsync_activity" in types
    assert "event_certificate_mapping_failure" in types
    assert "event_suspicious_certificate_issuance" in types
    assert result["summary"]["parsed_events"] == len(events)


def test_posture_evidence_verifies_endpoint_controls(tmp_path):
    evidence = {
        "DC1": {
            "LDAPServerIntegrity": 1,
            "LdapEnforceChannelBinding": 0,
            "RestrictNTLMInDomain": 0,
            "RequireSecuritySignature": 0,
            "DefaultDomainSupportedEncTypes": "0x1c",
            "CertificateMappingMethods": "0x1f",
        }
    }
    path = tmp_path / "posture.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")

    result = PostureEvidenceAnalyzer().analyze([str(path)])
    types = {risk["type"] for risk in result["risks"]}
    assert "posture_ldap_signing_weak" in types
    assert "posture_channel_binding_weak" in types
    assert "posture_ntlm_restriction_weak" in types
    assert "posture_smb_signing_weak" in types
    assert "posture_kerberos_rc4_allowed" in types
    assert "posture_certificate_mapping_weak" in types
    assert result["summary"]["missing_controls"] == []


def test_snapshot_delta_tracks_privilege_risk_and_attack_edge_changes(tmp_path):
    baseline = {
        "users": [{"sAMAccountName": "alice", "memberOf": ["CN=Users,DC=contoso,DC=com"]}],
        "computers": [], "groups": [], "gpos": [],
        "risks": [],
        "attack_graph_v2": {"edges": []},
    }
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline), encoding="utf-8")
    current_data = {
        "users": [{"sAMAccountName": "alice", "memberOf": ["CN=Domain Admins,DC=contoso,DC=com"]}],
        "computers": [], "groups": [], "gpos": [],
    }
    current_analysis = {
        "attack_graph_v2": {"edges": [{"source": "user:alice", "target": "group:domain_admins", "type": "MemberOf"}]},
    }
    current_risks = [{
        "type": "attack_graph_tier0_path", "severity": "critical",
        "affected_object": "alice", "title": "New path",
    }]

    result = BaselineComparator().compare_snapshot(current_data, current_analysis, current_risks, str(path))
    types = {risk["type"] for risk in result["risks"]}
    assert "snapshot_new_critical_risk" in types
    assert "snapshot_privilege_change" in types
    assert "snapshot_attack_edge_added" in types
    assert result["summary"]["added_attack_edges"] == 1


def test_confidence_scorer_builds_transparent_evidence_chain():
    direct = {
        "type": "event_dcsync_activity", "affected_object": "DC telemetry",
        "evidence": {"event_ids": [4662], "event_count": 2},
    }
    inferred = {"type": "hybrid_join_not_observed", "affected_object": "domain"}
    ConfidenceScorer().enrich(direct)
    ConfidenceScorer().enrich(inferred)
    assert direct["confidence_level"] == "high"
    assert direct["confidence_score"] == 99.0
    assert direct["evidence_chain"]
    assert inferred["confidence_level"] == "low"
    assert inferred["confidence_score"] < direct["confidence_score"]


def test_package_c_registry_export_and_turkish_titles():
    for key in ("event_correlation_risks", "posture_evidence_risks", "snapshot_delta_risks"):
        assert key in CONSOLIDATION_RISK_KEYS
    sliced = build_export_analysis_slice({
        "event_correlation": {"parsed_events": 5},
        "posture_evidence": {"covered_controls": ["ldap_signing"]},
        "snapshot_delta": {"summary": {"new_risks": 1}},
    })
    assert sliced["event_correlation"]["parsed_events"] == 5
    finding = {
        "type": "event_dcsync_activity", "severity": "critical",
        "title": "DCSync", "description": "English", "affected_object": "DC1",
    }
    localized = localize_finding_list([finding], "tr")[0]
    assert localized["type"] == "event_dcsync_activity"
    assert localized["title"] == "Olay Kayıtlarında DCSync Etkinliği"


def test_cli_accepts_evidence_inputs_and_attack_graph_export(tmp_path):
    event_path = tmp_path / "events.json"
    posture_path = tmp_path / "posture.json"
    baseline_path = tmp_path / "baseline.json"
    for path in (event_path, posture_path, baseline_path):
        path.write_text("{}", encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args([
        "--domain", "example.com", "--username", "auditor",
        "--event-log", str(event_path), "--posture-file", str(posture_path),
        "--baseline", str(baseline_path), "--attack-graph-export", str(tmp_path / "graph.json"),
    ])
    validate_cli_arguments(parser, args)
    assert args.event_log == [str(event_path)]
    assert args.posture_file == [str(posture_path)]
    assert args.attack_graph_export.endswith("graph.json")


def test_attack_graph_export_writes_opengraph_payload(tmp_path):
    path = tmp_path / "graph.json"
    graph = {"opengraph": {"graph": {"nodes": [{"id": "user:alice"}], "edges": []}}}
    ExportFormats.export_attack_graph(graph, str(path))
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["graph"]["nodes"][0]["id"] == "user:alice"
