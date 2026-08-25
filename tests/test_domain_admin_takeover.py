"""Tests for the Domain Admin takeover map."""

from __future__ import annotations

import os
import tempfile
import unittest

from analysis.domain_admin_takeover_analyzer import (
    DA_PATH_CATALOG,
    DomainAdminTakeoverAnalyzer,
)
from analysis.registry import (
    CONSOLIDATION_RISK_KEYS,
    EXPORT_KEY_TO_ANALYSIS_KEY,
    build_export_analysis_slice,
)
from reporting.html_report import HTMLReportGenerator
from reporting.report_sections.domain_admin_section import DomainAdminSectionMixin


class TestDomainAdminTakeoverAnalyzer(unittest.TestCase):
    """Map scored findings onto pentest Domain Admin paths."""

    def test_catalog_has_stable_unique_ids(self):
        ids = [spec["id"] for spec in DA_PATH_CATALOG]
        self.assertGreaterEqual(len(ids), 24)
        self.assertEqual(len(ids), len(set(ids)))
        for spec in DA_PATH_CATALOG:
            self.assertTrue(spec.get("why_da"))
            self.assertTrue(spec.get("starting_access"))
            self.assertTrue(spec.get("stages"))
            self.assertTrue(spec.get("break_path"))

    def test_dcsync_finding_opens_dcsync_path(self):
        result = DomainAdminTakeoverAnalyzer().analyze(
            [
                {
                    "type": "dcsync_rights",
                    "severity": "critical",
                    "title": "DCSync rights on helper",
                    "affected_object": "helper",
                }
            ]
        )
        open_ids = [path["id"] for path in result["open_paths"]]
        self.assertEqual(open_ids, ["dcsync"])
        path = result["open_paths"][0]
        self.assertTrue(path["da_equivalent"])
        self.assertEqual(path["status"], "open")
        self.assertIn("helper", path["evidence_objects"])
        self.assertEqual(result["summary"]["open_path_count"], 1)
        self.assertEqual(result["summary"]["unobserved_count"], len(DA_PATH_CATALOG) - 1)

    def test_empty_risks_leave_catalog_unobserved(self):
        result = DomainAdminTakeoverAnalyzer().analyze([])
        self.assertEqual(result["open_paths"], [])
        self.assertEqual(len(result["unobserved_paths"]), len(DA_PATH_CATALOG))
        self.assertEqual(result["summary"]["open_path_count"], 0)

    def test_acl_escalation_does_not_match_adcs(self):
        result = DomainAdminTakeoverAnalyzer().analyze(
            [
                {
                    "type": "acl_privilege_escalation_path",
                    "severity": "high",
                    "title": "ACL path to Domain Admins",
                    "affected_object": "alice",
                }
            ]
        )
        open_ids = [path["id"] for path in result["open_paths"]]
        self.assertIn("acl_generic_all", open_ids)
        self.assertNotIn("adcs", open_ids)

    def test_certificate_esc1_opens_adcs_path(self):
        result = DomainAdminTakeoverAnalyzer().analyze(
            [
                {
                    "type": "certificate_esc1",
                    "severity": "critical",
                    "title": "ESC1 template",
                    "affected_object": "VulnerableTemplate",
                }
            ]
        )
        self.assertEqual([path["id"] for path in result["open_paths"]], ["adcs"])


class TestDomainAdminTakeoverExportAndReport(unittest.TestCase):
    """JSON export and HTML report wiring."""

    def test_export_slice_keeps_takeover_as_dict(self):
        self.assertIn("domain_admin_takeover", EXPORT_KEY_TO_ANALYSIS_KEY)
        self.assertNotIn("domain_admin_takeover", CONSOLIDATION_RISK_KEYS)
        empty = build_export_analysis_slice({})
        self.assertIsNone(empty["domain_admin_takeover"])
        payload = {"summary": {"open_path_count": 2}, "open_paths": [], "unobserved_paths": []}
        out = build_export_analysis_slice({"domain_admin_takeover": payload})
        self.assertEqual(out["domain_admin_takeover"], payload)

    def test_html_section_renders_open_path_reason(self):
        takeover = DomainAdminTakeoverAnalyzer().analyze(
            [
                {
                    "type": "dcsync_rights",
                    "severity": "critical",
                    "title": "DCSync rights on helper",
                    "affected_object": "helper",
                }
            ]
        )
        html = DomainAdminSectionMixin()._generate_domain_admin_takeover_section(takeover)
        self.assertIn("Domain Admin takeover map", html)
        self.assertIn("Why this becomes Domain Admin", html)
        self.assertIn("DCSync", html)
        self.assertIn("helper", html)
        self.assertIn("How to break the path", html)

    def test_full_report_includes_takeover_tab(self):
        risks = [
            {
                "type": "dcsync_rights",
                "title": "DCSync rights on helper",
                "description": "Replication rights grant hash retrieval.",
                "affected_object": "helper",
                "object_type": "user",
                "severity": "critical",
                "impact": "Domain Admin equivalent",
                "attack_scenario": "Request KRBTGT hashes",
                "mitigation": "Remove the replication ACE",
            }
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as handle:
            output_file = handle.name
        try:
            HTMLReportGenerator().generate(
                users=[{"sAMAccountName": "helper", "memberOf": [], "distinguishedName": "CN=helper,DC=local"}],
                computers=[],
                groups=[],
                gpos=[],
                risks=risks,
                misconfig_findings=[],
                domain_score=40.0,
                executive_summary={"top_critical_risks": [], "summary": "Test"},
                output_file=output_file,
            )
            with open(output_file, encoding="utf-8") as handle:
                report = handle.read()
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass
        self.assertIn("domain-admin-takeover", report)
        self.assertIn("Domain Admin Map", report)
        self.assertIn("Domain Admin takeover map", report)
        self.assertIn("DCSync", report)


if __name__ == "__main__":
    unittest.main()
