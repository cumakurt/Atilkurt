"""
Test that the generated HTML report contains report-accordion class and CSS.
Run from project root: python -m pytest tests/test_report_accordion.py -v
"""

import os
import tempfile
import unittest


class TestReportAccordionRendering(unittest.TestCase):
    """Verify report HTML contains new accordion markup and styles."""

    def test_report_contains_report_accordion_class_and_css(self):
        from reporting.html_report import HTMLReportGenerator

        # Minimal mock data: one risk that produces accordion (Impact, Mitigation)
        users = [{"sAMAccountName": "testuser", "memberOf": [], "distinguishedName": "CN=test,DC=local"}]
        computers = [{"name": "PC01", "distinguishedName": "CN=PC01,DC=local"}]
        groups = [{"name": "Domain Users", "member": [], "distinguishedName": "CN=Domain Users,DC=local"}]
        gpos = []
        risks = [
            {
                "type": "user_password_never_expires",
                "title": "Password never expires",
                "description": "Test risk",
                "affected_object": "testuser",
                "object_type": "user",
                "severity": "high",
                "impact": "Test impact",
                "attack_scenario": "Test scenario",
                "mitigation": "Test mitigation",
                "base_score": 30,
                "score": 45.0,
            }
        ]
        misconfig_findings = []
        domain_score = 70.0
        executive_summary = {"top_critical_risks": [], "summary": "Test"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            output_file = f.name
        try:
            gen = HTMLReportGenerator()
            gen.generate(
                users=users,
                computers=computers,
                groups=groups,
                gpos=gpos,
                risks=risks,
                misconfig_findings=misconfig_findings,
                domain_score=domain_score,
                executive_summary=executive_summary,
                output_file=output_file,
            )
            with open(output_file, "r", encoding="utf-8") as f:
                html = f.read()
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

        # Must contain the accordion wrapper class
        self.assertIn("report-accordion", html, "Report HTML should contain class 'report-accordion' on accordion divs")

        # Must contain the CSS for .report-accordion
        self.assertIn(".report-accordion", html, "Report HTML should contain CSS rule for .report-accordion")
        self.assertIn("border-left: 3px solid", html, "Report HTML should contain new accordion button left border style")
        self.assertIn("accordion-button", html, "Report should contain Bootstrap accordion buttons")
        self.assertIn("Impact", html, "Report should contain Impact section from risk card")
        self.assertIn("Mitigation", html, "Report should contain Mitigation section from risk card")
