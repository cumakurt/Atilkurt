"""Security regression tests for attacker-controlled report values."""

import os
import tempfile
import unittest

from reporting.html_report import HTMLReportGenerator
from reporting.html_safety import json_for_html_script


class TestHTMLReportSecurity(unittest.TestCase):
    """LDAP-controlled values must not become executable report markup."""

    def test_json_serializer_cannot_terminate_script_element(self):
        """Embedded JSON escapes characters significant to the HTML parser."""
        payload = "</script><script>alert('xss')</script>&"

        serialized = json_for_html_script({"value": payload})

        self.assertNotIn("</script>", serialized)
        self.assertNotIn("<script>", serialized)
        self.assertNotIn("&", serialized)
        self.assertIn("\\u003c/script\\u003e", serialized)
        self.assertIn("\\u0026", serialized)

    def test_generated_report_escapes_ldap_controlled_values(self):
        """Malicious directory attributes remain inert in the complete report."""
        payload = "</script><script>alert('xss')</script><img src=x onerror=alert(1)>"
        users = [
            {
                "sAMAccountName": payload,
                "displayName": payload,
                "description": payload,
                "memberOf": [f"CN={payload},DC=example,DC=com"],
                "distinguishedName": f"CN={payload},DC=example,DC=com",
                "userAccountControl": 0x10000,
                "isDisabled": True,
                "isLocked": True,
            }
        ]
        computers = [
            {
                "name": payload,
                "operatingSystem": payload,
                "distinguishedName": f"CN={payload},DC=example,DC=com",
            }
        ]
        groups = [
            {
                "name": payload,
                "member": [f"CN={payload},DC=example,DC=com"],
                "distinguishedName": f"CN={payload},DC=example,DC=com",
            }
        ]
        risks = [
            {
                "type": "user_password_never_expires",
                "title": payload,
                "description": payload,
                "affected_object": payload,
                "object_type": "user",
                "severity": "high",
                "impact": payload,
                "attack_scenario": payload,
                "mitigation": payload,
                "final_score": 70.0,
                "severity_level": "High",
            }
        ]

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as output_file:
            output_path = output_file.name
        try:
            HTMLReportGenerator().generate(
                users=users,
                computers=computers,
                groups=groups,
                gpos=[],
                risks=risks,
                misconfig_findings=[],
                domain_score=30.0,
                executive_summary={"top_critical_risks": []},
                output_file=output_path,
                domain="example.com",
                dc_ip="10.0.0.1",
            )
            with open(output_path, encoding="utf-8") as file_handle:
                report = file_handle.read()
        finally:
            os.unlink(output_path)

        self.assertNotIn(payload, report)
        self.assertNotIn("<img src=x onerror=alert(1)>", report)
        self.assertTrue(
            "&lt;/script&gt;" in report or "\\u003c/script\\u003e" in report,
            "The payload should be preserved only in an escaped form",
        )


if __name__ == "__main__":
    unittest.main()
