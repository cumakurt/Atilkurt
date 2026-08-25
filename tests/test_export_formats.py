"""Tests for risk export sanitization."""

import csv
import os
import tempfile
import unittest

from reporting.export_formats import ExportFormats, _csv_safe_cell


class TestCsvExportSafety(unittest.TestCase):
    def test_formula_prefix_is_neutralized(self):
        self.assertEqual(_csv_safe_cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(_csv_safe_cell("+2+3"), "'+2+3")
        self.assertEqual(_csv_safe_cell("normal title"), "normal title")

    def test_export_csv_prefixes_formula_cells(self):
        handle, output_path = tempfile.mkstemp(suffix=".csv")
        os.close(handle)
        try:
            ExportFormats.export_csv(
                [{
                    "type": "gpp_password_found",
                    "title": "=HYPERLINK(\"http://evil\",\"x\")",
                    "affected_object": "user1",
                    "severity": "critical",
                }],
                output_path,
            )
            with open(output_path, encoding="utf-8", newline="") as file_handle:
                rows = list(csv.DictReader(file_handle))
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["title"].startswith("'="))
            self.assertNotEqual(rows[0]["title"][:1], "=")
        finally:
            os.unlink(output_path)


if __name__ == "__main__":
    unittest.main()
