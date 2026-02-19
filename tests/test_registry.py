"""
Tests for Analysis Registry
Single source of risk keys and export slice.
"""

import unittest
from analysis.registry import (
    CONSOLIDATION_RISK_KEYS,
    EXPORT_KEY_TO_ANALYSIS_KEY,
    get_consolidated_risk_lists,
    build_export_analysis_slice,
    ANALYSIS_STEPS,
)


class TestRegistryConstants(unittest.TestCase):
    """Test registry constants are non-empty and consistent."""

    def test_consolidation_risk_keys_non_empty(self):
        self.assertGreater(len(CONSOLIDATION_RISK_KEYS), 10)

    def test_export_mapping_has_expected_keys(self):
        self.assertIn("shadow_credentials_risks", EXPORT_KEY_TO_ANALYSIS_KEY)
        self.assertEqual(EXPORT_KEY_TO_ANALYSIS_KEY["shadow_credentials_risks"], "shadow_cred_risks")
        self.assertIn("legacy_os_data", EXPORT_KEY_TO_ANALYSIS_KEY)
        self.assertEqual(EXPORT_KEY_TO_ANALYSIS_KEY["legacy_os_data"], "legacy_os_results")

    def test_analysis_steps_registered(self):
        self.assertGreater(len(ANALYSIS_STEPS), 20)
        for desc, runner in ANALYSIS_STEPS:
            self.assertIsInstance(desc, str)
            self.assertTrue(callable(runner))


class TestGetConsolidatedRiskLists(unittest.TestCase):
    """Test get_consolidated_risk_lists."""

    def test_empty_analysis(self):
        lists = get_consolidated_risk_lists({})
        self.assertEqual(len(lists), len(CONSOLIDATION_RISK_KEYS))
        for L in lists:
            self.assertEqual(L, [])

    def test_analysis_with_some_keys(self):
        analysis = {"user_risks": [{"a": 1}], "computer_risks": [{"b": 2}]}
        lists = get_consolidated_risk_lists(analysis)
        self.assertEqual(len(lists), len(CONSOLIDATION_RISK_KEYS))
        idx_user = list(CONSOLIDATION_RISK_KEYS).index("user_risks")
        idx_computer = list(CONSOLIDATION_RISK_KEYS).index("computer_risks")
        self.assertEqual(lists[idx_user], [{"a": 1}])
        self.assertEqual(lists[idx_computer], [{"b": 2}])


class TestBuildExportAnalysisSlice(unittest.TestCase):
    """Test build_export_analysis_slice."""

    def test_empty_analysis(self):
        out = build_export_analysis_slice({})
        self.assertIn("misconfig_findings", out)
        self.assertIn("legacy_os_data", out)
        self.assertIn("shadow_credentials_risks", out)
        self.assertEqual(out["misconfig_findings"], [])
        self.assertIsNone(out.get("legacy_os_data"))

    def test_renames_applied(self):
        analysis = {"shadow_cred_risks": [{"x": 1}], "legacy_os_results": {"total_count": 5}}
        out = build_export_analysis_slice(analysis)
        self.assertEqual(out["shadow_credentials_risks"], [{"x": 1}])
        self.assertEqual(out["legacy_os_data"], {"total_count": 5})
