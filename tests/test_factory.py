"""
Tests for Factory Pattern
"""

import unittest
from core.factory import AnalyzerFactory, RiskScorerFactory
from core.base_analyzer import BaseAnalyzer
from analysis.user_risks import UserRiskAnalyzer
from scoring.risk_scorer import RiskScorer


class TestAnalyzerFactory(unittest.TestCase):
    """Test cases for AnalyzerFactory."""
    
    def test_create_user_analyzer(self):
        """Test creating user analyzer."""
        analyzer = AnalyzerFactory.create_analyzer('user')
        self.assertIsInstance(analyzer, UserRiskAnalyzer)
    
    def test_create_unknown_analyzer(self):
        """Test creating unknown analyzer raises error."""
        with self.assertRaises(ValueError):
            AnalyzerFactory.create_analyzer('unknown_analyzer')
    
    def test_list_analyzers(self):
        """Test listing all analyzers."""
        analyzers = AnalyzerFactory.list_analyzers()
        self.assertIn('user', analyzers)
        self.assertIn('computer', analyzers)
        self.assertIn('group', analyzers)
    
    def test_register_analyzer(self):
        """Test registering custom analyzer."""
        class CustomAnalyzer(BaseAnalyzer):
            def analyze(self, *args, **kwargs):
                return []
        
        AnalyzerFactory.register_analyzer('custom', CustomAnalyzer)
        analyzer = AnalyzerFactory.create_analyzer('custom')
        self.assertIsInstance(analyzer, CustomAnalyzer)


class TestRiskScorerFactory(unittest.TestCase):
    """Test cases for RiskScorerFactory."""
    
    def test_create_scorer(self):
        """Test creating risk scorer."""
        scorer = RiskScorerFactory.create_scorer()
        self.assertIsInstance(scorer, RiskScorer)


if __name__ == '__main__':
    unittest.main()
