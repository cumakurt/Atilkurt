"""
Baseline Comparator Module
Compares current scan results with previous baseline to detect drift
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class BaselineComparator:
    """Compares current scan with baseline for drift detection."""

    def load_baseline(self, baseline_path: str) -> Optional[Dict[str, Any]]:
        """
        Load baseline from JSON file (from --json-export or checkpoint).
        """
        path = Path(baseline_path)
        if not path.exists():
            logger.error(f"Baseline file not found: {baseline_path}")
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return None

    def compare(
        self,
        current_risks: List[Dict[str, Any]],
        baseline_risks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compare current risks with baseline.
        Returns new risks, resolved risks, and summary.
        """
        def _risk_key(r: Dict) -> str:
            return f"{r.get('type', '')}|{r.get('affected_object', '')}"

        baseline_keys = {_risk_key(r) for r in baseline_risks}
        current_keys = {_risk_key(r) for r in current_risks}

        new_risks = [r for r in current_risks if _risk_key(r) not in baseline_keys]
        resolved_risks = [r for r in baseline_risks if _risk_key(r) not in current_keys]
        unchanged_risks = [r for r in current_risks if _risk_key(r) in baseline_keys]

        return {
            'new_risks': new_risks,
            'resolved_risks': resolved_risks,
            'unchanged_risks': unchanged_risks,
            'summary': {
                'baseline_count': len(baseline_risks),
                'current_count': len(current_risks),
                'new_count': len(new_risks),
                'resolved_count': len(resolved_risks),
                'unchanged_count': len(unchanged_risks),
                'drift': len(current_risks) - len(baseline_risks),
            },
            'timestamp': datetime.now().isoformat(),
        }

    def compare_full(
        self,
        current_data: Dict[str, Any],
        baseline_path: str
    ) -> Dict[str, Any]:
        """
        Full comparison using baseline file.
        current_data should have 'risks' key from main scan.
        """
        baseline = self.load_baseline(baseline_path)
        if not baseline:
            return {'error': 'Baseline not loaded', 'comparison': None}

        baseline_risks = baseline.get('risks', []) or baseline.get('data', {}).get('risks', [])
        current_risks = current_data.get('risks', [])

        comparison = self.compare(current_risks, baseline_risks)
        comparison['baseline_file'] = baseline_path
        comparison['baseline_timestamp'] = baseline.get('timestamp') or baseline.get('data', {}).get('timestamp')
        return comparison
