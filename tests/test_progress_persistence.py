"""
Tests for Progress Persistence Module
"""

import unittest
import tempfile
import os
from pathlib import Path
from core.progress_persistence import ProgressPersistence


class TestProgressPersistence(unittest.TestCase):
    """Test cases for ProgressPersistence - checkpoint security."""

    def setUp(self):
        """Create temporary directory for checkpoint tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.persistence = ProgressPersistence(checkpoint_dir=os.path.join(
            self.temp_dir, ".atilkurt_checkpoints"
        ))

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_valid_checkpoint_save(self):
        """Test saving valid checkpoint."""
        data = {"domain": "test.com", "users": [], "risks": []}
        path = self.persistence.save_checkpoint("test_001", data)
        self.assertIn("test_001.json", path)
        self.assertTrue(os.path.exists(path))

    def test_checkpoint_file_permissions(self):
        """Test checkpoint files have restrictive permissions (0o600)."""
        data = {"domain": "test.com"}
        path = self.persistence.save_checkpoint("perms_test", data)
        mode = os.stat(path).st_mode
        # Owner read/write only - no group/other access
        self.assertEqual(mode & 0o777, 0o600)

    def test_checkpoint_id_path_traversal_rejected(self):
        """Test path traversal in checkpoint_id is rejected."""
        with self.assertRaises(ValueError):
            self.persistence.save_checkpoint("../../../etc/passwd", {})
        with self.assertRaises(ValueError):
            self.persistence.save_checkpoint("id/with/slash", {})
        with self.assertRaises(ValueError):
            self.persistence.save_checkpoint("id\\with\\backslash", {})


if __name__ == '__main__':
    unittest.main()
