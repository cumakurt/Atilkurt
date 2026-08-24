"""
Tests for Progress Persistence Module
"""

import unittest
import tempfile
import os
import json
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

    def test_path_traversal_is_rejected_for_all_checkpoint_operations(self):
        """Load and delete must enforce the same path validation as save."""
        outside_path = os.path.join(self.temp_dir, "outside.json")
        with open(outside_path, "w", encoding="utf-8") as file_handle:
            json.dump({"data": {"secret": True}}, file_handle)

        with self.assertRaises(ValueError):
            self.persistence.load_checkpoint("../outside")
        with self.assertRaises(ValueError):
            self.persistence.delete_checkpoint("../outside")

        self.assertTrue(os.path.exists(outside_path))

    def test_checkpoint_directory_permissions(self):
        """Checkpoint directory metadata is restricted to its owner."""
        mode = os.stat(self.persistence.checkpoint_dir).st_mode
        self.assertEqual(mode & 0o777, 0o700)

    def test_checkpoint_write_rejects_external_symlink(self):
        """Saving must reject a checkpoint symlink that resolves outside the directory."""
        outside_path = os.path.join(self.temp_dir, "outside.json")
        with open(outside_path, "w", encoding="utf-8") as file_handle:
            file_handle.write("unchanged")
        checkpoint_link = self.persistence.checkpoint_dir / "linked.json"
        checkpoint_link.symlink_to(outside_path)

        with self.assertRaises(ValueError):
            self.persistence.save_checkpoint("linked", {"changed": True})

        with open(outside_path, encoding="utf-8") as file_handle:
            self.assertEqual(file_handle.read(), "unchanged")


if __name__ == '__main__':
    unittest.main()
