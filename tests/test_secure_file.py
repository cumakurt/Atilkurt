"""Tests for secure assessment output writes."""

import tempfile
import unittest
from pathlib import Path

from core.secure_file import atomic_text_writer, atomic_write_text


class TestSecureFileWrites(unittest.TestCase):
    """Assessment outputs should be private and crash-safe."""

    def test_atomic_write_uses_owner_only_permissions(self):
        """New output files are readable and writable only by their owner."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "report.json"

            atomic_write_text(output_path, '{"result": "ok"}')

            self.assertEqual(output_path.read_text(encoding="utf-8"), '{"result": "ok"}')
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)

    def test_failed_write_preserves_existing_output(self):
        """An exception during generation must not truncate a valid report."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "report.html"
            output_path.write_text("existing report", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                with atomic_text_writer(output_path) as file_handle:
                    file_handle.write("partial report")
                    raise RuntimeError("generation failed")

            self.assertEqual(output_path.read_text(encoding="utf-8"), "existing report")

    def test_atomic_write_does_not_follow_output_symlink(self):
        """Replacing an output path must not overwrite a symlink target."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            outside_path = directory / "outside.txt"
            outside_path.write_text("unchanged", encoding="utf-8")
            output_path = directory / "report.html"
            output_path.symlink_to(outside_path)

            atomic_write_text(output_path, "new report")

            self.assertFalse(output_path.is_symlink())
            self.assertEqual(output_path.read_text(encoding="utf-8"), "new report")
            self.assertEqual(outside_path.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
