"""
Tests for Secure Password Manager
Validates memory clearing, deprecation warnings, and input handling
"""

import sys
import unittest
import warnings
from core.secure_password import SecurePasswordManager


class TestSecurePasswordManager(unittest.TestCase):
    """Test cases for SecurePasswordManager."""

    def test_initial_state(self):
        """Password manager starts with no password."""
        pm = SecurePasswordManager()
        self.assertIsNone(pm.get_password())
        self.assertFalse(pm.is_set())

    def test_get_password_from_arg_shows_deprecation(self):
        """CLI password arg triggers DeprecationWarning."""
        pm = SecurePasswordManager()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = pm.get_password_from_arg("test123")
            self.assertEqual(result, "test123")
            self.assertTrue(pm.is_set())
            # Check that a DeprecationWarning was raised
            self.assertTrue(
                any(issubclass(warning.category, DeprecationWarning) for warning in w),
                "Expected DeprecationWarning for CLI password arg"
            )

    def test_clear_password(self):
        """clear_password() resets state."""
        pm = SecurePasswordManager()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pm.get_password_from_arg("secret")
        self.assertTrue(pm.is_set())
        pm.clear_password()
        self.assertIsNone(pm.get_password())
        self.assertFalse(pm.is_set())

    def test_clear_password_when_none(self):
        """clear_password() does nothing when no password is set."""
        pm = SecurePasswordManager()
        pm.clear_password()  # Should not raise
        self.assertIsNone(pm.get_password())

    def test_get_password_returns_stored(self):
        """get_password() returns stored value."""
        pm = SecurePasswordManager()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pm.get_password_from_arg("myPass!")
        self.assertEqual(pm.get_password(), "myPass!")


if __name__ == '__main__':
    unittest.main()
