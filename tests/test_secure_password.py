"""
Tests for Secure Password Manager
Validates memory clearing, deprecation warnings, and input handling
"""

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

    def test_clear_password_does_not_mutate_shared_string(self):
        """Clearing the manager must never mutate an immutable source string."""
        shared_password = "shared-password-漢字"
        same_reference = shared_password
        pm = SecurePasswordManager()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pm.get_password_from_arg(shared_password)

        pm.clear_password()

        self.assertEqual(shared_password, "shared-password-漢字")
        self.assertEqual(same_reference, "shared-password-漢字")

    def test_set_password_replaces_and_clears_owned_buffer(self):
        """Replacing a password clears the previous owned byte buffer."""
        pm = SecurePasswordManager()
        pm.set_password("first")
        previous_buffer = pm._password_buffer

        pm.set_password("second")

        self.assertEqual(previous_buffer, bytearray(b"\x00" * 5))
        self.assertEqual(pm.get_password(), "second")

    def test_get_password_returns_stored(self):
        """get_password() returns stored value."""
        pm = SecurePasswordManager()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pm.get_password_from_arg("myPass!")
        self.assertEqual(pm.get_password(), "myPass!")


if __name__ == '__main__':
    unittest.main()
