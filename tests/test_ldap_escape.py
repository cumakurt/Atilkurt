"""
Tests for LDAP Filter Escaping (LDAP Injection Prevention)
"""

import unittest
from ldap3.utils.conv import escape_filter_chars


class TestLDAPFilterEscape(unittest.TestCase):
    """Test cases for LDAP filter character escaping."""

    def test_special_characters_escaped(self):
        """Test that LDAP special characters are properly escaped."""
        # Asterisk - wildcard
        result = escape_filter_chars("user*")
        self.assertIn("\\2a", result)

        # Parentheses
        result = escape_filter_chars("(test)")
        self.assertIn("\\28", result)
        self.assertIn("\\29", result)

        # Backslash
        result = escape_filter_chars("user\\name")
        self.assertIn("\\5c", result)

    def test_normal_string_unchanged(self):
        """Test normal usernames pass through correctly."""
        result = escape_filter_chars("admin")
        self.assertEqual(result, "admin")

        result = escape_filter_chars("user123")
        self.assertEqual(result, "user123")

    def test_sam_account_name_safe(self):
        """Test sAMAccountName with special chars is safely escaped."""
        # Simulate what acl_security_analyzer does
        sam_account = "user*)(objectClass=*"
        escaped = escape_filter_chars(str(sam_account))
        # Escaped string should not contain raw parentheses that could extend filter
        self.assertNotIn(")(objectClass=", escaped)


if __name__ == '__main__':
    unittest.main()
