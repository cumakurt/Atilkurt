"""
Tests for Input Validation Module
"""

import unittest
import os
import tempfile
from core.validators import (
    validate_domain,
    validate_ip_address,
    validate_username,
    validate_password,
    validate_timeout,
    validate_output_file,
)
from core.exceptions import ValidationError


class TestValidateDomain(unittest.TestCase):
    """Test cases for validate_domain."""

    def test_valid_domain(self):
        """Test valid domain formats."""
        self.assertEqual(validate_domain("example.com"), "example.com")
        self.assertEqual(validate_domain("sub.example.com"), "sub.example.com")
        self.assertEqual(validate_domain("corp.local"), "corp.local")

    def test_empty_domain(self):
        """Test empty domain raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_domain("")
        with self.assertRaises(ValidationError):
            validate_domain(None)

    def test_invalid_domain_format(self):
        """Test invalid domain format."""
        with self.assertRaises(ValidationError):
            validate_domain("invalid")
        with self.assertRaises(ValidationError):
            validate_domain("example")


class TestValidateIPAddress(unittest.TestCase):
    """Test cases for validate_ip_address."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        self.assertEqual(validate_ip_address("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip_address("10.0.0.1"), "10.0.0.1")

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        self.assertEqual(
            validate_ip_address("2001:db8::1"),
            "2001:db8::1"
        )

    def test_invalid_ip(self):
        """Test invalid IP raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_ip_address("invalid")
        with self.assertRaises(ValidationError):
            validate_ip_address("256.256.256.256")


class TestValidateOutputFile(unittest.TestCase):
    """Test cases for validate_output_file - path traversal prevention."""

    def test_valid_output_path(self):
        """Test valid output paths return normalized form."""
        self.assertEqual(validate_output_file("report.html"), "report.html")
        # normpath will produce OS-native path separators
        result = validate_output_file("reports/domain_report.html")
        self.assertEqual(result, os.path.normpath("reports/domain_report.html"))

    def test_path_traversal_rejected(self):
        """Test path traversal is rejected."""
        with self.assertRaises(ValidationError) as ctx:
            validate_output_file("../../../etc/passwd")
        self.assertIn("Path traversal", str(ctx.exception))

        with self.assertRaises(ValidationError):
            validate_output_file("..\\..\\windows\\system32")

    def test_invalid_characters(self):
        """Test invalid characters are rejected."""
        with self.assertRaises(ValidationError):
            validate_output_file("report<.html")
        with self.assertRaises(ValidationError):
            validate_output_file("report|.html")


class TestValidateTimeout(unittest.TestCase):
    """Test cases for validate_timeout."""

    def test_valid_timeout(self):
        """Test valid timeout values."""
        self.assertEqual(validate_timeout(30), 30)
        self.assertEqual(validate_timeout(60), 60)
        self.assertEqual(validate_timeout(300), 300)
        self.assertEqual(validate_timeout(None), 30)

    def test_invalid_timeout(self):
        """Test invalid timeout raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_timeout(0)
        with self.assertRaises(ValidationError):
            validate_timeout(400)


class TestValidateUsername(unittest.TestCase):
    """Test cases for validate_username."""

    def test_valid_username(self):
        """Test valid usernames."""
        self.assertEqual(validate_username("admin"), "admin")
        self.assertEqual(validate_username("user123"), "user123")

    def test_empty_username(self):
        """Test empty username raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_username("")


class TestValidatePassword(unittest.TestCase):
    """Test cases for validate_password."""

    def test_valid_password(self):
        """Test valid passwords."""
        self.assertEqual(validate_password("secret"), "secret")
        self.assertEqual(validate_password("P@ssw0rd!"), "P@ssw0rd!")

    def test_empty_password(self):
        """Test empty password raises ValidationError."""
        with self.assertRaises(ValidationError):
            validate_password("")


if __name__ == '__main__':
    unittest.main()
