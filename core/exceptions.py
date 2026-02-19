"""
Custom Exceptions Module
Custom exception classes for better error handling
"""


class AtilKurtException(Exception):
    """Base exception for AtilKurt application."""
    pass


class LDAPConnectionError(AtilKurtException):
    """Raised when LDAP connection fails."""
    pass


class LDAPSearchError(AtilKurtException):
    """Raised when LDAP search operation fails."""
    pass


class DataCollectionError(AtilKurtException):
    """Raised when data collection fails."""
    pass


class AnalysisError(AtilKurtException):
    """Raised when analysis operation fails."""
    pass


class ValidationError(AtilKurtException):
    """Raised when input validation fails."""
    pass


class ExportError(AtilKurtException):
    """Raised when export operation fails."""
    pass
