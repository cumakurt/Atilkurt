"""
Secure Password Management Module
Handles secure password input and memory management
"""

import getpass
import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)


class SecurePasswordManager:
    """
    Secure password manager that handles password input and owned-buffer clearing.

    Python strings are immutable and may be shared or interned, so mutating a
    ``str`` object's internal memory is unsafe. The manager keeps its own
    mutable UTF-8 buffer and overwrites that buffer when it is cleared. Any
    string returned to a caller remains subject to normal Python memory
    management and cannot be reliably wiped by this class.
    """

    def __init__(self) -> None:
        """Initialize secure password manager."""
        self._password_buffer: Optional[bytearray] = None
        self._password_set = False

    def set_password(self, password: str) -> str:
        """Store a password in an owned mutable buffer and return it."""
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        self.clear_password()
        self._password_buffer = bytearray(password, "utf-8")
        self._password_set = True
        return password

    def get_password_from_prompt(self, prompt: str = "Password: ") -> str:
        """
        Securely get password from user input using getpass.

        Args:
            prompt: Prompt message for password input

        Returns:
            str: Password entered by user
        """
        try:
            password = getpass.getpass(prompt)
            return self.set_password(password)
        except KeyboardInterrupt:
            print("\n[-] Password input cancelled")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error getting password: {e}")
            raise

    def get_password_from_arg(self, password: str) -> str:
        """
        Store password from command line argument.

        .. deprecated::
            Passing passwords via CLI is insecure (visible in ``ps aux``
            and ``/proc/<pid>/cmdline``). Use environment variables or
            interactive prompt instead.

        Args:
            password: Password from command line

        Returns:
            str: Password
        """
        import warnings
        warnings.warn(
            "Passing passwords via command line is insecure (visible in process "
            "listings). Use environment variables or interactive prompt instead.",
            DeprecationWarning,
            stacklevel=2
        )
        return self.set_password(password)

    def get_password(self) -> Optional[str]:
        """
        Get stored password.

        Returns:
            str: Stored password or None
        """
        if self._password_buffer is None:
            return None
        return self._password_buffer.decode("utf-8")

    def clear_password(self) -> None:
        """
        Overwrite and release the manager-owned password buffer.

        This deliberately does not attempt to mutate immutable Python string
        objects because doing so can corrupt shared interpreter state.
        """
        if self._password_buffer is not None:
            self._password_buffer[:] = b"\x00" * len(self._password_buffer)
            self._password_buffer = None
        self._password_set = False

    def is_set(self) -> bool:
        """Check if password is set."""
        return self._password_set


def get_password_secure(prompt: str = "Password: ", use_prompt: bool = True) -> str:
    """
    Convenience function to get password securely.

    Args:
        prompt: Prompt message
        use_prompt: If True, use getpass prompt. If False, read from stdin (for scripts)

    Returns:
        str: Password
    """
    if use_prompt:
        return getpass.getpass(prompt)
    else:
        # For non-interactive use, read from stdin
        return sys.stdin.readline().rstrip('\n')
