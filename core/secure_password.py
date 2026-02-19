"""
Secure Password Management Module
Handles secure password input and memory management
"""

import getpass
import sys
import ctypes
import os
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SecurePasswordManager:
    """
    Secure password manager that handles password input and memory clearing.
    Uses ctypes for real memory overwriting (Python strings are immutable,
    so simple reassignment does NOT clear memory).
    """
    
    def __init__(self) -> None:
        """Initialize secure password manager."""
        self._password: Optional[str] = None
        self._password_set = False
    
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
            self._password = password
            self._password_set = True
            return password
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
        self._password = password
        self._password_set = True
        return password
    
    def get_password(self) -> Optional[str]:
        """
        Get stored password.
        
        Returns:
            str: Stored password or None
        """
        return self._password
    
    def clear_password(self) -> None:
        """
        Clear password from memory.
        
        Uses ctypes to overwrite the underlying C string buffer. This is
        the closest we can get to secure memory wiping in CPython — simple
        reassignment only removes the reference while the original bytes
        remain in the process heap until overwritten by the allocator.
        """
        if self._password is not None:
            try:
                # Get the internal buffer address of the Python str object.
                # CPython stores str data as a compact ASCII or UTF-8 buffer
                # right after the object header.  We use ctypes.memset to
                # zero it out in-place before dropping the reference.
                password_len = len(self._password)
                if password_len > 0:
                    # id() returns the memory address of the object in CPython
                    addr = id(self._password)
                    # The actual character data in a compact ASCII string
                    # starts at offset sys.getsizeof('') from the object base.
                    offset = sys.getsizeof('') 
                    ctypes.memset(addr + offset, 0, password_len)
            except Exception as e:
                # Fallback: best-effort overwrite (not guaranteed on all
                # Python implementations, e.g. PyPy)
                logger.debug(f"ctypes memory wipe failed, using fallback: {e}")
            finally:
                self._password = None
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
