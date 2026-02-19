"""
Input Validation Module
Validates user inputs and configuration parameters
"""

import re
import ipaddress
from typing import Optional
from core.exceptions import ValidationError


def validate_domain(domain: str) -> str:
    """
    Validate domain name format.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        str: Validated domain name
        
    Raises:
        ValidationError: If domain is invalid
    """
    if not domain or not isinstance(domain, str):
        raise ValidationError("Domain must be a non-empty string")
    
    domain = domain.strip()
    
    # Basic domain validation (FQDN format)
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, domain):
        raise ValidationError(f"Invalid domain format: {domain}")
    
    return domain


def validate_ip_address(ip: str) -> str:
    """
    Validate IP address format.
    
    Args:
        ip: IP address to validate
        
    Returns:
        str: Validated IP address
        
    Raises:
        ValidationError: If IP address is invalid
    """
    if not ip or not isinstance(ip, str):
        raise ValidationError("IP address must be a non-empty string")
    
    ip = ip.strip()
    
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValidationError(f"Invalid IP address format: {ip}")
    
    return ip


def validate_username(username: str) -> str:
    """
    Validate username format.
    
    Args:
        username: Username to validate
        
    Returns:
        str: Validated username
        
    Raises:
        ValidationError: If username is invalid
    """
    if not username or not isinstance(username, str):
        raise ValidationError("Username must be a non-empty string")
    
    username = username.strip()
    
    if len(username) > 256:  # AD username max length
        raise ValidationError("Username exceeds maximum length (256 characters)")
    
    return username


def validate_password(password: str) -> str:
    """
    Validate password (basic check - not empty).
    
    Args:
        password: Password to validate
        
    Returns:
        str: Validated password
        
    Raises:
        ValidationError: If password is invalid
    """
    if not password or not isinstance(password, str):
        raise ValidationError("Password must be a non-empty string")
    
    return password


def validate_timeout(timeout: Optional[int]) -> int:
    """
    Validate timeout value.
    
    Args:
        timeout: Timeout in seconds
        
    Returns:
        int: Validated timeout
        
    Raises:
        ValidationError: If timeout is invalid
    """
    if timeout is None:
        return 30  # Default
    
    if not isinstance(timeout, int):
        raise ValidationError("Timeout must be an integer")
    
    if timeout < 1 or timeout > 300:
        raise ValidationError("Timeout must be between 1 and 300 seconds")
    
    return timeout


def validate_output_file(output_file: str) -> str:
    """
    Validate output file path and prevent path traversal attacks.
    
    Args:
        output_file: Output file path
        
    Returns:
        str: Validated file path (resolved to real path)
        
    Raises:
        ValidationError: If file path is invalid
    """
    import os
    
    if not output_file or not isinstance(output_file, str):
        raise ValidationError("Output file must be a non-empty string")
    
    output_file = output_file.strip()
    
    # Check for path traversal
    if '..' in output_file:
        raise ValidationError("Path traversal (..) is not allowed in output path")
    
    # Check for invalid characters
    invalid_chars = ['<', '>', '"', '|', '?', '*', '\x00']
    if any(char in output_file for char in invalid_chars):
        raise ValidationError(f"Output file contains invalid characters: {output_file}")
    
    # Normalize path and reject path traversal
    normalized = os.path.normpath(output_file)
    if '..' in normalized.split(os.sep):
        raise ValidationError("Path traversal (..) is not allowed in output path")
    
    # Return the normalized (sanitized) path, not the original
    return normalized
