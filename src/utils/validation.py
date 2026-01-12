"""
Input Validation and Sanitization

This module provides security-critical validation for all user inputs.
It prevents command injection, validates targets against allowlists,
and ensures all inputs are safe for use in shell commands.

WARNING: Modifications to this file should be reviewed carefully.
"""

import ipaddress
import os
import re
import socket
from fnmatch import fnmatch
from typing import Optional
from urllib.parse import urlparse

# Characters that could be used for command injection
DANGEROUS_CHARS = set(';&|`$(){}[]<>\\\'\"!#*?\n\r\t')

# Valid characters for hostnames (RFC 1123)
HOSTNAME_REGEX = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$'
)

# Valid port specification patterns
PORT_SPEC_REGEX = re.compile(r'^[0-9,\-T:U ]+$')


def get_allowed_targets() -> list[str]:
    """Get the list of allowed target patterns from environment."""
    allowed = os.environ.get("MCP_ALLOWED_TARGETS", "").strip()
    if not allowed:
        return []  # Empty means all allowed (but blocked still applies)
    return [t.strip() for t in allowed.split(",") if t.strip()]


def get_blocked_targets() -> list[str]:
    """Get the list of blocked target patterns from environment."""
    blocked = os.environ.get(
        "MCP_BLOCKED_TARGETS",
        "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,224.0.0.0/4"
    )
    return [t.strip() for t in blocked.split(",") if t.strip()]


def is_valid_ip(value: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_network(value: str) -> bool:
    """Check if a string is a valid IP network (CIDR notation)."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname."""
    if len(hostname) > 253:
        return False
    return bool(HOSTNAME_REGEX.match(hostname))


def ip_in_network(ip: str, network: str) -> bool:
    """Check if an IP address is within a network range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        net_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in net_obj
    except ValueError:
        return False


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to IP addresses."""
    try:
        result = socket.getaddrinfo(hostname, None)
        return list(set(item[4][0] for item in result))
    except socket.gaierror:
        return []


def is_target_blocked(target: str) -> tuple[bool, str]:
    """
    Check if a target is in the blocked list.
    Returns (is_blocked, reason).
    """
    blocked = get_blocked_targets()

    for pattern in blocked:
        # Check direct match
        if target == pattern:
            return True, f"Target '{target}' is explicitly blocked"

        # Check wildcard match
        if fnmatch(target, pattern):
            return True, f"Target '{target}' matches blocked pattern '{pattern}'"

        # Check if pattern is a network and target is an IP
        if is_valid_network(pattern):
            # If target is an IP, check directly
            if is_valid_ip(target):
                if ip_in_network(target, pattern):
                    return True, f"Target '{target}' is in blocked network '{pattern}'"
            # If target is a hostname, resolve and check
            elif is_valid_hostname(target):
                for ip in resolve_hostname(target):
                    if ip_in_network(ip, pattern):
                        return True, f"Target '{target}' resolves to '{ip}' which is in blocked network '{pattern}'"

    return False, ""


def is_target_allowed(target: str) -> tuple[bool, str]:
    """
    Check if a target is in the allowed list.
    Returns (is_allowed, reason).

    If no allowed targets are configured, all non-blocked targets are allowed.
    """
    allowed = get_allowed_targets()

    # If no allowlist configured, allow everything (that's not blocked)
    if not allowed:
        return True, "No allowlist configured"

    for pattern in allowed:
        # Check direct match
        if target == pattern:
            return True, f"Target matches allowed pattern '{pattern}'"

        # Check wildcard match
        if fnmatch(target, pattern):
            return True, f"Target matches allowed pattern '{pattern}'"

        # Check if pattern is a network and target is an IP
        if is_valid_network(pattern):
            if is_valid_ip(target):
                if ip_in_network(target, pattern):
                    return True, f"Target is in allowed network '{pattern}'"
            elif is_valid_hostname(target):
                for ip in resolve_hostname(target):
                    if ip_in_network(ip, pattern):
                        return True, f"Target resolves to IP in allowed network '{pattern}'"

    return False, f"Target '{target}' is not in the allowed list"


def sanitize_input(value: str) -> str:
    """
    Sanitize a string input by removing dangerous characters.
    Returns the sanitized string.

    This is a safety net - inputs should be validated before this.
    """
    if not isinstance(value, str):
        raise ValueError(f"Expected string, got {type(value).__name__}")

    # Remove any dangerous characters
    sanitized = "".join(c for c in value if c not in DANGEROUS_CHARS)

    # Collapse multiple spaces
    sanitized = " ".join(sanitized.split())

    return sanitized.strip()


def validate_target(target: str, allow_url: bool = False) -> str:
    """
    Validate and extract a target (hostname or IP) from input.

    Args:
        target: The target string to validate
        allow_url: If True, URLs are accepted and the hostname is extracted

    Returns:
        The validated target (hostname or IP)

    Raises:
        ValueError: If the target is invalid
        PermissionError: If the target is not allowed
    """
    if not target:
        raise ValueError("Target cannot be empty")

    target = target.strip()

    # Extract hostname from URL if needed
    if allow_url and (target.startswith("http://") or target.startswith("https://")):
        parsed = urlparse(target)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Invalid URL: {target}")
        target_to_check = hostname
    else:
        # Remove any protocol prefix if present (shouldn't be for non-URL targets)
        if "://" in target:
            raise ValueError(f"Invalid target format. Use hostname or IP, not URL: {target}")

        # Handle host:port format
        if ":" in target and not target.startswith("["):
            target_to_check = target.rsplit(":", 1)[0]
        else:
            target_to_check = target

    # Validate format
    if not is_valid_ip(target_to_check) and not is_valid_hostname(target_to_check):
        raise ValueError(f"Invalid target format: {target_to_check}")

    # Check blocked list first
    is_blocked, reason = is_target_blocked(target_to_check)
    if is_blocked:
        raise PermissionError(reason)

    # Check allowed list
    is_allowed, reason = is_target_allowed(target_to_check)
    if not is_allowed:
        raise PermissionError(reason)

    return target


def validate_url(url: str) -> str:
    """
    Validate a URL and ensure the target is allowed.

    Args:
        url: The URL to validate

    Returns:
        The validated URL

    Raises:
        ValueError: If the URL is invalid
        PermissionError: If the target is not allowed
    """
    if not url:
        raise ValueError("URL cannot be empty")

    url = url.strip()

    # Must be HTTP or HTTPS
    if not url.startswith("http://") and not url.startswith("https://"):
        raise ValueError("URL must start with http:// or https://")

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError(f"Invalid URL: {url}")

    # Validate the hostname/target
    validate_target(parsed.hostname)

    # Basic URL sanitization - remove any obviously dangerous content
    if any(c in url for c in ['<', '>', '"', "'", '\n', '\r']):
        raise ValueError("URL contains invalid characters")

    return url


def validate_port_spec(ports: str) -> str:
    """
    Validate a port specification string.

    Valid formats:
    - Single port: "80"
    - Port range: "1-1000"
    - Port list: "22,80,443"
    - Nmap format: "T:80,443,U:53"

    Args:
        ports: The port specification to validate

    Returns:
        The validated port specification

    Raises:
        ValueError: If the format is invalid
    """
    if not ports:
        raise ValueError("Port specification cannot be empty")

    ports = ports.strip()

    # Check for valid characters only
    if not PORT_SPEC_REGEX.match(ports):
        raise ValueError(f"Invalid port specification format: {ports}")

    # Validate individual ports are in valid range
    # Extract all numbers from the spec
    numbers = re.findall(r'\d+', ports)
    for num in numbers:
        port = int(num)
        if port < 1 or port > 65535:
            raise ValueError(f"Port {port} is out of valid range (1-65535)")

    return ports


def validate_wordlist_choice(choice: str, valid_choices: list[str]) -> str:
    """
    Validate a wordlist choice against allowed options.

    Args:
        choice: The user's choice
        valid_choices: List of valid options

    Returns:
        The validated choice

    Raises:
        ValueError: If the choice is not valid
    """
    if not choice:
        raise ValueError("Wordlist choice cannot be empty")

    choice = choice.strip().lower()

    if choice not in [c.lower() for c in valid_choices]:
        raise ValueError(f"Invalid wordlist choice '{choice}'. Valid options: {', '.join(valid_choices)}")

    return choice


def validate_integer_range(value: int, min_val: int, max_val: int, name: str) -> int:
    """
    Validate an integer is within a specified range.

    Args:
        value: The value to validate
        min_val: Minimum allowed value (inclusive)
        max_val: Maximum allowed value (inclusive)
        name: Name of the parameter for error messages

    Returns:
        The validated integer

    Raises:
        ValueError: If the value is out of range
    """
    if not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")

    if value < min_val or value > max_val:
        raise ValueError(f"{name} must be between {min_val} and {max_val}")

    return value
