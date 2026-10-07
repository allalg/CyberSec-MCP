"""Input validation — sanitize all user-controlled input before it reaches any tool or sandbox.

Security-critical: every target, argument, and file path passes through here.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath

from server.models import AllowedTargets


class ValidationError(Exception):
    """Raised when input fails validation."""


# Characters that could enable shell injection
SHELL_METACHARACTERS = set(";|&`$(){}[]!><\n\r\\")

# Valid domain regex (RFC 1035 + practical usage)
DOMAIN_REGEX = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)

# Valid port range
PORT_MIN = 1
PORT_MAX = 65535


def _check_shell_injection(value: str, field_name: str = "input") -> None:
    """Reject any value containing shell metacharacters."""
    found = set(value) & SHELL_METACHARACTERS
    if found:
        raise ValidationError(
            f"Shell injection detected in {field_name}: "
            f"forbidden characters {found!r} in {value!r}"
        )


def validate_target(target: str, allowed_targets: AllowedTargets) -> str:
    """Validate and normalize a target string (IP or domain).

    Returns the cleaned target string or raises ValidationError.
    """
    target = target.strip()

    if not target:
        raise ValidationError("Target must not be empty")

    _check_shell_injection(target, "target")

    # Try as IP address
    try:
        ip = ipaddress.ip_address(target)

        # Reject multicast
        if ip.is_multicast:
            raise ValidationError(f"Multicast addresses not allowed: {target}")

        # Reject broadcast (IPv4 only)
        if hasattr(ip, "is_reserved") and str(ip) == "255.255.255.255":
            raise ValidationError(f"Broadcast address not allowed: {target}")

        # Check against allowlist
        if not allowed_targets.is_ip_allowed(target):
            raise ValidationError(
                f"IP {target} is not in the allowed networks. "
                f"Only private/lab targets are permitted."
            )

        return str(ip)

    except ValueError:
        pass  # Not an IP — try as domain

    # Try as domain
    if not DOMAIN_REGEX.match(target):
        raise ValidationError(f"Invalid domain format: {target!r}")

    if not allowed_targets.is_domain_allowed(target):
        raise ValidationError(
            f"Domain {target!r} is not in the allowed domains. "
            f"Only lab/test domains are permitted."
        )

    return target.lower()


def validate_port_spec(port_spec: str) -> str:
    """Validate a port specification (single, range, or comma-separated).

    Examples: "80", "1-1024", "22,80,443", "80,443,8000-9000"
    """
    port_spec = port_spec.strip()

    if not port_spec:
        raise ValidationError("Port specification must not be empty")

    _check_shell_injection(port_spec, "port_spec")

    parts = port_spec.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            # Range like "1-1024"
            range_parts = part.split("-")
            if len(range_parts) != 2:
                raise ValidationError(f"Invalid port range: {part!r}")
            try:
                start, end = int(range_parts[0]), int(range_parts[1])
            except ValueError:
                raise ValidationError(f"Non-numeric port range: {part!r}")
            if not (PORT_MIN <= start <= PORT_MAX and PORT_MIN <= end <= PORT_MAX):
                raise ValidationError(f"Port out of range (1-65535): {part!r}")
            if start > end:
                raise ValidationError(f"Invalid port range (start > end): {part!r}")
        else:
            # Single port
            try:
                port = int(part)
            except ValueError:
                raise ValidationError(f"Non-numeric port: {part!r}")
            if not (PORT_MIN <= port <= PORT_MAX):
                raise ValidationError(f"Port out of range (1-65535): {part!r}")

    return port_spec


def validate_file_path(file_path: str, allowed_dir: str = "/tmp/cybersec-mcp") -> str:
    """Validate a file path — prevent path traversal attacks.

    Only allows files within the allowed_dir.
    """
    file_path = file_path.strip()

    if not file_path:
        raise ValidationError("File path must not be empty")

    _check_shell_injection(file_path, "file_path")

    # Normalize and check for traversal
    normalized = PurePosixPath(file_path)

    if ".." in normalized.parts:
        raise ValidationError(f"Path traversal detected: {file_path!r}")

    # Must be absolute and within allowed directory
    if not str(normalized).startswith(allowed_dir):
        raise ValidationError(
            f"File path {file_path!r} is outside allowed directory {allowed_dir!r}"
        )

    return str(normalized)


def validate_arguments(arguments: dict, tool_name: str) -> dict:
    """General argument sanitizer — check all string values for injection."""
    sanitized = {}
    for key, value in arguments.items():
        # Validate key
        _check_shell_injection(str(key), f"argument key '{key}'")

        # For hash_file payload content, allow arbitrary text (it will be base64-isolated)
        if tool_name == "hash_file" and key in ("text", "content", "string", "input", "data"):
            sanitized[key] = str(value)
            continue

        # Validate string values
        if isinstance(value, str):
            _check_shell_injection(value, f"argument '{key}'")
            sanitized[key] = value.strip()
        elif isinstance(value, list):
            sanitized_list = []
            for item in value:
                if isinstance(item, str):
                    _check_shell_injection(item, f"argument '{key}' list item")
                    sanitized_list.append(item.strip())
                else:
                    sanitized_list.append(item)
            sanitized[key] = sanitized_list
        else:
            sanitized[key] = value

    return sanitized


def validate_record_type(record_type: str) -> str:
    """Validate DNS record type."""
    valid_types = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "ANY"}
    rt = record_type.strip().upper()
    if rt not in valid_types:
        raise ValidationError(f"Invalid DNS record type: {record_type!r}. Valid: {valid_types}")
    return rt


def validate_http_method(method: str) -> str:
    """Validate HTTP method."""
    valid = {"GET", "HEAD", "OPTIONS"}
    m = method.strip().upper()
    if m not in valid:
        raise ValidationError(f"Invalid HTTP method: {method!r}. Allowed: {valid}")
    return m


def validate_scan_type(scan_type: str) -> str:
    """Validate nmap scan type."""
    valid = {"syn", "connect", "udp", "ping"}
    st = scan_type.strip().lower()
    if st not in valid:
        raise ValidationError(f"Invalid scan type: {scan_type!r}. Allowed: {valid}")
    return st
