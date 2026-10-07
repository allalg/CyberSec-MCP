"""Unit tests for input validation and sanitization security layer."""

from __future__ import annotations

import pytest

from server.models import AllowedTargets
from server.security.validation import (
    ValidationError,
    validate_arguments,
    validate_file_path,
    validate_http_method,
    validate_port_spec,
    validate_record_type,
    validate_scan_type,
    validate_target,
)


@pytest.fixture
def targets() -> AllowedTargets:
    return AllowedTargets(
        networks=["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"],
        domains=["*.lab.local", "localhost"],
    )


def test_validate_target_valid_ip(targets: AllowedTargets):
    assert validate_target("192.168.1.100", targets) == "192.168.1.100"
    assert validate_target("127.0.0.1", targets) == "127.0.0.1"


def test_validate_target_valid_domain(targets: AllowedTargets):
    assert validate_target("target.lab.local", targets) == "target.lab.local"
    assert validate_target("localhost", targets) == "localhost"


def test_validate_target_unauthorized_ip(targets: AllowedTargets):
    with pytest.raises(ValidationError, match="not in the allowed networks"):
        validate_target("8.8.8.8", targets)

    with pytest.raises(ValidationError, match="not in the allowed networks"):
        validate_target("1.1.1.1", targets)


def test_validate_target_unauthorized_domain(targets: AllowedTargets):
    with pytest.raises(ValidationError, match="not in the allowed domains"):
        validate_target("example.com", targets)


def test_validate_target_shell_injection(targets: AllowedTargets):
    malicious = [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && whoami",
        "192.168.1.1 | cat /etc/passwd",
        "`id`",
        "$(id).lab.local",
        "192.168.1.1\ncat /etc/shadow",
    ]
    for payload in malicious:
        with pytest.raises(ValidationError, match="Shell injection detected"):
            validate_target(payload, targets)


def test_validate_port_spec():
    assert validate_port_spec("80") == "80"
    assert validate_port_spec("1-1024") == "1-1024"
    assert validate_port_spec("22,80,443") == "22,80,443"

    # Out of range
    with pytest.raises(ValidationError, match="Port out of range"):
        validate_port_spec("70000")

    # Inverted range
    with pytest.raises(ValidationError, match="start > end"):
        validate_port_spec("100-50")

    # Shell injection in port
    with pytest.raises(ValidationError, match="Shell injection detected"):
        validate_port_spec("80; id")


def test_validate_file_path():
    assert validate_file_path("/tmp/test.txt", allowed_dir="/tmp") == "/tmp/test.txt"

    # Path traversal attack
    with pytest.raises(ValidationError, match="Path traversal detected"):
        validate_file_path("/tmp/../../etc/passwd", allowed_dir="/tmp")

    # Outside allowed directory
    with pytest.raises(ValidationError, match="outside allowed directory"):
        validate_file_path("/var/log/syslog", allowed_dir="/tmp")


def test_validate_arguments():
    safe = {"key": "value", "list": ["a", "b"], "num": 42}
    result = validate_arguments(safe, "test_tool")
    assert result == safe

    # Injection in value
    with pytest.raises(ValidationError, match="Shell injection detected"):
        validate_arguments({"flag": "-sV; touch /tmp/pwned"}, "test_tool")

    # Injection in list
    with pytest.raises(ValidationError, match="Shell injection detected"):
        validate_arguments({"items": ["safe", "malicious; ls"]}, "test_tool")


def test_validate_enums():
    assert validate_http_method("get") == "GET"
    with pytest.raises(ValidationError):
        validate_http_method("PUT")  # Non-safe probe method

    assert validate_record_type("a") == "A"
    with pytest.raises(ValidationError):
        validate_record_type("INVALID")

    assert validate_scan_type("CONNECT") == "connect"
    with pytest.raises(ValidationError):
        validate_scan_type("exploit")
