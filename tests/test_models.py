"""Unit tests for Pydantic models and data validation contracts."""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from server.models import (
    AllowedTargets,
    AuditEntry,
    ExecutionStatus,
    PolicyDecision,
    PolicyRule,
    RiskLevel,
    SandboxProfile,
    ToolRequest,
    ToolResult,
)


def test_tool_request_validation():
    # Valid
    req = ToolRequest(tool_name="nmap_scan", target="192.168.1.1")
    assert req.tool_name == "nmap_scan"
    assert req.target == "192.168.1.1"
    assert req.arguments == {}
    assert req.request_id is not None

    # Empty tool name
    with pytest.raises(ValidationError):
        ToolRequest(tool_name="  ", target="192.168.1.1")

    # Empty target
    with pytest.raises(ValidationError):
        ToolRequest(tool_name="nmap_scan", target="")


def test_tool_result_serialization():
    req_id = uuid4()
    result = ToolResult(
        tool_name="nmap_scan",
        target="192.168.1.1",
        status=ExecutionStatus.SUCCESS,
        duration_ms=450,
        findings=[{"port": 80, "state": "open"}],
        request_id=req_id,
        metadata={"test": 123},
    )

    data = result.model_dump()
    assert data["tool_name"] == "nmap_scan"
    assert data["status"] == "success"
    assert data["duration_ms"] == 450
    assert len(data["findings"]) == 1

    # Verify JSON roundtrip
    json_str = result.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["tool_name"] == "nmap_scan"
    assert parsed["findings"][0]["port"] == 80


def test_allowed_targets():
    allowed = AllowedTargets(
        networks=["10.0.0.0/8", "192.168.0.0/16"],
        domains=["*.lab.local", "test.internal"],
    )

    # Allowed IPs
    assert allowed.is_ip_allowed("10.1.2.3") is True
    assert allowed.is_ip_allowed("192.168.1.50") is True

    # Denied IPs
    assert allowed.is_ip_allowed("8.8.8.8") is False
    assert allowed.is_ip_allowed("1.1.1.1") is False
    assert allowed.is_ip_allowed("invalid-ip") is False

    # Allowed domains
    assert allowed.is_domain_allowed("app.lab.local") is True
    assert allowed.is_domain_allowed("lab.local") is True
    assert allowed.is_domain_allowed("test.internal") is True

    # Denied domains
    assert allowed.is_domain_allowed("google.com") is False
    assert allowed.is_domain_allowed("evil.com") is False


def test_sandbox_profile_defaults():
    profile = SandboxProfile(image_name="cybersec-mcp/nmap:latest")
    assert profile.network_mode == "bridge"
    assert profile.memory_limit == "128m"
    assert profile.cpu_limit == 0.5
    assert profile.read_only_fs is True


def test_audit_entry():
    entry = AuditEntry(
        request_id="req-123",
        tool_name="nmap_scan",
        target="192.168.1.10",
        policy_decision="approved",
        status="success",
        duration_ms=120,
    )
    assert entry.tool_name == "nmap_scan"
    assert entry.findings_count == 0
    assert entry.timestamp is not None
