"""Unit and integration tests for cybersecurity tools execution pipeline."""

from __future__ import annotations

import pytest

from server.models import ExecutionStatus, ToolRequest
from server.sandbox.manager import SandboxManager
from server.security.audit import AuditLogger
from server.security.policy import PolicyEngine
from server.tools.base import BaseTool
from server.tools.recon import DnsLookupTool, NmapScanTool
from server.tools.registry import ToolRegistry
from server.tools.web import HttpProbeTool
from tests.conftest import MockDockerBackend


@pytest.mark.asyncio
async def test_tool_registry_initialization():
    registry = ToolRegistry.create_default()
    names = registry.tool_names()
    assert "nmap_scan" in names
    assert "dns_lookup" in names
    assert "whois_lookup" in names
    assert "http_probe" in names
    assert "directory_scan" in names
    assert "hash_file" in names
    assert len(names) == 6


@pytest.mark.asyncio
async def test_nmap_tool_pipeline_success(policy_engine: PolicyEngine, temp_audit_logger: AuditLogger):
    sample_xml = """<?xml version="1.0"?>
    <nmaprun><host><status state="up"/><ports>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports></host></nmaprun>"""

    mock_backend = MockDockerBackend(stdout=sample_xml)
    sandbox_manager = SandboxManager(docker_backend=mock_backend)

    tool = NmapScanTool(
        policy_engine=policy_engine,
        sandbox_manager=sandbox_manager,
        audit_logger=temp_audit_logger,
    )

    req = ToolRequest(
        tool_name="nmap_scan",
        target="192.168.1.100",
        arguments={"ports": "80"},
    )

    result = await tool.execute(req)
    assert result.status == ExecutionStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0]["port"] == 80
    assert result.findings[0]["service"] == "http"
    assert "timing_ms" in result.metadata
    assert mock_backend.executed_commands  # verified command executed


@pytest.mark.asyncio
async def test_tool_policy_denied(policy_engine: PolicyEngine, temp_audit_logger: AuditLogger):
    mock_backend = MockDockerBackend()
    sandbox_manager = SandboxManager(docker_backend=mock_backend)

    tool = NmapScanTool(
        policy_engine=policy_engine,
        sandbox_manager=sandbox_manager,
        audit_logger=temp_audit_logger,
    )

    # Public IP target is denied by policy
    req = ToolRequest(
        tool_name="nmap_scan",
        target="8.8.8.8",
        arguments={"ports": "80"},
    )

    result = await tool.execute(req)
    assert result.status == ExecutionStatus.DENIED
    assert "not in the allowed list" in result.error
    assert len(mock_backend.executed_commands) == 0  # Sandbox NEVER reached


@pytest.mark.asyncio
async def test_tool_timeout_handling(policy_engine: PolicyEngine, temp_audit_logger: AuditLogger):
    mock_backend = MockDockerBackend(timed_out=True)
    sandbox_manager = SandboxManager(docker_backend=mock_backend)

    tool = DnsLookupTool(
        policy_engine=policy_engine,
        sandbox_manager=sandbox_manager,
        audit_logger=temp_audit_logger,
    )

    req = ToolRequest(
        tool_name="dns_lookup",
        target="lab.local",
    )

    result = await tool.execute(req)
    assert result.status == ExecutionStatus.TIMEOUT
    assert "timed out" in result.error


@pytest.mark.asyncio
async def test_hash_file_tool_text_payload(policy_engine: PolicyEngine, temp_audit_logger: AuditLogger):
    sample_output = "8ead59be3b2925833cbdf612c35f11c13b47de9de3e67a9b153e842dd9179a6a  -\n"
    mock_backend = MockDockerBackend(stdout=sample_output)
    sandbox_manager = SandboxManager(docker_backend=mock_backend)

    from server.tools.analysis import HashFileTool
    tool = HashFileTool(
        policy_engine=policy_engine,
        sandbox_manager=sandbox_manager,
        audit_logger=temp_audit_logger,
    )

    req = ToolRequest(
        tool_name="hash_file",
        target="payload",
        arguments={"text": "Hello, CyberSec MCP!"},
    )

    result = await tool.execute(req)
    assert result.status == ExecutionStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0]["sha256"] == "8ead59be3b2925833cbdf612c35f11c13b47de9de3e67a9b153e842dd9179a6a"

