"""Unit tests for the SQLite-backed AuditLogger."""

from __future__ import annotations

import pytest

from server.models import ExecutionStatus, ToolRequest, ToolResult
from server.security.audit import AuditLogger


@pytest.mark.asyncio
async def test_audit_log_and_query(temp_audit_logger: AuditLogger):
    req = ToolRequest(
        tool_name="nmap_scan",
        target="192.168.1.100",
        arguments={"ports": "80"},
        session_id="session-alpha",
    )

    result = ToolResult(
        tool_name="nmap_scan",
        target="192.168.1.100",
        status=ExecutionStatus.SUCCESS,
        duration_ms=250,
        findings=[{"port": 80, "state": "open"}],
        request_id=req.request_id,
    )

    await temp_audit_logger.log(req, result=result, policy_decision="approved")

    # Query recent
    entries = await temp_audit_logger.get_recent(limit=10)
    assert len(entries) == 1
    assert entries[0]["tool_name"] == "nmap_scan"
    assert entries[0]["status"] == "success"
    assert entries[0]["findings_count"] == 1
    assert entries[0]["session_id"] == "session-alpha"


@pytest.mark.asyncio
async def test_audit_session_filtering(temp_audit_logger: AuditLogger):
    req1 = ToolRequest(
        tool_name="dns_lookup",
        target="lab.local",
        session_id="session-1",
    )
    req2 = ToolRequest(
        tool_name="http_probe",
        target="172.28.0.10",
        session_id="session-2",
    )

    await temp_audit_logger.log_attempt(req1, policy_decision="approved", status="success")
    await temp_audit_logger.log_attempt(req2, policy_decision="approved", status="success")

    s1_entries = await temp_audit_logger.get_session("session-1")
    assert len(s1_entries) == 1
    assert s1_entries[0]["tool_name"] == "dns_lookup"

    s2_entries = await temp_audit_logger.get_session("session-2")
    assert len(s2_entries) == 1
    assert s2_entries[0]["tool_name"] == "http_probe"


@pytest.mark.asyncio
async def test_audit_stats(temp_audit_logger: AuditLogger):
    req1 = ToolRequest(tool_name="nmap_scan", target="192.168.1.10")
    req2 = ToolRequest(tool_name="nmap_scan", target="192.168.1.10")
    await temp_audit_logger.log_attempt(req1, status="success", duration_ms=100)
    await temp_audit_logger.log_attempt(req2, status="denied", duration_ms=5)

    stats = await temp_audit_logger.get_stats()
    assert stats["total_executions"] == 2
    assert stats["by_status"]["success"] == 1
    assert stats["by_status"]["denied"] == 1
    assert stats["by_tool"]["nmap_scan"] == 2
