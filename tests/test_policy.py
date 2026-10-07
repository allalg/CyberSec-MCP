"""Unit tests for the PolicyEngine security gatekeeper."""

from __future__ import annotations

import pytest

from server.models import PolicyConfig, PolicyRule, RiskLevel, ToolRequest
from server.security.policy import PolicyEngine


def test_evaluate_approved_request(policy_engine: PolicyEngine):
    req = ToolRequest(
        tool_name="nmap_scan",
        target="192.168.1.100",
        arguments={"ports": "80,443"},
    )
    decision = policy_engine.evaluate(req)
    assert decision.allowed is True
    assert decision.risk_level == RiskLevel.MEDIUM
    assert decision.timeout == 120


def test_evaluate_unknown_tool(policy_engine: PolicyEngine):
    req = ToolRequest(
        tool_name="nonexistent_tool",
        target="192.168.1.100",
    )
    decision = policy_engine.evaluate(req)
    assert decision.allowed is False
    assert "Unknown tool" in decision.reason


def test_evaluate_unauthorized_target(policy_engine: PolicyEngine):
    req = ToolRequest(
        tool_name="nmap_scan",
        target="8.8.8.8",
    )
    decision = policy_engine.evaluate(req)
    assert decision.allowed is False
    assert "not in the allowed list" in decision.reason


def test_evaluate_blocked_flags(policy_engine: PolicyEngine):
    req = ToolRequest(
        tool_name="nmap_scan",
        target="192.168.1.50",
        arguments={"flags": "-sE"},
    )
    decision = policy_engine.evaluate(req)
    assert decision.allowed is False
    assert "Blocked flag" in decision.reason


def test_evaluate_blocked_wildcard_flags(policy_engine: PolicyEngine):
    req = ToolRequest(
        tool_name="nmap_scan",
        target="192.168.1.50",
        arguments={"flags": "--script=exploit/smb"},
    )
    decision = policy_engine.evaluate(req)
    assert decision.allowed is False
    assert "Blocked flag" in decision.reason


def test_evaluate_requires_approval(policy_engine: PolicyEngine):
    req = ToolRequest(
        tool_name="critical_tool",
        target="192.168.1.50",
    )
    decision = policy_engine.evaluate(req)
    assert decision.allowed is False
    assert "requires explicit approval" in decision.reason
