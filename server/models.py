"""Pydantic models — data contracts for requests, results, policies, audit, and sandbox profiles."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Risk classification for tools."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(str, Enum):
    """Outcome of a tool execution."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"


# ---------------------------------------------------------------------------
# Tool Request / Result
# ---------------------------------------------------------------------------

class ToolRequest(BaseModel):
    """Incoming request to execute a cybersecurity tool."""
    tool_name: str
    target: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    request_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str | None = None

    @field_validator("tool_name")
    @classmethod
    def tool_name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("tool_name must not be empty")
        return v.strip().lower()

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target must not be empty")
        return v.strip()


class Finding(BaseModel):
    """A single finding from tool execution (flexible schema per tool)."""
    data: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    """Structured result returned to the AI agent."""
    tool_name: str
    target: str
    status: ExecutionStatus
    duration_ms: int = 0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    raw_output: str | None = None
    request_id: UUID
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)  # latency breakdown etc.


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class PolicyRule(BaseModel):
    """Policy rule for a single tool."""
    risk: RiskLevel = RiskLevel.MEDIUM
    requires_approval: bool = False
    timeout: int = 120  # seconds
    blocked_flags: list[str] = Field(default_factory=list)
    max_concurrent: int = 2


class AllowedTargets(BaseModel):
    """Allowlisted networks and domain patterns."""
    networks: list[str] = Field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"
    ])
    domains: list[str] = Field(default_factory=lambda: [
        "*.lab.local", "*.test", "localhost"
    ])

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Check if an IP address falls within any allowed network."""
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(
            ip in ipaddress.ip_network(net, strict=False)
            for net in self.networks
        )

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain matches any allowed pattern."""
        domain = domain.lower().strip()
        for pattern in self.domains:
            pattern = pattern.lower().strip()
            if pattern.startswith("*."):
                # Wildcard: *.lab.local matches foo.lab.local and lab.local
                suffix = pattern[1:]  # .lab.local
                if domain.endswith(suffix) or domain == pattern[2:]:
                    return True
            elif domain == pattern:
                return True
        return False


class PolicyConfig(BaseModel):
    """Top-level policy configuration loaded from YAML."""
    tools: dict[str, PolicyRule] = Field(default_factory=dict)
    allowed_targets: AllowedTargets = Field(default_factory=AllowedTargets)


class PolicyDecision(BaseModel):
    """Result of evaluating a request against policy."""
    allowed: bool
    reason: str = ""
    timeout: int = 120
    risk_level: RiskLevel = RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class SandboxProfile(BaseModel):
    """Configuration for a Docker-based sandbox container."""
    image_name: str
    network_mode: str = "bridge"
    memory_limit: str = "128m"
    cpu_limit: float = 0.5
    timeout: int = 120
    read_only_fs: bool = True
    allowed_env: list[str] = Field(default_factory=list)


class SandboxResult(BaseModel):
    """Raw result from sandbox execution."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: int = 0
    timed_out: bool = False
    container_id: str | None = None


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

class AuditEntry(BaseModel):
    """Immutable audit log entry for every tool execution attempt."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str | None = None
    agent_id: str | None = None
    request_id: str
    tool_name: str
    target: str
    arguments: str = "{}"  # JSON string
    sandbox_id: str | None = None
    policy_decision: str  # "approved", "denied", "timeout"
    duration_ms: int = 0
    status: str  # ExecutionStatus value
    error: str | None = None
    findings_count: int = 0
