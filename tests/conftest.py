"""Pytest fixtures for CyberSec MCP tests."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import AsyncGenerator

import pytest

from server.models import AllowedTargets, PolicyConfig, PolicyRule, RiskLevel, SandboxResult
from server.sandbox.manager import SandboxManager
from server.security.audit import AuditLogger
from server.security.policy import PolicyEngine


class MockDockerBackend:
    """Mock Docker backend that returns predefined results without running real containers."""

    def __init__(self, stdout: str = "", stderr: str = "", exit_code: int = 0, timed_out: bool = False):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.executed_commands: list[list[str]] = []

    def image_exists(self, image_name: str) -> bool:
        return True

    async def execute(self, profile, command, timeout=None, volumes=None):
        self.executed_commands.append(command)
        return SandboxResult(
            stdout=self.stdout,
            stderr=self.stderr,
            exit_code=self.exit_code,
            duration_ms=50,
            timed_out=self.timed_out,
            container_id="mock-container-12345",
        )


@pytest.fixture
def sample_allowed_targets() -> AllowedTargets:
    return AllowedTargets(
        networks=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
        domains=["*.lab.local", "*.test", "localhost"],
    )


@pytest.fixture
def sample_policy_config(sample_allowed_targets: AllowedTargets) -> PolicyConfig:
    return PolicyConfig(
        tools={
            "nmap_scan": PolicyRule(
                risk=RiskLevel.MEDIUM,
                requires_approval=False,
                timeout=120,
                blocked_flags=["-sE", "--script=exploit*"],
            ),
            "dns_lookup": PolicyRule(
                risk=RiskLevel.LOW,
                requires_approval=False,
                timeout=30,
            ),
            "critical_tool": PolicyRule(
                risk=RiskLevel.CRITICAL,
                requires_approval=True,
                timeout=60,
            ),
        },
        allowed_targets=sample_allowed_targets,
    )


@pytest.fixture
def policy_engine(sample_policy_config: PolicyConfig) -> PolicyEngine:
    engine = PolicyEngine()
    engine.config = sample_policy_config
    return engine


@pytest.fixture
async def temp_audit_logger() -> AsyncGenerator[AuditLogger, None]:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    logger = AuditLogger(db_path=db_path)
    yield logger
    # Cleanup temp db
    Path(db_path).unlink(missing_ok=True)
