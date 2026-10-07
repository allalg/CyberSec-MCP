"""Base Tool abstraction — implements the uniform 5-step security pipeline.

Pipeline:
1. Input validation & sanitization
2. Policy evaluation (gatekeeper)
3. Sandboxed execution (Docker container)
4. Structured output parsing
5. Immutable audit logging
"""

from __future__ import annotations

import abc
import logging
import time
from typing import Any

from server.models import (
    ExecutionStatus,
    PolicyDecision,
    SandboxProfile,
    ToolRequest,
    ToolResult,
)
from server.sandbox.manager import SandboxManager
from server.sandbox.profiles import get_profile
from server.security.audit import AuditLogger
from server.security.policy import PolicyEngine

logger = logging.getLogger(__name__)


class BaseTool(abc.ABC):
    """Abstract base class for all cybersecurity tools."""

    name: str
    description: str
    risk_level: str = "medium"

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        sandbox_manager: SandboxManager | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.audit_logger = audit_logger or AuditLogger()

    @property
    def sandbox_profile(self) -> SandboxProfile:
        """Lookup default sandbox profile for this tool."""
        return get_profile(self.name)

    @abc.abstractmethod
    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        """Validate and sanitize arguments specific to this tool.

        Raises:
            ValidationError on disallowed or malformed arguments.
        """
        ...

    @abc.abstractmethod
    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        """Construct the command line list to execute inside the sandbox container."""
        ...

    @abc.abstractmethod
    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Parse raw stdout from container into (findings, summary)."""
        ...

    async def execute(self, request: ToolRequest) -> ToolResult:
        """Execute tool through the controlled security pipeline.

        Returns:
            ToolResult containing structured findings, timing metrics, and status.
        """
        start_time = time.monotonic()
        timing: dict[str, float] = {}

        # ── Step 1: Input Validation ──────────────────────────────────
        t0 = time.monotonic()
        try:
            validated_args = self.validate_arguments(request)
        except Exception as e:
            logger.warning("Tool %s validation failed: %s", self.name, e)
            duration_ms = int((time.monotonic() - start_time) * 1000)
            res = ToolResult(
                tool_name=self.name,
                target=request.target,
                status=ExecutionStatus.ERROR,
                duration_ms=duration_ms,
                request_id=request.request_id,
                error=f"Validation failed: {e}",
            )
            await self.audit_logger.log_attempt(
                request=request,
                policy_decision="validation_failed",
                status=ExecutionStatus.ERROR.value,
                duration_ms=duration_ms,
                error=str(e),
            )
            return res
        timing["validation_ms"] = round((time.monotonic() - t0) * 1000, 2)

        # ── Step 2: Policy Evaluation ─────────────────────────────────
        t0 = time.monotonic()
        decision: PolicyDecision = self.policy_engine.evaluate(request)
        timing["policy_ms"] = round((time.monotonic() - t0) * 1000, 2)

        if not decision.allowed:
            logger.info("Tool %s denied by policy: %s", self.name, decision.reason)
            duration_ms = int((time.monotonic() - start_time) * 1000)
            status = (
                ExecutionStatus.PENDING_APPROVAL
                if "approval" in decision.reason.lower()
                else ExecutionStatus.DENIED
            )
            res = ToolResult(
                tool_name=self.name,
                target=request.target,
                status=status,
                duration_ms=duration_ms,
                request_id=request.request_id,
                error=decision.reason,
                metadata={"timing_ms": timing},
            )
            await self.audit_logger.log_attempt(
                request=request,
                policy_decision="approved" if decision.allowed else "denied",
                status=status.value,
                duration_ms=duration_ms,
                error=decision.reason,
            )
            return res

        # ── Step 3: Command Construction & Sandbox Execution ─────────
        cmd = self.build_command(validated_args, request.target)
        t0 = time.monotonic()
        sandbox_res = await self.sandbox_manager.execute(
            tool_name=self.name,
            command=cmd,
            timeout=decision.timeout,
            profile=self.sandbox_profile,
        )
        timing["sandbox_ms"] = round((time.monotonic() - t0) * 1000, 2)

        # Handle Timeout or Container Error
        if sandbox_res.timed_out:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            timing["total_ms"] = duration_ms
            res = ToolResult(
                tool_name=self.name,
                target=request.target,
                status=ExecutionStatus.TIMEOUT,
                duration_ms=duration_ms,
                raw_output=sandbox_res.stdout or sandbox_res.stderr,
                request_id=request.request_id,
                error=f"Execution timed out after {decision.timeout}s",
                metadata={"timing_ms": timing, "container_id": sandbox_res.container_id},
            )
            await self.audit_logger.log_attempt(
                request=request,
                policy_decision="approved",
                status=ExecutionStatus.TIMEOUT.value,
                duration_ms=duration_ms,
                sandbox_id=sandbox_res.container_id,
                error="Timeout exceeded",
            )
            return res

        if sandbox_res.exit_code != 0 and not sandbox_res.stdout:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            timing["total_ms"] = duration_ms
            res = ToolResult(
                tool_name=self.name,
                target=request.target,
                status=ExecutionStatus.ERROR,
                duration_ms=duration_ms,
                raw_output=sandbox_res.stderr,
                request_id=request.request_id,
                error=f"Process exited with code {sandbox_res.exit_code}: {sandbox_res.stderr.strip()}",
                metadata={"timing_ms": timing, "container_id": sandbox_res.container_id},
            )
            await self.audit_logger.log_attempt(
                request=request,
                policy_decision="approved",
                status=ExecutionStatus.ERROR.value,
                duration_ms=duration_ms,
                sandbox_id=sandbox_res.container_id,
                error=sandbox_res.stderr[:200],
            )
            return res

        # ── Step 4: Output Parsing ────────────────────────────────────
        t0 = time.monotonic()
        findings, summary = self.parse_output(sandbox_res.stdout)
        timing["parsing_ms"] = round((time.monotonic() - t0) * 1000, 2)

        # ── Step 5: Final Result & Audit Log ──────────────────────────
        duration_ms = int((time.monotonic() - start_time) * 1000)
        timing["total_ms"] = duration_ms

        metadata: dict[str, Any] = {
            "timing_ms": timing,
            "container_id": sandbox_res.container_id,
            "summary": summary,
        }

        result = ToolResult(
            tool_name=self.name,
            target=request.target,
            status=ExecutionStatus.SUCCESS,
            duration_ms=duration_ms,
            findings=findings,
            raw_output=sandbox_res.stdout,
            request_id=request.request_id,
            metadata=metadata,
        )

        await self.audit_logger.log_attempt(
            request=request,
            policy_decision="approved",
            status=ExecutionStatus.SUCCESS.value,
            duration_ms=duration_ms,
            sandbox_id=sandbox_res.container_id,
            findings_count=len(findings),
        )

        return result
