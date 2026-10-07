"""Policy Engine — the security gate between every tool request and execution.

Every request must pass through PolicyEngine.evaluate() before reaching a sandbox.
No request bypasses policy.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path

import yaml

from server.models import (
    AllowedTargets,
    PolicyConfig,
    PolicyDecision,
    PolicyRule,
    RiskLevel,
    ToolRequest,
)

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Evaluates tool requests against security policy rules.

    Flow:
        Tool Request
          → is_tool_allowed?
          → is_target_allowed?
          → are_arguments_valid?
          → does_tool_require_approval?
          → resource_limits
          → APPROVED / DENIED / PENDING_APPROVAL
    """

    def __init__(self, config: PolicyConfig | None = None, config_path: str | None = None):
        if config is not None:
            self._config = config
        elif config_path is not None:
            self._config = self._load_config(Path(config_path))
        else:
            self._config = PolicyConfig()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    @staticmethod
    def _load_config(path: Path) -> PolicyConfig:
        """Load policy configuration from a YAML file."""
        if not path.exists():
            logger.warning("Policy config not found at %s, using defaults", path)
            return PolicyConfig()

        with open(path) as f:
            raw = yaml.safe_load(f) or {}

        return PolicyConfig(**raw)

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def is_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check if the tool is registered in the policy config."""
        if tool_name not in self._config.tools:
            return False, f"Unknown tool: {tool_name!r}. Allowed: {list(self._config.tools.keys())}"
        return True, ""

    def is_target_allowed(self, target: str) -> tuple[bool, str]:
        """Check target against allowed networks and domain patterns."""
        allowed = self._config.allowed_targets

        # Try as IP first
        if allowed.is_ip_allowed(target):
            return True, ""

        # Try as domain
        if allowed.is_domain_allowed(target):
            return True, ""

        return False, (
            f"Target {target!r} is not in the allowed list. "
            f"Only private/lab targets are permitted."
        )

    def validate_arguments(self, tool_name: str, arguments: dict) -> tuple[bool, str]:
        """Check tool arguments against blocked flags."""
        rule = self._config.tools.get(tool_name)
        if rule is None:
            return False, f"No policy rule for tool {tool_name!r}"

        if not rule.blocked_flags:
            return True, ""

        # Check all argument values for blocked flags
        for key, value in arguments.items():
            str_val = str(value)
            for blocked in rule.blocked_flags:
                # Support glob patterns like "--script=exploit*"
                if fnmatch.fnmatch(str_val, blocked):
                    return False, f"Blocked flag detected: {str_val!r} matches {blocked!r}"
                # Also check if the blocked flag appears as a substring in flags-type args
                if key == "flags" and isinstance(value, (list, str)):
                    flags = value if isinstance(value, list) else value.split()
                    for flag in flags:
                        if fnmatch.fnmatch(flag, blocked):
                            return False, f"Blocked flag detected: {flag!r} matches {blocked!r}"

        return True, ""

    def check_approval(self, tool_name: str) -> tuple[bool, str]:
        """Check if the tool requires explicit user approval."""
        rule = self._config.tools.get(tool_name)
        if rule is None:
            return True, "Unknown tool requires approval"

        if rule.requires_approval:
            return True, f"Tool {tool_name!r} (risk={rule.risk.value}) requires explicit approval"

        return False, ""

    def get_resource_limits(self, tool_name: str) -> PolicyRule:
        """Get resource limits (timeout, concurrency) for a tool."""
        return self._config.tools.get(tool_name, PolicyRule())

    # ------------------------------------------------------------------
    # Main evaluator
    # ------------------------------------------------------------------

    def evaluate(self, request: ToolRequest) -> PolicyDecision:
        """Evaluate a tool request against all policy rules.

        Returns a PolicyDecision with allowed=True/False and reason.
        """
        # 1. Is tool registered?
        allowed, reason = self.is_tool_allowed(request.tool_name)
        if not allowed:
            logger.warning("DENIED (unknown tool): %s", reason)
            return PolicyDecision(allowed=False, reason=reason)

        # 2. Is target allowed?
        allowed, reason = self.is_target_allowed(request.target)
        if not allowed:
            logger.warning("DENIED (unauthorized target): %s", reason)
            return PolicyDecision(allowed=False, reason=reason)

        # 3. Are arguments valid?
        allowed, reason = self.validate_arguments(request.tool_name, request.arguments)
        if not allowed:
            logger.warning("DENIED (blocked arguments): %s", reason)
            return PolicyDecision(allowed=False, reason=reason)

        # 4. Does tool require approval?
        needs_approval, reason = self.check_approval(request.tool_name)
        if needs_approval:
            rule = self._config.tools[request.tool_name]
            logger.info("PENDING_APPROVAL: %s", reason)
            return PolicyDecision(
                allowed=False,
                reason=reason,
                timeout=rule.timeout,
                risk_level=rule.risk,
            )

        # 5. All checks passed — approved
        rule = self._config.tools[request.tool_name]
        logger.info(
            "APPROVED: tool=%s target=%s risk=%s",
            request.tool_name, request.target, rule.risk.value,
        )
        return PolicyDecision(
            allowed=True,
            reason="All policy checks passed",
            timeout=rule.timeout,
            risk_level=rule.risk,
        )

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @property
    def registered_tools(self) -> list[str]:
        """List all tools registered in the policy config."""
        return list(self._config.tools.keys())

    @property
    def config(self) -> PolicyConfig:
        return self._config

    @config.setter
    def config(self, value: PolicyConfig) -> None:
        self._config = value
