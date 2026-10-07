"""Tool Registry — auto-discovery, registration, and lookup for all MCP cybersecurity tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from server.tools.analysis import HashFileTool
from server.tools.base import BaseTool
from server.tools.recon import DnsLookupTool, NmapScanTool, WhoisLookupTool
from server.tools.web import DirectoryScanTool, HttpProbeTool

if TYPE_CHECKING:
    from server.sandbox.manager import SandboxManager
    from server.security.audit import AuditLogger
    from server.security.policy import PolicyEngine

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Central registry for discovering and accessing cybersecurity tools."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance."""
        if tool.name in self._tools:
            logger.warning("Overwriting existing tool registration: %s", tool.name)
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s", tool.name)

    def get(self, name: str) -> BaseTool | None:
        """Retrieve a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[BaseTool]:
        """Return all registered tools."""
        return list(self._tools.values())

    def tool_names(self) -> list[str]:
        """Return names of all registered tools."""
        return list(self._tools.keys())

    @classmethod
    def create_default(
        cls,
        policy_engine: PolicyEngine | None = None,
        sandbox_manager: SandboxManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> ToolRegistry:
        """Instantiate and register all 6 built-in cybersecurity tools."""
        registry = cls()
        default_tools: list[BaseTool] = [
            NmapScanTool(policy_engine, sandbox_manager, audit_logger),
            DnsLookupTool(policy_engine, sandbox_manager, audit_logger),
            WhoisLookupTool(policy_engine, sandbox_manager, audit_logger),
            HttpProbeTool(policy_engine, sandbox_manager, audit_logger),
            DirectoryScanTool(policy_engine, sandbox_manager, audit_logger),
            HashFileTool(policy_engine, sandbox_manager, audit_logger),
        ]
        for tool in default_tools:
            registry.register(tool)

        logger.info("Initialized default ToolRegistry with %d tools: %s", len(registry._tools), registry.tool_names())
        return registry
