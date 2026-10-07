"""MCP Client interface for the custom security agent.

Allows the agent to discover tools and execute actions through CyberSec MCP
either in-process (fastest) or via standard MCP JSON-RPC protocol.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from server.models import ToolRequest
from server.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class LocalMCPClient:
    """In-process and protocol client for CyberSec MCP tools."""

    def __init__(self) -> None:
        self.registry = ToolRegistry.create_default()

    def get_tools_declarations(self) -> list[dict[str, Any]]:
        """Return tool definitions suitable for Gemini function calling."""
        declarations = []

        for tool in self.registry.list_tools():
            # Build parameter schema based on tool requirements
            if tool.name == "nmap_scan":
                properties = {
                    "target": {"type": "STRING", "description": "Target IP or hostname (e.g. 127.0.0.1, 172.28.0.10)"},
                    "ports": {"type": "STRING", "description": "Port spec e.g. '80', '1-1000', '22,80,443'"},
                    "scan_type": {"type": "STRING", "description": "Scan type: 'connect', 'syn', 'ping', 'udp'"},
                    "service_detection": {"type": "BOOLEAN", "description": "Probe open ports for service and version detection"},
                }
                required = ["target"]
            elif tool.name == "dns_lookup":
                properties = {
                    "target": {"type": "STRING", "description": "Domain name to resolve (e.g. lab.local)"},
                    "record_type": {"type": "STRING", "description": "Record type: 'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'"},
                    "server": {"type": "STRING", "description": "Optional DNS server IP to query"},
                }
                required = ["target"]
            elif tool.name == "whois_lookup":
                properties = {
                    "target": {"type": "STRING", "description": "Domain name or IP address"},
                }
                required = ["target"]
            elif tool.name == "http_probe":
                properties = {
                    "target": {"type": "STRING", "description": "Target URL or host (e.g. http://127.0.0.1:8000)"},
                    "method": {"type": "STRING", "description": "HTTP method ('GET', 'HEAD', 'OPTIONS')"},
                    "follow_redirects": {"type": "BOOLEAN", "description": "Follow HTTP redirects"},
                    "timeout": {"type": "INTEGER", "description": "Request timeout in seconds (1-60)"},
                }
                required = ["target"]
            elif tool.name == "directory_scan":
                properties = {
                    "target": {"type": "STRING", "description": "Target URL (e.g. http://127.0.0.1:8080)"},
                    "wordlist": {"type": "STRING", "description": "Optional wordlist path"},
                    "extensions": {"type": "STRING", "description": "Optional comma-separated extensions (e.g. 'php,txt')"},
                    "threads": {"type": "INTEGER", "description": "Concurrent threads (1-25)"},
                }
                required = ["target"]
            elif tool.name == "hash_file":
                properties = {
                    "file_path": {"type": "STRING", "description": "Absolute file path to hash (within /data or /tmp)"},
                }
                required = ["file_path"]
            else:
                properties = {"target": {"type": "STRING", "description": "Target"}}
                required = ["target"]

            declarations.append({
                "name": tool.name,
                "description": tool.description,
                "parameters": {
                    "type": "OBJECT",
                    "properties": properties,
                    "required": required,
                },
            })

        return declarations

    def get_openai_tools(self) -> list[dict[str, Any]]:
        """Return tool definitions in standard OpenAI/Groq function calling format."""
        raw = self.get_tools_declarations()
        openai_tools = []
        for t in raw:
            params = t["parameters"]
            props = {}
            for k, v in params["properties"].items():
                t_type = v.get("type", "STRING").lower()
                if t_type == "bool":
                    t_type = "boolean"
                elif t_type == "int":
                    t_type = "integer"
                props[k] = {"type": t_type, "description": v.get("description", "")}

            openai_tools.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": params.get("required", []),
                    },
                },
            })
        return openai_tools

    async def execute_tool(self, name: str, arguments: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
        """Execute a tool through the CyberSec MCP security pipeline."""
        tool = self.registry.get(name)
        if not tool:
            return {"error": f"Tool '{name}' not found in registry"}

        target = arguments.get("target") or arguments.get("file_path") or ""
        req = ToolRequest(
            tool_name=name,
            target=str(target),
            arguments=arguments,
            session_id=session_id,
        )

        result = await tool.execute(req)
        return json.loads(result.model_dump_json())
