"""CyberSec MCP Server — controlled, sandboxed cybersecurity execution for AI agents.

Entrypoint for MCP stdio protocol server exposing tools, resources, and policy enforcement.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.mcpserver import MCPServer

from server.config import get_settings
from server.models import ToolRequest
from server.sandbox.manager import SandboxManager
from server.security.audit import AuditLogger
from server.security.policy import PolicyEngine
from server.tools.registry import ToolRegistry

# Configure logging
settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cybersec-mcp")

# Initialize core architecture singletons
policy_engine = PolicyEngine(config_path="config/policies.yaml")
audit_logger = AuditLogger(db_path=settings.audit_db_path)
sandbox_manager = SandboxManager(max_concurrent=settings.max_concurrent_sandboxes)
tool_registry = ToolRegistry.create_default(
    policy_engine=policy_engine,
    sandbox_manager=sandbox_manager,
    audit_logger=audit_logger,
)

# Initialize MCP Server
app = MCPServer("cybersec-mcp")


# ── MCP Tool Definitions ───────────────────────────────────────────────────


@app.tool()
async def nmap_scan(
    target: str,
    ports: str = "1-1000",
    scan_type: str = "connect",
    service_detection: bool = True,
    session_id: str | None = None,
) -> str:
    """Scan target ports and identify running services and versions.

    Only targets within allowed private/lab networks (RFC 1918, localhost) are permitted.
    Blocked flags: exploit scripts, raw packet crafting (-sE).

    Args:
        target: Target IP address or lab hostname (e.g. 192.168.1.50 or target.lab.local).
        ports: Port specification (e.g. '80', '1-1024', or '22,80,443'). Default '1-1000'.
        scan_type: Scan type ('connect', 'syn', 'ping', 'udp'). Default 'connect'.
        service_detection: Probe open ports to determine service/version info. Default True.
        session_id: Optional tracking session ID for multi-step investigations.
    """
    tool = tool_registry.get("nmap_scan")
    if not tool:
        return json.dumps({"error": "Tool nmap_scan not registered"})

    req = ToolRequest(
        tool_name="nmap_scan",
        target=target,
        arguments={
            "ports": ports,
            "scan_type": scan_type,
            "service_detection": service_detection,
        },
        session_id=session_id,
    )
    result = await tool.execute(req)
    return result.model_dump_json(indent=2)


@app.tool()
async def dns_lookup(
    target: str,
    record_type: str = "A",
    server: str | None = None,
    session_id: str | None = None,
) -> str:
    """Perform DNS query for domain resource records (A, AAAA, MX, NS, TXT, CNAME).

    Args:
        target: Target domain name (e.g. lab.local).
        record_type: Resource record type (A, AAAA, MX, NS, TXT, CNAME). Default 'A'.
        server: Optional custom DNS server IP.
        session_id: Optional tracking session ID.
    """
    tool = tool_registry.get("dns_lookup")
    if not tool:
        return json.dumps({"error": "Tool dns_lookup not registered"})

    req = ToolRequest(
        tool_name="dns_lookup",
        target=target,
        arguments={"record_type": record_type, "server": server},
        session_id=session_id,
    )
    result = await tool.execute(req)
    return result.model_dump_json(indent=2)


@app.tool()
async def whois_lookup(
    target: str,
    session_id: str | None = None,
) -> str:
    """Query WHOIS registration and contact information for an allowed domain or IP.

    Args:
        target: Domain name or IP address.
        session_id: Optional tracking session ID.
    """
    tool = tool_registry.get("whois_lookup")
    if not tool:
        return json.dumps({"error": "Tool whois_lookup not registered"})

    req = ToolRequest(
        tool_name="whois_lookup",
        target=target,
        arguments={},
        session_id=session_id,
    )
    result = await tool.execute(req)
    return result.model_dump_json(indent=2)


@app.tool()
async def http_probe(
    target: str,
    method: str = "GET",
    follow_redirects: bool = True,
    timeout: int = 10,
    session_id: str | None = None,
) -> str:
    """Inspect HTTP service response headers, status codes, server headers, and security configs.

    Args:
        target: URL or hostname/IP of the web service (e.g. http://192.168.1.50:8080).
        method: HTTP method (GET, HEAD, OPTIONS). Default 'GET'.
        follow_redirects: Automatically follow HTTP redirects. Default True.
        timeout: Request timeout in seconds (1-60). Default 10.
        session_id: Optional tracking session ID.
    """
    tool = tool_registry.get("http_probe")
    if not tool:
        return json.dumps({"error": "Tool http_probe not registered"})

    req = ToolRequest(
        tool_name="http_probe",
        target=target,
        arguments={
            "method": method,
            "follow_redirects": follow_redirects,
            "timeout": timeout,
        },
        session_id=session_id,
    )
    result = await tool.execute(req)
    return result.model_dump_json(indent=2)


@app.tool()
async def directory_scan(
    target: str,
    wordlist: str | None = None,
    extensions: str | None = None,
    threads: int = 10,
    session_id: str | None = None,
) -> str:
    """Scan a target web server for common directories, endpoints, and hidden administrative routes.

    Args:
        target: Base URL of web application (e.g. http://172.28.0.10:8080).
        wordlist: Optional path to wordlist inside container.
        extensions: Optional comma-separated extensions (e.g. 'php,txt,html').
        threads: Concurrency limit (1-25). Default 10.
        session_id: Optional tracking session ID.
    """
    tool = tool_registry.get("directory_scan")
    if not tool:
        return json.dumps({"error": "Tool directory_scan not registered"})

    req = ToolRequest(
        tool_name="directory_scan",
        target=target,
        arguments={
            "wordlist": wordlist,
            "extensions": extensions,
            "threads": threads,
        },
        session_id=session_id,
    )
    result = await tool.execute(req)
    return result.model_dump_json(indent=2)


@app.tool()
async def hash_file(
    file_path: str,
    session_id: str | None = None,
) -> str:
    """Compute cryptographic hashes (MD5, SHA1, SHA256) of a file in an air-gapped sandbox.

    Args:
        file_path: Absolute path to the file (must be within /data or /tmp).
        session_id: Optional tracking session ID.
    """
    tool = tool_registry.get("hash_file")
    if not tool:
        return json.dumps({"error": "Tool hash_file not registered"})

    req = ToolRequest(
        tool_name="hash_file",
        target=file_path,
        arguments={"file_path": file_path},
        session_id=session_id,
    )
    result = await tool.execute(req)
    return result.model_dump_json(indent=2)


# ── MCP Resources ──────────────────────────────────────────────────────────


@app.resource("audit://recent")
async def get_recent_audit_logs() -> str:
    """Recent cybersecurity tool execution audit records."""
    logs = await audit_logger.get_recent(limit=25)
    return json.dumps(logs, indent=2)


@app.resource("audit://session/{session_id}")
async def get_session_audit_logs(session_id: str) -> str:
    """Complete audit trail for an investigation session."""
    logs = await audit_logger.get_session(session_id=session_id)
    return json.dumps(logs, indent=2)


@app.resource("policy://rules")
async def get_policy_rules() -> str:
    """Current active security policy rules and target allowlists."""
    return json.dumps(policy_engine.config.model_dump(), indent=2)


# ── MCP Prompts ────────────────────────────────────────────────────────────


@app.prompt()
def investigate_target(target: str) -> str:
    """Prompt template guiding an AI agent through a comprehensive authorized investigation."""
    return (
        f"You are conducting an authorized security assessment of target '{target}'.\n"
        f"Follow these strict operational guidelines:\n"
        f"1. Start with passive and DNS reconnaissance using `dns_lookup`.\n"
        f"2. Perform port and service enumeration using `nmap_scan` (e.g. ports '1-1000' or common ports).\n"
        f"3. For detected HTTP/HTTPS services, perform `http_probe` to inspect headers, technologies, and status codes.\n"
        f"4. If web interfaces exist, perform a focused `directory_scan` to discover critical endpoints.\n"
        f"5. Synthesize all findings into a structured risk and remediation report.\n"
        f"Note: All commands run in isolated sandboxes and are restricted to allowed lab networks."
    )


@app.prompt()
def quick_recon(target: str) -> str:
    """Prompt template for rapid, low-impact reconnaissance."""
    return (
        f"Perform rapid low-impact reconnaissance on target '{target}'.\n"
        f"1. Query DNS records (A, AAAA, MX) using `dns_lookup`.\n"
        f"2. Probe web ports using `http_probe`.\n"
        f"3. Summarize responsive services without launching intensive scans."
    )


@app.prompt()
def web_assessment(target: str) -> str:
    """Prompt template focused on web application profiling."""
    return (
        f"Perform web security profiling on endpoint '{target}'.\n"
        f"1. Inspect HTTP response headers, security headers (CSP, HSTS, X-Frame-Options), and server banners via `http_probe`.\n"
        f"2. Enumerate common paths via `directory_scan`.\n"
        f"3. Highlight missing security headers and publicly accessible administrative interfaces."
    )


def main() -> None:
    """Run the CyberSec MCP server over stdio transport."""
    logger.info("Starting CyberSec MCP Server over stdio...")
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
