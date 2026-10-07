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


# ── Web Dashboard Route (for Browser Access on /) ─────────────────────────

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberSec MCP — Server Dashboard</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: rgba(22, 27, 34, 0.85);
      --border: rgba(48, 54, 61, 0.7);
      --accent: #58a6ff;
      --accent-glow: rgba(88, 166, 255, 0.15);
      --success: #3fb950;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      padding: 40px 20px;
      line-height: 1.6;
    }
    .container {
      max-width: 860px;
      margin: 0 auto;
    }
    header {
      margin-bottom: 32px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    h1 {
      font-size: 26px;
      color: var(--text-bright);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: rgba(63, 185, 80, 0.15);
      color: var(--success);
      border: 1px solid rgba(63, 185, 80, 0.3);
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 600;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.9); }
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
      backdrop-filter: blur(10px);
    }
    .card-title {
      font-size: 18px;
      color: var(--text-bright);
      margin-bottom: 12px;
      font-weight: 600;
    }
    .url-box {
      display: flex;
      align-items: center;
      gap: 10px;
      background: rgba(13, 17, 23, 0.8);
      border: 1px solid var(--border);
      padding: 12px 16px;
      border-radius: 8px;
      font-family: monospace;
      font-size: 15px;
      color: #79c0ff;
      margin: 12px 0;
    }
    .btn {
      background: #238636;
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
      transition: background 0.2s;
    }
    .btn:hover { background: #2ea043; }
    .btn-secondary {
      background: rgba(56, 139, 253, 0.15);
      color: var(--accent);
      border: 1px solid rgba(56, 139, 253, 0.4);
    }
    .btn-secondary:hover { background: rgba(56, 139, 253, 0.25); }
    .tool-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-top: 16px;
    }
    .tool-pill {
      background: rgba(13, 17, 23, 0.6);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .tool-name {
      font-weight: 600;
      color: var(--accent);
      font-family: monospace;
      font-size: 14px;
    }
    .tool-desc {
      font-size: 12px;
      color: #8b949e;
      margin-top: 4px;
    }
    .steps {
      padding-left: 20px;
      margin-top: 10px;
    }
    .steps li {
      margin-bottom: 8px;
      font-size: 14px;
    }
    code {
      background: rgba(110, 118, 129, 0.2);
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 13px;
      color: #e6edf3;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🛡️ CyberSec MCP Server</h1>
      <div class="status-badge">
        <span class="status-dot"></span> Online (SSE Active)
      </div>
    </header>

    <div class="card" style="border-left: 4px solid var(--accent);">
      <div class="card-title">📡 Server-Sent Events (SSE) Endpoint</div>
      <p style="font-size: 14px;">Connect your browser extension, Gemini client, or web application to the live SSE stream below:</p>
      <div class="url-box">
        <span id="sse-url">http://127.0.0.1:8000/sse</span>
        <button class="btn" style="margin-left: auto;" onclick="copyURL()">Copy URL</button>
        <a href="/sse" target="_blank" class="btn btn-secondary" style="text-decoration:none;">Open Stream</a>
      </div>
    </div>

    <div class="card">
      <div class="card-title">🔌 How to Connect to Gemini in Browser</div>
      <ol class="steps">
        <li><strong>Browser Extension Method:</strong> In Chrome, install an MCP bridge extension (e.g., <em>MCP SuperAssistant</em>).</li>
        <li><strong>Add Server:</strong> Enter URL <code>http://127.0.0.1:8000/sse</code> with transport <code>SSE</code>.</li>
        <li><strong>Navigate:</strong> Open <a href="https://gemini.google.com" target="_blank" style="color:var(--accent);">gemini.google.com</a> or Google AI Studio — the extension injects the 6 security tools directly into your prompt context.</li>
      </ol>
    </div>

    <div class="card">
      <div class="card-title">🧰 Available Cybersecurity Tools (6)</div>
      <div class="tool-grid">
        <div class="tool-pill">
          <div class="tool-name">nmap_scan</div>
          <div class="tool-desc">Port and service reconnaissance with version detection inside an isolated sandbox.</div>
        </div>
        <div class="tool-pill">
          <div class="tool-name">dns_lookup</div>
          <div class="tool-desc">DNS resource record querying (A, AAAA, MX, NS, TXT, CNAME) via dig.</div>
        </div>
        <div class="tool-pill">
          <div class="tool-name">whois_lookup</div>
          <div class="tool-desc">WHOIS domain registration, nameserver, and contact lookup.</div>
        </div>
        <div class="tool-pill">
          <div class="tool-name">http_probe</div>
          <div class="tool-desc">HTTP status codes, headers, and security header audit.</div>
        </div>
        <div class="tool-pill">
          <div class="tool-name">directory_scan</div>
          <div class="tool-desc">Web path and hidden endpoint discovery using wordlists via gobuster.</div>
        </div>
        <div class="tool-pill">
          <div class="tool-name">hash_file</div>
          <div class="tool-desc">MD5, SHA1, and SHA256 file hashing inside an air-gapped container.</div>
        </div>
      </div>
    </div>
  </div>

  <script>
    function copyURL() {
      const url = document.getElementById('sse-url').innerText;
      navigator.clipboard.writeText(url).then(() => {
        alert('Copied SSE URL: ' + url);
      });
    }
  </script>
</body>
</html>"""


from starlette.responses import HTMLResponse
from starlette.routing import Route


async def _dashboard_handler(request: Any) -> HTMLResponse:
    """Serve the web dashboard on the root path."""
    return HTMLResponse(HTML_DASHBOARD)


# Register root route
app._custom_starlette_routes.append(Route("/", endpoint=_dashboard_handler, methods=["GET"]))


def main() -> None:
    """Run the CyberSec MCP server over stdio or SSE transport."""
    import argparse

    parser = argparse.ArgumentParser(description="CyberSec MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio; use 'sse' for browser / HTTP connectivity)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host interface for SSE server")
    parser.add_argument("--port", type=int, default=8000, help="Port for SSE server")
    args = parser.parse_args()

    if args.transport == "sse":
        logger.info("Starting CyberSec MCP Server over SSE at http://%s:%d/sse...", args.host, args.port)
        app.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        logger.info("Starting CyberSec MCP Server over streamable-http at http://%s:%d...", args.host, args.port)
        app.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        logger.info("Starting CyberSec MCP Server over stdio...")
        app.run(transport="stdio")


if __name__ == "__main__":
    main()
