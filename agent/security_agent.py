"""Custom Cybersecurity Agent — powered by Google Gemini API and CyberSec MCP.

Orchestrates defensive security assessments, runs nmap/web/dns tools through
the sandboxed MCP security pipeline, and generates audit reports.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from agent.mcp_client import LocalMCPClient

SYSTEM_INSTRUCTION = """You are CyberSecAgent, an authorized defensive security auditing agent.
Your mission is to perform controlled, authorized security assessments on specified lab environments and local infrastructure.

You have access to 6 sandboxed MCP cybersecurity tools:
1. `nmap_scan`: Port and service reconnaissance with version detection.
2. `http_probe`: Inspect HTTP response headers, security headers, and status codes.
3. `directory_scan`: Discover web endpoints and administrative routes.
4. `dns_lookup`: Resolve domain resource records (A, MX, TXT, etc.).
5. `whois_lookup`: Query registration and registrar metadata.
6. `hash_file`: Air-gapped cryptographic hashing of artifacts.

OPERATIONAL RULES:
- Always start with reconnaissance before intrusive actions.
- Examine findings and correlate discovered ports/services (e.g. if port 80/8080 is found open, probe it with http_probe).
- If a tool call is denied by the security policy engine, explain the restriction clearly to the user.
- Summarize your findings in a structured, actionable security report highlighting open ports, services, missing security headers, and remediation advice.
"""


class SecurityAgent:
    """Autonomous Cybersecurity Agent using Gemini and CyberSec MCP."""

    def __init__(self, api_key: str | None = None, model: str = "gemini-2.5-flash"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model
        self.mcp_client = LocalMCPClient()
        self._init_gemini()

    def _init_gemini(self) -> None:
        """Initialize Google GenAI client if API key is present."""
        if not self.api_key:
            self.client = None
            return

        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            print(f"[!] Warning: Could not initialize Gemini client: {e}")
            self.client = None

    async def run(self, user_prompt: str, session_id: str = "session-agent-01") -> str:
        """Run the agent on a user prompt through tool execution loop."""
        if not self.client:
            return await self._run_autonomous_offline(user_prompt, session_id)

        from google.genai import types

        # Register MCP tools for Gemini
        raw_tools = self.mcp_client.get_tools_declarations()
        gemini_function_declarations = []
        for t in raw_tools:
            gemini_function_declarations.append(
                types.FunctionDeclaration(
                    name=t["name"],
                    description=t["description"],
                    parameters=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            k: types.Schema(type=getattr(types.Type, v.get("type", "STRING")), description=v.get("description", ""))
                            for k, v in t["parameters"]["properties"].items()
                        },
                        required=t["parameters"].get("required", []),
                    ),
                )
            )

        tools = [types.Tool(function_declarations=gemini_function_declarations)]
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            temperature=0.2,
            tools=tools,
        )

        chat = self.client.chats.create(model=self.model_name, config=config)

        print(f"\n[Agent] Thinking on task: '{user_prompt}'...")
        response = chat.send_message(user_prompt)

        # Tool execution loop
        max_turns = 10
        turn = 0
        while response.function_calls and turn < max_turns:
            turn += 1
            for call in response.function_calls:
                tool_name = call.name
                args = dict(call.args)
                print(f"\n  [*] [Agent Tool Call] -> {tool_name}({args})")

                # Execute through CyberSec MCP pipeline
                result = await self.mcp_client.execute_tool(tool_name, args, session_id=session_id)
                status = result.get("status", "unknown")
                findings_count = len(result.get("findings", []))

                print(f"  [+] [MCP Result] Status: {status} | Findings: {findings_count}")
                if result.get("error"):
                    print(f"  [!] [Policy/Error]: {result.get('error')}")

                # Send tool response back to Gemini
                response = chat.send_message(
                    types.Part.from_function_response(
                        name=tool_name,
                        response={"result": result},
                    )
                )

        return response.text or "[Agent completed investigation with no text response]"

    async def _run_autonomous_offline(self, prompt: str, session_id: str) -> str:
        """Autonomous heuristic test runner when no GEMINI_API_KEY is configured."""
        print("\n[!] No GEMINI_API_KEY detected. Running in Autonomous Offline Test Mode...")
        print(f"[Agent Plan] Analyzing request: '{prompt}'")

        report_lines = [
            "# CyberSec Agent Assessment Report (Autonomous Mode)",
            f"**Objective**: {prompt}",
            f"**Session ID**: {session_id}",
            "---",
        ]

        # Extract target from prompt if any
        import re
        target = "127.0.0.1"
        url_match = re.search(r"https?://([^\s/]+)", prompt)
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", prompt)
        if url_match:
            target = url_match.group(1).split(":")[0]
        elif ip_match:
            target = ip_match.group(0)

        # Step 1: Nmap scan
        print(f"\n  [*] [Step 1] Executing sandboxed nmap_scan on target '{target}'...")
        nmap_res = await self.mcp_client.execute_tool("nmap_scan", {"target": target, "ports": "80,443,8000,8080"}, session_id=session_id)
        report_lines.append(f"### 1. Port Reconnaissance (`nmap_scan`)\n- Status: `{nmap_res.get('status')}`")
        if nmap_res.get("findings"):
            for f in nmap_res["findings"]:
                report_lines.append(f"  - Port **{f.get('port')}** ({f.get('protocol')}): `{f.get('state')}` - Service: `{f.get('service')}`")
        else:
            report_lines.append(f"  - Error / Note: {nmap_res.get('error', 'No open ports detected')}")

        # Step 2: HTTP probe
        probe_target = f"http://{target}:8000" if "8000" in prompt else f"http://{target}"
        print(f"\n  [*] [Step 2] Executing sandboxed http_probe on '{probe_target}'...")
        http_res = await self.mcp_client.execute_tool("http_probe", {"target": probe_target}, session_id=session_id)
        report_lines.append(f"\n### 2. HTTP Inspection (`http_probe`)\n- Status: `{http_res.get('status')}`")
        if http_res.get("findings"):
            f = http_res["findings"][0]
            report_lines.append(f"  - HTTP Status: `{f.get('status_code')} {f.get('status_message')}`")
            report_lines.append(f"  - Server Banner: `{f.get('server')}`")
            report_lines.append(f"  - Missing Security Headers: `{', '.join(f.get('missing_security_headers', []))}`")
        else:
            report_lines.append(f"  - Error: {http_res.get('error')}")

        # Summary
        report_lines.append("\n### 3. Recommendations & Next Steps")
        report_lines.append("1. **Verify Services**: Ensure only necessary ports are accessible.")
        report_lines.append("2. **Security Headers**: Implement `Content-Security-Policy` and `X-Frame-Options` to mitigate clickjacking and XSS.")
        report_lines.append("3. **Audit Trail**: Every action taken above has been recorded in `audit.db`.")

        return "\n".join(report_lines)


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="CyberSec AI Security Agent")
    parser.add_argument("prompt", nargs="?", default=None, help="Security assessment goal / task")
    parser.add_argument("--key", default=None, help="Gemini API Key (optional, defaults to GEMINI_API_KEY env)")
    args = parser.parse_args()

    agent = SecurityAgent(api_key=args.key)

    if args.prompt:
        result = await agent.run(args.prompt)
        print("\n" + "=" * 60)
        print(result)
        print("=" * 60)
        return

    # Interactive CLI mode
    print("=" * 65)
    print("CyberSec AI Agent -- Interactive Security Assessment Console")
    print("=" * 65)
    if agent.client:
        print("[+] Backend: Google Gemini API (Live Agent Mode)")
    else:
        print("[!] Backend: Autonomous Offline Engine (Set GEMINI_API_KEY for live LLM)")
    print("Type 'exit' or 'quit' to leave.\n")

    while True:
        try:
            user_input = input("CyberSecAgent> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                break

            result = await agent.run(user_input)
            print("\n" + "=" * 60)
            print(result)
            print("=" * 60 + "\n")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting CyberSecAgent.")
            break


if __name__ == "__main__":
    asyncio.run(main())
