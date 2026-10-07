"""Custom Cybersecurity Agent — powered by Google Gemini API and Groq API fallback with CyberSec MCP.

Orchestrates defensive security assessments, runs nmap/web/dns tools through
the sandboxed MCP security pipeline, and generates audit reports.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from dotenv import load_dotenv

load_dotenv()

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
    """Autonomous Cybersecurity Agent using Gemini with Groq fallback and CyberSec MCP."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        groq_key: str | None = None,
        groq_model: str | None = None,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model or os.getenv("GEMINI_MODEL") or "gemini-3.8-flash"
        self.groq_key = groq_key or os.getenv("GROQ_API_KEY")
        self.groq_model = groq_model or os.getenv("GROQ_MODEL") or "qwen/qwen3.8-27b"
        self.mcp_client = LocalMCPClient()

        self.client = None
        self.groq_client = None

        self._init_gemini()
        self._init_groq()

    def _init_gemini(self) -> None:
        """Initialize Google GenAI client if API key is present."""
        if not self.api_key:
            return

        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            print(f"[!] Warning: Could not initialize Gemini client: {e}")
            self.client = None

    def _init_groq(self) -> None:
        """Initialize Groq client if API key is present."""
        if not self.groq_key:
            return

        try:
            from groq import Groq
            self.groq_client = Groq(api_key=self.groq_key)
        except Exception as e:
            print(f"[!] Warning: Could not initialize Groq client: {e}")
            self.groq_client = None

    async def run(self, user_prompt: str, session_id: str = "session-agent-01") -> str:
        """Run the agent on a user prompt with Gemini primary and Groq fallback."""
        # 1. Try Gemini if configured
        if self.client:
            try:
                return await self._run_gemini(user_prompt, session_id)
            except Exception as e:
                err_str = str(e)
                print(f"\n[!] Gemini API encountered an issue ({e}). Checking Groq fallback...")

        # 2. Try Groq if configured
        if self.groq_client:
            try:
                print(f"[+] Switching to Groq API (model: {self.groq_model})...")
                return await self._run_groq(user_prompt, session_id)
            except Exception as e:
                print(f"\n[!] Groq API encountered an issue ({e}). Falling back to autonomous mode...")

        # 3. Fallback to Autonomous Offline Engine
        return await self._run_autonomous_offline(user_prompt, session_id)

    async def _run_gemini(self, user_prompt: str, session_id: str) -> str:
        """Run via Google GenAI SDK."""
        from google.genai import types

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

        candidate_models = list(dict.fromkeys([self.model_name, "gemini-2.0-flash", "gemini-1.5-flash"]))
        chat = None
        response = None
        last_err = None

        print(f"\n[Agent -> Gemini] Thinking on task: '{user_prompt}'...")

        for m_name in candidate_models:
            for attempt in range(2):
                try:
                    chat = self.client.chats.create(model=m_name, config=config)
                    response = chat.send_message(user_prompt)
                    self.model_name = m_name
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    err_str = str(e)
                    if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                        # Rate limit reached on Gemini
                        raise e
                    elif "503" in err_str or "UNAVAILABLE" in err_str:
                        print(f"  [!] Model {m_name} busy (503). Retrying...")
                        await asyncio.sleep(2)
                    else:
                        break
            if response is not None:
                break

        if response is None:
            raise last_err or RuntimeError("No Gemini response")

        # Tool execution loop
        max_turns = 10
        turn = 0
        while response.function_calls and turn < max_turns:
            turn += 1
            for call in response.function_calls:
                tool_name = call.name
                args = dict(call.args)
                print(f"\n  [*] [Agent Tool Call] -> {tool_name}({args})")

                result = await self.mcp_client.execute_tool(tool_name, args, session_id=session_id)
                status = result.get("status", "unknown")
                findings_count = len(result.get("findings", []))

                print(f"  [+] [MCP Result] Status: {status} | Findings: {findings_count}")
                if result.get("error"):
                    print(f"  [!] [Policy/Error]: {result.get('error')}")

                tool_part = types.Part.from_function_response(
                    name=tool_name,
                    response={"result": result},
                )
                response = chat.send_message(tool_part)

        return response.text or "[Agent completed investigation]"

    async def _run_groq(self, user_prompt: str, session_id: str) -> str:
        """Execute reasoning and tool calling loop using Groq API with automatic model fallback."""
        tools = self.mcp_client.get_openai_tools()
        messages = [
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_prompt},
        ]

        candidate_models = list(dict.fromkeys([
            self.groq_model,
            "qwen/qwen3.8-27b",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "llama-3.3-70b-versatile",
        ]))

        active_model = self.groq_model
        print(f"\n[Agent -> Groq] Thinking with {active_model} on task: '{user_prompt}'...")

        max_turns = 10
        turn = 0
        while turn < max_turns:
            turn += 1
            response = None
            last_err = None

            for m_candidate in candidate_models:
                try:
                    response = self.groq_client.chat.completions.create(
                        model=m_candidate,
                        messages=messages,
                        tools=tools,
                        tool_choice="auto",
                        temperature=0.2,
                    )
                    active_model = m_candidate
                    self.groq_model = m_candidate
                    break
                except Exception as e:
                    last_err = e
                    err_str = str(e)
                    if "model_not_found" in err_str or "404" in err_str or "does not exist" in err_str:
                        continue
                    else:
                        raise e

            if response is None:
                raise last_err or RuntimeError("No response from Groq candidate models")

            msg = response.choices[0].message
            messages.append(msg)

            if not msg.tool_calls:
                return msg.content or "[Groq completed investigation with no text response]"

            for tc in msg.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except Exception:
                    args = {}

                print(f"\n  [*] [Agent Tool Call] -> {tool_name}({args})")
                result = await self.mcp_client.execute_tool(tool_name, args, session_id=session_id)
                status = result.get("status", "unknown")
                findings_count = len(result.get("findings", []))

                print(f"  [+] [MCP Result] Status: {status} | Findings: {findings_count}")
                if result.get("error"):
                    print(f"  [!] [Policy/Error]: {result.get('error')}")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                })

        return "[Agent completed multi-turn tool execution limit]"

    async def _run_autonomous_offline(self, prompt: str, session_id: str) -> str:
        """Autonomous heuristic test runner when no LLM API keys are active."""
        print("\n[!] Running in Autonomous Offline Mode...")
        print(f"[Agent Plan] Analyzing request: '{prompt}'")

        # If the request is for hashing
        if "hash" in prompt.lower():
            import re
            quoted = re.findall(r"['\"]([^'\"]+)['\"]", prompt)
            hash_target = None
            for q in quoted:
                if q.lower() not in ("sha256", "sha-256", "md5", "sha1", "json"):
                    hash_target = q
                    break
            if not hash_target:
                match = re.search(r"exact string\s+(.+?)(?:\.|\s+Return|$)", prompt, re.IGNORECASE)
                if match:
                    hash_target = match.group(1).strip()
                else:
                    hash_target = "Hello, CyberSec MCP!"

            print(f"\n  [*] [Step 1] Executing sandboxed hash_file on input '{hash_target}'...")
            hash_res = await self.mcp_client.execute_tool("hash_file", {"text": hash_target}, session_id=session_id)
            findings = hash_res.get("findings", [{}])[0]
            sha256 = findings.get("sha256")
            status = hash_res.get("status", "success")

            result_obj = {
                "algorithm": "SHA-256",
                "input": hash_target,
                "hash": sha256,
                "status": status,
            }
            return json.dumps(result_obj, indent=2)

        report_lines = [
            "# CyberSec Agent Assessment Report (Autonomous Mode)",
            f"**Objective**: {prompt}",
            f"**Session ID**: {session_id}",
            "---",
        ]

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
            report_lines.append(f"  - Note: {nmap_res.get('error', 'No open ports detected')}")

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
    parser.add_argument("--model", default=None, help="Gemini model name (default: gemini-3.8-flash)")
    parser.add_argument("--groq-key", default=None, help="Groq API Key (optional, defaults to GROQ_API_KEY env)")
    parser.add_argument("--groq-model", default=None, help="Groq model (default: qwen/qwen3.8-27b)")
    args = parser.parse_args()

    agent = SecurityAgent(
        api_key=args.key,
        model=args.model,
        groq_key=args.groq_key,
        groq_model=args.groq_model,
    )

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
        print("[+] Primary Backend: Google Gemini API")
    if agent.groq_client:
        print(f"[+] Fallback Backend: Groq API ({agent.groq_model})")
    if not agent.client and not agent.groq_client:
        print("[!] Backend: Autonomous Offline Engine (Set GEMINI_API_KEY or GROQ_API_KEY)")
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
