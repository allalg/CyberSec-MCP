"""Integration test script verifying MCP client connectivity to CyberSec MCP server."""

from __future__ import annotations

import json
import subprocess
import sys


def main():
    print("=" * 60)
    print("Testing CyberSec MCP Server Agent Connection")
    print("=" * 60)

    # Launch server as an agent would
    proc = subprocess.Popen(
        [sys.executable, "-m", "server.main"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def send_rpc(msg: dict) -> dict:
        line = json.dumps(msg) + "\n"
        proc.stdin.write(line)
        proc.stdin.flush()
        resp_line = proc.stdout.readline()
        if not resp_line:
            stderr_out = proc.stderr.read()
            raise RuntimeError(f"Server closed connection unexpectedly. Stderr: {stderr_out}")
        return json.loads(resp_line)

    try:
        # Step 1: Initialize
        print("[1] Initializing MCP Handshake...")
        init_res = send_rpc({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "AI-Agent-Client", "version": "1.0.0"},
            },
        })
        server_info = init_res.get("result", {}).get("serverInfo", {})
        print(f"    Connected to: {server_info.get('name')} (protocol: {init_res.get('result', {}).get('protocolVersion')})")

        # Notify initialized
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        # Step 2: Discover Tools
        print("\n[2] Discovering Available Tools...")
        tools_res = send_rpc({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        })
        tools = tools_res.get("result", {}).get("tools", [])
        print(f"    Discovered {len(tools)} tools:")
        for t in tools:
            print(f"      - {t['name']}: {t.get('description', '').split('.')[0]}")

        # Step 3: Discover Resources
        print("\n[3] Discovering Available Resources...")
        res_res = send_rpc({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/list",
            "params": {},
        })
        resources = res_res.get("result", {}).get("resources", [])
        print(f"    Discovered {len(resources)} resources:")
        for r in resources:
            print(f"      - {r['uri']}: {r.get('description', '')}")

        # Step 4: Discover Prompts
        print("\n[4] Discovering Available Prompts...")
        prompts_res = send_rpc({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "prompts/list",
            "params": {},
        })
        prompts = prompts_res.get("result", {}).get("prompts", [])
        print(f"    Discovered {len(prompts)} prompts:")
        for p in prompts:
            print(f"      - {p['name']}: {p.get('description', '')}")

        # Step 5: Test Tool Execution (Testing Policy Gate: Unauthorized Target)
        print("\n[5] Testing Tool Call with Policy Gate (Unauthorized public IP target: 8.8.8.8)...")
        call_res = send_rpc({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "nmap_scan",
                "arguments": {"target": "8.8.8.8", "ports": "80"},
            },
        })
        call_content = call_res.get("result", {}).get("content", [])
        if call_content:
            raw_text = call_content[0].get("text", "")
            parsed_result = json.loads(raw_text)
            print(f"    Status: {parsed_result.get('status')}")
            print(f"    Error/Reason: {parsed_result.get('error')}")
            assert parsed_result.get("status") == "denied", "Expected denied status"

        print("\n" + "=" * 60)
        print("All Agent MCP Connection Checks Passed Successfully!")
        print("=" * 60)

    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
