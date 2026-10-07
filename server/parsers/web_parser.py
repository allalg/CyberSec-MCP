"""Web output parser — parses HTTP probe responses (curl) and directory scans (gobuster)."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def parse_http_probe_output(raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse HTTP probe output (from curl with -i headers).

    Returns:
        tuple of (findings, summary)
    """
    if not raw_output or not raw_output.strip():
        return [], {"error": "Empty HTTP probe output", "status_code": None}

    # Split headers from body (separated by double CRLF or double LF)
    parts = re.split(r"\r?\n\r?\n", raw_output, maxsplit=1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    headers: dict[str, str] = {}
    status_code: int | None = None
    http_version: str | None = None
    status_message: str | None = None

    lines = header_block.splitlines()
    if lines:
        status_line = lines[0].strip()
        # Format: HTTP/1.1 200 OK or HTTP/2 200
        status_match = re.match(r"^(HTTP/[\d\.]+)\s+(\d{3})(?:\s+(.*))?$", status_line)
        if status_match:
            http_version = status_match.group(1)
            status_code = int(status_match.group(2))
            status_message = status_match.group(3) or ""

        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

    # Security header inspection
    security_headers = {
        "content-security-policy": headers.get("content-security-policy"),
        "strict-transport-security": headers.get("strict-transport-security"),
        "x-frame-options": headers.get("x-frame-options"),
        "x-content-type-options": headers.get("x-content-type-options"),
        "x-xss-protection": headers.get("x-xss-protection"),
        "referrer-policy": headers.get("referrer-policy"),
    }

    missing_security_headers = [k for k, v in security_headers.items() if v is None]

    finding = {
        "status_code": status_code,
        "http_version": http_version,
        "status_message": status_message,
        "server": headers.get("server"),
        "content_type": headers.get("content-type"),
        "content_length": headers.get("content-length"),
        "headers": headers,
        "security_headers": security_headers,
        "missing_security_headers": missing_security_headers,
        "body_preview": body[:500] if body else None,
    }

    summary = {
        "status_code": status_code,
        "server": headers.get("server"),
        "missing_security_headers_count": len(missing_security_headers),
    }

    return [finding], summary


def parse_directory_scan_output(raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse directory brute-force scan output (gobuster / dirsearch).

    Gobuster typical line:
    /admin                (Status: 301) [Size: 178] [--> http://target/admin/]
    /login                (Status: 200) [Size: 2450]
    /api                  (Status: 200) [Size: 52]

    Returns:
        tuple of (findings, summary)
    """
    findings: list[dict[str, Any]] = []

    if not raw_output or not raw_output.strip():
        return [], {"total_paths_found": 0}

    # Regex for Gobuster output lines
    # e.g.: /admin (Status: 301) [Size: 178]
    pattern = re.compile(
        r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)\s+\[Size:\s*(?P<size>\d+)\](?:\s+\[-->\s*(?P<redirect>\S+)\])?",
        re.MULTILINE,
    )

    status_counts: dict[str, int] = {}

    for match in pattern.finditer(raw_output):
        path = match.group("path")
        status = int(match.group("status"))
        size = int(match.group("size"))
        redirect = match.group("redirect")

        status_key = f"{status // 100}xx"
        status_counts[status_key] = status_counts.get(status_key, 0) + 1

        finding = {
            "path": path,
            "status_code": status,
            "size": size,
            "redirect_url": redirect,
        }
        findings.append(finding)

    summary = {
        "total_paths_found": len(findings),
        "status_distribution": status_counts,
    }

    return findings, summary
