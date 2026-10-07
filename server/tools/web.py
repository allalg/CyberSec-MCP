"""Web security inspection tools — http_probe, directory_scan."""

from __future__ import annotations

import logging
from typing import Any

from server.models import ToolRequest
from server.parsers.web_parser import parse_directory_scan_output, parse_http_probe_output
from server.security.validation import (
    ValidationError,
    validate_arguments,
    validate_http_method,
)
from server.tools.base import BaseTool

logger = logging.getLogger(__name__)


class HttpProbeTool(BaseTool):
    """Probe an HTTP/HTTPS endpoint to inspect headers, status codes, and server signatures."""

    name = "http_probe"
    description = (
        "Inspect an HTTP service to check status code, headers, TLS, and security configurations. "
        "Useful for service profiling and identifying misconfigurations."
    )
    risk_level = "low"

    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        sanitized = validate_arguments(request.arguments, self.name)

        method = sanitized.get("method", "GET")
        sanitized["method"] = validate_http_method(str(method))

        sanitized["follow_redirects"] = bool(sanitized.get("follow_redirects", True))
        sanitized["max_redirs"] = min(int(sanitized.get("max_redirs", 5)), 10)

        # Timeout cap
        timeout = int(sanitized.get("timeout", 10))
        sanitized["timeout"] = min(max(timeout, 1), 60)

        return sanitized

    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        # Ensure target starts with http:// or https://
        url = target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        cmd = [
            "curl",
            "-i",  # Include HTTP headers in output
            "-s",  # Silent
            "-S",  # Show errors
            "-X", validated_args.get("method", "GET"),
            "--max-time", str(validated_args.get("timeout", 10)),
        ]

        if validated_args.get("follow_redirects", True):
            cmd.extend(["-L", "--max-redirs", str(validated_args.get("max_redirs", 5))])

        cmd.append(url)
        return cmd

    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return parse_http_probe_output(raw_output)


class DirectoryScanTool(BaseTool):
    """Enumerate web application paths and endpoints using a wordlist."""

    name = "directory_scan"
    description = (
        "Scan a web application for common directories and hidden administrative endpoints. "
        "Outputs discovered paths, response status codes, and sizes."
    )
    risk_level = "medium"

    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        sanitized = validate_arguments(request.arguments, self.name)

        # Ensure wordlist is safe path if specified
        wordlist = sanitized.get("wordlist")
        if wordlist and ".." in str(wordlist):
            raise ValidationError("Path traversal in wordlist path")

        # Extensions: comma separated e.g. "php,txt,html"
        extensions = sanitized.get("extensions")
        if extensions:
            sanitized["extensions"] = str(extensions).strip()

        threads = int(sanitized.get("threads", 10))
        sanitized["threads"] = min(max(threads, 1), 25)

        return sanitized

    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        url = target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"

        # Standard minimal wordlist path in the web-tools container
        wordlist_path = validated_args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

        cmd = [
            "gobuster",
            "dir",
            "-u", url,
            "-w", wordlist_path,
            "-t", str(validated_args.get("threads", 10)),
            "-q",  # Quiet mode (only findings)
            "-n",  # No progress
        ]

        extensions = validated_args.get("extensions")
        if extensions:
            cmd.extend(["-x", str(extensions)])

        return cmd

    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return parse_directory_scan_output(raw_output)
