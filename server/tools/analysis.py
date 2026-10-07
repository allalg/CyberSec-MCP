"""Artifact analysis tools — hash_file, file signature analysis."""

from __future__ import annotations

import logging
import re
from typing import Any

from server.models import ToolRequest
from server.security.validation import (
    ValidationError,
    validate_arguments,
    validate_file_path,
)
from server.tools.base import BaseTool

logger = logging.getLogger(__name__)


class HashFileTool(BaseTool):
    """Compute cryptographic hashes (MD5, SHA1, SHA256) of a file or string inside an isolated sandbox."""

    name = "hash_file"
    description = (
        "Compute cryptographic hashes (MD5, SHA1, SHA256) of a target file or raw text string. "
        "Operates inside an air-gapped sandbox with no network connectivity."
    )
    risk_level = "low"

    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        sanitized = validate_arguments(request.arguments, self.name)

        # 1. Direct text/string payload
        raw_text = (
            sanitized.get("text")
            or sanitized.get("content")
            or sanitized.get("string")
            or sanitized.get("input")
            or sanitized.get("data")
        )
        if raw_text is not None:
            sanitized["is_text"] = True
            sanitized["text"] = str(raw_text)
            return sanitized

        # 2. File path parameter
        file_path = sanitized.get("file_path", request.target)
        if not file_path:
            raise ValidationError("Either 'text' or 'file_path' must be provided to hash_file")

        # In container, data is mounted at /data or allowed dir
        try:
            validated_path = validate_file_path(file_path, allowed_dir="/data")
        except ValidationError:
            # Also allow /tmp/cybersec-mcp
            try:
                validated_path = validate_file_path(file_path, allowed_dir="/tmp")
            except ValidationError:
                # If path validation fails, treat as raw text
                sanitized["is_text"] = True
                sanitized["text"] = str(file_path)
                return sanitized

        sanitized["file_path"] = validated_path
        return sanitized

    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        if validated_args.get("is_text"):
            import base64
            text = validated_args["text"]
            b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
            return [
                "sh",
                "-c",
                f"echo -n '{b64}' | base64 -d | md5sum; echo -n '{b64}' | base64 -d | sha1sum; echo -n '{b64}' | base64 -d | sha256sum",
            ]

        path = validated_args.get("file_path", target)
        # Run md5sum, sha1sum, sha256sum sequentially
        return [
            "sh",
            "-c",
            f"md5sum '{path}' 2>/dev/null; sha1sum '{path}' 2>/dev/null; sha256sum '{path}' 2>/dev/null",
        ]

    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Parse hash tool outputs.

        Output lines format:
        <hash>  <filename or ->
        """
        hashes: dict[str, str] = {}
        if not raw_output or not raw_output.strip():
            return [], {"error": "Empty hash output"}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.match(r"^([a-fA-F0-9]{32,64})\s+(.+)$", line)
            if match:
                hash_val = match.group(1).lower()
                length = len(hash_val)
                if length == 32:
                    hashes["md5"] = hash_val
                elif length == 40:
                    hashes["sha1"] = hash_val
                elif length == 64:
                    hashes["sha256"] = hash_val

        findings = [hashes] if hashes else []
        summary = {
            "algorithms_computed": list(hashes.keys()),
            "sha256": hashes.get("sha256"),
            "md5": hashes.get("md5"),
            "sha1": hashes.get("sha1"),
        }
        return findings, summary
