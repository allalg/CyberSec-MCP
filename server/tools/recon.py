"""Reconnaissance tools — nmap_scan, dns_lookup, whois_lookup."""

from __future__ import annotations

import logging
from typing import Any

from server.models import ToolRequest
from server.parsers.dns_parser import parse_dns_output
from server.parsers.nmap_parser import parse_nmap_output
from server.parsers.whois_parser import parse_whois_output
from server.security.validation import (
    validate_arguments,
    validate_port_spec,
    validate_record_type,
    validate_scan_type,
)
from server.tools.base import BaseTool

logger = logging.getLogger(__name__)


class NmapScanTool(BaseTool):
    """Port and service reconnaissance using Nmap inside an isolated container."""

    name = "nmap_scan"
    description = (
        "Scan target ports and identify running services and versions. "
        "Outputs structured port, state, and service information."
    )
    risk_level = "medium"

    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        sanitized = validate_arguments(request.arguments, self.name)

        # Validate ports if provided
        ports = sanitized.get("ports", "1-1000")
        if ports:
            ports = validate_port_spec(str(ports))
        sanitized["ports"] = ports

        # Validate scan type
        scan_type = sanitized.get("scan_type", "connect")
        sanitized["scan_type"] = validate_scan_type(str(scan_type))

        # Service detection flag
        sanitized["service_detection"] = bool(sanitized.get("service_detection", True))

        return sanitized

    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        cmd = ["nmap", "-oX", "-"]  # XML stdout for structured parsing

        scan_type = validated_args.get("scan_type", "connect")
        if scan_type == "connect":
            cmd.append("-sT")
        elif scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "udp":
            cmd.append("-sU")
        elif scan_type == "ping":
            cmd.append("-sn")

        if validated_args.get("service_detection", True) and scan_type != "ping":
            cmd.append("-sV")

        ports = validated_args.get("ports")
        if ports and scan_type != "ping":
            cmd.extend(["-p", str(ports)])

        # Timing and non-DNS flags for lab performance
        cmd.extend(["-T4", "-n", target])
        return cmd

    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return parse_nmap_output(raw_output)


class DnsLookupTool(BaseTool):
    """Query DNS resource records (A, AAAA, MX, NS, TXT, CNAME, etc.) via dig."""

    name = "dns_lookup"
    description = (
        "Perform DNS queries for domain names. "
        "Returns structured DNS resource records (type, TTL, value, section)."
    )
    risk_level = "low"

    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        sanitized = validate_arguments(request.arguments, self.name)

        record_type = sanitized.get("record_type", "A")
        sanitized["record_type"] = validate_record_type(str(record_type))

        server = sanitized.get("server")
        if server:
            sanitized["server"] = str(server).strip()

        return sanitized

    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        cmd = ["dig"]
        server = validated_args.get("server")
        if server:
            cmd.append(f"@{server}")

        cmd.extend([
            target,
            validated_args.get("record_type", "A"),
            "+stats",
            "+comments",
        ])
        return cmd

    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return parse_dns_output(raw_output)


class WhoisLookupTool(BaseTool):
    """Query domain and IP WHOIS databases for registration and ownership details."""

    name = "whois_lookup"
    description = (
        "Lookup WHOIS registration information for a domain or IP address. "
        "Returns registrar, contact information, name servers, and dates."
    )
    risk_level = "low"

    def validate_arguments(self, request: ToolRequest) -> dict[str, Any]:
        return validate_arguments(request.arguments, self.name)

    def build_command(self, validated_args: dict[str, Any], target: str) -> list[str]:
        return ["whois", target]

    def parse_output(self, raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return parse_whois_output(raw_output)
