"""Nmap output parser — converts XML and plain text nmap scans into structured JSON findings."""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

logger = logging.getLogger(__name__)


def parse_nmap_output(raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse nmap scan output (XML or standard text).

    Returns:
        tuple of (findings, summary)
    """
    if not raw_output or not raw_output.strip():
        return [], {"error": "Empty nmap output", "open_ports": 0}

    # Attempt XML parse first (standard when -oX - is supplied)
    if "<nmaprun" in raw_output:
        try:
            return _parse_nmap_xml(raw_output)
        except Exception as e:
            logger.warning("Failed to parse nmap output as XML, falling back to text parser: %s", e)

    return _parse_nmap_text(raw_output)


def _parse_nmap_xml(xml_content: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Extract findings and summary from nmap XML output."""
    # Find start of XML if leading stdout exists
    start_idx = xml_content.find("<nmaprun")
    if start_idx != -1:
        xml_content = xml_content[start_idx:]

    root = ET.fromstring(xml_content)
    findings: list[dict[str, Any]] = []
    total_open = 0
    total_closed = 0
    total_filtered = 0

    for host in root.findall("host"):
        # Status
        status_elem = host.find("status")
        host_state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

        # Addresses
        addresses = []
        for addr in host.findall("address"):
            addresses.append({
                "addr": addr.get("addr"),
                "type": addr.get("addrtype"),
            })

        # Hostnames
        hostnames = []
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                hostnames.append(hn.get("name"))

        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                protocol = port.get("protocol", "tcp")
                port_id = int(port.get("portid", 0))

                state_elem = port.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                reason = state_elem.get("reason", "") if state_elem is not None else ""

                if state == "open":
                    total_open += 1
                elif state == "closed":
                    total_closed += 1
                elif state == "filtered":
                    total_filtered += 1

                service_elem = port.find("service")
                service_info: dict[str, Any] = {}
                if service_elem is not None:
                    service_info = {
                        "name": service_elem.get("name", "unknown"),
                        "product": service_elem.get("product", ""),
                        "version": service_elem.get("version", ""),
                        "extrainfo": service_elem.get("extrainfo", ""),
                        "tunnel": service_elem.get("tunnel", ""),
                    }

                # Script outputs if any
                scripts = []
                for script in port.findall("script"):
                    scripts.append({
                        "id": script.get("id"),
                        "output": script.get("output", "").strip(),
                    })

                finding = {
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "reason": reason,
                    "service": service_info.get("name", "unknown"),
                    "product": service_info.get("product", ""),
                    "version": service_info.get("version", ""),
                    "extra_info": service_info.get("extrainfo", ""),
                    "scripts": scripts,
                    "host_state": host_state,
                }
                findings.append(finding)

    summary = {
        "open_ports": total_open,
        "closed_ports": total_closed,
        "filtered_ports": total_filtered,
        "total_ports_reported": len(findings),
    }

    return findings, summary


def _parse_nmap_text(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Fallback text regex parser for nmap output."""
    findings: list[dict[str, Any]] = []
    # Pattern: 80/tcp open http Apache httpd 2.4.54
    pattern = re.compile(
        r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|closed|filtered)\s+(?P<service>\S+)(?:\s+(?P<version>.*))?$",
        re.MULTILINE,
    )

    total_open = 0
    total_closed = 0
    total_filtered = 0

    for match in pattern.finditer(text):
        port_num = int(match.group("port"))
        proto = match.group("proto")
        state = match.group("state")
        service = match.group("service")
        version = (match.group("version") or "").strip()

        if state == "open":
            total_open += 1
        elif state == "closed":
            total_closed += 1
        elif state == "filtered":
            total_filtered += 1

        findings.append({
            "port": port_num,
            "protocol": proto,
            "state": state,
            "service": service,
            "version": version,
        })

    summary = {
        "open_ports": total_open,
        "closed_ports": total_closed,
        "filtered_ports": total_filtered,
        "total_ports_reported": len(findings),
    }

    return findings, summary
