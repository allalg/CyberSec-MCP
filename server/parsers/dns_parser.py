"""DNS output parser — extracts structured DNS records from `dig` and `nslookup` output."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def parse_dns_output(raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse raw DNS query output (from `dig` or `nslookup`).

    Returns:
        tuple of (records, summary)
    """
    if not raw_output or not raw_output.strip():
        return [], {"error": "Empty DNS output", "total_records": 0}

    # Attempt dig parsing first
    if ";; ANSWER SECTION:" in raw_output or ";; QUESTION SECTION:" in raw_output:
        return _parse_dig_output(raw_output)

    # Fallback to general line parser
    return _parse_general_dns(raw_output)


def _parse_dig_output(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Extract records from `dig` standard output."""
    records: list[dict[str, Any]] = []

    # Check for ANSWER SECTION
    in_answer = False
    in_authority = False
    in_additional = False

    # Regex for standard resource record:
    # name.  ttl  class  type  rdata
    # e.g.: example.com.  300  IN  A  93.184.216.34
    rr_pattern = re.compile(
        r"^(?P<name>\S+)\s+(?P<ttl>\d+)\s+(?P<class>\S+)\s+(?P<type>[A-Z0-9]+)\s+(?P<value>.+)$"
    )

    query_time = None
    server = None

    for line in text.splitlines():
        line = line.strip()

        if line.startswith(";; ANSWER SECTION:"):
            in_answer = True
            in_authority = False
            in_additional = False
            continue
        elif line.startswith(";; AUTHORITY SECTION:"):
            in_answer = False
            in_authority = True
            in_additional = False
            continue
        elif line.startswith(";; ADDITIONAL SECTION:"):
            in_answer = False
            in_authority = False
            in_additional = True
            continue
        elif line.startswith(";; Query time:"):
            m = re.search(r";; Query time:\s+(\d+)\s+msec", line)
            if m:
                query_time = int(m.group(1))
            continue
        elif line.startswith(";; SERVER:"):
            m = re.search(r";; SERVER:\s+(\S+)", line)
            if m:
                server = m.group(1)
            continue
        elif line.startswith(";;") or not line:
            continue

        section = "answer" if in_answer else ("authority" if in_authority else ("additional" if in_additional else "other"))
        match = rr_pattern.match(line)
        if match:
            records.append({
                "name": match.group("name").rstrip("."),
                "ttl": int(match.group("ttl")),
                "class": match.group("class"),
                "type": match.group("type"),
                "value": match.group("value").strip(),
                "section": section,
            })

    summary = {
        "total_records": len(records),
        "answer_count": sum(1 for r in records if r.get("section") == "answer"),
        "query_time_ms": query_time,
        "server": server,
    }

    return records, summary


def _parse_general_dns(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Generic fallback parser for other DNS response formats."""
    records: list[dict[str, Any]] = []

    # Look for Address: X or Name: Y pairs
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Look for IP matches
        ip_match = re.search(r"(?:Address|has address|points to)\s*[:=]?\s*([0-9a-fA-F.:]+)", line)
        if ip_match:
            records.append({
                "type": "A" if "." in ip_match.group(1) else "AAAA",
                "value": ip_match.group(1),
                "section": "answer",
            })

    summary = {
        "total_records": len(records),
        "answer_count": len(records),
    }
    return records, summary
