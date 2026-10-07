"""Whois output parser — parses whois query text into structured entity, domain, and registrar metadata."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def parse_whois_output(raw_output: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse raw whois client output.

    Returns:
        tuple of (findings, summary)
    """
    if not raw_output or not raw_output.strip():
        return [], {"error": "Empty whois output"}

    lines = raw_output.splitlines()

    extracted: dict[str, Any] = {
        "domain_name": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "nameservers": [],
        "status": [],
        "registrant": {},
        "admin_contact": {},
        "tech_contact": {},
        "emails": [],
    }

    # Common regex patterns for WHOIS keys
    for line in lines:
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, val = [p.strip() for p in line.split(":", 1)]
        k_lower = key.lower()

        if "domain name" in k_lower and not extracted["domain_name"]:
            extracted["domain_name"] = val
        elif "registrar" in k_lower and not extracted["registrar"]:
            extracted["registrar"] = val
        elif any(term in k_lower for term in ["creation date", "created", "registration date"]):
            if not extracted["creation_date"]:
                extracted["creation_date"] = val
        elif any(term in k_lower for term in ["expiry date", "expiration date", "registry expiry"]):
            if not extracted["expiration_date"]:
                extracted["expiration_date"] = val
        elif any(term in k_lower for term in ["updated date", "last update"]):
            if not extracted["updated_date"]:
                extracted["updated_date"] = val
        elif "name server" in k_lower or "nserver" in k_lower:
            val_clean = val.lower().rstrip(".")
            if val_clean and val_clean not in extracted["nameservers"]:
                extracted["nameservers"].append(val_clean)
        elif "domain status" in k_lower or "status" in k_lower:
            if val and val not in extracted["status"]:
                extracted["status"].append(val)
        elif "registrant organization" in k_lower or "org-name" in k_lower:
            extracted["registrant"]["organization"] = val
        elif "registrant country" in k_lower or "country" in k_lower:
            extracted["registrant"]["country"] = val

        # Collect email addresses
        email_matches = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", val)
        for email in email_matches:
            if email not in extracted["emails"]:
                extracted["emails"].append(email)

    findings = [
        {
            "domain": extracted["domain_name"],
            "registrar": extracted["registrar"],
            "creation_date": extracted["creation_date"],
            "expiration_date": extracted["expiration_date"],
            "updated_date": extracted["updated_date"],
            "nameservers": extracted["nameservers"],
            "status": extracted["status"],
            "registrant": extracted["registrant"],
            "emails": extracted["emails"],
        }
    ]

    summary = {
        "domain": extracted["domain_name"],
        "registrar": extracted["registrar"],
        "nameserver_count": len(extracted["nameservers"]),
    }

    return findings, summary
