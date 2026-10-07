"""Sandbox profiles — per-tool Docker container configurations.

Each tool maps to a profile that specifies the image, resource limits,
network access, and timeout constraints for its sandbox container.
"""

from __future__ import annotations

from server.models import SandboxProfile

# ---------------------------------------------------------------------------
# Pre-defined sandbox profiles for the 6 MVP tools
# ---------------------------------------------------------------------------

SANDBOX_PROFILES: dict[str, SandboxProfile] = {
    # ── Recon Tools ────────────────────────────────────────────────────
    "nmap": SandboxProfile(
        image_name="cybersec-mcp/nmap:latest",
        network_mode="bridge",       # nmap needs network access
        memory_limit="128m",
        cpu_limit=0.5,
        timeout=120,
        read_only_fs=True,
    ),
    "dns": SandboxProfile(
        image_name="cybersec-mcp/web-tools:latest",
        network_mode="bridge",       # DNS queries need network
        memory_limit="64m",
        cpu_limit=0.25,
        timeout=30,
        read_only_fs=True,
    ),
    "whois": SandboxProfile(
        image_name="cybersec-mcp/web-tools:latest",
        network_mode="bridge",
        memory_limit="64m",
        cpu_limit=0.25,
        timeout=30,
        read_only_fs=True,
    ),

    # ── Web Tools ──────────────────────────────────────────────────────
    "web": SandboxProfile(
        image_name="cybersec-mcp/web-tools:latest",
        network_mode="bridge",       # HTTP probing needs network
        memory_limit="256m",
        cpu_limit=1.0,
        timeout=180,
        read_only_fs=True,
    ),

    # ── Analysis Tools ─────────────────────────────────────────────────
    "analysis": SandboxProfile(
        image_name="cybersec-mcp/analysis:latest",
        network_mode="none",         # NO network — file analysis only
        memory_limit="64m",
        cpu_limit=0.25,
        timeout=30,
        read_only_fs=True,
    ),
}


def get_profile(tool_name: str) -> SandboxProfile:
    """Get the sandbox profile for a given tool name.

    Maps tool names to their sandbox category:
    - nmap_scan → nmap
    - dns_lookup, whois_lookup → dns/whois
    - http_probe, directory_scan → web
    - hash_file → analysis
    """
    mapping: dict[str, str] = {
        "nmap_scan": "nmap",
        "dns_lookup": "dns",
        "whois_lookup": "whois",
        "http_probe": "web",
        "directory_scan": "web",
        "hash_file": "analysis",
    }
    profile_key = mapping.get(tool_name, tool_name)
    if profile_key not in SANDBOX_PROFILES:
        raise ValueError(f"No sandbox profile for tool {tool_name!r} (mapped to {profile_key!r})")
    return SANDBOX_PROFILES[profile_key]
