"""Unit tests for SandboxManager and sandbox profiles."""

from __future__ import annotations

import asyncio
import pytest

from server.models import SandboxProfile
from server.sandbox.manager import SandboxManager
from server.sandbox.profiles import get_profile
from tests.conftest import MockDockerBackend


def test_sandbox_profiles_lookup():
    p_nmap = get_profile("nmap_scan")
    assert p_nmap.image_name == "cybersec-mcp/nmap:latest"
    assert p_nmap.network_mode == "bridge"

    p_analysis = get_profile("hash_file")
    assert p_analysis.image_name == "cybersec-mcp/analysis:latest"
    assert p_analysis.network_mode == "none"  # Air-gapped!

    with pytest.raises(ValueError):
        get_profile("invalid_tool_unknown")


@pytest.mark.asyncio
async def test_sandbox_concurrency_limiting():
    # Verify semaphore limits concurrent runs
    backend = MockDockerBackend()
    manager = SandboxManager(max_concurrent=2, docker_backend=backend)

    active_executions = 0
    max_observed_active = 0

    async def mock_run():
        nonlocal active_executions, max_observed_active
        async with manager._semaphore:
            active_executions += 1
            max_observed_active = max(max_observed_active, active_executions)
            await asyncio.sleep(0.05)
            active_executions -= 1

    tasks = [mock_run() for _ in range(5)]
    await asyncio.gather(*tasks)

    assert max_observed_active <= 2
