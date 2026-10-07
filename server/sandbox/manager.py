"""Sandbox Manager — orchestrates sandboxed tool execution.

High-level interface used by MCP tools:
    manager = SandboxManager()
    result = await manager.execute("nmap_scan", ["nmap", "-sV", "target"])

Handles: profile lookup, concurrency limiting, execution, and cleanup.
"""

from __future__ import annotations

import asyncio
import logging

from server.models import SandboxProfile, SandboxResult
from server.sandbox.docker_backend import DockerBackend
from server.sandbox.profiles import SANDBOX_PROFILES, get_profile

logger = logging.getLogger(__name__)


class SandboxManager:
    """Manages sandboxed execution of cybersecurity tools via Docker containers."""

    def __init__(
        self,
        max_concurrent: int = 3,
        docker_backend: DockerBackend | None = None,
    ):
        self._max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._backend = docker_backend
        self._initialized = False

    def _ensure_backend(self) -> DockerBackend:
        """Lazily initialize the Docker backend."""
        if self._backend is None:
            self._backend = DockerBackend()
            self._initialized = True
        return self._backend

    async def health_check(self) -> dict:
        """Check Docker availability and required images."""
        try:
            backend = self._ensure_backend()
            health = backend.health_check()

            # Check sandbox images
            images = backend.check_required_images(SANDBOX_PROFILES)
            health["sandbox_images"] = images
            health["all_images_available"] = all(images.values())

            return health
        except RuntimeError as e:
            return {"status": "unhealthy", "error": str(e)}

    async def execute(
        self,
        tool_name: str,
        command: list[str],
        timeout: int | None = None,
        profile: SandboxProfile | None = None,
        volumes: dict | None = None,
    ) -> SandboxResult:
        """Execute a command in a sandboxed container for the given tool.

        Args:
            tool_name: The tool requesting execution (used to look up profile).
            command: The command to run inside the container.
            timeout: Override timeout (uses profile default if None).
            profile: Override sandbox profile (looked up from tool_name if None).
            volumes: Optional volume mounts for the container.

        Returns:
            SandboxResult with stdout, stderr, exit_code, duration, and timeout flag.
        """
        if profile is None:
            profile = get_profile(tool_name)

        backend = self._ensure_backend()

        # Check if image exists
        if not backend.image_exists(profile.image_name):
            logger.error("Sandbox image not found: %s", profile.image_name)
            return SandboxResult(
                stderr=f"Sandbox image not found: {profile.image_name}. Run 'make build-sandboxes' first.",
                exit_code=-1,
            )

        # Acquire semaphore (concurrency limiting)
        logger.debug(
            "Waiting for sandbox slot (%d/%d in use)",
            self._max_concurrent - self._semaphore._value,
            self._max_concurrent,
        )
        async with self._semaphore:
            logger.info(
                "Executing in sandbox: tool=%s image=%s cmd=%s",
                tool_name, profile.image_name, " ".join(command),
            )
            result = await backend.execute(
                profile=profile,
                command=command,
                timeout=timeout,
                volumes=volumes,
            )

            if result.timed_out:
                logger.warning(
                    "Sandbox execution timed out: tool=%s duration=%dms",
                    tool_name, result.duration_ms,
                )
            elif result.exit_code != 0:
                logger.warning(
                    "Sandbox execution failed: tool=%s exit_code=%d stderr=%s",
                    tool_name, result.exit_code, result.stderr[:200],
                )
            else:
                logger.info(
                    "Sandbox execution completed: tool=%s duration=%dms",
                    tool_name, result.duration_ms,
                )

            return result

    def close(self) -> None:
        """Clean up resources."""
        if self._backend is not None:
            self._backend.close()
