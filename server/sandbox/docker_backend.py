"""Docker Backend — low-level Docker SDK wrapper for container lifecycle.

Handles: image checks, container creation, execution, log capture, timeout, cleanup.
"""

from __future__ import annotations

import asyncio
import logging
import time

import docker
from docker.errors import DockerException, ImageNotFound, NotFound

from server.models import SandboxProfile, SandboxResult

logger = logging.getLogger(__name__)


class DockerBackend:
    """Manages Docker containers for sandboxed tool execution."""

    def __init__(self):
        try:
            self._client = docker.from_env()
            self._client.ping()
            logger.info("Docker connection established")
        except DockerException as e:
            logger.error("Failed to connect to Docker: %s", e)
            raise RuntimeError(
                "Docker is not available. Ensure Docker Desktop is running."
            ) from e

    def health_check(self) -> dict:
        """Verify Docker is running and return version info."""
        try:
            info = self._client.info()
            return {
                "status": "healthy",
                "server_version": info.get("ServerVersion", "unknown"),
                "containers_running": info.get("ContainersRunning", 0),
                "images": info.get("Images", 0),
            }
        except DockerException as e:
            return {"status": "unhealthy", "error": str(e)}

    def image_exists(self, image_name: str) -> bool:
        """Check if a Docker image exists locally."""
        try:
            self._client.images.get(image_name)
            return True
        except ImageNotFound:
            return False

    def check_required_images(self, profiles: dict[str, SandboxProfile]) -> dict[str, bool]:
        """Check which required sandbox images are available."""
        seen = set()
        results = {}
        for name, profile in profiles.items():
            if profile.image_name not in seen:
                seen.add(profile.image_name)
                results[profile.image_name] = self.image_exists(profile.image_name)
        return results

    async def execute(
        self,
        profile: SandboxProfile,
        command: list[str],
        timeout: int | None = None,
        volumes: dict | None = None,
    ) -> SandboxResult:
        """Execute a command inside a disposable container.

        Lifecycle: create → start → wait (with timeout) → collect logs → destroy
        """
        timeout = timeout or profile.timeout
        container = None
        start_time = time.monotonic()

        try:
            # Build container config
            container_config = {
                "image": profile.image_name,
                "command": command,
                "detach": True,
                "network_mode": profile.network_mode,
                "mem_limit": profile.memory_limit,
                "nano_cpus": int(profile.cpu_limit * 1e9),
                "read_only": profile.read_only_fs,
                "auto_remove": False,  # we remove manually after collecting logs
            }

            if volumes:
                container_config["volumes"] = volumes

            # Create and start
            container = await asyncio.to_thread(
                self._client.containers.create, **container_config
            )
            container_id = container.short_id
            logger.info("Container created: %s (image=%s)", container_id, profile.image_name)

            await asyncio.to_thread(container.start)
            logger.debug("Container started: %s", container_id)

            # Wait with timeout
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(container.wait),
                    timeout=timeout,
                )
                exit_code = result.get("StatusCode", -1)
                timed_out = False
            except asyncio.TimeoutError:
                logger.warning("Container %s timed out after %ds", container_id, timeout)
                await asyncio.to_thread(container.kill)
                exit_code = -1
                timed_out = True

            # Collect logs
            stdout = await asyncio.to_thread(
                container.logs, stdout=True, stderr=False
            )
            stderr = await asyncio.to_thread(
                container.logs, stdout=False, stderr=True
            )

            duration_ms = int((time.monotonic() - start_time) * 1000)

            return SandboxResult(
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=exit_code,
                duration_ms=duration_ms,
                timed_out=timed_out,
                container_id=container_id,
            )

        except DockerException as e:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            logger.error("Docker execution failed: %s", e)
            return SandboxResult(
                stderr=str(e),
                exit_code=-1,
                duration_ms=duration_ms,
                timed_out=False,
            )

        finally:
            # Always clean up the container
            if container is not None:
                try:
                    await asyncio.to_thread(container.remove, force=True)
                    logger.debug("Container removed: %s", container.short_id)
                except (NotFound, DockerException):
                    pass  # already removed or failed to remove

    def close(self) -> None:
        """Close the Docker client."""
        self._client.close()
