"""Proxy registration and health check management.

This module provides Python functions to interact with the unified proxy's
internal API for container registration and lifecycle management.

Security Model:
- Communicates with proxy via Unix socket, HTTP, or docker exec
- Used by container lifecycle scripts (new.sh, destroy.sh)
- Not exposed to containers themselves

Environment Variables:
- PROXY_SOCKET_PATH: Full path to proxy internal API socket (host-side)
- PROXY_CONTAINER_NAME: Explicit unified-proxy container name
- PROXY_URL: Alternative HTTP URL for proxy (for development/testing)
- CONTAINER_NAME: Fallback for deriving proxy container name
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Any, Callable

from foundry_sandbox._bridge import bridge_main
from foundry_sandbox.utils import log_debug, log_error, log_info, log_warn

# Constants
DEFAULT_TTL_SECONDS = 86400
INTERNAL_SOCKET_PATH = "/var/run/proxy/internal.sock"
DEFAULT_NETWORK = "credential-isolation"


def proxy_container_name() -> str:
    """Get the proxy container name from environment variables.

    Returns:
        Proxy container name, or empty string if not determinable.
    """
    proxy_name = os.environ.get("PROXY_CONTAINER_NAME", "")
    if proxy_name:
        return proxy_name

    container_name = os.environ.get("CONTAINER_NAME", "")
    if container_name:
        return f"{container_name}-unified-proxy-1"

    return ""


def proxy_curl(
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    *,
    include_status_code: bool = False,
) -> dict[str, Any]:
    """Execute HTTP request to proxy using appropriate transport.

    Args:
        method: HTTP method (GET, POST, DELETE, etc.)
        path: API path (e.g., "/internal/health")
        data: Optional JSON data to send in request body
        include_status_code: If True, return dict with "body" and "http_code" keys

    Returns:
        If include_status_code=False: Parsed JSON response body
        If include_status_code=True: {"body": <json>, "http_code": <int>}

    Raises:
        RuntimeError: If curl command fails or JSON parsing fails
    """
    # Determine transport mode
    proxy_url = os.environ.get("PROXY_URL", "")
    proxy_socket = os.environ.get("PROXY_SOCKET_PATH", "")

    try:
        if proxy_url:
            # Mode 1: Direct HTTP
            cmd = ["curl", "-s", "-X", method]
            if include_status_code:
                cmd.extend(["-w", "\n%{http_code}"])
            if data:
                cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
            cmd.append(f"{proxy_url}{path}")

            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)

        elif proxy_socket:
            # Mode 2: Unix socket
            cmd = ["curl", "-s", "--unix-socket", proxy_socket, "-X", method]
            if include_status_code:
                cmd.extend(["-w", "\n%{http_code}"])
            if data:
                cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
            cmd.append(f"http://localhost{path}")

            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)

        else:
            # Mode 3: Docker exec fallback
            proxy_container = proxy_container_name()
            if not proxy_container:
                raise RuntimeError("proxy_curl: PROXY_CONTAINER_NAME or CONTAINER_NAME required")

            cmd = ["docker", "exec", proxy_container, "curl", "-s",
                   "--unix-socket", INTERNAL_SOCKET_PATH, "-X", method]
            if include_status_code:
                cmd.extend(["-w", "\n%{http_code}"])
            if data:
                cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
            cmd.append(f"http://localhost{path}")

            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)

        if result.returncode != 0:
            raise RuntimeError(f"curl failed with exit code {result.returncode}: {result.stderr}")

        output = result.stdout

        if include_status_code:
            # Parse HTTP code from last line
            lines = output.strip().split("\n")
            if len(lines) < 2:
                raise RuntimeError("Unexpected curl output format (missing HTTP code)")
            http_code = int(lines[-1])
            body_text = "\n".join(lines[:-1])
            # Parse JSON body
            try:
                body = json.loads(body_text) if body_text else {}
            except json.JSONDecodeError:
                body = {"raw": body_text}
            return {"body": body, "http_code": http_code}
        else:
            # Parse JSON directly
            return json.loads(output) if output else {}

    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"curl timed out after 30s: {e}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Failed to parse JSON response: {e}")


def proxy_register(
    container_id: str,
    ip_address: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Register a container with the proxy.

    Args:
        container_id: The container ID
        ip_address: The container's IP address
        ttl_seconds: TTL in seconds (default: 86400 = 24 hours)
        metadata: Optional metadata as dict

    Returns:
        JSON response string on success

    Raises:
        RuntimeError: If registration fails
    """
    if not container_id or not ip_address:
        raise RuntimeError("proxy_register: container_id and ip_address required")

    # Build request body
    body: dict[str, Any] = {
        "container_id": container_id,
        "ip_address": ip_address,
        "ttl_seconds": ttl_seconds,
    }
    if metadata:
        body["metadata"] = metadata

    try:
        response = proxy_curl("POST", "/internal/containers", body)
    except RuntimeError as e:
        log_error(f"proxy_register: curl error: {e}")
        raise

    # Check status in response
    status = response.get("status", "")
    if status == "registered":
        log_debug(f"Registered container {container_id} with IP {ip_address}")
        return json.dumps(response)

    # Extract error message
    error_msg = response.get("message", response.get("error", "Unknown error"))
    log_error(f"proxy_register: Failed to register container: {error_msg}")
    raise RuntimeError(f"Registration failed: {error_msg}")


def proxy_unregister(container_id: str) -> int:
    """Unregister a container from the proxy.

    Args:
        container_id: The container ID to unregister

    Returns:
        0 always (never fails, to avoid blocking destroy operations)
    """
    if not container_id:
        log_error("proxy_unregister: container_id required")
        return 0

    try:
        result = proxy_curl("DELETE", f"/internal/containers/{container_id}", include_status_code=True)
        http_code = result["http_code"]

        if http_code == 200:
            log_debug(f"Unregistered container {container_id}")
        elif http_code == 404:
            log_debug(f"Container {container_id} not found (already unregistered)")
        else:
            body = result["body"]
            error_msg = body.get("message", body.get("error", "Unknown error"))
            log_warn(f"proxy_unregister: Unexpected response ({http_code}): {error_msg}")

    except Exception as e:
        log_warn(f"proxy_unregister: error (may be expected if proxy stopped): {e}")

    return 0


def proxy_wait_ready(
    timeout: int = 30,
    *,
    _sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Wait for proxy to be ready with exponential backoff.

    Args:
        timeout: Maximum time to wait in seconds (default: 30)
        _sleep: Sleep function for testing (default: time.sleep)

    Returns:
        True if proxy is healthy within timeout, False otherwise
    """
    elapsed = 0
    delay = 1
    max_delay = 8

    log_debug(f"Waiting for proxy to be ready (timeout: {timeout}s)...")

    while elapsed < timeout:
        try:
            result = proxy_curl("GET", "/internal/health", include_status_code=True)
            if result["http_code"] == 200:
                body = result["body"]
                if body.get("status") == "healthy":
                    log_debug(f"Proxy is ready (took {elapsed}s)")
                    return True
        except Exception:
            # Ignore errors during health check polling
            pass

        # Calculate sleep time for this iteration
        remaining = timeout - elapsed
        if delay > remaining:
            delay = remaining

        if delay > 0:
            _sleep(delay)
            elapsed += delay

        # Exponential backoff: 1, 2, 4, 8, 8, 8... seconds
        if delay < max_delay:
            delay = min(delay * 2, max_delay)

    # Timeout reached
    log_error(f"Proxy health check timed out after {timeout}s")
    log_error("Remediation steps:")
    log_error("  1. Check if proxy container is running: docker ps | grep unified-proxy")
    log_error("  2. View proxy logs: docker logs <proxy-container>")
    log_error("  3. Check internal API: docker exec <proxy-container> curl --unix-socket /var/run/proxy/internal.sock http://localhost/internal/health")
    return False


def proxy_get_container_ip(container_id: str, network: str = DEFAULT_NETWORK) -> str:
    """Get container IP address on a specific network.

    Args:
        container_id: Docker container ID
        network: Network name (default: credential-isolation)

    Returns:
        IP address string, or empty string if not found
    """
    try:
        # Use docker inspect with index function for network names
        cmd = [
            "docker", "inspect", "-f",
            f"{{{{(index .NetworkSettings.Networks \"{network}\").IPAddress}}}}",
            container_id
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)

        if result.returncode == 0:
            ip = result.stdout.strip()
            # Docker returns "<no value>" when network not found
            if ip and ip != "<no value>":
                return ip
    except Exception:
        pass

    return ""


def setup_proxy_registration(
    container_id: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Setup proxy registration for a container.

    This is the main entry point for integration with sandbox startup.
    Handles the full registration lifecycle with proper error handling.

    Args:
        container_id: Docker container ID
        metadata: Optional metadata dict

    Raises:
        RuntimeError: If setup fails (fails sandbox start)
    """
    log_debug(f"Setting up proxy registration for container {container_id}...")

    # Wait for proxy to be ready (with 30s timeout)
    if not proxy_wait_ready(30):
        raise RuntimeError("Proxy is not ready")

    # Get container IP on credential-isolation network
    container_ip = proxy_get_container_ip(container_id, DEFAULT_NETWORK)

    if not container_ip:
        # Try with project prefix pattern (e.g., myproject_credential-isolation)
        project_prefix = container_id.rsplit("-dev-1", 1)[0] if "-dev-1" in container_id else ""
        if project_prefix:
            container_ip = proxy_get_container_ip(container_id, f"{project_prefix}_credential-isolation")

    if not container_ip:
        log_error("Could not determine container IP address on credential-isolation network")
        log_error("Remediation steps:")
        log_error("  1. Verify container is connected to credential-isolation network")
        log_error("  2. Check docker-compose.credential-isolation.yml network configuration")
        log_error("  3. Try: docker network inspect credential-isolation")
        raise RuntimeError("Could not determine container IP address")

    log_debug(f"Container IP: {container_ip}")

    # Register with proxy (discarding output)
    proxy_register(container_id, container_ip, DEFAULT_TTL_SECONDS, metadata)

    log_debug("Proxy registration complete")


def cleanup_proxy_registration(container_id: str) -> int:
    """Cleanup proxy registration for a container being destroyed.

    Best-effort cleanup - should not block sandbox destruction.

    Args:
        container_id: Docker container ID

    Returns:
        0 always (cleanup should not block destroy)
    """
    if not container_id:
        return 0

    log_debug("Cleaning up proxy registration...")

    # Unregister - ignore failures (proxy may be stopped)
    proxy_unregister(container_id)

    return 0


def proxy_is_registered(container_id: str) -> bool:
    """Check if a container is registered with the proxy.

    Args:
        container_id: Docker container ID

    Returns:
        True if registered, False if not registered or error
    """
    if not container_id:
        return False

    try:
        result = proxy_curl("GET", f"/internal/containers/{container_id}", include_status_code=True)
        return result["http_code"] == 200
    except Exception:
        return False


# Bridge command handlers

def _cmd_proxy_container_name() -> str:
    """Bridge command: Get proxy container name."""
    return proxy_container_name()


def _cmd_proxy_register(
    container_id: str,
    ip_address: str,
    ttl_seconds: str = str(DEFAULT_TTL_SECONDS),
    metadata_json: str = "",
) -> str:
    """Bridge command: Register container with proxy."""
    ttl = int(ttl_seconds)
    metadata = json.loads(metadata_json) if metadata_json else None
    return proxy_register(container_id, ip_address, ttl, metadata)


def _cmd_proxy_unregister(container_id: str) -> int:
    """Bridge command: Unregister container from proxy."""
    return proxy_unregister(container_id)


def _cmd_proxy_wait_ready(timeout: str = "30") -> bool:
    """Bridge command: Wait for proxy to be ready."""
    return proxy_wait_ready(int(timeout))


def _cmd_proxy_get_container_ip(container_id: str, network: str = DEFAULT_NETWORK) -> str:
    """Bridge command: Get container IP on network."""
    return proxy_get_container_ip(container_id, network)


def _cmd_setup_proxy_registration(container_id: str, metadata_json: str = "") -> str:
    """Bridge command: Setup proxy registration."""
    metadata = json.loads(metadata_json) if metadata_json else None
    setup_proxy_registration(container_id, metadata)
    return "success"


def _cmd_cleanup_proxy_registration(container_id: str) -> int:
    """Bridge command: Cleanup proxy registration."""
    return cleanup_proxy_registration(container_id)


def _cmd_proxy_is_registered(container_id: str) -> bool:
    """Bridge command: Check if container is registered."""
    return proxy_is_registered(container_id)


if __name__ == "__main__":
    bridge_main({
        "proxy-container-name": _cmd_proxy_container_name,
        "proxy-register": _cmd_proxy_register,
        "proxy-unregister": _cmd_proxy_unregister,
        "proxy-wait-ready": _cmd_proxy_wait_ready,
        "proxy-get-container-ip": _cmd_proxy_get_container_ip,
        "setup-proxy-registration": _cmd_setup_proxy_registration,
        "cleanup-proxy-registration": _cmd_cleanup_proxy_registration,
        "proxy-is-registered": _cmd_proxy_is_registered,
    })
