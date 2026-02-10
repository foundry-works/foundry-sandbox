"""Docker image freshness checking.

Migrated from lib/image.sh. Compares Dockerfile modification time against
Docker image creation time to detect stale images.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from foundry_sandbox.constants import DOCKER_IMAGE
from foundry_sandbox.utils import log_debug, log_warn


def _get_repo_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parent.parent


def check_image_freshness() -> bool:
    """Check if Dockerfile is newer than the Docker image.

    Compares the Dockerfile modification time against the image creation
    timestamp. Returns True if the image is stale (Dockerfile is newer).

    Returns:
        True if image is stale and should be rebuilt, False otherwise.
    """
    dockerfile = _get_repo_root() / "Dockerfile"

    if not dockerfile.exists():
        log_debug("Dockerfile not found, skipping freshness check")
        return False

    dockerfile_time = dockerfile.stat().st_mtime

    # Get image creation time via docker inspect
    result = subprocess.run(
        ["docker", "inspect", DOCKER_IMAGE, "--format", "{{.Created}}"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        log_warn("Sandbox image not found.")
        return True

    # Parse the ISO 8601 timestamp from docker inspect
    image_created = result.stdout.strip()
    try:
        from datetime import datetime, timezone
        # Handle fractional seconds and Z suffix
        ts = image_created.replace("Z", "+00:00")
        image_time = datetime.fromisoformat(ts).timestamp()
    except (ValueError, OSError):
        log_debug("Could not parse image timestamp, skipping freshness check")
        return False

    if dockerfile_time > image_time:
        log_warn("Dockerfile has changed since the image was built.")
        return True

    return False
