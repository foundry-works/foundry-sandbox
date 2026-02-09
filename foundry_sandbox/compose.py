"""Docker Compose override YAML assembly for foundry-sandbox.

Extracted from lib/container_config.sh compose generation logic.
Orchestrates docker-compose.override.yml assembly from sandbox configuration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from foundry_sandbox.network import (
    add_claude_home_to_override,
    add_network_to_override,
    add_ssh_agent_to_override,
    add_timezone_to_override,
    append_override_list_item,
    ensure_override_header,
)
from foundry_sandbox.utils import log_debug


def assemble_override(
    override_file: str,
    *,
    claude_home: str = "",
    network_mode: str = "limited",
    ssh_agent_sock: str = "",
    extra_volumes: list[str] | None = None,
    isolate_credentials: bool = False,
) -> None:
    """Assemble a docker-compose override file from sandbox configuration.

    Orchestrates the complete override file assembly in the correct order,
    matching the sequence from commands/new.sh:
      1. Ensure header (services:/dev:)
      2. Add extra volume mounts
      3. Add network configuration (non-credential-isolation only)
      4. Add Claude home volume
      5. Add timezone
      6. Add SSH agent

    Args:
        override_file: Path to docker-compose override file.
        claude_home: Host path to Claude config directory.
        network_mode: Network mode ('limited', 'host-only', 'none').
        ssh_agent_sock: Host path to SSH agent socket (empty to skip).
        extra_volumes: Additional volume mount strings to include.
        isolate_credentials: Whether credential isolation is enabled.
    """
    log_debug(f"Assembling override: {override_file}")

    # 1. Ensure override file has proper header
    ensure_override_header(override_file)

    # 2. Add extra volume mounts (e.g., from metadata)
    if extra_volumes:
        for mount in extra_volumes:
            append_override_list_item(override_file, "volumes", mount)

    # 3. Add network configuration (only for non-credential-isolation mode)
    if not isolate_credentials:
        add_network_to_override(network_mode, override_file)

    # 4. Add Claude home volume mount
    add_claude_home_to_override(override_file, claude_home)

    # 5. Add timezone configuration
    add_timezone_to_override(override_file)

    # 6. Add SSH agent configuration
    add_ssh_agent_to_override(override_file, ssh_agent_sock)

    log_debug(f"Override assembled: {override_file}")


def ensure_override_dir(override_file: str) -> None:
    """Ensure the directory for the override file exists.

    Args:
        override_file: Path to docker-compose override file.
    """
    path = Path(override_file)
    path.parent.mkdir(parents=True, exist_ok=True)
