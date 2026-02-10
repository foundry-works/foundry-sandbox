"""Network mode management for sandbox containers.

This module handles network mode configuration for Docker containers,
including docker-compose override file manipulation for network isolation.

Supported modes:
  limited    - Whitelist only (GitHub, AI APIs, research APIs) - default
  host-only  - Local network only (Docker gateway, private subnets)
  none       - Complete block (loopback only)
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional

from foundry_sandbox._bridge import bridge_main
from foundry_sandbox.utils import log_warn

# Constants
SSH_AGENT_CONTAINER_SOCK = "/ssh-agent"


def validate_network_mode(mode: str) -> None:
    """Validate network mode is one of the supported modes.

    Args:
        mode: Network mode to validate.

    Raises:
        ValueError: If mode is invalid or 'full' (removed for security).
    """
    valid_modes = {"limited", "host-only", "none"}

    if mode == "full":
        raise ValueError(
            "Network mode 'full' has been removed for security reasons.\n"
            "Available modes: limited (default), host-only, none\n"
            "\n"
            "To allow additional domains, set SANDBOX_ALLOWED_DOMAINS before creating the sandbox."
        )

    if mode not in valid_modes:
        raise ValueError(f"Invalid network mode: {mode} (use: limited, host-only, none)")


def generate_network_config(mode: str, override_file: str) -> None:
    """Append network configuration to docker-compose override file.

    Args:
        mode: Network mode ('none', 'limited', or 'host-only').
        override_file: Path to docker-compose override file.
    """
    with open(override_file, "a") as f:
        if mode == "none":
            # True Docker network isolation - no network interface at all
            f.write('    network_mode: "none"\n')
        elif mode in ("limited", "host-only"):
            # Limited/host-only: use bridge network + iptables
            # Add capabilities for iptables
            f.write("    cap_add:\n")
            f.write("      - NET_ADMIN\n")
            f.write("    environment:\n")
            f.write(f"      - SANDBOX_NETWORK_MODE={mode}\n")


def ensure_override_header(override_file: str) -> None:
    """Initialize override file with services/dev header if needed.

    Args:
        override_file: Path to docker-compose override file.
    """
    path = Path(override_file)

    if not path.exists():
        # Create new file with header (with trailing newline to match shell heredoc)
        with open(override_file, "w") as f:
            f.write("services:\n  dev:\n")
    else:
        # Check if header exists
        with open(override_file, "r") as f:
            content = f.read()

        if not content.startswith("services:"):
            # File exists but missing header - prepend it
            with open(override_file, "w") as f:
                f.write("services:\n  dev:\n")
                f.write(content)


def strip_network_config(override_file: str) -> None:
    """Remove network-related config from override file.

    Removes:
    - cap_add entries for NET_ADMIN, NET_RAW, SYS_ADMIN
    - environment entries for SANDBOX_NETWORK_MODE
    - Empty cap_add/environment headers if all items stripped

    Args:
        override_file: Path to docker-compose override file.
    """
    path = Path(override_file)
    if not path.exists():
        return

    with open(override_file, "r") as f:
        lines = f.readlines()

    result = []
    in_cap_add = False
    in_environment = False
    cap_add_header = ""
    env_header = ""
    cap_add_items = []
    env_items = []

    for line in lines:
        stripped = line.rstrip()

        # Check for cap_add header (4 spaces)
        if stripped == "    cap_add:":
            # Flush previous environment block if active
            if in_environment:
                if env_items:
                    result.append(env_header)
                    result.extend(env_items)
                in_environment = False
                env_items = []
            # Start cap_add block
            in_cap_add = True
            cap_add_header = line
            cap_add_items = []
            continue

        # Check for environment header (4 spaces)
        if stripped == "    environment:":
            # Flush previous cap_add block if active
            if in_cap_add:
                if cap_add_items:
                    result.append(cap_add_header)
                    result.extend(cap_add_items)
                in_cap_add = False
                cap_add_items = []
            # Start environment block
            in_environment = True
            env_header = line
            env_items = []
            continue

        # Process cap_add items
        if in_cap_add:
            # Check if this is a list item (6 spaces + dash)
            if stripped.startswith("      -"):
                # Check if it's a network capability
                if any(cap in stripped for cap in ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]):
                    # Skip this item
                    continue
                else:
                    # Keep this item
                    cap_add_items.append(line)
                    continue
            else:
                # No longer in cap_add section - flush it
                if cap_add_items:
                    result.append(cap_add_header)
                    result.extend(cap_add_items)
                in_cap_add = False
                cap_add_items = []
                # Fall through to process this line normally

        # Process environment items
        if in_environment:
            # Check if this is a list item (6 spaces + dash)
            if stripped.startswith("      -"):
                # Check if it's SANDBOX_NETWORK_MODE
                if "SANDBOX_NETWORK_MODE=" in stripped:
                    # Skip this item
                    continue
                else:
                    # Keep this item
                    env_items.append(line)
                    continue
            else:
                # No longer in environment section - flush it
                if env_items:
                    result.append(env_header)
                    result.extend(env_items)
                in_environment = False
                env_items = []
                # Fall through to process this line normally

        # Regular line, not in any special block
        if not in_cap_add and not in_environment:
            result.append(line)

    # Handle case where file ends while in a block
    if in_cap_add and cap_add_items:
        result.append(cap_add_header)
        result.extend(cap_add_items)
    if in_environment and env_items:
        result.append(env_header)
        result.extend(env_items)

    # Write back
    with open(override_file, "w") as f:
        f.writelines(result)


def strip_ssh_agent_config(override_file: str) -> None:
    """Remove SSH agent configuration from override file.

    Removes:
    - Volume mounts targeting SSH_AGENT_CONTAINER_SOCK
    - group_add entries for "0"
    - SSH_AUTH_SOCK environment entries

    Args:
        override_file: Path to docker-compose override file.
    """
    path = Path(override_file)
    if not path.exists():
        return

    with open(override_file, "r") as f:
        lines = f.readlines()

    result = []
    in_volumes = False
    in_group_add = False
    in_environment = False
    volumes_header = ""
    group_add_header = ""
    env_header = ""
    volumes_items = []
    group_add_items = []
    env_items = []

    def flush_block(block_name: str) -> None:
        """Flush a block if it has items."""
        nonlocal in_volumes, in_group_add, in_environment
        nonlocal volumes_items, group_add_items, env_items

        if block_name == "volumes" and volumes_items:
            result.append(volumes_header)
            result.extend(volumes_items)
            volumes_items = []
        elif block_name == "group_add" and group_add_items:
            result.append(group_add_header)
            result.extend(group_add_items)
            group_add_items = []
        elif block_name == "environment" and env_items:
            result.append(env_header)
            result.extend(env_items)
            env_items = []

        in_volumes = False
        in_group_add = False
        in_environment = False

    for line in lines:
        stripped = line.rstrip()

        # Check for block headers (4 spaces)
        if stripped == "    volumes:":
            if in_volumes or in_group_add or in_environment:
                flush_block("volumes" if in_volumes else "group_add" if in_group_add else "environment")
            in_volumes = True
            volumes_header = line
            volumes_items = []
            continue

        if stripped == "    group_add:":
            if in_volumes or in_group_add or in_environment:
                flush_block("volumes" if in_volumes else "group_add" if in_group_add else "environment")
            in_group_add = True
            group_add_header = line
            group_add_items = []
            continue

        if stripped == "    environment:":
            if in_volumes or in_group_add or in_environment:
                flush_block("volumes" if in_volumes else "group_add" if in_group_add else "environment")
            in_environment = True
            env_header = line
            env_items = []
            continue

        # Process volumes items
        if in_volumes:
            if stripped.startswith("      -"):
                if f":{SSH_AGENT_CONTAINER_SOCK}" in stripped:
                    continue
                else:
                    volumes_items.append(line)
                    continue
            else:
                flush_block("volumes")
                # Fall through to process this line

        # Process group_add items
        if in_group_add:
            if stripped.startswith("      -"):
                # Check if this is group "0" (with or without quotes)
                stripped_item = stripped.strip()
                if stripped_item in ('- "0"', "- '0'", "- 0"):
                    continue
                else:
                    group_add_items.append(line)
                    continue
            else:
                flush_block("group_add")
                # Fall through to process this line

        # Process environment items
        if in_environment:
            if stripped.startswith("      -"):
                if "SSH_AUTH_SOCK=" in stripped:
                    continue
                else:
                    env_items.append(line)
                    continue
            else:
                flush_block("environment")
                # Fall through to process this line

        # Regular line
        if not in_volumes and not in_group_add and not in_environment:
            result.append(line)

    # Handle case where file ends while in a block
    if in_volumes and volumes_items:
        result.append(volumes_header)
        result.extend(volumes_items)
    if in_group_add and group_add_items:
        result.append(group_add_header)
        result.extend(group_add_items)
    if in_environment and env_items:
        result.append(env_header)
        result.extend(env_items)

    # Write back
    with open(override_file, "w") as f:
        f.writelines(result)


def strip_claude_home_config(override_file: str) -> None:
    """Remove Claude home volume mount from override file.

    Removes volume mounts targeting /home/ubuntu/.claude.

    Args:
        override_file: Path to docker-compose override file.
    """
    path = Path(override_file)
    if not path.exists():
        return

    target = "/home/ubuntu/.claude"

    with open(override_file, "r") as f:
        lines = f.readlines()

    result = []
    in_volumes = False
    volumes_header = ""
    volumes_items = []

    for line in lines:
        stripped = line.rstrip()

        # Check for volumes header (4 spaces)
        if stripped == "    volumes:":
            in_volumes = True
            volumes_header = line
            volumes_items = []
            continue

        # Process volumes items
        if in_volumes:
            if stripped.startswith("      -"):
                # Check if this volume mounts to target
                if f":{target}" in stripped:
                    continue
                else:
                    volumes_items.append(line)
                    continue
            else:
                # No longer in volumes - flush it
                if volumes_items:
                    result.append(volumes_header)
                    result.extend(volumes_items)
                in_volumes = False
                volumes_items = []
                # Fall through to process this line

        # Regular line
        if not in_volumes:
            result.append(line)

    # Handle case where file ends while in volumes
    if in_volumes and volumes_items:
        result.append(volumes_header)
        result.extend(volumes_items)

    # Write back
    with open(override_file, "w") as f:
        f.writelines(result)


def strip_timezone_config(override_file: str) -> None:
    """Remove timezone configuration from override file.

    Removes:
    - /etc/localtime and /etc/timezone volume mounts
    - TZ= environment entries

    Args:
        override_file: Path to docker-compose override file.
    """
    path = Path(override_file)
    if not path.exists():
        return

    with open(override_file, "r") as f:
        lines = f.readlines()

    result = []
    in_volumes = False
    in_environment = False
    volumes_header = ""
    env_header = ""
    volumes_items = []
    env_items = []

    for line in lines:
        stripped = line.rstrip()

        # Check for volumes header (4 spaces)
        if stripped == "    volumes:":
            # Flush previous environment block if active
            if in_environment:
                if env_items:
                    result.append(env_header)
                    result.extend(env_items)
                in_environment = False
                env_items = []
            # Start volumes block
            in_volumes = True
            volumes_header = line
            volumes_items = []
            continue

        # Check for environment header (4 spaces)
        if stripped == "    environment:":
            # Flush previous volumes block if active
            if in_volumes:
                if volumes_items:
                    result.append(volumes_header)
                    result.extend(volumes_items)
                in_volumes = False
                volumes_items = []
            # Start environment block
            in_environment = True
            env_header = line
            env_items = []
            continue

        # Process volumes items
        if in_volumes:
            if stripped.startswith("      -"):
                # Check if this is a timezone volume
                if ":/etc/localtime" in stripped or ":/etc/timezone" in stripped:
                    continue
                else:
                    volumes_items.append(line)
                    continue
            else:
                # No longer in volumes - flush it
                if volumes_items:
                    result.append(volumes_header)
                    result.extend(volumes_items)
                in_volumes = False
                volumes_items = []
                # Fall through to process this line

        # Process environment items
        if in_environment:
            if stripped.startswith("      -"):
                # Check if it's TZ=
                if "TZ=" in stripped:
                    continue
                else:
                    env_items.append(line)
                    continue
            else:
                # No longer in environment - flush it
                if env_items:
                    result.append(env_header)
                    result.extend(env_items)
                in_environment = False
                env_items = []
                # Fall through to process this line

        # Regular line
        if not in_volumes and not in_environment:
            result.append(line)

    # Handle case where file ends while in a block
    if in_volumes and volumes_items:
        result.append(volumes_header)
        result.extend(volumes_items)
    if in_environment and env_items:
        result.append(env_header)
        result.extend(env_items)

    # Write back
    with open(override_file, "w") as f:
        f.writelines(result)


def append_override_list_item(override_file: str, key: str, item: str) -> None:
    """Append an item to a YAML list in the override file.

    Creates the list key if it doesn't exist. Items are indented 6 spaces with '- ' prefix.

    Args:
        override_file: Path to docker-compose override file.
        key: The YAML list key (e.g., 'volumes', 'environment').
        item: The item to append (without '- ' prefix).
    """
    with open(override_file, "r") as f:
        lines = f.readlines()

    result = []
    inserted = False
    in_list = False
    key_pattern = f"    {key}:"

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()

        # Check if this is our key
        if stripped == key_pattern:
            in_list = True
            result.append(line)
            i += 1
            continue

        # If we're in the list, look for the end of list items
        if in_list:
            if stripped.startswith("      -"):
                # Still in list, keep the item
                result.append(line)
                i += 1
                continue
            else:
                # End of list - insert our item before this line
                result.append(f"      - {item}\n")
                inserted = True
                in_list = False
                # Continue processing this line

        result.append(line)
        i += 1

    # If we reached end of file while in list, append there
    if in_list and not inserted:
        result.append(f"      - {item}\n")
        inserted = True

    # If key was never found, append it at the end
    if not inserted:
        result.append(f"    {key}:\n")
        result.append(f"      - {item}\n")

    # Write back
    with open(override_file, "w") as f:
        f.writelines(result)


def detect_host_timezone() -> Optional[str]:
    """Detect the host's timezone.

    Tries in order:
    1. Read /etc/timezone
    2. Extract from /etc/localtime symlink (zoneinfo path)
    3. Return $TZ environment variable

    Returns:
        Timezone string if detected, None otherwise.
    """
    # Try /etc/timezone
    timezone_file = Path("/etc/timezone")
    if timezone_file.exists():
        try:
            tz = timezone_file.read_text().strip()
            if tz:
                return tz
        except (OSError, UnicodeDecodeError):
            pass

    # Try readlink /etc/localtime
    localtime_file = Path("/etc/localtime")
    if localtime_file.exists():
        try:
            link = os.readlink(localtime_file)
            # Extract timezone after "zoneinfo/"
            if "/zoneinfo/" in link:
                tz = link.split("/zoneinfo/", 1)[1]
                if tz:
                    return tz
        except OSError:
            pass

    # Try $TZ environment variable
    tz = os.environ.get("TZ")
    if tz:
        return tz

    return None


def add_claude_home_to_override(override_file: str, claude_home: str) -> None:
    """Add Claude home volume mount to override file.

    Strips existing config first, then adds new mount if claude_home is provided.

    Args:
        override_file: Path to docker-compose override file.
        claude_home: Host path to Claude config directory (empty to just strip).
    """
    ensure_override_header(override_file)
    strip_claude_home_config(override_file)

    if not claude_home:
        return

    # Escape double quotes in path to prevent YAML injection
    safe_path = claude_home.replace('"', '\\"')
    mount_entry = f'"{safe_path}:/home/ubuntu/.claude"'
    append_override_list_item(override_file, "volumes", mount_entry)


def add_ssh_agent_to_override(override_file: str, agent_sock: str) -> None:
    """Add SSH agent configuration to override file.

    Strips existing config first, then adds volume mount and environment variable.

    Args:
        override_file: Path to docker-compose override file.
        agent_sock: Host path to SSH agent socket (empty to just strip).
    """
    ensure_override_header(override_file)
    strip_ssh_agent_config(override_file)

    if not agent_sock:
        return

    # Escape double quotes in path to prevent YAML injection
    safe_sock = agent_sock.replace('"', '\\"')
    mount_entry = f'"{safe_sock}:{SSH_AGENT_CONTAINER_SOCK}"'
    append_override_list_item(override_file, "volumes", mount_entry)
    append_override_list_item(override_file, "environment", f"SSH_AUTH_SOCK={SSH_AGENT_CONTAINER_SOCK}")


def add_timezone_to_override(override_file: str) -> None:
    """Add timezone configuration to override file.

    Strips existing config first, then adds /etc/localtime, /etc/timezone mounts
    and TZ environment variable if detectable.

    Args:
        override_file: Path to docker-compose override file.
    """
    ensure_override_header(override_file)
    strip_timezone_config(override_file)

    # Add /etc/localtime if readable
    localtime = Path("/etc/localtime")
    if localtime.exists() and os.access(localtime, os.R_OK):
        append_override_list_item(override_file, "volumes", '"/etc/localtime:/etc/localtime:ro"')

    # Add /etc/timezone if readable
    timezone = Path("/etc/timezone")
    if timezone.exists() and os.access(timezone, os.R_OK):
        append_override_list_item(override_file, "volumes", '"/etc/timezone:/etc/timezone:ro"')

    # Add TZ environment variable if detectable
    host_tz = detect_host_timezone()
    if host_tz:
        append_override_list_item(override_file, "environment", f"TZ={host_tz}")


def add_network_to_override(mode: str, override_file: str) -> None:
    """Add network configuration to an existing or new override file.

    Args:
        mode: Network mode ('none', 'limited', or 'host-only').
        override_file: Path to docker-compose override file.
    """
    ensure_override_header(override_file)
    strip_network_config(override_file)
    generate_network_config(mode, override_file)


# Bridge command implementations

def _cmd_validate_network_mode(mode: str) -> None:
    """Bridge command: Validate network mode."""
    validate_network_mode(mode)


def _cmd_generate_network_config(mode: str, override_file: str) -> None:
    """Bridge command: Generate network config."""
    generate_network_config(mode, override_file)


def _cmd_ensure_override_header(override_file: str) -> None:
    """Bridge command: Ensure override header."""
    ensure_override_header(override_file)


def _cmd_strip_network_config(override_file: str) -> None:
    """Bridge command: Strip network config."""
    strip_network_config(override_file)


def _cmd_strip_ssh_agent_config(override_file: str) -> None:
    """Bridge command: Strip SSH agent config."""
    strip_ssh_agent_config(override_file)


def _cmd_strip_claude_home_config(override_file: str) -> None:
    """Bridge command: Strip Claude home config."""
    strip_claude_home_config(override_file)


def _cmd_strip_timezone_config(override_file: str) -> None:
    """Bridge command: Strip timezone config."""
    strip_timezone_config(override_file)


def _cmd_add_claude_home_to_override(override_file: str, claude_home: str) -> None:
    """Bridge command: Add Claude home to override."""
    add_claude_home_to_override(override_file, claude_home)


def _cmd_add_ssh_agent_to_override(override_file: str, agent_sock: str) -> None:
    """Bridge command: Add SSH agent to override."""
    add_ssh_agent_to_override(override_file, agent_sock)


def _cmd_add_timezone_to_override(override_file: str) -> None:
    """Bridge command: Add timezone to override."""
    add_timezone_to_override(override_file)


def _cmd_add_network_to_override(mode: str, override_file: str) -> None:
    """Bridge command: Add network to override."""
    add_network_to_override(mode, override_file)


if __name__ == "__main__":
    bridge_main({
        "validate-network-mode": _cmd_validate_network_mode,
        "generate-network-config": _cmd_generate_network_config,
        "ensure-override-header": _cmd_ensure_override_header,
        "strip-network-config": _cmd_strip_network_config,
        "strip-ssh-agent-config": _cmd_strip_ssh_agent_config,
        "strip-claude-home-config": _cmd_strip_claude_home_config,
        "strip-timezone-config": _cmd_strip_timezone_config,
        "add-claude-home-to-override": _cmd_add_claude_home_to_override,
        "add-ssh-agent-to-override": _cmd_add_ssh_agent_to_override,
        "add-timezone-to-override": _cmd_add_timezone_to_override,
        "add-network-to-override": _cmd_add_network_to_override,
    })
