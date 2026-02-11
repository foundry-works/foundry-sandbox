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
import re
import tempfile
from pathlib import Path
from typing import Callable, Optional

from foundry_sandbox.constants import SSH_AGENT_CONTAINER_SOCK
from foundry_sandbox.utils import log_warn

# Characters safe for use in YAML volume mount paths (no YAML special chars)
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_./ -]+$")


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


def _strip_yaml_blocks(
    override_file: str,
    block_filters: dict[str, Callable[[str], bool]],
) -> None:
    """Remove matching items from YAML list blocks in an override file.

    Scans the file for 4-space-indented block headers (e.g. ``    volumes:``)
    that match keys in *block_filters*. Within each block, list items
    (6-space ``      -`` prefix) are passed to the corresponding predicate;
    items where the predicate returns ``True`` are dropped. Empty blocks
    (all items removed) have their header dropped as well.

    Args:
        override_file: Path to docker-compose override file.
        block_filters: Mapping of block name (e.g. ``"volumes"``) to a
            predicate that receives the right-stripped line and returns
            ``True`` for items that should be **removed**.
    """
    path = Path(override_file)
    if not path.exists():
        return

    with open(override_file, "r") as f:
        lines = f.readlines()

    result: list[str] = []
    current_block: str | None = None
    block_header = ""
    block_items: list[str] = []

    def _flush() -> None:
        nonlocal current_block, block_items
        if current_block is not None and block_items:
            result.append(block_header)
            result.extend(block_items)
        current_block = None
        block_items = []

    for line in lines:
        stripped = line.rstrip()

        # Detect a tracked block header (4-space indent)
        matched = None
        for name in block_filters:
            if stripped == f"    {name}:":
                matched = name
                break

        if matched is not None:
            _flush()
            current_block = matched
            block_header = line
            block_items = []
            continue

        # Inside a tracked block — filter list items
        if current_block is not None:
            if stripped.startswith("      -"):
                if block_filters[current_block](stripped):
                    continue  # drop this item
                block_items.append(line)
                continue
            else:
                _flush()
                # fall through to append as a regular line

        result.append(line)

    # File may end while still inside a block
    _flush()

    with open(override_file, "w") as f:
        f.writelines(result)


def strip_network_config(override_file: str) -> None:
    """Remove network-related config from override file.

    Removes cap_add entries for NET_ADMIN/NET_RAW/SYS_ADMIN and
    environment entries for SANDBOX_NETWORK_MODE.

    Args:
        override_file: Path to docker-compose override file.
    """
    _strip_yaml_blocks(override_file, {
        "cap_add": lambda line: any(c in line for c in ("NET_ADMIN", "NET_RAW", "SYS_ADMIN")),
        "environment": lambda line: "SANDBOX_NETWORK_MODE=" in line,
    })


def strip_ssh_agent_config(override_file: str) -> None:
    """Remove SSH agent configuration from override file.

    Removes volume mounts targeting SSH_AGENT_CONTAINER_SOCK,
    group_add entries for "0", and SSH_AUTH_SOCK environment entries.

    Args:
        override_file: Path to docker-compose override file.
    """
    _strip_yaml_blocks(override_file, {
        "volumes": lambda line: f":{SSH_AGENT_CONTAINER_SOCK}" in line,
        "group_add": lambda line: line.strip() in ('- "0"', "- '0'", "- 0"),
        "environment": lambda line: "SSH_AUTH_SOCK=" in line,
    })


def strip_claude_home_config(override_file: str) -> None:
    """Remove Claude home volume mount from override file.

    Removes volume mounts targeting /home/ubuntu/.claude.

    Args:
        override_file: Path to docker-compose override file.
    """
    _strip_yaml_blocks(override_file, {
        "volumes": lambda line: ":/home/ubuntu/.claude" in line,
    })


def strip_timezone_config(override_file: str) -> None:
    """Remove timezone configuration from override file.

    Removes /etc/localtime and /etc/timezone volume mounts and TZ=
    environment entries.

    Args:
        override_file: Path to docker-compose override file.
    """
    _strip_yaml_blocks(override_file, {
        "volumes": lambda line: ":/etc/localtime" in line or ":/etc/timezone" in line,
        "environment": lambda line: "TZ=" in line,
    })


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

    # Reject paths with YAML-unsafe characters to prevent injection
    if not _SAFE_PATH_RE.match(claude_home):
        raise ValueError(
            f"Claude home path contains unsafe characters: {claude_home!r}\n"
            "Paths may only contain alphanumerics, spaces, dots, underscores, hyphens, and slashes."
        )
    mount_entry = f'"{claude_home}:/home/ubuntu/.claude"'
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

    # Reject paths with YAML-unsafe characters to prevent injection
    if not _SAFE_PATH_RE.match(agent_sock):
        raise ValueError(
            f"SSH agent socket path contains unsafe characters: {agent_sock!r}\n"
            "Paths may only contain alphanumerics, spaces, dots, underscores, hyphens, and slashes."
        )
    mount_entry = f'"{agent_sock}:{SSH_AGENT_CONTAINER_SOCK}"'
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


def ensure_override_from_metadata(name: str, override_file: str) -> None:
    """Rebuild the docker-compose override file from saved sandbox metadata.

    Loads the sandbox metadata for *name*, writes a fresh override header,
    re-appends volume mounts, and applies the network mode.

    Args:
        name: Sandbox name.
        override_file: Path to docker-compose override file.

    Raises:
        ValueError: If the network mode in metadata is invalid.
        OSError: If the override file cannot be written.
    """
    from foundry_sandbox.paths import ensure_dir
    from foundry_sandbox.state import load_sandbox_metadata

    metadata = load_sandbox_metadata(name) or {}
    ensure_dir(Path(override_file).parent)
    Path(override_file).write_text("services:\n  dev:\n")

    mounts = metadata.get("mounts", [])
    if isinstance(mounts, list):
        for mount in mounts:
            if isinstance(mount, str) and mount:
                append_override_list_item(override_file, "volumes", mount)

    network_mode = str(metadata.get("network_mode", "")).strip()
    if network_mode:
        add_network_to_override(network_mode, override_file)

