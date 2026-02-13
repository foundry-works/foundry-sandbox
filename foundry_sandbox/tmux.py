"""Tmux session management for sandbox containers.

Migrated from lib/tmux.sh. Provides functions for creating, attaching, and
managing tmux sessions that connect to sandbox Docker containers.
"""

from __future__ import annotations

import os
import shlex
import subprocess

from foundry_sandbox.constants import CONTAINER_USER, TIMEOUT_LOCAL_CMD
from foundry_sandbox.utils import log_info


def tmux_session_name(name: str) -> str:
    """Return the tmux session name for a sandbox.

    Currently just returns the sandbox name as-is.

    Args:
        name: Sandbox name.

    Returns:
        Tmux session name.
    """
    return name


def session_exists(session: str) -> bool:
    """Check if a tmux session exists.

    Args:
        session: Session name.

    Returns:
        True if session exists.
    """
    result = subprocess.run(
        ["tmux", "has-session", "-t", session],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_LOCAL_CMD,
    )
    return result.returncode == 0


def create_and_attach(
    session: str,
    worktree_path: str,
    container_id: str,
    working_dir: str = "",
) -> None:
    """Create a new tmux session and attach to it.

    Creates a detached session running docker exec into the container,
    configures scrollback and mouse settings, then replaces the current
    process with tmux attach.

    Args:
        session: Session name.
        worktree_path: Path to worktree directory.
        container_id: Docker container ID/name.
        working_dir: Working directory inside container.
    """
    log_info(f"Creating tmux session: {session}")

    container_user = os.environ.get("CONTAINER_USER", CONTAINER_USER)

    if working_dir:
        exec_cmd = f"bash -c 'cd /workspace/{shlex.quote(working_dir)} 2>/dev/null; exec bash'"
    else:
        exec_cmd = "bash"

    scrollback = os.environ.get("SANDBOX_TMUX_SCROLLBACK", "200000")
    mouse = os.environ.get("SANDBOX_TMUX_MOUSE", "1")

    docker_command = (
        f"docker exec -u {shlex.quote(container_user)} -it {shlex.quote(container_id)} {exec_cmd}; "
        "echo 'Container exited. Press enter to close.'; read"
    )

    subprocess.run(
        [
            "tmux", "new-session", "-d", "-s", session,
            "-c", worktree_path,
            docker_command,
        ],
        check=False,
        timeout=TIMEOUT_LOCAL_CMD,
    )

    subprocess.run(
        ["tmux", "set-option", "-t", session, "history-limit", scrollback],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_LOCAL_CMD,
    )

    mouse_setting = "on" if mouse == "1" else "off"
    subprocess.run(
        ["tmux", "set-option", "-t", session, "mouse", mouse_setting],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=TIMEOUT_LOCAL_CMD,
    )

    os.execvp("tmux", ["tmux", "attach-session", "-t", session])


def attach_existing(session: str) -> None:
    """Attach to an existing tmux session.

    Replaces the current process with tmux attach.

    Args:
        session: Session name.
    """
    log_info(f"Attaching to existing tmux session: {session}")
    os.execvp("tmux", ["tmux", "attach-session", "-t", session])


def attach(
    name: str,
    container_id: str,
    worktree_path: str,
    working_dir: str = "",
) -> None:
    """Create or attach to tmux session for sandbox.

    Args:
        name: Sandbox name (used as tmux session name).
        container_id: Docker container ID/name.
        worktree_path: Path to worktree directory.
        working_dir: Working directory inside container.
    """
    session = name  # tmux session name is just the sandbox name

    if session_exists(session):
        attach_existing(session)
    else:
        create_and_attach(session, worktree_path, container_id, working_dir)
