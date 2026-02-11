"""Git worktree path fixes for sandbox containers.

Migrated from lib/container_config.sh: fix_proxy_worktree_paths,
fix_worktree_paths, detect_nested_git_repos.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import sys

from foundry_sandbox.constants import CONTAINER_USER, TIMEOUT_DOCKER_EXEC, get_sandbox_verbose
from foundry_sandbox.utils import log_debug, log_warn


def _validate_host_user(host_user: str) -> bool:
    """Validate host_user to prevent shell injection.

    Only allows alphanumeric, dot, underscore, and hyphen.
    """
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', host_user))


def fix_proxy_worktree_paths(proxy_container: str, host_user: str) -> None:
    """Fix git worktree paths in proxy container.

    Creates symlinks from host paths to container paths and configures
    git worktree settings for /git-workspace.

    Args:
        proxy_container: Proxy container name or ID
        host_user: Host username to fix paths for
    """
    # Guard: return if empty
    if not host_user or not proxy_container:
        return

    # Validate host_user to prevent injection
    if not _validate_host_user(host_user):
        log_warn(f"Invalid host_user for path fixing: {host_user}")
        return

    if get_sandbox_verbose():
        print(f"[VERBOSE] Fixing proxy worktree paths for user: {host_user}", file=sys.stderr)

    # Construct the shell script to run inside the container
    script = f"""
if [ ! -e '/home/{host_user}' ] && [ -d '/home/ubuntu' ]; then
    ln -s /home/ubuntu '/home/{host_user}' 2>/dev/null || true
fi
if [ ! -e '/Users/{host_user}' ] && [ -d '/home/ubuntu' ]; then
    mkdir -p /Users 2>/dev/null || true
    ln -s /home/ubuntu '/Users/{host_user}' 2>/dev/null || true
fi
if [ -f /git-workspace/.git ]; then
    GITDIR_PATH=$(grep 'gitdir:' /git-workspace/.git | sed 's/gitdir: //')
    if [ -d "$GITDIR_PATH" ]; then
        BARE_DIR=$(cat "$GITDIR_PATH/commondir" 2>/dev/null || echo '..')
        case "$BARE_DIR" in /*) ;; *) BARE_DIR="$GITDIR_PATH/$BARE_DIR" ;; esac
        ls "$BARE_DIR" >/dev/null 2>&1 || true
        cat "$BARE_DIR/config" >/dev/null 2>&1 || true
        git config --file "$BARE_DIR/config" extensions.worktreeConfig true
        REPO_VER=$(git config --file "$BARE_DIR/config" --get core.repositoryformatversion 2>/dev/null || echo 0)
        if [ "$REPO_VER" -lt 1 ] 2>/dev/null; then
            git config --file "$BARE_DIR/config" core.repositoryformatversion 1
        fi
        touch "$GITDIR_PATH/config.worktree" 2>/dev/null || true
        git config --file "$GITDIR_PATH/config.worktree" core.worktree /git-workspace
        git config --file "$GITDIR_PATH/config.worktree" core.bare false
    fi
fi
"""

    # Execute the script in the container
    subprocess.run(
        ["docker", "exec", proxy_container, "sh", "-c", script],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


def fix_worktree_paths(container_id: str, host_user: str) -> None:
    """Fix git worktree paths in main container.

    Replaces host-specific paths in .git file with container paths
    and updates git config.

    Args:
        container_id: Container name or ID
        host_user: Host username to fix paths for
    """
    # Guard: return if empty
    if not host_user:
        return

    # Validate host_user to prevent injection
    if not _validate_host_user(host_user):
        log_warn(f"Invalid host_user for path fixing: {host_user}")
        return

    if get_sandbox_verbose():
        print(f"[VERBOSE] Fixing worktree paths for user: {host_user}", file=sys.stderr)

    # Construct the shell script to run inside the container
    script = f"""
if [ -f /workspace/.git ]; then
    if grep -q '/home/{host_user}' /workspace/.git 2>/dev/null || \
       grep -q '/Users/{host_user}' /workspace/.git 2>/dev/null; then
        sed -i \
            -e 's|/home/{host_user}|/home/ubuntu|g' \
            -e 's|/Users/{host_user}|/home/ubuntu|g' \
            /workspace/.git
        GITDIR_PATH=$(grep 'gitdir:' /workspace/.git | sed 's/gitdir: //')
        if [ -d "$GITDIR_PATH" ]; then
            echo '/workspace/.git' > "$GITDIR_PATH/gitdir"
            touch "$GITDIR_PATH/config.worktree" 2>/dev/null || true
            git config --file "$GITDIR_PATH/config.worktree" core.worktree /workspace
        fi
    fi
fi
"""

    # Execute the script in the container
    subprocess.run(
        ["docker", "exec", container_id, "sh", "-c", script],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=TIMEOUT_DOCKER_EXEC,
    )


def detect_nested_git_repos(container_id: str, workspace_path: str = "/workspace") -> list[str]:
    """Detect and warn about nested git repositories.

    Searches for .git directories nested within workspace and prints
    warnings if found, as these can shadow the sparse worktree.

    Args:
        container_id: Container name or ID
        workspace_path: Path to workspace inside container (default: /workspace)

    Returns:
        List of nested .git directory paths found, or empty list if none or on error
    """
    if get_sandbox_verbose():
        print(f"[VERBOSE] Detecting nested git repos in container at {workspace_path}", file=sys.stderr)

    # Construct the shell script to run inside the container
    # This version only finds and returns paths - warnings are handled by caller
    script = f'find {shlex.quote(workspace_path)} -mindepth 2 -name ".git" -type d 2>/dev/null'

    try:
        # Execute the script in the container
        result = subprocess.run(
            ["docker", "exec", container_id, "sh", "-c", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=TIMEOUT_DOCKER_EXEC,
        )

        # Return empty list on failure
        if result.returncode != 0:
            return []

        # Parse and return paths, stripping whitespace
        paths = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return paths

    except Exception:
        log_warn("Failed to detect nested git repos")
        return []
