"""Prune command — remove stale/orphaned sandbox resources.

Migrated from commands/prune.sh. Performs cleanup in three stages:
  1. Orphaned configs: Claude configs without a matching worktree
  2. No container (--no-container): Worktrees without running containers
  3. Orphaned networks (--networks): Docker networks with no running containers

Flags:
  --no-container: Remove worktrees without running containers
  --networks: Remove orphaned Docker networks
  --all: Enable both --no-container and --networks
  --force/-f: Skip interactive confirmation prompts
  --json: Output results as JSON array
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import click

from foundry_sandbox.constants import get_claude_configs_dir, get_worktrees_dir
from foundry_sandbox.docker import container_is_running, remove_stubs_volume, remove_hmac_volume
from foundry_sandbox.git_worktree import cleanup_sandbox_branch, remove_worktree
from foundry_sandbox.paths import derive_sandbox_paths, safe_remove
from foundry_sandbox.proxy import cleanup_proxy_registration
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import format_kv, log_warn
from foundry_sandbox.commands._helpers import repo_url_to_bare_path as _repo_url_to_bare_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_prune_metadata(name: str) -> tuple[str, str]:
    """Load metadata for a sandbox to get branch and repo_url for cleanup.

    Args:
        name: Sandbox name.

    Returns:
        Tuple of (branch, repo_url). Empty strings if metadata not found.
    """
    try:
        metadata = load_sandbox_metadata(name)
        if metadata:
            return metadata.get("branch", ""), metadata.get("repo_url", "")
    except (OSError, ValueError):
        pass
    return "", ""


def _container_name_from_sandbox(name: str) -> str:
    """Derive container name from sandbox name.

    Uses derive_sandbox_paths to match the naming scheme.

    Args:
        name: Sandbox name.

    Returns:
        Container name (e.g., "sandbox-foo-bar").
    """
    paths = derive_sandbox_paths(name)
    return paths.container_name


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompts")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--no-container", is_flag=True, help="Remove sandboxes without running containers")
@click.option("--networks", is_flag=True, help="Remove orphaned Docker networks")
@click.option("--all", "all_flag", is_flag=True, help="Enable both --no-container and --networks")
def prune(
    force: bool,
    json_output: bool,
    no_container: bool,
    networks: bool,
    all_flag: bool,
) -> None:
    """Remove stale/orphaned sandbox resources."""

    # Resolve --all flag
    if all_flag:
        no_container = True
        networks = True

    # Track what was removed (for reporting)
    removed_orphaned_configs: list[str] = []
    removed_no_container: list[str] = []
    removed_networks: list[str] = []

    # Check noninteractive mode from environment
    noninteractive = os.environ.get("SANDBOX_NONINTERACTIVE", "") == "1"
    skip_confirm = force or noninteractive

    # -----------------------------------------------------------------------
    # Stage 1: Remove orphaned configs (configs without a worktree)
    # -----------------------------------------------------------------------
    configs_dir = get_claude_configs_dir()
    worktrees_dir = get_worktrees_dir()

    if configs_dir.is_dir():
        for config_dir in configs_dir.iterdir():
            if not config_dir.is_dir():
                continue

            name = config_dir.name
            worktree_path = worktrees_dir / name

            # If worktree doesn't exist, this is an orphaned config
            if not worktree_path.is_dir():
                if not skip_confirm:
                    click.echo(f"\nOrphaned config: {name}")
                    click.echo(format_kv("Claude config", str(config_dir)))
                    try:
                        if not click.confirm("Remove this config?", default=False):
                            continue
                    except click.Abort:
                        continue

                # Load metadata for branch cleanup
                branch, repo_url = _load_prune_metadata(name)

                # Remove config directory
                safe_remove(config_dir)

                # Cleanup sandbox branch
                if branch and repo_url:
                    try:
                        bare_path = _repo_url_to_bare_path(repo_url)
                        cleanup_sandbox_branch(branch, bare_path)
                    except (OSError, subprocess.SubprocessError):
                        pass  # Best effort

                removed_orphaned_configs.append(name)

    # -----------------------------------------------------------------------
    # Stage 2: Remove sandboxes with no running container (--no-container)
    # -----------------------------------------------------------------------
    if no_container:
        if worktrees_dir.is_dir():
            for worktree_dir in worktrees_dir.iterdir():
                if not worktree_dir.is_dir():
                    continue

                name = worktree_dir.name
                container = _container_name_from_sandbox(name)
                config_dir = configs_dir / name

                # Check if container is running (stopped containers count as "no container")
                # The shell version uses: docker ps --filter "name=^${container}-dev-1$" -q
                # We use container_is_running which checks for running dev containers
                running = True  # Fail-safe: assume running if Docker is unreachable
                try:
                    # Match shell behavior: check for exact container name
                    result = subprocess.run(
                        ["docker", "ps", "--filter", f"name=^{container}-dev-1$", "-q"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    running = bool(result.stdout.strip())
                except (OSError, subprocess.SubprocessError):
                    running = True  # Fail-safe: assume running if Docker is unreachable

                if not running:
                    if not skip_confirm:
                        click.echo(f"\nNo container: {name}")
                        click.echo(format_kv("Worktree", str(worktree_dir)))
                        if config_dir.is_dir():
                            click.echo(format_kv("Claude config", str(config_dir)))
                        try:
                            if not click.confirm("Remove this sandbox?", default=False):
                                continue
                        except click.Abort:
                            continue

                    # Load metadata for branch cleanup
                    branch, repo_url = _load_prune_metadata(name)

                    # Cleanup proxy registration (best effort)
                    try:
                        container_id = f"{container}-dev-1"
                        prev_cn = os.environ.get("CONTAINER_NAME")
                        os.environ["CONTAINER_NAME"] = container
                        try:
                            cleanup_proxy_registration(container_id)
                        finally:
                            if prev_cn is None:
                                os.environ.pop("CONTAINER_NAME", None)
                            else:
                                os.environ["CONTAINER_NAME"] = prev_cn
                    except (OSError, subprocess.SubprocessError):
                        pass

                    # Remove worktree
                    try:
                        remove_worktree(str(worktree_dir))
                    except Exception as exc:
                        log_warn(f"Failed to remove worktree {worktree_dir}: {exc}")
                        continue

                    # Remove config if it exists
                    if config_dir.is_dir():
                        safe_remove(config_dir)

                    # Remove stubs and HMAC volumes (best effort)
                    try:
                        remove_stubs_volume(container)
                    except (OSError, subprocess.SubprocessError):
                        pass
                    try:
                        remove_hmac_volume(container)
                    except (OSError, subprocess.SubprocessError):
                        pass

                    # Cleanup sandbox branch
                    if branch and repo_url:
                        try:
                            bare_path = _repo_url_to_bare_path(repo_url)
                            cleanup_sandbox_branch(branch, bare_path)
                        except (OSError, subprocess.SubprocessError):
                            pass  # Best effort

                    removed_no_container.append(name)

    # -----------------------------------------------------------------------
    # Stage 3: Remove orphaned Docker networks (--networks)
    # -----------------------------------------------------------------------
    if networks:
        try:
            # Get all Docker networks
            result = subprocess.run(
                ["docker", "network", "ls", "--format", "{{.Name}}"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                network_pattern = re.compile(r"^sandbox-.*_(credential-isolation|proxy-egress)$")
                for line in result.stdout.splitlines():
                    network_name = line.strip()
                    if not network_name or not network_pattern.match(network_name):
                        continue

                    # Extract sandbox name from network name
                    # e.g., sandbox-foo-bar_credential-isolation -> sandbox-foo-bar
                    sandbox_name = network_name
                    if sandbox_name.endswith("_credential-isolation"):
                        sandbox_name = sandbox_name[: -len("_credential-isolation")]
                    elif sandbox_name.endswith("_proxy-egress"):
                        sandbox_name = sandbox_name[: -len("_proxy-egress")]

                    # Check if any RUNNING containers belong to this sandbox
                    # Stopped containers are not a reason to keep the network
                    has_running = True  # Fail-safe: assume running if Docker is unreachable
                    try:
                        ps_result = subprocess.run(
                            ["docker", "ps", "-q", "--filter", f"name=^{sandbox_name}-"],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        has_running = bool(ps_result.stdout.strip())
                    except (OSError, subprocess.SubprocessError):
                        has_running = True  # Fail-safe: assume running if Docker is unreachable

                    if not has_running:
                        if not skip_confirm:
                            click.echo(f"\nOrphaned network: {network_name}")
                            try:
                                if not click.confirm("Remove this network?", default=False):
                                    continue
                            except click.Abort:
                                continue

                        # Remove stopped containers that reference this sandbox
                        try:
                            stopped_result = subprocess.run(
                                [
                                    "docker",
                                    "ps",
                                    "-aq",
                                    "--filter",
                                    "status=exited",
                                    "--filter",
                                    f"name=^{sandbox_name}-",
                                ],
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            for stopped_id in stopped_result.stdout.splitlines():
                                stopped_id = stopped_id.strip()
                                if stopped_id:
                                    subprocess.run(
                                        ["docker", "rm", stopped_id],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                        check=False,
                                    )
                        except (OSError, subprocess.SubprocessError):
                            pass

                        # Disconnect any dangling endpoints before removal
                        try:
                            inspect_result = subprocess.run(
                                [
                                    "docker",
                                    "network",
                                    "inspect",
                                    "--format",
                                    "{{range .Containers}}{{.Name}} {{end}}",
                                    network_name,
                                ],
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            if inspect_result.returncode == 0:
                                endpoints = inspect_result.stdout.strip().split()
                                for endpoint in endpoints:
                                    if endpoint:
                                        subprocess.run(
                                            ["docker", "network", "disconnect", "-f", network_name, endpoint],
                                            stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL,
                                            check=False,
                                        )
                        except (OSError, subprocess.SubprocessError):
                            pass

                        # Remove the network
                        try:
                            rm_result = subprocess.run(
                                ["docker", "network", "rm", network_name],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                check=False,
                            )
                            if rm_result.returncode == 0:
                                removed_networks.append(network_name)
                            else:
                                log_warn(f"Failed to remove network: {network_name}")
                        except (OSError, subprocess.SubprocessError):
                            log_warn(f"Failed to remove network: {network_name}")

        except (OSError, subprocess.SubprocessError):
            pass  # Docker may not be available

    # -----------------------------------------------------------------------
    # Output results
    # -----------------------------------------------------------------------
    if json_output:
        # Build JSON array
        json_items = []
        for name in removed_orphaned_configs:
            json_items.append({"name": name, "type": "orphaned_config"})
        for name in removed_no_container:
            json_items.append({"name": name, "type": "no_container"})
        for name in removed_networks:
            json_items.append({"name": name, "type": "orphaned_network"})
        click.echo(json.dumps(json_items))
        return

    # Text output
    any_removed = False

    if removed_orphaned_configs:
        any_removed = True
        click.echo("\nRemoved orphaned configs:")
        for name in removed_orphaned_configs:
            click.echo(f"  - {name}")

    if removed_no_container:
        any_removed = True
        click.echo("\nRemoved sandboxes (no container):")
        for name in removed_no_container:
            click.echo(f"  - {name}")

    if removed_networks:
        any_removed = True
        click.echo("\nRemoved orphaned networks:")
        for name in removed_networks:
            click.echo(f"  - {name}")

    if not any_removed:
        # Match shell script messaging based on what flags were set
        if all_flag:
            click.echo(format_kv("Prune", "no orphans found"))
        elif networks:
            click.echo(format_kv("Prune", "no orphaned networks"))
        elif no_container:
            click.echo(format_kv("Prune", "no orphans found"))
        else:
            click.echo(format_kv("Prune", "no orphaned configs"))
