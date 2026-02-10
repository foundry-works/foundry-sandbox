"""Compatibility adapter for legacy `_bridge_*` shell calls.

This module lets partially migrated command code call old bridge names
without going through `sandbox.sh`, which now dispatches directly to
the Click CLI.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable

from foundry_sandbox import api_keys, container_io, container_setup, credential_setup, docker, foundry_plugin
from foundry_sandbox.constants import get_claude_configs_dir, get_repos_dir, get_worktrees_dir
from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths
from foundry_sandbox.network import add_network_to_override, append_override_list_item
from foundry_sandbox.paths import derive_sandbox_paths, ensure_dir
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.tmux import attach as tmux_attach
from foundry_sandbox.validate import (
    check_docker_network_capacity,
    validate_git_remotes,
    validate_git_url,
    validate_mount_path,
)

SCRIPT_DIR = Path(__file__).resolve().parent.parent
SANDBOX_SH = SCRIPT_DIR / "sandbox.sh"


def _cp(
    args: list[str],
    returncode: int,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=args, returncode=returncode, stdout=stdout, stderr=stderr)


def _sanitize_ref_component(component: str) -> str:
    text = component.strip().replace("/", "-")
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^A-Za-z0-9._-]", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip(".-")
    if text in {"", ".", ".."}:
        return ""
    return text


def _repo_to_path(repo_url: str) -> str:
    repos_dir = str(get_repos_dir())

    if not repo_url:
        return f"{repos_dir}/unknown.git"

    if repo_url.startswith(("~/", "/", "./", "../")):
        expanded = os.path.expanduser(repo_url)
        try:
            expanded = str(Path(expanded).resolve())
        except OSError:
            pass
        stripped = expanded.lstrip("/")
        return f"{repos_dir}/local/{stripped}.git"

    path = repo_url
    path = path.removeprefix("https://")
    path = path.removeprefix("http://")
    path = path.removeprefix("git@")
    path = path.replace(":", "/", 1) if ":" in path else path
    if path.endswith(".git"):
        path = path[:-4]
    return f"{repos_dir}/{path}.git"


def _sandbox_name(bare_path: str, branch: str) -> str:
    repo = Path(bare_path).name
    if repo.endswith(".git"):
        repo = repo[:-4]
    repo = _sanitize_ref_component(repo) or "repo"
    branch_part = _sanitize_ref_component(branch) or "branch"
    name = f"{repo}-{branch_part}".lower()
    if len(name) > 120:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
        name = f"{name[:111]}-{digest}"
    return name


def _find_next_sandbox_name(base_name: str) -> str:
    worktrees = get_worktrees_dir()
    configs = get_claude_configs_dir()

    def _taken(candidate: str) -> bool:
        return (worktrees / candidate).exists() or (configs / candidate).exists()

    if not _taken(base_name):
        return base_name

    for i in range(2, 10_000):
        candidate = f"{base_name}-{i}"
        if not _taken(candidate):
            return candidate
    return f"{base_name}-{os.getpid()}"


def _container_name(name: str) -> str:
    return f"sandbox-{name}"


def _resolve_ssh_agent_sock() -> str:
    sock = os.environ.get("SSH_AUTH_SOCK", "")
    if not sock:
        return ""
    p = Path(sock)
    return sock if p.exists() else ""


def _generate_sandbox_id(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _ensure_override_from_metadata(name: str, override_file: str) -> tuple[int, str]:
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
        try:
            add_network_to_override(network_mode, override_file)
        except Exception as exc:  # pragma: no cover - defensive compatibility path
            return 1, str(exc)

    return 0, ""


def _run_bridge(command: str, bridge_args: list[str]) -> tuple[int, str, str]:
    if command == "_bridge_validate_git_url":
        ok, msg = validate_git_url(bridge_args[0] if bridge_args else "")
        return (0, "", "") if ok else (1, "", msg)

    if command == "_bridge_validate_mount_path":
        ok, msg = validate_mount_path(bridge_args[0] if bridge_args else "")
        return (0, "", "") if ok else (1, "", msg)

    if command == "_bridge_check_claude_key_required":
        ok, msg = api_keys.check_claude_key_required()
        if ok:
            return 0, msg, ""
        return 1, "", msg

    if command == "_bridge_check_docker_network_capacity":
        isolate = (bridge_args[0] if bridge_args else "true") == "true"
        ok, msg = check_docker_network_capacity(isolate_credentials=isolate)
        return (0, "", "") if ok else (1, "", msg)

    if command == "_bridge_validate_git_remotes":
        git_dir = bridge_args[0] if bridge_args else ".git"
        ok, msg = validate_git_remotes(git_dir)
        return (0, "", "") if ok else (1, "", msg)

    if command == "_bridge_add_network_to_override":
        mode = bridge_args[0] if bridge_args else ""
        override_file = bridge_args[1] if len(bridge_args) > 1 else ""
        add_network_to_override(mode, override_file)
        return 0, "", ""

    if command == "_bridge_prepopulate_foundry_global":
        claude_home = bridge_args[0] if bridge_args else ""
        skip = (bridge_args[1] if len(bridge_args) > 1 else "0") == "1"
        foundry_plugin.prepopulate_foundry_global(claude_home, skip_if_populated=skip)
        return 0, "", ""

    if command == "_bridge_show_cli_status":
        api_keys.show_cli_status()
        return 0, "", ""

    if command == "_bridge_export_gh_token":
        token = api_keys.export_gh_token()
        if token:
            os.environ["GITHUB_TOKEN"] = token
            os.environ["GH_TOKEN"] = token
            return 0, token, ""
        return 1, "", ""

    if command == "_bridge_fix_proxy_worktree_paths":
        proxy_container = bridge_args[0] if bridge_args else ""
        host_user = bridge_args[1] if len(bridge_args) > 1 else ""
        fix_proxy_worktree_paths(proxy_container, host_user)
        return 0, "", ""

    if command == "_bridge_compose_down":
        worktree_path = bridge_args[0] if bridge_args else ""
        claude_config_path = bridge_args[1] if len(bridge_args) > 1 else ""
        container = bridge_args[2] if len(bridge_args) > 2 else ""
        override_file = bridge_args[3] if len(bridge_args) > 3 else ""
        remove_volumes = (bridge_args[4] if len(bridge_args) > 4 else "false") == "true"
        isolate = (bridge_args[5] if len(bridge_args) > 5 else "false") == "true"
        docker.compose_down(
            worktree_path=worktree_path,
            claude_config_path=claude_config_path,
            container=container,
            override_file=override_file,
            remove_volumes=remove_volumes,
            isolate_credentials=isolate,
        )
        return 0, "", ""

    if command == "_bridge_copy_configs_to_container":
        container_id = bridge_args[0] if bridge_args else ""
        skip_plugins = (bridge_args[1] if len(bridge_args) > 1 else "0") == "1"
        enable_ssh = (bridge_args[2] if len(bridge_args) > 2 else "0") == "1"
        working_dir = bridge_args[3] if len(bridge_args) > 3 else ""
        isolate_credentials = bool(bridge_args[4]) if len(bridge_args) > 4 else False
        from_branch = bridge_args[5] if len(bridge_args) > 5 else ""
        branch = bridge_args[6] if len(bridge_args) > 6 else ""
        repo_url = bridge_args[7] if len(bridge_args) > 7 else ""
        credential_setup.copy_configs_to_container(
            container_id,
            skip_plugins=skip_plugins,
            enable_ssh=enable_ssh,
            working_dir=working_dir,
            isolate_credentials=isolate_credentials,
            from_branch=from_branch,
            branch=branch,
            repo_url=repo_url,
        )
        return 0, "", ""

    if command == "_bridge_copy_dir_to_container":
        container_io.copy_dir_to_container(bridge_args[0], bridge_args[1], bridge_args[2])
        return 0, "", ""

    if command == "_bridge_copy_file_to_container":
        container_io.copy_file_to_container(bridge_args[0], bridge_args[1], bridge_args[2])
        return 0, "", ""

    if command == "_bridge_install_pip_requirements":
        container_setup.install_pip_requirements(bridge_args[0], bridge_args[1])
        return 0, "", ""

    if command == "_bridge_tmux_attach":
        name = bridge_args[0] if bridge_args else ""
        working_dir = bridge_args[1] if len(bridge_args) > 1 else ""
        paths = derive_sandbox_paths(name)
        tmux_attach(name, f"{paths.container_name}-dev-1", str(paths.worktree_path), working_dir)
        return 0, "", ""

    if command == "_bridge_sync_creds":
        credential_setup.sync_runtime_credentials(bridge_args[0] if bridge_args else "")
        return 0, "", ""

    if command == "_bridge_sanitize_ref_component":
        return 0, _sanitize_ref_component(bridge_args[0] if bridge_args else ""), ""

    if command == "_bridge_repo_to_path":
        return 0, _repo_to_path(bridge_args[0] if bridge_args else ""), ""

    if command == "_bridge_sandbox_name":
        bare_path = bridge_args[0] if bridge_args else ""
        branch = bridge_args[1] if len(bridge_args) > 1 else ""
        return 0, _sandbox_name(bare_path, branch), ""

    if command == "_bridge_find_next_sandbox_name":
        return 0, _find_next_sandbox_name(bridge_args[0] if bridge_args else ""), ""

    if command == "_bridge_container_name":
        return 0, _container_name(bridge_args[0] if bridge_args else ""), ""

    if command == "_bridge_resolve_ssh_agent_sock":
        return 0, _resolve_ssh_agent_sock(), ""

    if command == "_bridge_generate_sandbox_id":
        return 0, _generate_sandbox_id(bridge_args[0] if bridge_args else ""), ""

    if command == "_bridge_has_opencode_key":
        return 0, "1" if api_keys.has_opencode_key() else "", ""

    if command == "_bridge_ensure_override_from_metadata":
        name = bridge_args[0] if bridge_args else ""
        override_file = bridge_args[1] if len(bridge_args) > 1 else ""
        rc, msg = _ensure_override_from_metadata(name, override_file)
        return rc, "", msg

    return 1, "", f"Unknown legacy bridge command: {command}"


def run_legacy_command(*args: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    """Run a legacy command used by partially migrated command modules."""
    if not args:
        return _cp(args=[], returncode=1, stderr="Missing command")

    command = args[0]
    if command.startswith("_bridge_"):
        rc, out, err = _run_bridge(command, list(args[1:]))
        if not capture_output:
            if out:
                print(out)
            if err:
                print(err, file=sys.stderr)
        return _cp(args=list(args), returncode=rc, stdout=out, stderr=err)

    kwargs = {"check": False}
    if capture_output:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    return subprocess.run([str(SANDBOX_SH), *args], **kwargs)
