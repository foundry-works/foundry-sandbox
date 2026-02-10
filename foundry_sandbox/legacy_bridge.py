"""Compatibility adapter for legacy `_bridge_*` shell calls.

This module lets partially migrated command code call old bridge names
without going through `sandbox.sh`, which now dispatches directly to
the Click CLI.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

from foundry_sandbox import api_keys, container_io, container_setup, credential_setup, docker, foundry_plugin
from foundry_sandbox.commands._helpers import repo_url_to_bare_path as _repo_url_to_bare_path
from foundry_sandbox.constants import SANDBOX_NAME_MAX_LENGTH, get_claude_configs_dir, get_repos_dir, get_worktrees_dir
from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths
from foundry_sandbox.network import add_network_to_override, append_override_list_item
from foundry_sandbox.paths import derive_sandbox_paths, ensure_dir
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import sanitize_ref_component
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


def _parse_bool_arg(value: str | None) -> bool:
    """Parse shell bridge boolean arguments."""
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _repo_to_path(repo_url: str) -> str:
    """Convert a repository URL to its bare-clone path.

    Delegates to the shared implementation in commands._helpers.
    """
    return _repo_url_to_bare_path(repo_url)


def _sandbox_name(bare_path: str, branch: str) -> str:
    from foundry_sandbox.commands._helpers import sandbox_name
    return sandbox_name(bare_path, branch)


def _find_next_sandbox_name(base_name: str) -> str:
    from foundry_sandbox.commands._helpers import find_next_sandbox_name
    return find_next_sandbox_name(base_name)


def _container_name(name: str) -> str:
    return f"sandbox-{name}"


def _resolve_ssh_agent_sock() -> str:
    from foundry_sandbox.commands._helpers import resolve_ssh_agent_sock
    return resolve_ssh_agent_sock()


def _generate_sandbox_id(seed: str) -> str:
    from foundry_sandbox.commands._helpers import generate_sandbox_id
    return generate_sandbox_id(seed)


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


def _arg(args: list[str], idx: int, default: str = "") -> str:
    """Safely get a positional argument by index, with default."""
    return args[idx] if idx < len(args) else default


# --- Individual bridge handlers ---
# Each returns (returncode, stdout, stderr).


def _h_validate_git_url(a: list[str]) -> tuple[int, str, str]:
    ok, msg = validate_git_url(_arg(a, 0))
    return (0, "", "") if ok else (1, "", msg)


def _h_validate_mount_path(a: list[str]) -> tuple[int, str, str]:
    ok, msg = validate_mount_path(_arg(a, 0))
    return (0, "", "") if ok else (1, "", msg)


def _h_check_claude_key_required(a: list[str]) -> tuple[int, str, str]:
    ok, msg = api_keys.check_claude_key_required()
    return (0, msg, "") if ok else (1, "", msg)


def _h_check_docker_network_capacity(a: list[str]) -> tuple[int, str, str]:
    isolate = _parse_bool_arg(_arg(a, 0, "true"))
    ok, msg = check_docker_network_capacity(isolate_credentials=isolate)
    return (0, "", "") if ok else (1, "", msg)


def _h_validate_git_remotes(a: list[str]) -> tuple[int, str, str]:
    ok, msg = validate_git_remotes(_arg(a, 0, ".git"))
    return (0, "", "") if ok else (1, "", msg)


def _h_add_network_to_override(a: list[str]) -> tuple[int, str, str]:
    add_network_to_override(_arg(a, 0), _arg(a, 1))
    return 0, "", ""


def _h_prepopulate_foundry_global(a: list[str]) -> tuple[int, str, str]:
    foundry_plugin.prepopulate_foundry_global(
        _arg(a, 0), skip_if_populated=_arg(a, 1, "0") == "1",
    )
    return 0, "", ""


def _h_show_cli_status(a: list[str]) -> tuple[int, str, str]:
    api_keys.show_cli_status()
    return 0, "", ""


def _h_export_gh_token(a: list[str]) -> tuple[int, str, str]:
    token = api_keys.export_gh_token()
    if token:
        os.environ["GITHUB_TOKEN"] = token
        os.environ["GH_TOKEN"] = token
        return 0, "", ""
    return 1, "", ""


def _h_fix_proxy_worktree_paths(a: list[str]) -> tuple[int, str, str]:
    fix_proxy_worktree_paths(_arg(a, 0), _arg(a, 1))
    return 0, "", ""


def _h_compose_down(a: list[str]) -> tuple[int, str, str]:
    docker.compose_down(
        worktree_path=_arg(a, 0),
        claude_config_path=_arg(a, 1),
        container=_arg(a, 2),
        override_file=_arg(a, 3),
        remove_volumes=_parse_bool_arg(_arg(a, 4, "false")),
        isolate_credentials=_parse_bool_arg(_arg(a, 5, "false")),
    )
    return 0, "", ""


def _h_copy_configs_to_container(a: list[str]) -> tuple[int, str, str]:
    credential_setup.copy_configs_to_container(
        _arg(a, 0),
        skip_plugins=_parse_bool_arg(_arg(a, 1, "0")),
        enable_ssh=_parse_bool_arg(_arg(a, 2, "0")),
        working_dir=_arg(a, 3),
        isolate_credentials=_parse_bool_arg(_arg(a, 4)),
        from_branch=_arg(a, 5),
        branch=_arg(a, 6),
        repo_url=_arg(a, 7),
    )
    return 0, "", ""


def _h_copy_dir_to_container(a: list[str]) -> tuple[int, str, str]:
    container_io.copy_dir_to_container(_arg(a, 0), _arg(a, 1), _arg(a, 2))
    return 0, "", ""


def _h_copy_file_to_container(a: list[str]) -> tuple[int, str, str]:
    container_io.copy_file_to_container(_arg(a, 0), _arg(a, 1), _arg(a, 2))
    return 0, "", ""


def _h_install_pip_requirements(a: list[str]) -> tuple[int, str, str]:
    container_setup.install_pip_requirements(_arg(a, 0), _arg(a, 1))
    return 0, "", ""


def _h_tmux_attach(a: list[str]) -> tuple[int, str, str]:
    name = _arg(a, 0)
    paths = derive_sandbox_paths(name)
    tmux_attach(name, f"{paths.container_name}-dev-1", str(paths.worktree_path), _arg(a, 1))
    return 0, "", ""


def _h_sync_creds(a: list[str]) -> tuple[int, str, str]:
    credential_setup.sync_runtime_credentials(_arg(a, 0))
    return 0, "", ""


def _h_sanitize_ref_component(a: list[str]) -> tuple[int, str, str]:
    return 0, sanitize_ref_component(_arg(a, 0)), ""


def _h_repo_to_path(a: list[str]) -> tuple[int, str, str]:
    return 0, _repo_to_path(_arg(a, 0)), ""


def _h_sandbox_name(a: list[str]) -> tuple[int, str, str]:
    return 0, _sandbox_name(_arg(a, 0), _arg(a, 1)), ""


def _h_find_next_sandbox_name(a: list[str]) -> tuple[int, str, str]:
    return 0, _find_next_sandbox_name(_arg(a, 0)), ""


def _h_container_name(a: list[str]) -> tuple[int, str, str]:
    return 0, _container_name(_arg(a, 0)), ""


def _h_resolve_ssh_agent_sock(a: list[str]) -> tuple[int, str, str]:
    return 0, _resolve_ssh_agent_sock(), ""


def _h_generate_sandbox_id(a: list[str]) -> tuple[int, str, str]:
    return 0, _generate_sandbox_id(_arg(a, 0)), ""


def _h_has_opencode_key(a: list[str]) -> tuple[int, str, str]:
    return 0, "1" if api_keys.has_opencode_key() else "", ""


def _h_ensure_override_from_metadata(a: list[str]) -> tuple[int, str, str]:
    rc, msg = _ensure_override_from_metadata(_arg(a, 0), _arg(a, 1))
    return rc, "", msg


# Dispatch table: command name → handler(args) → (returncode, stdout, stderr)
_BRIDGE_DISPATCH: dict[str, Callable[[list[str]], tuple[int, str, str]]] = {
    "_bridge_validate_git_url": _h_validate_git_url,
    "_bridge_validate_mount_path": _h_validate_mount_path,
    "_bridge_check_claude_key_required": _h_check_claude_key_required,
    "_bridge_check_docker_network_capacity": _h_check_docker_network_capacity,
    "_bridge_validate_git_remotes": _h_validate_git_remotes,
    "_bridge_add_network_to_override": _h_add_network_to_override,
    "_bridge_prepopulate_foundry_global": _h_prepopulate_foundry_global,
    "_bridge_show_cli_status": _h_show_cli_status,
    "_bridge_export_gh_token": _h_export_gh_token,
    "_bridge_fix_proxy_worktree_paths": _h_fix_proxy_worktree_paths,
    "_bridge_compose_down": _h_compose_down,
    "_bridge_copy_configs_to_container": _h_copy_configs_to_container,
    "_bridge_copy_dir_to_container": _h_copy_dir_to_container,
    "_bridge_copy_file_to_container": _h_copy_file_to_container,
    "_bridge_install_pip_requirements": _h_install_pip_requirements,
    "_bridge_tmux_attach": _h_tmux_attach,
    "_bridge_sync_creds": _h_sync_creds,
    "_bridge_sanitize_ref_component": _h_sanitize_ref_component,
    "_bridge_repo_to_path": _h_repo_to_path,
    "_bridge_sandbox_name": _h_sandbox_name,
    "_bridge_find_next_sandbox_name": _h_find_next_sandbox_name,
    "_bridge_container_name": _h_container_name,
    "_bridge_resolve_ssh_agent_sock": _h_resolve_ssh_agent_sock,
    "_bridge_generate_sandbox_id": _h_generate_sandbox_id,
    "_bridge_has_opencode_key": _h_has_opencode_key,
    "_bridge_ensure_override_from_metadata": _h_ensure_override_from_metadata,
}


def _run_bridge(command: str, bridge_args: list[str]) -> tuple[int, str, str]:
    handler = _BRIDGE_DISPATCH.get(command)
    if handler is None:
        return 1, "", f"Unknown legacy bridge command: {command}"
    return handler(bridge_args)


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
