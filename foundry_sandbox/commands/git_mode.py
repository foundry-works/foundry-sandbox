"""Toggle sandbox git configuration between host and sandbox modes.

This command updates per-worktree git config so host-side tooling and
sandbox-side git proxy mode can be switched explicitly.
"""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.atomic_io import file_lock
from foundry_sandbox.commands._helpers import (
    auto_detect_sandbox as _auto_detect_sandbox,
    list_sandbox_names as _list_sandbox_names_shared,
)
from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, get_repos_dir, get_worktrees_dir
from foundry_sandbox.git_path_fixer import fix_proxy_worktree_paths
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.utils import log_error
from foundry_sandbox.validate import validate_existing_sandbox_name


def _list_sandboxes_simple() -> None:
    """Print available sandbox names."""
    sandboxes = _list_sandbox_names_shared()
    if sandboxes:
        click.echo("Available sandboxes:")
        for sandbox in sandboxes:
            click.echo(f"  - {sandbox}")
    else:
        click.echo("No sandboxes found.")


def _resolve_sandbox_name(name: str | None) -> str:
    """Resolve sandbox name from argument or cwd auto-detection."""
    if not name:
        name = _auto_detect_sandbox()
        if name:
            click.echo(f"Auto-detected sandbox: {name}")

    if not name:
        click.echo("Usage: cast git-mode [sandbox-name] --mode <host|sandbox>")
        click.echo("")
        _list_sandboxes_simple()
        sys.exit(1)

    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(name_error)
        sys.exit(1)

    return name


def _is_within(path: Path, root: Path) -> bool:
    """Return True when *path* resolves under *root*."""
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _resolve_git_paths(worktree_path: Path) -> tuple[Path, Path]:
    """Resolve (gitdir, bare_dir) from a worktree path."""
    dot_git = worktree_path / ".git"
    if not dot_git.is_file():
        raise RuntimeError(f"Expected .git file in worktree: {dot_git}")

    try:
        gitdir_line = dot_git.read_text(encoding="utf-8", errors="replace").strip()
    except OSError as exc:
        raise RuntimeError(f"Failed to read worktree .git file: {exc}") from exc

    if not gitdir_line.startswith("gitdir: "):
        raise RuntimeError(f"Unexpected .git file format: {dot_git}")

    gitdir_raw = gitdir_line.removeprefix("gitdir: ").strip()
    if not gitdir_raw:
        raise RuntimeError(f"Missing gitdir pointer in: {dot_git}")

    gitdir = Path(gitdir_raw)
    if not gitdir.is_absolute():
        gitdir = (worktree_path / gitdir).resolve()

    if not gitdir.is_dir():
        raise RuntimeError(f"Worktree gitdir does not exist: {gitdir}")

    commondir_file = gitdir / "commondir"
    if not commondir_file.is_file():
        raise RuntimeError(f"Missing commondir in worktree gitdir: {commondir_file}")

    try:
        commondir_raw = commondir_file.read_text(encoding="utf-8", errors="replace").strip() or ".."
    except OSError as exc:
        raise RuntimeError(f"Failed to read commondir: {exc}") from exc

    commondir_path = Path(commondir_raw)
    if commondir_path.is_absolute():
        bare_dir = commondir_path.resolve()
    else:
        bare_dir = (gitdir / commondir_path).resolve()

    if not bare_dir.is_dir():
        raise RuntimeError(f"Resolved bare repository does not exist: {bare_dir}")

    return gitdir, bare_dir


def _validate_git_paths(worktree_path: Path, gitdir: Path, bare_dir: Path) -> None:
    """Enforce trust boundaries for git config writes."""
    repos_root = get_repos_dir().resolve()
    worktrees_root = get_worktrees_dir().resolve()

    if not _is_within(worktree_path, worktrees_root):
        raise RuntimeError(f"Worktree path escapes sandbox root: {worktree_path}")
    if not _is_within(gitdir, repos_root):
        raise RuntimeError(f"Gitdir path escapes repos root: {gitdir}")
    if not _is_within(bare_dir, repos_root):
        raise RuntimeError(f"Bare repo path escapes repos root: {bare_dir}")


def _git_config_set(config_file: Path, key: str, value: str) -> None:
    """Set one git config key in a specific config file."""
    try:
        subprocess.run(
            ["git", "config", "--file", str(config_file), key, value],
            check=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_GIT_QUERY,
        )
    except subprocess.CalledProcessError as exc:
        details = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise RuntimeError(f"Failed to set {key} in {config_file}: {details}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Failed to set {key} in {config_file}: {exc}") from exc


def _apply_git_mode(
    *,
    mode: str,
    name: str,
    worktree_path: Path,
    gitdir: Path,
    bare_dir: Path,
) -> None:
    """Apply host or sandbox git mode."""
    worktree_config = gitdir / "config.worktree"
    bare_config = bare_dir / "config"

    worktree_config.parent.mkdir(parents=True, exist_ok=True)
    worktree_config.touch(exist_ok=True)

    if mode == "host":
        with file_lock(worktree_config):
            _git_config_set(worktree_config, "core.worktree", str(worktree_path))
            _git_config_set(worktree_config, "core.bare", "false")
        return

    if not bare_config.is_file():
        raise RuntimeError(f"Bare config file not found: {bare_config}")

    # Lock shared and worktree config in fixed order to avoid races.
    with file_lock(bare_config):
        with file_lock(worktree_config):
            _git_config_set(bare_config, "extensions.worktreeConfig", "true")
            _git_config_set(bare_config, "core.repositoryformatversion", "1")
            _git_config_set(worktree_config, "core.worktree", "/git-workspace")
            _git_config_set(worktree_config, "core.bare", "false")

    # Best-effort proxy sync for running sandboxes.
    proxy_container = f"sandbox-{name}-unified-proxy-1"
    host_user = os.environ.get("USER") or getpass.getuser()
    fix_proxy_worktree_paths(proxy_container, host_user)


@click.command("git-mode")
@click.argument("name", required=False, default=None)
@click.option(
    "--mode",
    required=True,
    type=click.Choice(["host", "sandbox"], case_sensitive=False),
    help="Target git mode: host or sandbox.",
)
def git_mode(name: str | None, mode: str) -> None:
    """Toggle sandbox git config between host and sandbox-compatible modes."""
    mode = mode.lower()
    name = _resolve_sandbox_name(name)

    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path

    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found")
        sys.exit(1)

    try:
        gitdir, bare_dir = _resolve_git_paths(worktree_path)
        _validate_git_paths(worktree_path, gitdir, bare_dir)
        _apply_git_mode(
            mode=mode,
            name=name,
            worktree_path=worktree_path,
            gitdir=gitdir,
            bare_dir=bare_dir,
        )
    except RuntimeError as exc:
        log_error(str(exc))
        sys.exit(1)

    target_worktree = str(worktree_path) if mode == "host" else "/git-workspace"
    click.echo(f"Applied git mode '{mode}' for sandbox: {name}")
    click.echo(f"  core.worktree={target_worktree}")


def git_mode_shim() -> None:
    """Entrypoint used by the `git-mode` script to avoid Click errors for GitHub CLI."""
    args = sys.argv[1:]
    if "--mode" not in args:
        # GitHub CLI (and similar) may call `git mode` without arguments; treat as no-op.
        return
    # Delegate to the Click command for real work.
    git_mode.main()
