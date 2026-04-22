"""Toggle sandbox git configuration between host and sandbox modes.

This command updates per-worktree git config so host-side tooling and
sandbox-side git proxy mode can be switched explicitly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.atomic_io import file_lock
from foundry_sandbox.commands._helpers import resolve_sandbox_name
from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, get_repos_dir, get_worktrees_dir
from foundry_sandbox.git import remove_stale_git_locks
from foundry_sandbox.paths import resolve_host_worktree_path
from foundry_sandbox.state import load_sandbox_metadata
from foundry_sandbox.utils import log_error


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


def _validate_git_paths(
    name: str, worktree_path: Path, gitdir: Path, bare_dir: Path
) -> None:
    """Enforce trust boundaries for git config writes.

    Accepts both legacy (``~/.sandboxes/worktrees/``) and sbx-managed
    (``<repo>/.sbx/<name>-worktrees/<branch>/``) layouts. Dispatches on
    ``metadata.host_worktree_path`` first, falls back to path-shape detection
    when metadata is absent. Fails closed on unrecognised layouts.
    """
    metadata = load_sandbox_metadata(name)
    host_worktree_path = metadata.get("host_worktree_path", "") if metadata else ""

    if host_worktree_path:
        _validate_new_layout_paths(worktree_path, gitdir, bare_dir, host_worktree_path)
        return

    if metadata is not None:
        # Metadata exists but host_worktree_path is empty → legacy sandbox.
        _validate_legacy_layout_paths(worktree_path, gitdir, bare_dir)
        return

    # No metadata — fall back to path-shape detection.
    worktrees_root = get_worktrees_dir().resolve()
    if _is_within(worktree_path, worktrees_root):
        _validate_legacy_layout_paths(worktree_path, gitdir, bare_dir)
    else:
        raise RuntimeError(
            f"Cannot determine layout for sandbox '{name}' "
            f"(no metadata, worktree not under {worktrees_root}): {worktree_path}"
        )


def _validate_new_layout_paths(
    worktree_path: Path, gitdir: Path, bare_dir: Path, host_worktree_path: str
) -> None:
    """Validate paths for sbx-managed (new-layout) worktrees."""
    ws_resolved = Path(host_worktree_path).resolve()
    wt_resolved = worktree_path.resolve()

    if wt_resolved != ws_resolved:
        raise RuntimeError(
            f"Worktree {wt_resolved} doesn't match metadata host_worktree_path {ws_resolved}"
        )

    # Derive repo root from host_worktree_path: <repo_root>/.sbx/<name>-worktrees/<branch>/
    parts = ws_resolved.parts
    try:
        sbx_idx = parts.index(".sbx")
    except ValueError:
        raise RuntimeError(f"New-layout workspace missing .sbx component: {ws_resolved}")

    repo_root = Path(*parts[:sbx_idx]).resolve()

    if not _is_within(gitdir, (repo_root / ".git" / "worktrees").resolve()):
        raise RuntimeError(f"Gitdir escapes repo .git/worktrees: {gitdir}")

    expected_git_dir = (repo_root / ".git").resolve()
    if bare_dir.resolve() != expected_git_dir:
        raise RuntimeError(
            f"Commondir doesn't point to repo .git: {bare_dir} (expected {expected_git_dir})"
        )


def _validate_legacy_layout_paths(
    worktree_path: Path, gitdir: Path, bare_dir: Path
) -> None:
    """Validate paths for legacy (cast-managed) worktrees."""
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
    remove_stale_git_locks(config_file.parent)
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
    name = resolve_sandbox_name(name)

    worktree_path = resolve_host_worktree_path(name)

    if not worktree_path.is_dir():
        log_error(f"Sandbox '{name}' not found at {worktree_path}")
        sys.exit(1)

    try:
        gitdir, bare_dir = _resolve_git_paths(worktree_path)
        _validate_git_paths(name, worktree_path, gitdir, bare_dir)
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
    has_mode_flag = "--mode" in args
    has_mode_value = any(arg in {"host", "sandbox"} for arg in args)
    if not has_mode_flag and not has_mode_value:
        # GitHub CLI (and similar) may call `git mode` without arguments; treat as no-op.
        return
    # Delegate to the Click command for real work.
    git_mode.main()
