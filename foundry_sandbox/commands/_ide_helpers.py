"""Shared IDE helper functions used by attach, open, and up commands."""

from __future__ import annotations

import click


def get_ide_args(ide_config: object | None) -> list[str]:
    """Extract extra args from IDE config."""
    if ide_config:
        return list(getattr(ide_config, "args", []))
    return []


def maybe_auto_git_mode(name: str, ide_config: object | None) -> None:
    """Optionally apply git-mode host after IDE launch.

    Convenience behavior gated by ``auto_git_mode_host`` in user IDE config.
    Failures are warnings, never fatal.
    """
    if not ide_config or not getattr(ide_config, "auto_git_mode_host", False):
        return
    try:
        from foundry_sandbox.commands.git_mode import (
            _apply_git_mode,
            _resolve_git_paths,
            _validate_git_paths,
        )
        from foundry_sandbox.paths import resolve_host_worktree_path

        worktree_path = resolve_host_worktree_path(name)
        gitdir, bare_dir = _resolve_git_paths(worktree_path)
        _validate_git_paths(name, worktree_path, gitdir, bare_dir)
        _apply_git_mode(
            mode="host",
            name=name,
            worktree_path=worktree_path,
            gitdir=gitdir,
            bare_dir=bare_dir,
        )
        click.echo("  Auto git-mode host applied")
    except RuntimeError as exc:
        click.echo(f"  Warning: auto git-mode host failed: {exc}", err=True)
    except Exception as exc:
        click.echo(f"  Warning: auto git-mode host failed: {exc}", err=True)
