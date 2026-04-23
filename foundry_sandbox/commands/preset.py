"""Preset management commands for cast new.

Migrated from commands/preset.sh. Provides list, show, and delete
subcommands for managing saved cast-new presets.
"""

from __future__ import annotations

import re
import sys

import click

from foundry_sandbox.state import (
    delete_cast_preset,
    list_cast_presets,
    load_cast_preset,
    load_sandbox_metadata,
    save_cast_preset,
    show_cast_preset,
)
from foundry_sandbox.sbx import sbx_is_running, sbx_sandbox_exists, sbx_template_rm, sbx_template_save
from foundry_sandbox.commands._helpers import resolve_sandbox_name
from foundry_sandbox.utils import log_error, log_warn


def _validate_preset_name(name: str) -> None:
    """Validate preset name to prevent path traversal."""
    if not name or "/" in name or "\\" in name or ".." in name or name.startswith("."):
        click.echo(f"Error: Invalid preset name: {name}", err=True)
        sys.exit(1)


def _managed_tag_for_preset(preset_name: str) -> str:
    """Derive a safe sbx template tag from a preset name.

    Normalizes the name by replacing non-alphanumeric chars with hyphens,
    then prepends 'preset-' and appends ':latest'.

    Raises ValueError if the resulting tag is empty or starts/ends with
    a hyphen/dot (invalid Docker tag).
    """
    normalized = re.sub(r"[^a-zA-Z0-9._-]", "-", preset_name)
    tag = f"preset-{normalized}:latest"
    # Validate the image name portion (before ':')
    image_name = tag.split(":")[0]
    if not image_name or image_name[-1] in ".-" or len(image_name) < 2:
        raise ValueError(f"Cannot derive a valid template tag from preset name: {preset_name!r}")
    return tag


def _list_presets() -> None:
    """Print saved presets to stdout."""
    click.echo("Saved presets:")
    click.echo("")
    names = list_cast_presets()
    for name in names:
        click.echo(name)


@click.group(invoke_without_command=True)
@click.pass_context
def preset(ctx: click.Context) -> None:
    """Manage saved presets."""
    if ctx.invoked_subcommand is None:
        _list_presets()


@preset.command("help")
@click.pass_context
def help_cmd(ctx: click.Context) -> None:
    """Show preset usage information."""
    parent = ctx.parent
    if parent is not None:
        click.echo(parent.get_help())


@preset.command("list")
def list_cmd() -> None:
    """List all saved presets."""
    _list_presets()


@preset.command("show")
@click.argument("name")
def show(name: str) -> None:
    """Show preset details."""
    _validate_preset_name(name)
    result = show_cast_preset(name)
    if result is None:
        log_error(f"Preset not found: {name}")
        sys.exit(1)
    click.echo(result)


@preset.command("save")
@click.argument("name")
@click.option("--sandbox", "sandbox_name", default=None, help="Sandbox to snapshot (auto-detected from CWD if omitted).")
def save(name: str, sandbox_name: str | None) -> None:
    """Save a preset from a running sandbox (includes filesystem snapshot)."""
    _validate_preset_name(name)

    # Resolve sandbox name
    sandbox_name = resolve_sandbox_name(sandbox_name, allow_fzf=False)

    # Validate sandbox exists and is running
    if not sbx_sandbox_exists(sandbox_name):
        log_error(f"Sandbox not found: {sandbox_name}")
        sys.exit(1)
    if not sbx_is_running(sandbox_name):
        log_error(f"Sandbox is not running: {sandbox_name}")
        sys.exit(1)

    # Load metadata
    metadata = load_sandbox_metadata(sandbox_name)
    if metadata is None:
        log_error(f"No metadata for sandbox: {sandbox_name}")
        sys.exit(1)

    # Derive managed tag
    try:
        managed_tag = _managed_tag_for_preset(name)
    except ValueError as exc:
        log_error(str(exc))
        sys.exit(1)

    # Snapshot the sandbox into a managed template
    result = sbx_template_save(sandbox_name, managed_tag)
    if result.returncode != 0:
        log_error(f"Failed to save template: {result.stderr.strip()}")
        sys.exit(1)

    # Save preset with metadata-derived args and managed template ref
    save_cast_preset(
        name,
        repo=metadata.get("repo_url", ""),
        agent=metadata.get("agent", "claude"),
        branch=metadata.get("branch", ""),
        from_branch=metadata.get("from_branch", ""),
        working_dir=metadata.get("working_dir", ""),
        pip_requirements=metadata.get("pip_requirements", ""),
        allow_pr=metadata.get("allow_pr", False),
        enable_opencode=metadata.get("enable_opencode", False),
        enable_zai=metadata.get("enable_zai", False),
        copies=metadata.get("copies", []),
        template=managed_tag,
        template_managed=True,
        ide=metadata.get("ide", ""),
    )
    click.echo(f"Saved preset '{name}' with template '{managed_tag}'")


def _delete_with_cleanup(name: str) -> None:
    """Delete a preset and clean up managed templates if appropriate."""
    _validate_preset_name(name)

    # Load preset metadata before deleting
    preset_data = load_cast_preset(name)
    if preset_data is None:
        log_error(f"Preset not found: {name}")
        sys.exit(1)

    template_tag = preset_data.get("template", "")
    is_managed = preset_data.get("template_managed", False)

    # Delete the preset JSON
    deleted = delete_cast_preset(name)
    if not deleted:
        log_error(f"Preset not found: {name}")
        sys.exit(1)

    click.echo(f"Deleted preset: {name}")

    # Clean up managed template if no other preset references it
    if is_managed and template_tag:
        _cleanup_managed_template(template_tag)


def _cleanup_managed_template(template_tag: str) -> None:
    """Remove a managed template if no remaining presets reference it."""
    remaining_names = list_cast_presets()
    for other_name in remaining_names:
        other_data = load_cast_preset(other_name)
        if other_data and other_data.get("template") == template_tag:
            return  # Still referenced

    try:
        result = sbx_template_rm(template_tag)
        if result.returncode == 0:
            log_warn(f"Removed managed template: {template_tag}")
        else:
            log_warn(f"Failed to remove managed template {template_tag}: {result.stderr.strip()}")
    except Exception as exc:
        log_warn(f"Failed to remove managed template {template_tag}: {exc}")


@preset.command("delete")
@click.argument("name")
def delete(name: str) -> None:
    """Delete a preset."""
    _delete_with_cleanup(name)
