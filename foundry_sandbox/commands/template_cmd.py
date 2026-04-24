"""cast template — manage cached profile templates."""

from __future__ import annotations

import click
from foundry_sandbox.utils import log_error


@click.group(invoke_without_command=True)
@click.pass_context
def template(ctx: click.Context) -> None:
    """Manage cached profile templates."""
    if ctx.invoked_subcommand is None:
        _list_templates()


@template.command("list")
def list_cmd() -> None:
    """List all cached profile templates."""
    _list_templates()


def _list_templates() -> None:
    from foundry_sandbox.template_cache import list_cached_templates

    entries = list_cached_templates()
    if not entries:
        click.echo("No cached profile templates.")
        return

    click.echo("Cached profile templates:\n")
    click.echo(f"  {'Profile':<20} {'Cache Key':<18} {'Built At':<22} {'Template Tag'}")
    click.echo(f"  {'-' * 20} {'-' * 18} {'-' * 22} {'-' * 40}")
    for e in entries:
        built = e.built_at[:19].replace("T", " ") if e.built_at else "unknown"
        click.echo(f"  {e.profile_name:<20} {e.cache_key:<18} {built:<22} {e.template_tag}")


@template.command("show")
@click.argument("profile")
def show_cmd(profile: str) -> None:
    """Show details of a cached profile template."""
    from foundry_sandbox.template_cache import _read_cache_entry

    entry = _read_cache_entry(profile)
    if not entry:
        log_error(f"No cached template for profile '{profile}'.")
        raise SystemExit(1)

    click.echo(f"Profile template: {entry.profile_name}")
    click.echo(f"  Template tag:    {entry.template_tag}")
    click.echo(f"  Base template:   {entry.base_template}")
    click.echo(f"  Cache key:       {entry.cache_key}")
    click.echo(f"  Built at:        {entry.built_at}")
    click.echo(f"  sbx version:     {entry.sbx_version}")
    click.echo(f"  cast version:    {entry.cast_version}")

    inputs = entry.bakeable_inputs
    if inputs:
        click.echo("\n  Bakeable inputs:")
        pkgs = inputs.get("packages", {})
        if pkgs:
            click.echo("    packages:")
            for k, v in pkgs.items():
                click.echo(f"      {k}: {v}")
        tooling = inputs.get("tooling", [])
        if tooling:
            click.echo(f"    tooling: {tooling}")


@template.command("rebuild")
@click.argument("profile")
@click.option("--base-template", default=None, help="Override base template")
def rebuild_cmd(profile: str, base_template: str | None) -> None:
    """Force rebuild a profile's cached template."""
    from foundry_sandbox.sbx import sbx_check_available
    from foundry_sandbox.template_cache import (
        build_profile_template,
        invalidate_cached_template,
    )
    from foundry_sandbox.foundry_config import resolve_foundry_config, resolve_profile
    from pathlib import Path

    sbx_check_available()

    # Resolve user-level config only (no repo context for rebuild)
    config = resolve_foundry_config(Path.home())
    try:
        profile_config = resolve_profile(config, profile)
    except ValueError as exc:
        log_error(str(exc))
        raise SystemExit(1)

    base = base_template or profile_config.template or "foundry-git-wrapper:latest"

    click.echo(f"Invalidating existing template for '{profile}'...")
    invalidate_cached_template(profile)

    click.echo(f"Building template for '{profile}'...")
    tag = build_profile_template(profile, profile_config, config, base)
    click.echo(f"  Built: {tag}")


@template.command("rm")
@click.argument("profile")
def rm_cmd(profile: str) -> None:
    """Remove a cached profile template."""
    from foundry_sandbox.template_cache import invalidate_cached_template

    if invalidate_cached_template(profile):
        click.echo(f"Removed cached template for '{profile}'.")
    else:
        click.echo(f"No cached template found for '{profile}'.")
