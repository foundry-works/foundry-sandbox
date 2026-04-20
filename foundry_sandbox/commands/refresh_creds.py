"""Refresh credentials command — sync API keys via sbx secrets.

Uses `sbx secret set` to push API keys from the host into sbx-managed
secrets. No more direct/isolation mode distinction.
"""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.commands._helpers import (
    auto_detect_sandbox as _auto_detect_sandbox,
    fzf_select_sandbox as _fzf_select_sandbox_shared,
)
from foundry_sandbox.sbx import sbx_check_available, sbx_is_running, sbx_secret_set
from foundry_sandbox.state import load_last_attach
from foundry_sandbox.utils import log_error, log_info
from foundry_sandbox.validate import validate_existing_sandbox_name


def _push_secret(service: str, value: str) -> bool:
    """Push a secret to sbx.

    Returns:
        True on success, False on failure.
    """
    if not value:
        return True  # Skip empty values
    try:
        sbx_secret_set(service, value, global_scope=True)
        log_info(f"  Updated: {service}")
        return True
    except Exception as exc:
        log_error(f"  Failed: {service}: {exc}")
        return False


def _refresh_one(name: str) -> bool:
    """Refresh credentials for a single sandbox.

    Returns:
        True on success, False on failure.
    """
    valid_name, name_error = validate_existing_sandbox_name(name)
    if not valid_name:
        log_error(f"{name}: {name_error}")
        return False

    if not sbx_is_running(name):
        log_error(f"{name}: not running")
        return False

    ok = True

    # Push API keys from host environment
    services = {
        "anthropic": os.environ.get("ANTHROPIC_API_KEY", ""),
        "github": os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", ""),
        "openai": os.environ.get("OPENAI_API_KEY", ""),
    }

    for service, value in services.items():
        if not _push_secret(service, value):
            ok = False

    # Push user-defined service credentials
    try:
        from foundry_sandbox.user_services import _slug, get_user_services

        for svc in get_user_services():
            slug = _slug(str(svc["name"]))
            value = os.environ.get(str(svc["env_var"]), "")
            if not _push_secret(slug, value):
                ok = False
    except Exception as exc:
        from foundry_sandbox.utils import log_warn
        log_warn(f"User service credential push failed: {exc}")

    return ok


def _refresh_all() -> None:
    """Refresh credentials for all running sandboxes."""
    from foundry_sandbox.sbx import sbx_ls

    sandboxes = sbx_ls()
    running = [sb["name"] for sb in sandboxes if sb.get("status") == "running"]

    if not running:
        click.echo("No running sandboxes found.")
        return

    click.echo(f"Refreshing credentials for {len(running)} running sandbox(es)...\n")
    ok = 0
    failed = 0
    for name in running:
        click.echo(f"[{name}]")
        if _refresh_one(name):
            ok += 1
        else:
            failed += 1
        click.echo("")

    click.echo(f"Done: {ok} succeeded, {failed} failed.")
    if failed:
        sys.exit(1)


@click.command("refresh-credentials")
@click.argument("name", required=False, default=None)
@click.option("--last", "-l", is_flag=True, help="Refresh last attached sandbox")
@click.option("--all", "all_sandboxes", is_flag=True, help="Refresh all running sandboxes")
def refresh_creds(name: str | None, last: bool, all_sandboxes: bool) -> None:
    """Refresh credentials for a running sandbox.

    Pushes API keys from host environment to sbx secrets.

    Use --all to refresh every running sandbox at once.
    """
    sbx_check_available()

    # --all mode
    if all_sandboxes:
        if name or last:
            log_error("--all cannot be combined with NAME or --last")
            sys.exit(1)
        _refresh_all()
        return

    # Handle --last flag
    if last:
        name = load_last_attach()
        if not name:
            log_error("No last attached sandbox found.")
            sys.exit(1)
        click.echo(f"Refreshing credentials for: {name}")

    # Auto-detect from current directory
    if not name:
        name = _auto_detect_sandbox()

    # fzf selection fallback
    if not name:
        name = _fzf_select_sandbox_shared()
        if not name:
            click.echo("Usage: cast refresh-credentials <sandbox-name>")
            sys.exit(1)

    click.echo(f"[{name}]")
    if not _refresh_one(name):
        sys.exit(1)
