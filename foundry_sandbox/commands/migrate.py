"""Migration commands: migrate-to-sbx and migrate-from-sbx.

Provides the CLI interface for upgrading from 0.20.x (docker-compose) to
0.21.x (sbx) and rolling back if needed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from foundry_sandbox.config import load_json
from foundry_sandbox.constants import get_sandbox_home
from foundry_sandbox.migration import (
    classify_sandbox_dirs,
    convert_old_metadata_to_sbx,
    convert_old_preset_to_new,
    find_latest_snapshot,
    get_migration_lock,
    parse_legacy_env_metadata,
    push_credentials,
    remove_migration_lock,
    restore_from_snapshot,
    snapshot_sandbox_home,
)
from foundry_sandbox.paths import (
    path_claude_config,
    path_metadata_legacy_file,
    path_preset_file,
    path_presets_dir,
)
from foundry_sandbox.state import save_cast_preset, write_sandbox_metadata
from foundry_sandbox.utils import log_error, log_info, log_section, log_step, log_warn


def _confirm(msg: str, force: bool) -> bool:
    """Prompt for confirmation, or skip if --force."""
    if force:
        return True
    try:
        return click.confirm(f"  {msg}", default=False)
    except KeyboardInterrupt:
        click.echo("")
        return False


def _migrate_to_sbx_impl(
    plan: bool = False,
    force: bool = False,
    snapshot_dir: str | None = None,
) -> bool:
    """Implementation for migrate-to-sbx.

    Returns:
        True on success, False on failure.
    """
    sandbox_home = get_sandbox_home()

    if not sandbox_home.exists():
        log_error(f"Sandbox home not found: {sandbox_home}")
        log_error("No 0.20.x installation detected.")
        return False

    # Check for interrupted migration
    lock = get_migration_lock(sandbox_home)
    if lock and not plan:
        log_warn(f"Migration lock found from {lock.get('timestamp', 'unknown time')}")
        log_warn(f"Snapshot at: {lock.get('snapshot_dir', 'unknown')}")
        if not _confirm("A previous migration may be in progress. Continue anyway?", force):
            log_info("Aborted. Use --force to override or cast migrate-from-sbx to rollback.")
            return False

    # Phase 1: Classify sandbox directories
    log_section("Scanning sandboxes")
    dirs = classify_sandbox_dirs(sandbox_home)

    needs_migration = [d for d in dirs if d["format"] in ("old_json", "legacy_env")]
    already_sbx = [d for d in dirs if d["format"] == "sbx"]
    empty = [d for d in dirs if d["format"] == "empty"]

    # Scan presets
    presets_dir = path_presets_dir()
    preset_files = sorted(p.stem for p in presets_dir.glob("*.json")) if presets_dir.exists() else []

    if not needs_migration and not already_sbx and not preset_files:
        log_info("No sandboxes or presets found. Nothing to migrate.")
        return True

    for d in needs_migration:
        log_step(f"  {d['name']} ({d['format']}) — will migrate")
    for d in already_sbx:
        log_step(f"  {d['name']} (sbx) — already migrated, skip")
    for d in empty:
        log_step(f"  {d['name']} (empty) — skip")

    log_section("Migration plan")
    log_step(f"Sandboxes to migrate: {len(needs_migration)}")
    log_step(f"Sandboxes to skip: {len(already_sbx) + len(empty)}")
    log_step(f"Presets to convert: {len(preset_files)}")

    if not needs_migration and not preset_files:
        log_info("All sandboxes already on sbx backend. Nothing to do.")
        return True

    if plan:
        log_section("Dry run — no changes made")
        _plan_credentials()
        _plan_metadata(needs_migration)
        _plan_presets(preset_files)
        return True

    # Confirm
    if not _confirm("Proceed with migration?", force):
        log_info("Aborted.")
        return False

    # Phase 2: Snapshot
    log_section("Creating snapshot")
    snap_dir = snapshot_sandbox_home(
        sandbox_home,
        Path(snapshot_dir) if snapshot_dir else None,
    )
    log_step(f"Snapshot created: {snap_dir}")

    # Phase 3: Push credentials
    log_section("Pushing credentials to sbx")
    pushed, missing = push_credentials(dry_run=False)
    for svc in pushed:
        log_step(f"  Pushed: {svc}")
    for svc in missing:
        log_warn(f"  Missing: {svc} (set env var and run cast refresh-credentials)")

    # Phase 4: Convert metadata
    log_section("Converting sandbox metadata")
    all_warnings: list[str] = []
    for d in needs_migration:
        name = d["name"]
        config_dir = path_claude_config(name)
        warnings = _convert_one_sandbox(name, config_dir, d["format"])
        if warnings:
            all_warnings.extend(f"  {name}: {w}" for w in warnings)
            for w in warnings:
                log_warn(f"  {name}: {w}")
        else:
            log_step(f"  {name}: converted")

    # Phase 5: Convert presets
    if preset_files:
        log_section("Converting presets")
        for preset_name in preset_files:
            warnings = _convert_one_preset(preset_name)
            if warnings:
                all_warnings.extend(f"  preset '{preset_name}': {w}" for w in warnings)
                for w in warnings:
                    log_warn(f"  {preset_name}: {w}")
            else:
                log_step(f"  {preset_name}: converted")

    # Phase 6: Summary
    log_section("Migration complete")
    log_step(f"Sandboxes migrated: {len(needs_migration)}")
    log_step(f"Sandboxes skipped: {len(already_sbx) + len(empty)}")
    log_step(f"Presets converted: {len(preset_files)}")
    log_step(f"Credentials pushed: {len(pushed)}")
    log_step(f"Credentials missing: {len(missing)}")
    if all_warnings:
        log_step(f"Warnings: {len(all_warnings)}")
    log_step(f"Snapshot: {snap_dir}")
    log_info("")
    log_info("Rollback: cast migrate-from-sbx")
    if missing:
        log_info("Set missing credentials and run: cast refresh-credentials")
    if needs_migration:
        log_info("")
        log_info("Next steps:")
        log_info("  1. Verify: cast list")
        log_info("  2. Start each sandbox: cast start <name>")
        log_info("     (First start provisions the sbx sandbox — this may take a minute)")
        log_info("     Existing bare repos and worktrees are reused automatically.")

    return True


def _convert_one_sandbox(name: str, config_dir: Path, fmt: str) -> list[str]:
    """Convert a single sandbox's metadata.

    Returns:
        List of warning strings.
    """
    # Read old data
    if fmt == "legacy_env":
        env_path = path_metadata_legacy_file(name)
        old_data = parse_legacy_env_metadata(env_path)
    else:  # old_json
        json_path = config_dir / "metadata.json"
        old_data = load_json(str(json_path))

    if not old_data:
        return ["Empty or unreadable metadata, skipped"]

    # Convert
    new_data, warnings = convert_old_metadata_to_sbx(old_data, name)

    # Write new metadata
    write_sandbox_metadata(
        name,
        sbx_name=new_data["sbx_name"],
        agent=new_data["agent"],
        repo_url=new_data["repo_url"],
        branch=new_data["branch"],
        from_branch=new_data.get("from_branch", ""),
        network_profile=new_data["network_profile"],
        git_safety_enabled=new_data["git_safety_enabled"],
        working_dir=new_data.get("working_dir", ""),
        pip_requirements=new_data.get("pip_requirements", ""),
        allow_pr=new_data["allow_pr"],
        enable_opencode=new_data["enable_opencode"],
        enable_zai=new_data["enable_zai"],
        copies=new_data["copies"],
        template=new_data.get("template", ""),
    )

    # Rename old env file if it exists
    env_path = path_metadata_legacy_file(name)
    if env_path.exists():
        backup_path = config_dir / "metadata.env.pre-sbx-migration"
        env_path.rename(backup_path)

    # Write per-sandbox migration report
    report_path = config_dir / ".migration-report.json"
    report_path.write_text(json.dumps({
        "migrated_at": new_data.get("_migrated_at", ""),
        "old_format": fmt,
        "warnings": warnings,
    }, indent=2) + "\n")

    return warnings


def _convert_one_preset(preset_name: str) -> list[str]:
    """Convert a single preset file.

    Returns:
        List of warning strings.
    """
    preset_path = path_preset_file(preset_name)
    data = load_json(str(preset_path))
    if not data:
        return ["Empty preset file, skipped"]

    args = data.get("args", {})
    if not args:
        return ["No args found in preset, skipped"]

    new_args, warnings = convert_old_preset_to_new(args)

    # Update the preset using existing state functions
    save_cast_preset(
        preset_name,
        repo=new_args["repo"],
        agent=new_args.get("agent", "claude"),
        branch=new_args.get("branch", ""),
        from_branch=new_args.get("from_branch", ""),
        working_dir=new_args.get("working_dir", ""),
        pip_requirements=new_args.get("pip_requirements", ""),
        allow_pr=new_args.get("allow_pr", False),
        network_profile=new_args.get("network_profile", "balanced"),
        enable_opencode=new_args.get("enable_opencode", False),
        enable_zai=new_args.get("enable_zai", False),
        copies=new_args.get("copies", []),
    )

    return warnings


def _plan_credentials() -> None:
    """Show credential plan without executing."""
    log_step("Credentials:")
    pushed, missing = push_credentials(dry_run=True)
    log_step(f"  Would push: {', '.join(pushed) or 'none'}")
    log_step(f"  Missing: {', '.join(missing) or 'none'}")


def _plan_metadata(dirs: list[dict[str, str]]) -> None:
    """Show metadata conversion plan without executing."""
    log_step("Metadata conversions:")
    for d in dirs:
        name = d["name"]
        fmt = d["format"]
        if fmt == "legacy_env":
            env_path = path_metadata_legacy_file(name)
            old_data = parse_legacy_env_metadata(env_path)
        else:
            json_path = path_claude_config(name) / "metadata.json"
            old_data = load_json(str(json_path))

        _, warnings = convert_old_metadata_to_sbx(old_data or {}, name)
        log_step(f"  {name} ({fmt})")
        for w in warnings:
            log_step(f"    WARNING: {w}")


def _plan_presets(preset_files: list[str]) -> None:
    """Show preset conversion plan without executing."""
    log_step("Preset conversions:")
    for preset_name in preset_files:
        preset_path = path_preset_file(preset_name)
        data = load_json(str(preset_path))
        args = data.get("args", {}) if data else {}
        _, warnings = convert_old_preset_to_new(args)
        log_step(f"  {preset_name}")
        for w in warnings:
            log_step(f"    WARNING: {w}")


@click.command("migrate-to-sbx")
@click.option("--plan", is_flag=True, help="Dry-run: show plan without making changes")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompts")
@click.option("--snapshot-dir", default=None, help="Override snapshot directory path")
def migrate_to_sbx(plan: bool, force: bool, snapshot_dir: str | None) -> None:
    """Migrate 0.20.x docker-compose state to sbx backend.

    Converts sandbox metadata, presets, and credentials from the
    docker-compose backend (0.20.x) to the sbx microVM backend (0.21.x).
    Creates a snapshot for rollback before making changes.
    """
    if not _migrate_to_sbx_impl(plan=plan, force=force, snapshot_dir=snapshot_dir):
        sys.exit(1)


@click.command("migrate-from-sbx")
@click.option("--snapshot-dir", default=None, help="Override snapshot directory path")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompts")
def migrate_from_sbx(snapshot_dir: str | None, force: bool) -> None:
    """Rollback to 0.20.x state from a migration snapshot.

    Restores the metadata snapshot created by cast migrate-to-sbx.
    After rollback, downgrade the package: pip install foundry-sandbox==0.20.15
    """
    sandbox_home = get_sandbox_home()

    # Find snapshot
    snap_dir: Path
    if snapshot_dir:
        snap_dir = Path(snapshot_dir)
        if not snap_dir.exists():
            log_error(f"Snapshot directory not found: {snap_dir}")
            sys.exit(1)
    else:
        snap_dir_maybe = find_latest_snapshot(sandbox_home)
        if not snap_dir_maybe:
            log_error("No migration snapshot found. Cannot rollback.")
            log_error("Manual rollback: pip install foundry-sandbox==0.20.15")
            sys.exit(1)
        snap_dir = snap_dir_maybe

    log_info(f"Snapshot: {snap_dir}")

    # Load manifest
    manifest_path = snap_dir / "snapshot-manifest.json"
    if manifest_path.exists():
        manifest = load_json(str(manifest_path))
        log_info(f"Created: {manifest.get('timestamp', 'unknown')}")
        log_info(f"Sandboxes: {len(manifest.get('sandbox_names', []))}")
        log_info(f"Presets: {len(manifest.get('preset_names', []))}")

    if not _confirm("Restore from this snapshot?", force):
        log_info("Aborted.")
        return

    log_info("Restoring from snapshot...")
    restore_from_snapshot(snap_dir, sandbox_home)

    remove_migration_lock(sandbox_home)

    log_info("Rollback complete.")
    log_info("")
    log_info("Next steps:")
    log_info("  1. Downgrade: pip install foundry-sandbox==0.20.15")
    log_info("  2. Verify: cast list")
