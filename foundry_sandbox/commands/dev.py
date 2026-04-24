"""Dev command — create or reuse a sandbox, start, open IDE, and attach.

The single-command local-dev workflow. Resolves repo, finds an existing
sandbox by repo + profile, and either reuses it (up-flow) or creates a
new one (new-flow) before attaching.
"""

from __future__ import annotations

import os
import sys

import click

from foundry_sandbox.commands.new import (
    _branch_exists_on_remote,
    _detect_remote_default_branch,
    _ensure_repo_root,
    _generate_branch_name,
    _resolve_repo_input,
    _sandbox_name_collision_suffix,
)
from foundry_sandbox.commands.new_setup import _validate_preconditions, new_sbx_setup
from foundry_sandbox.foundry_config import load_user_ide_config, normalize_profile_packages, resolve_foundry_config, resolve_profile
from foundry_sandbox.ide import launch_ide
from foundry_sandbox.paths import (
    find_next_sandbox_name,
    path_sandbox_config,
    repo_name_from_url,
    resolve_host_worktree_path,
    sandbox_name as _helpers_sandbox_name,
)
from foundry_sandbox.sbx import sbx_check_available, sbx_is_running
from foundry_sandbox.state import (
    find_sandbox_by_profile,
    load_sandbox_metadata,
    save_last_attach,
    save_last_cast_new,
)
from foundry_sandbox.utils import log_error, log_warn
from foundry_sandbox.validate import validate_sandbox_name


def _up_flow(
    name: str,
    *,
    no_ide: bool = False,
    ide_value: str = "",
    ide_config: object | None = None,
) -> None:
    """Start sandbox if stopped, optionally launch IDE, then attach.

    Shared between the reuse and create paths.
    """
    from foundry_sandbox.commands.attach import _sbx_attach
    from foundry_sandbox.commands.start import start_sandbox
    from foundry_sandbox.commands._ide_helpers import get_ide_args, maybe_auto_git_mode
    from foundry_sandbox.commands.up import _resolve_ide_for_up

    # Start if not running
    if not sbx_is_running(name):
        click.echo("Sandbox not running. Starting...")
        start_sandbox(name)

    metadata = load_sandbox_metadata(name)
    working_dir = str(metadata.get("working_dir", "")) if metadata else ""

    save_last_attach(name)

    # IDE launch
    if not no_ide and os.isatty(0):
        spec = _resolve_ide_for_up(ide_value or None, ide_config, metadata)
        if spec is not None:
            worktree_path = resolve_host_worktree_path(name)
            extra_args = get_ide_args(ide_config)
            ok = launch_ide(spec, str(worktree_path), extra_args)
            if ok:
                maybe_auto_git_mode(name, ide_config)
            elif ide_value:
                log_error(f"IDE '{ide_value}' launch failed")
        elif ide_value:
            log_error(f"IDE '{ide_value}' could not be resolved")

    _sbx_attach(name, working_dir)


@click.command()
@click.argument("repo", required=False, default=".")
@click.option("--profile", "-p", default="default", help="Named dev profile for reuse matching")
@click.option("--branch", "-b", default="", help="Target branch (auto-generated if omitted)")
@click.option("--fresh", is_flag=True, help="Force new sandbox, skip reuse lookup")
@click.option("--agent", default=None, help="Agent type (claude, codex, copilot, gemini, kiro, opencode, shell)")
@click.option("--ide", default=None, help="Override IDE (alias, path, or command)")
@click.option("--no-ide", is_flag=True, help="Skip IDE launch")
@click.option("--name", "name_override", default="", help="Override auto-generated sandbox name")
@click.option("--wd", default=None, help="Working directory (relative)")
@click.option("--pip-requirements", "-r", default=None, help="Install Python packages from requirements file")
@click.option("--template", default=None, help="Template tag")
@click.option("--plan", "dry_run_plan", is_flag=True, help="Dry-run: show resolved config without creating")
def dev(
    repo: str,
    profile: str,
    branch: str,
    fresh: bool,
    agent: str | None,
    ide: str | None,
    no_ide: bool,
    name_override: str,
    wd: str | None,
    pip_requirements: str | None,
    template: str | None,
    dry_run_plan: bool,
) -> None:
    """Create or reuse a dev sandbox, open IDE, and attach.

    Defaults to the current directory. Reuses an existing sandbox matching
    the repo and profile unless --fresh is given.
    """
    from pathlib import Path

    sbx_check_available()
    ide_config = load_user_ide_config()

    # Resolve repo input
    if not repo:
        repo = "."
    repo_url, repo_root, _, current_branch = _resolve_repo_input(repo)

    if not repo_url:
        log_error(f"Not a git repository: {repo}")
        sys.exit(1)

    # For remote URLs, ensure a local checkout exists
    if not repo_root:
        repo_root = _ensure_repo_root(repo_url)

    # Resolve config and profile
    try:
        config = resolve_foundry_config(Path(repo_root or repo_url))
        profile_config = resolve_profile(config, profile)
    except ValueError as exc:
        log_error(f"Foundry config error: {exc}")
        sys.exit(1)

    # Merge: CLI flags override profile fields, which override hardcoded defaults
    effective_agent = agent or profile_config.agent or "claude"
    effective_ide = ide or profile_config.ide or ""
    effective_wd = wd or profile_config.wd or ""
    effective_pip = pip_requirements or profile_config.pip_requirements or ""
    effective_template = template or profile_config.template or "foundry-git-wrapper:latest"

    # Resolve packages from profile, bridge CLI --pip-requirements
    effective_packages = normalize_profile_packages(profile_config)
    if pip_requirements:
        effective_packages["pip"] = pip_requirements

    # Merge bundle packages into effective_packages
    if profile_config.tooling:
        from foundry_sandbox.foundry_config import collect_bundle_packages
        bundle_pkgs = collect_bundle_packages(config, profile_config)
        if bundle_pkgs:
            from foundry_sandbox.foundry_config import normalize_profile_packages as _npp
            from foundry_sandbox.foundry_config import DevProfile
            bp = _npp(DevProfile(packages=bundle_pkgs))
            for k, v in bp.items():
                if k not in effective_packages:
                    effective_packages[k] = v

    # --plan: dry-run mode
    if dry_run_plan:
        from foundry_sandbox.foundry_config import render_plan_text

        plan_output = render_plan_text(config, profile_name=profile)
        plan_output += "\nEffective settings:\n"
        plan_output += f"  agent:     {effective_agent}\n"
        plan_output += f"  ide:       {effective_ide or '(auto)'}\n"
        plan_output += f"  wd:        {effective_wd or '(repo root)'}\n"
        plan_output += f"  template:  {effective_template}\n"
        if effective_packages:
            plan_output += "  packages:\n"
            for pkg_type, pkg_val in effective_packages.items():
                plan_output += f"    {pkg_type}: {pkg_val}\n"
        else:
            plan_output += "  packages:  (none)\n"
        click.echo(plan_output)
        return

    # Reuse path: look for an existing sandbox matching repo + profile
    if not fresh:
        existing = find_sandbox_by_profile(repo_url, profile)
        if existing:
            click.echo(f"Reusing sandbox: {existing}")
            _up_flow(existing, no_ide=no_ide, ide_value=effective_ide, ide_config=ide_config)
            return

    # Create path: resolve branch, build sandbox, attach
    click.echo("Creating new sandbox...")

    # Check for a cached profile template
    cached_template_tag = None
    skip_bootstrap = False
    if profile != "default" and (effective_packages or profile_config.tooling):
        from foundry_sandbox.template_cache import lookup_cached_template, build_profile_template
        cached_template_tag = lookup_cached_template(profile)
        if cached_template_tag:
            click.echo(f"  Using cached profile template: {cached_template_tag}")
            effective_template = cached_template_tag
            skip_bootstrap = True
        else:
            click.echo(f"  Building profile template for '{profile}'...")
            try:
                cached_template_tag = build_profile_template(
                    profile_name=profile,
                    profile=profile_config,
                    config=config,
                    base_template=effective_template,
                )
                effective_template = cached_template_tag
                skip_bootstrap = True
            except Exception as exc:
                log_warn(f"Profile template build failed, using base template: {exc}")

    # Validate agent
    valid_agents = {"claude", "codex", "copilot", "gemini", "kiro", "opencode", "shell"}
    if effective_agent not in valid_agents:
        log_error(f"Invalid agent '{effective_agent}'. Must be one of: {', '.join(sorted(valid_agents))}")
        sys.exit(1)

    # Resolve branch
    from_branch = ""
    if repo_root and current_branch:
        if current_branch == "HEAD":
            log_error("Repository is in a detached HEAD state; specify a base branch.")
            sys.exit(1)

        if not branch:
            if _branch_exists_on_remote(repo_root, current_branch):
                from_branch = current_branch
            else:
                from_branch = _detect_remote_default_branch(repo_root)
                log_warn(
                    f"Current branch '{current_branch}' not found on remote; "
                    f"using '{from_branch}' as base."
                )

    if not branch:
        branch = _generate_branch_name(repo_url, from_branch or "main")
        from_branch = from_branch or "main"

    # Validate working directory
    if effective_wd:
        effective_wd = effective_wd.lstrip("./")

    # Validate preconditions
    _validate_preconditions(repo_url, (), False)

    # Generate sandbox name
    repo_name = repo_name_from_url(repo_url)
    if name_override:
        name = name_override
    else:
        name = _helpers_sandbox_name(repo_name, branch)

    valid_name, name_error = validate_sandbox_name(name)
    if not valid_name:
        log_error(f"Invalid sandbox name '{name}': {name_error}")
        sys.exit(1)

    # Atomically claim the sandbox name
    sandbox_config_path = path_sandbox_config(name)
    try:
        os.makedirs(sandbox_config_path, exist_ok=False)
    except FileExistsError:
        name = find_next_sandbox_name(name)
        base_name = _helpers_sandbox_name(repo_name, branch)
        suffix = _sandbox_name_collision_suffix(base_name, name)
        if suffix:
            branch = f"{branch}{suffix}"
        sandbox_config_path = path_sandbox_config(name)
        try:
            os.makedirs(sandbox_config_path, exist_ok=False)
        except FileExistsError:
            log_error(f"Sandbox name collision: '{name}' already exists")
            sys.exit(1)

    click.echo()
    click.echo(f"Setting up your sandbox: {name}")

    try:
        host_worktree_path = new_sbx_setup(
            repo_url=repo_url,
            repo_root=repo_root,
            branch=branch,
            from_branch=from_branch,
            name=name,
            agent=effective_agent,
            sandbox_config_path=sandbox_config_path,
            copies=[],
            allow_pr=False,
            pip_requirements=effective_pip,
            with_opencode=False,
            with_zai=False,
            wd=effective_wd,
            template=effective_template,
            ide=effective_ide,
            packages=effective_packages or None,
            profile_name=profile,
            skip_package_bootstrap=skip_bootstrap,
        )
    except RuntimeError as exc:
        log_error(str(exc))
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        log_error(f"Sandbox creation failed: {exc}")
        sys.exit(1)

    # Persist profile and template cache provenance in metadata
    from foundry_sandbox.state import patch_sandbox_metadata
    meta_patch: dict[str, str] = {"profile": profile}
    if cached_template_tag:
        from foundry_sandbox.template_cache import derive_cache_key
        meta_patch["template_cache_key"] = derive_cache_key(
            profile, profile_config, config, effective_template,
        )
        meta_patch["template_profile"] = profile
    patch_sandbox_metadata(name, **meta_patch)

    # Save state
    save_last_cast_new(
        repo=repo_url,
        agent=effective_agent,
        branch=branch,
        from_branch=from_branch,
        working_dir=effective_wd,
        pip_requirements=effective_pip,
        template=effective_template,
        ide=effective_ide,
        packages=effective_packages or None,
    )
    save_last_attach(name)

    click.echo()
    click.echo(f"Created sandbox: {name}")
    click.echo(f"  Worktree   {host_worktree_path}")
    click.echo(f"  Agent      {effective_agent}")
    click.echo(f"  Profile    {profile}")
    click.echo()

    # Attach
    _up_flow(name, no_ide=no_ide, ide_value=effective_ide, ide_config=ide_config)
