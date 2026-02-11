"""New command - create a new sandbox with worktree and container.

Migrated from commands/new.sh (1,343 lines) + lib/args.sh (281 lines).
Performs the following sequence:
  1. Parse arguments or run guided wizard
  2. Handle --last / --preset flags
  3. Resolve repository input (URL, local path, or shorthand)
  4. Generate branch name if not provided
  5. Validate inputs (git URL, network mode, working dir, sparse, mounts)
  6. Check API keys unless --skip-key-check
  7. Check image freshness
  8. Check Docker network capacity
  9. Clone/fetch bare repository
  10. Create worktree with optional sparse checkout
  11. Setup override file with mounts, network, Claude home, SSH, timezone
  12. Pre-populate foundry global skills
  13. Start containers via compose_up
  14. Register with proxy (if credential isolation)
  15. Copy configs to container
  16. Handle --copy paths
  17. Install pip requirements
  18. Apply network restrictions
  19. Save metadata and last command
  20. Prompt for IDE launch
  21. Attach to tmux session
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import click
from click.core import ParameterSource

from foundry_sandbox.commands._helpers import (
    find_next_sandbox_name,
    flag_enabled as _saved_flag_enabled,
    repo_url_to_bare_path,
    resolve_ssh_agent_sock,
    sandbox_name as _helpers_sandbox_name,
)
from foundry_sandbox.commands.new_setup import _SetupError, _new_setup, _rollback_new
from foundry_sandbox.commands.new_wizard import _guided_new
from foundry_sandbox.utils import sanitize_ref_component
from foundry_sandbox.api_keys import check_claude_key_required, has_opencode_key
from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_LOCAL_CMD
from foundry_sandbox.image import check_image_freshness
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import save_last_cast_new, save_cast_preset, load_last_cast_new, load_cast_preset, save_last_attach
from foundry_sandbox import tmux
from foundry_sandbox.utils import log_debug, log_error, log_info, log_section, log_warn
from foundry_sandbox.validate import check_docker_network_capacity, validate_git_url, validate_mount_path, validate_sandbox_name


@dataclass
class NewDefaults:
    """Resolved default values for the ``new`` command parameters."""

    repo: str
    branch: str
    from_branch: str
    mounts: tuple[str, ...]
    copies: tuple[str, ...]
    network: str
    with_ssh: bool
    with_opencode: bool
    with_zai: bool
    wd: str
    sparse: bool
    pip_requirements: str
    allow_pr: bool


def _apply_saved_new_defaults(
    saved: dict[str, object],
    *,
    explicit_params: set[str],
    repo: str,
    branch: str,
    from_branch: str,
    mounts: tuple[str, ...],
    copies: tuple[str, ...],
    network: str,
    with_ssh: bool,
    with_opencode: bool,
    with_zai: bool,
    wd: str,
    sparse: bool,
    pip_requirements: str,
    allow_pr: bool,
) -> NewDefaults:
    """Apply saved/preset values for parameters not explicitly set by the user."""
    if "repo" not in explicit_params:
        repo = str(saved.get("repo", "") or "")
    if "branch" not in explicit_params:
        branch = str(saved.get("branch", "") or "")
    if "from_branch" not in explicit_params:
        from_branch = str(saved.get("from_branch", "") or "")
    if "network" not in explicit_params:
        network = str(saved.get("network_mode", "") or "")
    if "wd" not in explicit_params:
        wd = str(saved.get("working_dir", "") or "")
    if "sparse" not in explicit_params:
        sparse = _saved_flag_enabled(saved.get("sparse", False))
    if "pip_requirements" not in explicit_params:
        pip_requirements = str(saved.get("pip_requirements", "") or "")
    if "allow_pr" not in explicit_params:
        allow_pr = _saved_flag_enabled(saved.get("allow_pr", False))
    if "with_ssh" not in explicit_params:
        with_ssh = _saved_flag_enabled(saved.get("sync_ssh", False))
    if "with_opencode" not in explicit_params:
        with_opencode = _saved_flag_enabled(saved.get("enable_opencode", False))
    if "with_zai" not in explicit_params:
        with_zai = _saved_flag_enabled(saved.get("enable_zai", False))

    if "mounts" not in explicit_params:
        saved_mounts = saved.get("mounts", [])
        if isinstance(saved_mounts, list) and all(isinstance(v, str) for v in saved_mounts):
            mounts = tuple(saved_mounts)
    if "copies" not in explicit_params:
        saved_copies = saved.get("copies", [])
        if isinstance(saved_copies, list) and all(isinstance(v, str) for v in saved_copies):
            copies = tuple(saved_copies)

    return NewDefaults(
        repo=repo,
        branch=branch,
        from_branch=from_branch,
        mounts=mounts,
        copies=copies,
        network=network,
        with_ssh=with_ssh,
        with_opencode=with_opencode,
        with_zai=with_zai,
        wd=wd,
        sparse=sparse,
        pip_requirements=pip_requirements,
        allow_pr=allow_pr,
    )


# ---------------------------------------------------------------------------
# Repository Resolution Helpers
# ---------------------------------------------------------------------------


def _resolve_repo_input(repo_input: str) -> tuple[str, str, str, str]:
    """Resolve repo input to URL, root path, display name, and current branch.

    Args:
        repo_input: User input (URL, '.', local path, or owner/repo).

    Returns:
        Tuple of (repo_url, repo_root, repo_display, current_branch).
        repo_root is empty for remote URLs.
    """
    # Local path inputs
    if repo_input in (".", "/", "./", "../", "~/") or repo_input.startswith(("/", "./", "../", "~/")):
        expanded = os.path.expanduser(repo_input)
        result = subprocess.run(
            ["git", "-C", expanded, "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        if result.returncode != 0:
            return ("", "", "", "")

        repo_root = result.stdout.strip()
        origin_result = subprocess.run(
            ["git", "-C", repo_root, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )

        if origin_result.returncode == 0 and origin_result.stdout.strip():
            repo_url = origin_result.stdout.strip()
            repo_display = repo_url
        else:
            repo_url = repo_root
            repo_display = repo_root

        branch_result = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""

        return (repo_url, repo_root, repo_display, current_branch)

    # URL or shorthand
    if repo_input.startswith(("http://", "https://", "git@")) or "://" in repo_input:
        repo_url = repo_input
    else:
        repo_url = f"https://github.com/{repo_input}"

    return (repo_url, "", repo_url, "")


def _get_local_branches(repo_root: str) -> list[str]:
    """Get list of local branches in a repo."""
    result = subprocess.run(
        ["git", "-C", repo_root, "for-each-ref", "--format=%(refname:short)", "refs/heads"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.strip().split("\n") if line]


def _generate_branch_name(repo_url: str, from_branch: str) -> str:
    """Generate a branch name for a new sandbox."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    repo_name = os.path.basename(repo_url.removesuffix(".git"))

    user_segment = os.environ.get("USER", "")
    if not user_segment:
        try:
            user_segment = subprocess.run(
                ["id", "-un"],
                capture_output=True,
                text=True,
                check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            ).stdout.strip()
        except Exception:
            log_debug("Failed to get username from id command")

    if not user_segment:
        user_segment = "user"

    user_segment = sanitize_ref_component(user_segment)
    safe_repo_name = sanitize_ref_component(repo_name)

    if not safe_repo_name:
        safe_repo_name = "repo"

    branch = f"{user_segment}/{safe_repo_name}-{timestamp}"

    # Validate branch name
    check_result = subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        capture_output=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if check_result.returncode != 0:
        fallback_branch = f"{safe_repo_name}-{timestamp}"
        check_fallback = subprocess.run(
            ["git", "check-ref-format", "--branch", fallback_branch],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        if check_fallback.returncode == 0:
            branch = fallback_branch
        else:
            branch = f"sandbox-{timestamp}"

    return branch


def _load_and_apply_defaults(
    data: dict[str, object] | None,
    label: str,
    *,
    explicit_params: set[str],
    repo: str,
    branch: str,
    from_branch: str,
    mounts: tuple[str, ...],
    copies: tuple[str, ...],
    network: str,
    with_ssh: bool,
    with_opencode: bool,
    with_zai: bool,
    wd: str,
    sparse: bool,
    pip_requirements: str,
    allow_pr: bool,
) -> NewDefaults:
    """Load saved/preset data, validate it, echo a banner, and apply defaults.

    Args:
        data: Loaded JSON data (from last command or preset), or ``None``.
        label: Human-readable label for error/banner (e.g. ``"last command"``).

    Returns:
        A :class:`NewDefaults` with merged values.

    Raises:
        SystemExit: If *data* is ``None``.
    """
    if not data:
        log_error(f"No previous '{label}' found")
        sys.exit(1)
    click.echo()
    click.echo(f"Repeating {label}")
    click.echo()
    return _apply_saved_new_defaults(
        data,
        explicit_params=explicit_params,
        repo=repo,
        branch=branch,
        from_branch=from_branch,
        mounts=mounts,
        copies=copies,
        network=network,
        with_ssh=with_ssh,
        with_opencode=with_opencode,
        with_zai=with_zai,
        wd=wd,
        sparse=sparse,
        pip_requirements=pip_requirements,
        allow_pr=allow_pr,
    )


# ---------------------------------------------------------------------------
# Command Implementation
# ---------------------------------------------------------------------------


@click.command()
@click.argument("repo", required=False, default="")
@click.argument("branch", required=False, default="")
@click.argument("from_branch", required=False, default="")
@click.option("--last", is_flag=True, help="Repeat last sandbox creation")
@click.option("--preset", metavar="NAME", help="Use saved preset")
@click.option("--mount", "-v", "mounts", multiple=True, help="Mount host:container[:ro]")
@click.option("--copy", "-c", "copies", multiple=True, help="Copy host:container (once at creation)")
@click.option("--network", "-n", metavar="MODE", help="Network mode (limited, host-only, none)")
@click.option("--with-ssh", is_flag=True, help="Enable SSH agent forwarding")
@click.option("--with-opencode", is_flag=True, help="Enable OpenCode setup")
@click.option("--with-zai", is_flag=True, help="Enable ZAI Claude alias")
@click.option("--no-isolate-credentials", is_flag=True, help="Disable credential isolation")
@click.option("--wd", metavar="PATH", help="Working directory (relative)")
@click.option("--sparse", is_flag=True, help="Enable sparse checkout (requires --wd)")
@click.option("--pip-requirements", "-r", metavar="PATH", help="Install Python packages from requirements.txt")
@click.option("--allow-pr", "--with-pr", is_flag=True, help="Allow PR operations")
@click.option("--save-as", metavar="NAME", help="Save configuration as named preset")
@click.option("--with-ide", metavar="NAME", help="Launch IDE after creation")
@click.option("--ide-only", metavar="NAME", help="Launch IDE only (no terminal)")
@click.option("--no-ide", is_flag=True, help="Skip IDE prompt")
@click.option("--skip-key-check", is_flag=True, help="Skip API key validation")
@click.option("--allow-dangerous-mount", is_flag=True, help="Bypass credential directory protection")
@click.option("--from", "from_flag", metavar="BRANCH", help="Base branch (alias for from_branch arg)")
@click.option("--name", "name_override", metavar="NAME", help="Override auto-generated sandbox name")
@click.pass_context
def new(
    ctx: click.Context,
    repo: str,
    branch: str,
    from_branch: str,
    last: bool,
    preset: str,
    mounts: tuple[str, ...],
    copies: tuple[str, ...],
    network: str,
    with_ssh: bool,
    with_opencode: bool,
    with_zai: bool,
    no_isolate_credentials: bool,
    wd: str,
    sparse: bool,
    pip_requirements: str,
    allow_pr: bool,
    save_as: str,
    with_ide: str,
    ide_only: str,
    no_ide: bool,
    skip_key_check: bool,
    allow_dangerous_mount: bool,
    from_flag: str,
    name_override: str,
) -> None:
    """Create a new sandbox with worktree and container."""

    if last and preset:
        log_error("Options --last and --preset cannot be used together")
        sys.exit(1)

    # Handle --from flag
    if from_flag and not from_branch:
        from_branch = from_flag

    explicit_param_names = {
        "repo",
        "branch",
        "from_branch",
        "mounts",
        "copies",
        "network",
        "with_ssh",
        "with_opencode",
        "with_zai",
        "wd",
        "sparse",
        "pip_requirements",
        "allow_pr",
    }
    explicit_params = {
        name for name in explicit_param_names
        if ctx.get_parameter_source(name) == ParameterSource.COMMANDLINE
    }
    if ctx.get_parameter_source("from_flag") == ParameterSource.COMMANDLINE:
        explicit_params.add("from_branch")

    # No args mode - run guided wizard
    if not repo and not last and not preset:
        wizard_repo, wizard_branch, wizard_from, wizard_wd, wizard_sparse, wizard_pip, wizard_pr = _guided_new()
        repo = wizard_repo
        branch = wizard_branch
        from_branch = wizard_from
        wd = wizard_wd
        sparse = wizard_sparse
        pip_requirements = wizard_pip
        allow_pr = wizard_pr

    # Handle --last / --preset flags
    if last or preset:
        if last:
            saved_data = load_last_cast_new()
            label = "cast new' command"
        else:
            saved_data = load_cast_preset(preset)
            label = f"preset '{preset}'"
        _defaults = _load_and_apply_defaults(
            saved_data,
            label,
            explicit_params=explicit_params,
            repo=repo,
            branch=branch,
            from_branch=from_branch,
            mounts=mounts,
            copies=copies,
            network=network,
            with_ssh=with_ssh,
            with_opencode=with_opencode,
            with_zai=with_zai,
            wd=wd,
            sparse=sparse,
            pip_requirements=pip_requirements,
            allow_pr=allow_pr,
        )
        repo = _defaults.repo
        branch = _defaults.branch
        from_branch = _defaults.from_branch
        mounts = _defaults.mounts
        copies = _defaults.copies
        network = _defaults.network
        with_ssh = _defaults.with_ssh
        with_opencode = _defaults.with_opencode
        with_zai = _defaults.with_zai
        wd = _defaults.wd
        sparse = _defaults.sparse
        pip_requirements = _defaults.pip_requirements
        allow_pr = _defaults.allow_pr

    # Resolve repo input
    if not repo:
        click.echo("Error: Repository required")
        sys.exit(1)

    repo_url, repo_root, repo_display, current_branch = _resolve_repo_input(repo)

    if not repo_url:
        log_error(f"Not a git repository: {repo}")
        sys.exit(1)

    # Handle local repo defaults
    if repo_root:
        if not current_branch or current_branch == "HEAD":
            log_error("Repository is in a detached HEAD state; specify a base branch.")
            sys.exit(1)

        if not branch and not from_branch:
            from_branch = current_branch

    # Generate branch name if not provided
    if not branch:
        branch = _generate_branch_name(repo_url, from_branch or "main")
        from_branch = from_branch or "main"

    # Validate working directory
    if wd:
        if wd.startswith("/"):
            log_error("Working directory must be relative, not absolute")
            sys.exit(1)
        if ".." in wd:
            log_error("Working directory cannot contain parent traversal")
            sys.exit(1)
        wd = wd.lstrip("./")

    # Validate sparse requires wd
    if sparse and not wd:
        log_error("--sparse requires --wd to specify which directory to include")
        sys.exit(1)

    # Expand repo URL shorthand
    if not repo_url.startswith(("http://", "https://", "git@")) and "://" not in repo_url and not repo_url.startswith("/"):
        repo_url = f"https://github.com/{repo_url}"

    # Validate git URL
    ok, msg = validate_git_url(repo_url)
    if not ok:
        log_error(msg)
        sys.exit(1)

    # Check API keys unless skipped
    if not skip_key_check:
        ok, msg = check_claude_key_required()
        if not ok:
            log_error("Sandbox creation cancelled - Claude authentication required.")
            sys.exit(1)

    # Validate --copy source paths
    for copy_spec in copies:
        src = copy_spec.split(":")[0]
        if not os.path.exists(src):
            log_error(f"Copy source does not exist: {src}")
            sys.exit(1)

    # Check image freshness
    if check_image_freshness():
        if click.confirm("Rebuild image now?", default=True):
            from foundry_sandbox.commands.build import build as build_cmd
            ctx.invoke(build_cmd)

    # Check network capacity
    isolate_credentials = not no_isolate_credentials
    ok, msg = check_docker_network_capacity(isolate_credentials)
    if not ok:
        log_error(msg)
        sys.exit(1)

    # Setup network and SSH flags
    network_mode = network or os.environ.get("SANDBOX_NETWORK_MODE", "limited")
    sync_ssh = "1" if with_ssh else "0"
    ssh_mode = "always" if with_ssh else "disabled"

    # Resolve SSH agent socket
    ssh_agent_sock = ""
    if sync_ssh == "1":
        ssh_agent_sock = resolve_ssh_agent_sock()
        if not ssh_agent_sock:
            log_warn("SSH agent not detected; SSH forwarding disabled (agent-only mode).")
            sync_ssh = "0"
    sync_ssh_enabled = sync_ssh == "1"

    # Generate sandbox name
    bare_path = repo_url_to_bare_path(repo_url)
    if name_override:
        name = name_override
    else:
        name = _helpers_sandbox_name(bare_path, branch)

    valid_name, name_error = validate_sandbox_name(name)
    if not valid_name:
        log_error(f"Invalid sandbox name '{name}': {name_error}")
        sys.exit(1)

    # Auto-generate unique name for --last / --preset
    if last or preset:
        original_name = name
        name = find_next_sandbox_name(name)
        if name != original_name:
            suffix = name[len(original_name):]
            branch = f"{branch}{suffix}"

    # Check for existing sandbox
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    container = paths.container_name
    override_file = paths.override_file
    claude_config_path = paths.claude_config_path

    if worktree_path.exists():
        log_error(f"Sandbox name collision: '{name}' already exists")
        sys.exit(1)

    # Validate mount paths
    if not allow_dangerous_mount:
        for mount in mounts:
            src = mount.split(":")[0]
            ok, msg = validate_mount_path(src)
            if not ok:
                log_error(msg)
                click.echo("Use --allow-dangerous-mount to bypass this check (not recommended)")
                sys.exit(1)

    # Setup opt-in tool enablement
    enable_opencode_flag = "0"
    enable_zai_flag = "0"

    if with_opencode:
        if has_opencode_key():
            enable_opencode_flag = "1"
        else:
            log_warn("OpenCode requested but auth file not found; skipping OpenCode setup.")

    if with_zai:
        if os.environ.get("ZHIPU_API_KEY"):
            enable_zai_flag = "1"
        else:
            log_warn("ZAI requested but ZHIPU_API_KEY not set; skipping ZAI setup.")

    # Save and restore environment around mutations (matches start.py pattern)
    _saved_env = dict(os.environ)
    try:
        os.environ["SANDBOX_ENABLE_OPENCODE"] = enable_opencode_flag
        os.environ["SANDBOX_ENABLE_ZAI"] = enable_zai_flag

        if enable_zai_flag != "1":
            os.environ["ZHIPU_API_KEY"] = ""

        # Start creation
        click.echo()
        click.echo(f"Setting up your sandbox: {name}")
        log_section("Repository")

        # -- Begin resource creation (wrapped for rollback on failure) --
        try:
            _new_setup(
                repo_url=repo_url,
                bare_path=bare_path,
                worktree_path=worktree_path,
                branch=branch,
                from_branch=from_branch or "",
                sparse=sparse,
                wd=wd or "",
                claude_config_path=claude_config_path,
                override_file=override_file,
                name=name,
                container=container,
                mounts=list(mounts),
                copies=list(copies),
                allow_dangerous_mount=allow_dangerous_mount,
                network_mode=network_mode or "",
                sync_ssh_enabled=sync_ssh_enabled,
                ssh_agent_sock=ssh_agent_sock,
                ssh_mode=ssh_mode,
                isolate_credentials=isolate_credentials,
                allow_pr=allow_pr,
                pip_requirements=pip_requirements or "",
                enable_opencode_flag=enable_opencode_flag,
                enable_zai_flag=enable_zai_flag,
            )
        except _SetupError as exc:
            log_error(str(exc))
            log_info("Cleaning up partial sandbox resources...")
            _rollback_new(worktree_path, claude_config_path, container, override_file)
            sys.exit(1)
        except SystemExit:
            raise
        except Exception as exc:
            log_error(f"Sandbox creation failed: {exc}")
            log_info("Cleaning up partial sandbox resources...")
            _rollback_new(worktree_path, claude_config_path, container, override_file)
            sys.exit(1)

        # Save last command
        save_last_cast_new(
            repo=repo_url,
            branch=branch,
            from_branch=from_branch or "",
            working_dir=wd or "",
            sparse=sparse,
            pip_requirements=pip_requirements or "",
            allow_pr=allow_pr,
            network_mode=network_mode or "",
            sync_ssh=sync_ssh_enabled,
            enable_opencode=with_opencode,
            enable_zai=with_zai,
            mounts=list(mounts),
            copies=list(copies),
        )

        # Save last attached
        save_last_attach(name)

        # Save preset
        if save_as:
            save_cast_preset(
                preset_name=save_as,
                repo=repo_url,
                branch=branch,
                from_branch=from_branch or "",
                working_dir=wd or "",
                sparse=sparse,
                pip_requirements=pip_requirements or "",
                allow_pr=allow_pr,
                network_mode=network_mode or "",
                sync_ssh=sync_ssh_enabled,
                enable_opencode=with_opencode,
                enable_zai=with_zai,
                mounts=list(mounts),
                copies=list(copies),
            )

        # Success message
        click.echo()
        click.echo(f"✓ Your sandbox is ready!")
        click.echo()
        click.echo(f"  Sandbox    {name}")
        click.echo(f"  Worktree   {worktree_path}")
        click.echo()
        click.echo("  Commands:")
        click.echo(f"    cast attach {name}   - reconnect later")
        click.echo("    cast reattach       - reconnect (auto-detects sandbox in worktree)")
        click.echo(f"    cast stop {name}     - pause the sandbox")
        click.echo(f"    cast destroy {name}  - remove completely")
        click.echo("    cast repeat         - repeat this setup")
        click.echo()

        # IDE launch logic
        skip_terminal = False

        if sys.stdin.isatty():
            from foundry_sandbox.ide import auto_launch_ide, prompt_ide_selection

            if no_ide:
                input("Press Enter to launch... ")
            elif with_ide:
                if auto_launch_ide(with_ide, str(worktree_path)):
                    if ide_only:
                        skip_terminal = True
                        click.echo()
                        click.echo(f"IDE launched. Run 'cast attach {name}' for terminal.")
                    else:
                        input("Press Enter to launch terminal... ")
                else:
                    input("Press Enter to launch... ")
            elif ide_only:
                prompt_ide_selection(str(worktree_path), name)
                skip_terminal = True
                click.echo()
                click.echo("  Run this in your IDE's terminal to connect:")
                click.echo()
                click.echo(f"    cast attach {name}")
                click.echo()
            else:
                ide_was_launched = prompt_ide_selection(str(worktree_path), name)
                if ide_was_launched:
                    click.echo()
                    click.echo("  Run this in your IDE's terminal to connect:")
                    click.echo()
                    click.echo(f"    cast attach {name}")
                    click.echo()
                    skip_terminal = True
                else:
                    input("Press Enter to launch terminal... ")

        if not skip_terminal and sys.stdin.isatty():
            tmux.attach(name, f"{container}-dev-1", str(worktree_path), wd or "")
    finally:
        os.environ.clear()
        os.environ.update(_saved_env)
