"""New command - create a new sandbox with sbx.

Creates a worktree, launches an sbx sandbox, starts git safety server,
and injects the git wrapper for authenticated git operations.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

import click
from click.core import ParameterSource

from foundry_sandbox.paths import (
    find_next_sandbox_name,
    repo_url_to_bare_path,
    sandbox_name as _helpers_sandbox_name,
)
from foundry_sandbox.commands.new_sbx import new_sbx_setup, rollback_new_sbx, SetupError
from foundry_sandbox.commands.new_resolver import (
    _resolve_repo_input,
    _generate_branch_name,
    _branch_exists_on_remote,
    _detect_remote_default_branch,
)
from foundry_sandbox.commands.new_validation import _validate_preconditions
from foundry_sandbox.api_keys import has_opencode_key, has_zai_key
from foundry_sandbox.paths import derive_sandbox_paths
from foundry_sandbox.state import save_last_cast_new, save_cast_preset, load_last_cast_new, load_cast_preset, save_last_attach
from foundry_sandbox.utils import log_error, log_info, log_warn
from foundry_sandbox.validate import validate_sandbox_name


@dataclass
class NewDefaults:
    """Resolved default values for the ``new`` command parameters."""

    repo: str
    branch: str
    from_branch: str
    copies: tuple[str, ...]
    agent: str
    with_opencode: bool
    with_zai: bool
    wd: str
    pip_requirements: str
    allow_pr: bool


def _apply_saved_new_defaults(
    saved: dict[str, object],
    *,
    explicit_params: set[str],
    repo: str,
    branch: str,
    from_branch: str,
    copies: tuple[str, ...],
    agent: str,
    with_opencode: bool,
    with_zai: bool,
    wd: str,
    pip_requirements: str,
    allow_pr: bool,
) -> NewDefaults:
    """Apply saved/preset values for parameters not explicitly set by the user."""
    data = saved or {}

    def _saved(key: str, default: str) -> str:
        if key in explicit_params:
            return str(locals().get("_" + key, default))
        val = data.get(key, default)
        return str(val) if val is not None else default

    raw_copies = data.get("copies", copies)
    resolved_copies: tuple[str, ...] = copies if "copies" in explicit_params else tuple(str(v) for v in raw_copies) if isinstance(raw_copies, (list, tuple)) else copies

    return NewDefaults(
        repo=repo if "repo" in explicit_params else str(data.get("repo", repo)),
        branch=branch if "branch" in explicit_params else str(data.get("branch", branch)),
        from_branch=from_branch if "from_branch" in explicit_params else str(data.get("from_branch", from_branch)),
        copies=resolved_copies,
        agent=agent if "agent" in explicit_params else str(data.get("agent", agent)),
        with_opencode=with_opencode if "with_opencode" in explicit_params else bool(data.get("enable_opencode", with_opencode)),
        with_zai=with_zai if "with_zai" in explicit_params else bool(data.get("enable_zai", with_zai)),
        wd=wd if "wd" in explicit_params else str(data.get("working_dir", wd)),
        pip_requirements=pip_requirements if "pip_requirements" in explicit_params else str(data.get("pip_requirements", pip_requirements)),
        allow_pr=allow_pr if "allow_pr" in explicit_params else bool(data.get("allow_pr", allow_pr)),
    )


def _load_and_apply_defaults(
    saved_data: dict[str, object] | None,
    label: str,
    **kwargs: object,
) -> NewDefaults:
    """Load saved data and apply defaults."""
    if not saved_data:
        log_error(f"No data found for {label}")
        sys.exit(1)

    ep = kwargs.pop("explicit_params", set())
    explicit_params: set[str] = ep if isinstance(ep, set) else set()
    raw_copies = kwargs.get("copies", ())
    copies_val: tuple[str, ...] = raw_copies if isinstance(raw_copies, tuple) else ()
    click.echo(f"Reusing {label}...")
    click.echo()
    return _apply_saved_new_defaults(
        saved_data,
        explicit_params=explicit_params,
        repo=str(kwargs.get("repo", "")),
        branch=str(kwargs.get("branch", "")),
        from_branch=str(kwargs.get("from_branch", "")),
        copies=copies_val,
        agent=str(kwargs.get("agent", "claude")),
        with_opencode=bool(kwargs.get("with_opencode", False)),
        with_zai=bool(kwargs.get("with_zai", False)),
        wd=str(kwargs.get("wd", "")),
        pip_requirements=str(kwargs.get("pip_requirements", "")),
        allow_pr=bool(kwargs.get("allow_pr", False)),
    )


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("repo", required=False, default="")
@click.argument("branch", required=False, default="")
@click.argument("from_branch", required=False, default="")
@click.option("--last", is_flag=True, help="Repeat last sandbox creation")
@click.option("--preset", metavar="NAME", help="Use saved preset")
@click.option("--agent", default="claude", help="Agent type (claude, codex, copilot, gemini, kiro, opencode, shell)")
@click.option("--copy", "-c", "copies", multiple=True, help="Copy host:container (once at creation)")
@click.option("--allow-pr", "--with-pr", is_flag=True, help="Allow PR operations")
@click.option("--pip-requirements", "-r", metavar="PATH", help="Install Python packages from requirements.txt")
@click.option("--wd", metavar="PATH", help="Working directory (relative)")
@click.option("--with-opencode", is_flag=True, help="Enable OpenCode setup")
@click.option("--with-zai", is_flag=True, help="Enable ZAI Claude alias")
@click.option("--save-as", metavar="NAME", help="Save configuration as named preset")
@click.option("--skip-key-check", is_flag=True, help="Skip API key validation")
@click.option("--name", "name_override", metavar="NAME", help="Override auto-generated sandbox name")
@click.option("--template", "template", default="foundry-git-wrapper:latest", show_default=True,
              help="Template tag for sandbox creation. Use 'none' to disable.")
@click.pass_context
def new(
    ctx: click.Context,
    repo: str,
    branch: str,
    from_branch: str,
    last: bool,
    preset: str,
    agent: str,
    copies: tuple[str, ...],
    allow_pr: bool,
    pip_requirements: str,
    wd: str,
    with_opencode: bool,
    with_zai: bool,
    save_as: str,
    skip_key_check: bool,
    name_override: str,
    template: str,
) -> None:
    """Create a new sandbox with sbx."""

    if last and preset:
        log_error("Options --last and --preset cannot be used together")
        sys.exit(1)

    explicit_param_names = {
        "repo", "branch", "from_branch", "copies", "agent",
        "with_opencode", "with_zai", "wd", "pip_requirements", "allow_pr",
    }
    explicit_params = {
        name for name in explicit_param_names
        if ctx.get_parameter_source(name) == ParameterSource.COMMANDLINE
    }

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
            copies=copies,
            agent=agent,
            with_opencode=with_opencode,
            with_zai=with_zai,
            wd=wd,
            pip_requirements=pip_requirements,
            allow_pr=allow_pr,
        )
        repo = _defaults.repo
        branch = _defaults.branch
        from_branch = _defaults.from_branch
        copies = _defaults.copies
        agent = _defaults.agent
        with_opencode = _defaults.with_opencode
        with_zai = _defaults.with_zai
        wd = _defaults.wd
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
            if _branch_exists_on_remote(repo_root, current_branch):
                from_branch = current_branch
            else:
                from_branch = _detect_remote_default_branch(repo_root)
                log_warn(
                    f"Current branch '{current_branch}' not found on remote; "
                    f"using '{from_branch}' as base."
                )

    # Generate branch name if not provided
    if not branch:
        branch = _generate_branch_name(repo_url, from_branch or "main")
        from_branch = from_branch or "main"

    # Validate working directory
    if wd:
        wd = wd.lstrip("./")

    # Expand repo URL shorthand
    if not repo_url.startswith(("http://", "https://", "git@")) and "://" not in repo_url and not repo_url.startswith("/"):
        repo_url = f"https://github.com/{repo_url}"

    # Validate preconditions: git URL, API keys, copies
    _validate_preconditions(ctx, repo_url, copies, skip_key_check)

    # Validate agent
    valid_agents = {"claude", "codex", "copilot", "gemini", "kiro", "opencode", "shell"}
    if agent not in valid_agents:
        log_error(f"Invalid agent '{agent}'. Must be one of: {', '.join(sorted(valid_agents))}")
        sys.exit(1)

    # Validate --with-opencode / --with-zai
    if with_opencode and not has_opencode_key():
        log_warn("OpenCode requested but auth file not found; skipping OpenCode setup.")
    if with_zai and not has_zai_key():
        log_error("--with-zai requires ZHIPU_API_KEY to be set in your environment.")
        sys.exit(1)

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
    base_name = name
    base_branch = branch
    if last or preset:
        name = find_next_sandbox_name(base_name)
        if name != base_name:
            suffix = name[len(base_name):]
            branch = f"{base_branch}{suffix}"

    # Atomically claim the sandbox name
    paths = derive_sandbox_paths(name)
    worktree_path = paths.worktree_path
    claude_config_path = paths.claude_config_path

    _MAX_NAME_RETRIES = 5
    _seen_names = {name}
    for _attempt in range(_MAX_NAME_RETRIES):
        try:
            os.makedirs(claude_config_path, exist_ok=False)
            break
        except FileExistsError:
            if not (last or preset):
                log_error(f"Sandbox name collision: '{name}' already exists")
                sys.exit(1)
            name = find_next_sandbox_name(base_name)
            if name in _seen_names:
                log_error(f"Name generation loop: '{name}' already tried")
                sys.exit(1)
            _seen_names.add(name)
            if name != base_name:
                suffix = name[len(base_name):]
                branch = f"{base_branch}{suffix}"
            else:
                branch = base_branch
            paths = derive_sandbox_paths(name)
            worktree_path = paths.worktree_path
            claude_config_path = paths.claude_config_path
    else:
        log_error(f"Could not claim a unique sandbox name after {_MAX_NAME_RETRIES} attempts")
        sys.exit(1)

    # Start creation
    click.echo()
    click.echo(f"Setting up your sandbox: {name}")

    try:
        new_sbx_setup(
            repo_url=repo_url,
            bare_path=bare_path,
            worktree_path=worktree_path,
            branch=branch,
            from_branch=from_branch or "",
            name=name,
            agent=agent,
            claude_config_path=claude_config_path,
            copies=list(copies),
            allow_pr=allow_pr,
            pip_requirements=pip_requirements or "",
            with_opencode=with_opencode,
            with_zai=with_zai,
            wd=wd or "",
            template=template,
        )
    except SetupError as exc:
        log_error(str(exc))
        log_info("Cleaning up partial sandbox resources...")
        rollback_new_sbx(worktree_path, claude_config_path, name)
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        log_error(f"Sandbox creation failed: {exc}")
        log_info("Cleaning up partial sandbox resources...")
        rollback_new_sbx(worktree_path, claude_config_path, name)
        sys.exit(1)

    # Save state
    save_last_cast_new(
        repo=repo_url,
        agent=agent,
        branch=branch,
        from_branch=from_branch or "",
        working_dir=wd or "",
        pip_requirements=pip_requirements or "",
        allow_pr=allow_pr,
        enable_opencode=with_opencode,
        enable_zai=with_zai,
        copies=list(copies),
    )
    save_last_attach(name)

    if save_as:
        save_cast_preset(
            preset_name=save_as,
            repo=repo_url,
            agent=agent,
            branch=branch,
            from_branch=from_branch or "",
            working_dir=wd or "",
            pip_requirements=pip_requirements or "",
            allow_pr=allow_pr,
            enable_opencode=with_opencode,
            enable_zai=with_zai,
            copies=list(copies),
        )

    # Success message
    click.echo()
    click.echo("Sandbox is ready!")
    click.echo()
    click.echo(f"  Sandbox    {name}")
    click.echo(f"  Worktree   {worktree_path}")
    click.echo(f"  Agent      {agent}")
    click.echo()
    click.echo("  Commands:")
    click.echo(f"    cast attach {name}   - reconnect later")
    click.echo(f"    cast stop {name}     - pause the sandbox")
    click.echo(f"    cast destroy {name}  - remove completely")
    click.echo("    cast repeat         - repeat this setup")
    click.echo()
