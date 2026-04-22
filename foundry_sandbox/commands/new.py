"""New command - create a new sandbox with sbx.

Creates an sbx sandbox with sbx-managed worktree, starts git safety server,
and injects the git wrapper for authenticated git operations.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime

import click
from click.core import ParameterSource

from foundry_sandbox.paths import (
    find_next_sandbox_name,
    repo_name_from_url,
    repo_url_to_checkout_path,
    sandbox_name as _helpers_sandbox_name,
)
from foundry_sandbox.commands.new_setup import new_sbx_setup, rollback_new_sbx, _validate_preconditions
from foundry_sandbox.api_keys import has_opencode_key, has_zai_key
from foundry_sandbox.constants import TIMEOUT_GIT_QUERY, TIMEOUT_LOCAL_CMD
from foundry_sandbox.paths import path_claude_config
from foundry_sandbox.state import save_last_cast_new, save_cast_preset, load_last_cast_new, load_cast_preset, save_last_attach
from foundry_sandbox.utils import log_debug, log_error, log_info, log_warn, sanitize_ref_component
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
    template: str
    template_managed: bool


# (NewDefaults field, saved-data key, type coerce)
_STR_FIELDS: list[tuple[str, str]] = [
    ("repo", "repo"),
    ("branch", "branch"),
    ("from_branch", "from_branch"),
    ("agent", "agent"),
    ("wd", "working_dir"),
    ("pip_requirements", "pip_requirements"),
    ("template", "template"),
]
_BOOL_FIELDS: list[tuple[str, str]] = [
    ("with_opencode", "enable_opencode"),
    ("with_zai", "enable_zai"),
    ("allow_pr", "allow_pr"),
]


def _apply_saved_new_defaults(
    saved: dict[str, object],
    explicit_params: set[str],
    **defaults: object,
) -> NewDefaults:
    """Apply saved/preset values for parameters not explicitly set by the user."""
    data = saved or {}
    resolved: dict[str, object] = {}

    # copies: needs list/tuple → tuple coercion
    caller_copies: tuple[str, ...] = defaults.get("copies", ())  # type: ignore[assignment]
    if "copies" in explicit_params:
        resolved["copies"] = caller_copies
    else:
        raw = data.get("copies", caller_copies)
        resolved["copies"] = tuple(str(v) for v in raw) if isinstance(raw, (list, tuple)) else caller_copies

    for field, saved_key in _STR_FIELDS:
        caller_val = str(defaults.get(field, ""))
        if field in explicit_params:
            resolved[field] = caller_val
        else:
            val = data.get(saved_key, caller_val)
            resolved[field] = str(val) if val is not None else caller_val

    for field, saved_key in _BOOL_FIELDS:
        bval = bool(defaults.get(field, False))
        if field in explicit_params:
            resolved[field] = bval
        else:
            braw = data.get(saved_key, bval)
            resolved[field] = bool(braw) if braw is not None else bval

    # template_managed is coupled to the "template" explicit key
    caller_tm = bool(defaults.get("template_managed", False))
    if "template" in explicit_params:
        resolved["template_managed"] = caller_tm
    else:
        val = data.get("template_managed", caller_tm)
        resolved["template_managed"] = bool(val) if val is not None else caller_tm

    return NewDefaults(**resolved)  # type: ignore[arg-type]


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
    click.echo(f"Reusing {label}...")
    click.echo()
    return _apply_saved_new_defaults(saved_data, explicit_params, **kwargs)


def _ensure_repo_root(repo_url: str) -> str:
    """Ensure a local repo checkout exists for a remote URL.

    For remote URLs, clones a regular (non-bare) checkout to
    ``~/.sandboxes/repos/<owner>/<repo>/`` if missing. Uses a per-repo
    file lock to serialize concurrent ``git worktree add`` operations.

    Args:
        repo_url: Remote repository URL.

    Returns:
        Absolute path to the local checkout.
    """
    from pathlib import Path

    from foundry_sandbox.atomic_io import file_lock
    from foundry_sandbox.git import ensure_repo_checkout

    checkout_path = repo_url_to_checkout_path(repo_url)
    checkout_dir = Path(os.path.dirname(checkout_path) or checkout_path)

    with file_lock(checkout_dir):
        ensure_repo_checkout(
            repo_url,
            checkout_path,
            branch="main",
        )

    return checkout_path


# ---------------------------------------------------------------------------
# Repo resolution helpers
# ---------------------------------------------------------------------------


def _resolve_repo_input(repo_input: str) -> tuple[str, str, str, str]:
    """Resolve repo input to URL, root path, display name, and current branch."""
    if repo_input in (".", "/", "./", "../", "~/") or repo_input.startswith(("/", "./", "../", "~/")):
        expanded = os.path.expanduser(repo_input)
        result = subprocess.run(
            ["git", "-C", expanded, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        if result.returncode != 0:
            return ("", "", "", "")

        repo_root = result.stdout.strip()
        origin_result = subprocess.run(
            ["git", "-C", repo_root, "remote", "get-url", "origin"],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )

        if origin_result.returncode == 0 and origin_result.stdout.strip():
            repo_url = origin_result.stdout.strip()
        else:
            repo_url = repo_root

        branch_result = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else ""

        return (repo_url, repo_root, repo_url, current_branch)

    if repo_input.startswith(("http://", "https://", "git@")) or "://" in repo_input:
        repo_url = repo_input
    else:
        repo_url = f"https://github.com/{repo_input}"

    return (repo_url, "", repo_url, "")


def _branch_exists_on_remote(repo_root: str, branch: str) -> bool:
    """Check if a branch exists on the remote (origin)."""
    result = subprocess.run(
        ["git", "-C", repo_root, "rev-parse", "--verify", f"refs/remotes/origin/{branch}"],
        capture_output=True, check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    return result.returncode == 0


def _detect_remote_default_branch(repo_root: str) -> str:
    """Detect the remote's default branch from a local repo."""
    result = subprocess.run(
        ["git", "-C", repo_root, "symbolic-ref", "refs/remotes/origin/HEAD"],
        capture_output=True, text=True, check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )
    if result.returncode == 0:
        ref = result.stdout.strip()
        prefix = "refs/remotes/origin/"
        if ref.startswith(prefix):
            return ref[len(prefix):]

    for candidate in ("main", "master"):
        if _branch_exists_on_remote(repo_root, candidate):
            return candidate

    log_warn(
        "Could not detect remote default branch (neither 'main' nor 'master' found); "
        "falling back to 'main'."
    )
    return "main"


def _generate_branch_name(repo_url: str, from_branch: str) -> str:
    """Generate a branch name for a new sandbox."""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M")
    repo_name = os.path.basename(repo_url.removesuffix(".git"))

    user_segment = os.environ.get("USER", "")
    if not user_segment:
        try:
            user_segment = subprocess.run(
                ["id", "-un"],
                capture_output=True, text=True, check=False,
                timeout=TIMEOUT_LOCAL_CMD,
            ).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            log_debug("Failed to get username from id command")

    if not user_segment:
        user_segment = "user"

    user_segment = sanitize_ref_component(user_segment)
    safe_repo_name = sanitize_ref_component(repo_name)

    if not safe_repo_name:
        safe_repo_name = "repo"

    branch = f"{user_segment}/{safe_repo_name}-{timestamp}"

    check_result = subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        capture_output=True, check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if check_result.returncode != 0:
        fallback_branch = f"{safe_repo_name}-{timestamp}"
        check_fallback = subprocess.run(
            ["git", "check-ref-format", "--branch", fallback_branch],
            capture_output=True, check=False,
            timeout=TIMEOUT_GIT_QUERY,
        )
        if check_fallback.returncode == 0:
            branch = fallback_branch
        else:
            branch = f"sandbox-{timestamp}"

    return branch


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
@click.option("--copy", "-c", "copies", multiple=True, help="Copy host path into sandbox (once at creation)")
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
        "template",
    }
    explicit_params = {
        name for name in explicit_param_names
        if ctx.get_parameter_source(name) == ParameterSource.COMMANDLINE
    }

    # Handle --last / --preset flags
    effective_template_managed = False
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
            template=template,
            template_managed=False,
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
        template = _defaults.template
        effective_template_managed = _defaults.template_managed

    # Resolve repo input
    if not repo:
        click.echo("Error: Repository required")
        sys.exit(1)

    repo_url, repo_root, repo_display, current_branch = _resolve_repo_input(repo)

    if not repo_url:
        log_error(f"Not a git repository: {repo}")
        sys.exit(1)

    # For remote URLs, ensure a local checkout exists
    if not repo_root:
        repo_root = _ensure_repo_root(repo_url)

    # Handle local repo defaults
    if repo_root and current_branch:
        if current_branch == "HEAD":
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
    _validate_preconditions(repo_url, copies, skip_key_check)

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

    # Generate sandbox name from repo name and branch
    repo_name = repo_name_from_url(repo_url)
    if name_override:
        name = name_override
    else:
        name = _helpers_sandbox_name(repo_name, branch)

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
    claude_config_path = path_claude_config(name)

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
            claude_config_path = path_claude_config(name)
    else:
        log_error(f"Could not claim a unique sandbox name after {_MAX_NAME_RETRIES} attempts")
        sys.exit(1)

    # Start creation
    click.echo()
    click.echo(f"Setting up your sandbox: {name}")

    try:
        host_worktree_path = new_sbx_setup(
            repo_url=repo_url,
            repo_root=repo_root,
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
    except RuntimeError as exc:
        log_error(str(exc))
        log_info("Cleaning up partial sandbox resources...")
        rollback_new_sbx(claude_config_path, name)
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        log_error(f"Sandbox creation failed: {exc}")
        log_info("Cleaning up partial sandbox resources...")
        rollback_new_sbx(claude_config_path, name)
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
        template=template,
        template_managed=effective_template_managed,
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
            template=template,
            template_managed=effective_template_managed,
        )

    # Success message
    click.echo()
    click.echo("Sandbox is ready!")
    click.echo()
    click.echo(f"  Sandbox    {name}")
    click.echo(f"  Worktree   {host_worktree_path}")
    click.echo(f"  Agent      {agent}")
    click.echo()
    click.echo("  Commands:")
    click.echo(f"    cast attach {name}   - reconnect later")
    click.echo(f"    cast stop {name}     - pause the sandbox")
    click.echo(f"    cast destroy {name}  - remove completely")
    click.echo("    cast new --last     - repeat this setup")
    click.echo()
