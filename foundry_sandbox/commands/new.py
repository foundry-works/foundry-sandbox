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

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import click

from foundry_sandbox.compose import assemble_override
from foundry_sandbox.constants import get_repos_dir
from foundry_sandbox.docker import compose_up, hmac_secret_file_count, populate_stubs_volume, repair_hmac_secret_permissions
from foundry_sandbox.git import ensure_bare_repo
from foundry_sandbox.git_worktree import create_worktree
from foundry_sandbox.image import check_image_freshness
from foundry_sandbox.network import add_claude_home_to_override, add_ssh_agent_to_override, add_timezone_to_override
from foundry_sandbox.paths import derive_sandbox_paths, ensure_dir, path_claude_home
from foundry_sandbox.permissions import install_workspace_permissions
from foundry_sandbox.proxy import setup_proxy_registration
from foundry_sandbox.state import load_sandbox_metadata, write_sandbox_metadata, save_last_cast_new, save_cast_preset, load_last_cast_new, load_cast_preset, save_last_attach
from foundry_sandbox.tui import tui_choose, tui_confirm, tui_input
from foundry_sandbox.utils import log_error, log_info, log_section, log_step, log_warn

SANDBOX_SH = Path(__file__).resolve().parent.parent.parent / "sandbox.sh"


# ---------------------------------------------------------------------------
# Shell Fallbacks
# ---------------------------------------------------------------------------


def _shell_call(*args: str) -> subprocess.CompletedProcess[str]:
    """Call sandbox.sh with arguments."""
    return subprocess.run([str(SANDBOX_SH), *args], check=False)


def _shell_call_capture(*args: str) -> str:
    """Call sandbox.sh with arguments and capture stdout."""
    result = subprocess.run(
        [str(SANDBOX_SH), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


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
        )
        if result.returncode != 0:
            return ("", "", "", "")

        repo_root = result.stdout.strip()
        origin_result = subprocess.run(
            ["git", "-C", repo_root, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
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
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.strip().split("\n") if line]


def _sanitize_ref_component(component: str) -> str:
    """Sanitize a string for use in git ref names."""
    result = _shell_call_capture("_bridge_sanitize_ref_component", component)
    return result if result else component.replace("/", "-").replace(" ", "-")


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
            ).stdout.strip()
        except Exception:
            pass

    if not user_segment:
        user_segment = "user"

    user_segment = _sanitize_ref_component(user_segment)
    safe_repo_name = _sanitize_ref_component(repo_name)

    if not safe_repo_name:
        safe_repo_name = "repo"

    branch = f"{user_segment}/{safe_repo_name}-{timestamp}"

    # Validate branch name
    check_result = subprocess.run(
        ["git", "check-ref-format", "--branch", branch],
        capture_output=True,
        check=False,
    )

    if check_result.returncode != 0:
        fallback_branch = f"{safe_repo_name}-{timestamp}"
        check_fallback = subprocess.run(
            ["git", "check-ref-format", "--branch", fallback_branch],
            capture_output=True,
            check=False,
        )
        if check_fallback.returncode == 0:
            branch = fallback_branch
        else:
            branch = f"sandbox-{timestamp}"

    return branch


def _repo_to_path(repo_url: str) -> str:
    """Convert repo URL to bare path using shell fallback."""
    return _shell_call_capture("_bridge_repo_to_path", repo_url)


def _sandbox_name(bare_path: str, branch: str) -> str:
    """Generate sandbox name using shell fallback."""
    return _shell_call_capture("_bridge_sandbox_name", bare_path, branch)


def _find_next_sandbox_name(base_name: str) -> str:
    """Find next available sandbox name using shell fallback."""
    return _shell_call_capture("_bridge_find_next_sandbox_name", base_name)


def _container_name(sandbox_name: str) -> str:
    """Generate container name using shell fallback."""
    return _shell_call_capture("_bridge_container_name", sandbox_name)


# ---------------------------------------------------------------------------
# Wizard Helpers
# ---------------------------------------------------------------------------


def _wizard_repo() -> tuple[str, str, str, str]:
    """Wizard step 1/7: Repository selection.

    Returns:
        Tuple of (repo_url, repo_root, repo_display, current_branch).
    """
    click.echo()
    click.echo("  Step 1/7: Repository")
    click.echo()

    # Check if current directory is a git repo
    current_result = subprocess.run(
        ["git", "-C", ".", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )

    if current_result.returncode == 0:
        current_repo_root = current_result.stdout.strip()
        origin_result = subprocess.run(
            ["git", "-C", current_repo_root, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        current_display = origin_result.stdout.strip() if origin_result.returncode == 0 else current_repo_root

        if tui_confirm(f"Use current repo? ({current_display})", default_yes=True):
            repo_url, repo_root, repo_display, current_branch = _resolve_repo_input(current_repo_root)
            if repo_url:
                return (repo_url, repo_root, repo_display, current_branch)

    while True:
        repo_input = tui_input("What repo are you working with? (owner/repo, full URL, local path, or '.')")
        if not repo_input:
            click.echo("  We need a repo to continue.")
            continue

        repo_url, repo_root, repo_display, current_branch = _resolve_repo_input(repo_input)
        if not repo_url:
            click.echo(f"  Not a git repository: {repo_input}")
            continue

        if tui_confirm(f"Use this repo? ({repo_display})", default_yes=True):
            return (repo_url, repo_root, repo_display, current_branch)


def _wizard_branch(repo_root: str, current_branch: str) -> tuple[str, str, bool]:
    """Wizard step 2/7: Branch strategy.

    Args:
        repo_root: Local repo root (empty if remote only).
        current_branch: Current branch if local repo.

    Returns:
        Tuple of (branch, from_branch, create_branch).
    """
    click.echo()
    click.echo("  Step 2/7: Branch")
    click.echo()

    choice = tui_choose("Branch strategy", ["Create new branch", "Checkout existing branch"])

    if choice == "Create new branch":
        while True:
            branch = tui_input("Name for new branch? (Leave blank to auto-generate)", default="")
            if branch:
                check_result = subprocess.run(
                    ["git", "check-ref-format", "--branch", branch],
                    capture_output=True,
                    check=False,
                )
                if check_result.returncode == 0:
                    break
                click.echo("  Invalid branch name. Try again.")
            else:
                break

        default_base = current_branch if current_branch and current_branch != "HEAD" else "main"

        if repo_root:
            local_branches = _get_local_branches(repo_root)
            if local_branches:
                options = local_branches + ["Type manually..."]
                base_choice = tui_choose("Base it on?", options)
                if base_choice == "Type manually...":
                    from_branch = tui_input("Base it on?", default=default_base)
                else:
                    from_branch = base_choice
            else:
                from_branch = tui_input("Base it on?", default=default_base)
        else:
            from_branch = tui_input("Base it on?", default=default_base)

        return (branch, from_branch, True)
    else:
        if repo_root:
            local_branches = _get_local_branches(repo_root)
            if local_branches:
                options = local_branches + ["Type manually..."]
                branch_choice = tui_choose("Which branch to checkout?", options)
                if branch_choice == "Type manually...":
                    while True:
                        branch = tui_input("Which branch to checkout?", default="main")
                        if branch:
                            break
                        click.echo("  Branch name is required.")
                else:
                    branch = branch_choice
            else:
                while True:
                    branch = tui_input("Which branch to checkout?", default="main")
                    if branch:
                        break
                    click.echo("  Branch name is required.")
        else:
            while True:
                branch = tui_input("Which branch to checkout?", default="main")
                if branch:
                    break
                click.echo("  Branch name is required.")

        return (branch, "", False)


def _wizard_working_dir(repo_root: str) -> str:
    """Wizard step 3/7: Working directory.

    Args:
        repo_root: Local repo root (empty if remote only).

    Returns:
        Working directory path (relative, empty for repo root).
    """
    click.echo()
    click.echo("  Step 3/7: Working directory")
    click.echo()

    if repo_root:
        cwd = os.getcwd()
        try:
            rel = os.path.relpath(cwd, repo_root)
            if rel.startswith(".."):
                rel = ""
        except ValueError:
            rel = ""

        if rel and rel != ".":
            if tui_confirm(f"Use current directory as working directory? ({rel})", default_yes=True):
                return rel
        elif cwd == repo_root or rel == ".":
            if tui_confirm("Use current directory as working directory? (repo root)", default_yes=True):
                return ""

    while True:
        working_dir = tui_input("Working directory? (For monorepos - leave blank for repo root)", default="")
        if not working_dir:
            return ""

        if working_dir.startswith("/"):
            click.echo("  Working directory must be relative.")
            continue

        if ".." in working_dir:
            click.echo("  Working directory cannot include '..'.")
            continue

        if repo_root and not (Path(repo_root) / working_dir).is_dir():
            click.echo(f"  Path does not exist in repo: {working_dir}")
            continue

        return working_dir


def _wizard_sparse(working_dir: str) -> bool:
    """Wizard step 4/7: Sparse checkout.

    Args:
        working_dir: Working directory (empty if repo root).

    Returns:
        True to enable sparse checkout.
    """
    click.echo()
    click.echo("  Step 4/7: Sparse checkout")
    click.echo()

    if not working_dir:
        return False

    return tui_confirm(
        "Enable sparse checkout? (Faster/leaner but repo-wide tools may miss files)",
        default_yes=False,
    )


def _wizard_deps() -> str:
    """Wizard step 5/7: Dependencies.

    Returns:
        Pip requirements path or 'auto' or empty.
    """
    click.echo()
    click.echo("  Step 5/7: Dependencies")
    click.echo()

    choice = tui_choose("Python dependencies", ["None", "Auto-detect", "Provide path"])

    if choice == "None":
        return ""
    elif choice == "Auto-detect":
        return "auto"
    else:
        while True:
            pip_path = tui_input("Where's your requirements file?", default="requirements.txt")
            if not pip_path:
                return ""

            expanded = os.path.expanduser(pip_path)
            if os.path.exists(expanded):
                return expanded

            click.echo(f"  File not found: {pip_path}")


def _wizard_pr() -> bool:
    """Wizard step 6/7: PR access.

    Returns:
        True to allow PR operations.
    """
    click.echo()
    click.echo("  Step 6/7: PR access")
    click.echo()

    return tui_confirm(
        "Allow PR operations? (Create PRs, add comments, request reviews - increases risk)",
        default_yes=False,
    )


def _wizard_summary(
    repo_display: str,
    branch: str,
    from_branch: str,
    create_branch: bool,
    working_dir: str,
    sparse: bool,
    pip_req: str,
    allow_pr: bool,
) -> None:
    """Wizard step 7/7: Summary display.

    Args:
        repo_display: Repository display name.
        branch: Target branch.
        from_branch: Base branch (if creating).
        create_branch: True if creating new branch.
        working_dir: Working directory.
        sparse: True if sparse checkout.
        pip_req: Pip requirements path.
        allow_pr: True if allowing PR operations.
    """
    click.echo()
    click.echo("  Step 7/7: Review")
    click.echo()
    click.echo("  Here's what we'll create:")
    click.echo()

    action_display = "Create new branch" if create_branch else "Checkout existing"
    branch_display = branch if branch else "(auto-generated)"
    dir_display = working_dir if working_dir else "(repo root)"
    sparse_display = "yes" if sparse else "no"
    pip_display = pip_req if pip_req else "no"
    pr_display = "yes" if allow_pr else "no"

    click.echo(f"  Repository:   {repo_display}")
    click.echo(f"  Action:       {action_display}")
    click.echo(f"  Branch:       {branch_display}")
    if create_branch:
        click.echo(f"  Based on:     {from_branch or 'main'}")
    click.echo(f"  Directory:    {dir_display}")
    click.echo(f"  Sparse clone: {sparse_display}")
    click.echo(f"  Python deps:  {pip_display}")
    click.echo(f"  PR access:    {pr_display}")
    click.echo()


def _guided_new() -> tuple[str, ...]:
    """Run the guided wizard for sandbox creation.

    Returns:
        Tuple of wizard results to pass to cmd_new logic, or raises SystemExit.
    """
    click.echo()
    click.echo("  Let's set up your sandbox")
    click.echo()

    repo_url, repo_root, repo_display, current_branch = _wizard_repo()
    branch, from_branch, create_branch = _wizard_branch(repo_root, current_branch)
    working_dir = _wizard_working_dir(repo_root)
    sparse = _wizard_sparse(working_dir)
    pip_req = _wizard_deps()
    allow_pr = _wizard_pr()

    while True:
        _wizard_summary(repo_display, branch, from_branch, create_branch, working_dir, sparse, pip_req, allow_pr)
        next_choice = tui_choose("Next step", ["Create sandbox", "Edit answers", "Cancel"])

        if next_choice == "Create sandbox":
            break
        elif next_choice == "Cancel":
            click.echo()
            click.echo("  Cancelled. Run 'cast new' again when you're ready.")
            sys.exit(1)
        else:
            edit = tui_choose("What do you want to edit?", [
                "Repository", "Branch", "Working directory", "Dependencies", "PR access"
            ])
            if edit == "Repository":
                repo_url, repo_root, repo_display, current_branch = _wizard_repo()
                branch, from_branch, create_branch = _wizard_branch(repo_root, current_branch)
                working_dir = _wizard_working_dir(repo_root)
                sparse = _wizard_sparse(working_dir)
            elif edit == "Branch":
                branch, from_branch, create_branch = _wizard_branch(repo_root, current_branch)
            elif edit == "Working directory":
                working_dir = _wizard_working_dir(repo_root)
                sparse = _wizard_sparse(working_dir)
            elif edit == "Dependencies":
                pip_req = _wizard_deps()
            elif edit == "PR access":
                allow_pr = _wizard_pr()

    # Return the resolved repo input (not URL) for proper handling
    repo_input = repo_root if repo_root else repo_url
    return (repo_input, branch, from_branch, working_dir, sparse, pip_req, allow_pr)


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
def new(
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
) -> None:
    """Create a new sandbox with worktree and container."""

    # Handle --from flag
    if from_flag and not from_branch:
        from_branch = from_flag

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

    # Handle --last flag
    if last:
        last_data = load_last_cast_new()
        if not last_data:
            log_error("No previous 'cast new' command found")
            sys.exit(1)
        click.echo()
        click.echo("Repeating last command")
        click.echo()
        # Note: The actual parameter override happens in shell layer for now
        # This is a hybrid approach where we validate but shell handles the reload

    # Handle --preset flag
    if preset:
        preset_data = load_cast_preset(preset)
        if not preset_data:
            log_error(f"Preset '{preset}' not found")
            sys.exit(1)
        click.echo()
        click.echo(f"Using preset '{preset}'")
        click.echo()
        # Note: The actual parameter override happens in shell layer for now

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

    # Validate git URL (shell fallback)
    validate_result = _shell_call("_bridge_validate_git_url", repo_url)
    if validate_result.returncode != 0:
        sys.exit(1)

    # Check API keys unless skipped
    if not skip_key_check:
        check_result = _shell_call("_bridge_check_claude_key_required")
        if check_result.returncode != 0:
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
            _shell_call("build")

    # Check network capacity
    isolate_credentials = not no_isolate_credentials
    check_capacity = _shell_call("_bridge_check_docker_network_capacity", "true" if isolate_credentials else "false")
    if check_capacity.returncode != 0:
        sys.exit(1)

    # Setup network and SSH flags
    network_mode = network or os.environ.get("SANDBOX_NETWORK_MODE", "limited")
    sync_ssh = "1" if with_ssh else "0"
    ssh_mode = "always" if with_ssh else "disabled"

    # Resolve SSH agent socket
    ssh_agent_sock = ""
    if sync_ssh == "1":
        ssh_agent_sock = _shell_call_capture("_bridge_resolve_ssh_agent_sock")
        if not ssh_agent_sock:
            log_warn("SSH agent not detected; SSH forwarding disabled (agent-only mode).")
            sync_ssh = "0"

    # Generate sandbox name
    bare_path = _repo_to_path(repo_url)
    name = _sandbox_name(bare_path, branch)

    # Auto-generate unique name for --last / --preset
    if last or preset:
        original_name = name
        name = _find_next_sandbox_name(name)
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
            validate_mount = _shell_call("_bridge_validate_mount_path", src)
            if validate_mount.returncode != 0:
                click.echo("Use --allow-dangerous-mount to bypass this check (not recommended)")
                sys.exit(1)

    # Setup opt-in tool enablement
    enable_opencode_flag = "0"
    enable_zai_flag = "0"

    if with_opencode:
        if _shell_call_capture("_bridge_has_opencode_key"):
            enable_opencode_flag = "1"
        else:
            log_warn("OpenCode requested but auth file not found; skipping OpenCode setup.")

    if with_zai:
        if os.environ.get("ZHIPU_API_KEY"):
            enable_zai_flag = "1"
        else:
            log_warn("ZAI requested but ZHIPU_API_KEY not set; skipping ZAI setup.")

    os.environ["SANDBOX_ENABLE_OPENCODE"] = enable_opencode_flag
    os.environ["SANDBOX_ENABLE_ZAI"] = enable_zai_flag

    if enable_zai_flag != "1":
        os.environ["ZHIPU_API_KEY"] = ""

    # Start creation
    click.echo()
    click.echo(f"Setting up your sandbox: {name}")
    log_section("Repository")

    # Clone/fetch bare repo
    ensure_bare_repo(repo_url, bare_path)

    # Create worktree
    create_worktree(
        bare_path,
        str(worktree_path),
        branch,
        from_branch or None,
        sparse,
        wd or None,
    )

    # Add specs/.backups to gitignore
    gitignore_file = worktree_path / ".gitignore"
    gitignore_content = gitignore_file.read_text() if gitignore_file.exists() else ""
    if "specs/.backups" not in gitignore_content:
        with gitignore_file.open("a") as f:
            f.write("specs/.backups\n")

    # Setup override file
    ensure_dir(claude_config_path)

    log_section("Configuration")

    # Add mounts
    if mounts:
        log_step("Custom mounts added")
        if allow_dangerous_mount:
            click.echo("WARNING: --allow-dangerous-mount bypasses credential directory protection. Use with caution.")

        with override_file.open("w") as f:
            f.write("services:\n")
            f.write("  dev:\n")
            f.write("    volumes:\n")
            for mount in mounts:
                f.write(f"      - {mount}\n")

    # Add network mode
    if network_mode:
        log_step(f"Network mode: {network_mode}")
        _shell_call("_bridge_add_network_to_override", network_mode, str(override_file))

    # Add Claude home
    claude_home_path = path_claude_home(name)
    ensure_dir(claude_home_path)
    add_claude_home_to_override(str(override_file), str(claude_home_path))
    add_timezone_to_override(str(override_file))

    # Pre-populate foundry global
    _shell_call("_bridge_prepopulate_foundry_global", str(claude_home_path), "0")

    # Show CLI status
    _shell_call("_bridge_show_cli_status")

    # Add SSH agent
    runtime_enable_ssh = "0"
    if sync_ssh == "1" and ssh_agent_sock:
        log_step("SSH agent forwarding: enabled")
        add_ssh_agent_to_override(str(override_file), ssh_agent_sock)
        runtime_enable_ssh = "1"
    else:
        add_ssh_agent_to_override(str(override_file), "")

    # Write metadata
    write_sandbox_metadata(
        name=name,
        repo_url=repo_url,
        branch=branch,
        from_branch=from_branch or "",
        working_dir=wd or "",
        sparse_checkout="1" if sparse else "0",
        pip_requirements=pip_requirements or "",
        allow_pr="1" if allow_pr else "0",
        network_mode=network_mode or "",
        sync_ssh=sync_ssh,
        ssh_mode=ssh_mode,
        enable_opencode=enable_opencode_flag,
        enable_zai=enable_zai_flag,
        mounts=list(mounts),
        copies=list(copies),
    )

    container_id = f"{container}-dev-1"

    # Export GH token
    _shell_call("_bridge_export_gh_token")

    log_section("Container")
    log_step("Starting container...")

    if isolate_credentials:
        log_step("Credential isolation: enabled")

        # Check for auth files
        codex_auth = Path.home() / ".codex/auth.json"
        if not codex_auth.is_file():
            log_warn("Credential isolation: ~/.codex/auth.json not found; Codex CLI will not work.")

        opencode_auth = Path.home() / ".local/share/opencode/auth.json"
        if enable_opencode_flag != "1" and not opencode_auth.is_file():
            log_warn("Credential isolation: ~/.local/share/opencode/auth.json not found; OpenCode CLI will not work.")

        gemini_oauth = Path.home() / ".gemini/oauth_creds.json"
        gemini_key = os.environ.get("GEMINI_API_KEY", "")
        if not gemini_oauth.is_file() and not gemini_key:
            log_warn("Credential isolation: ~/.gemini/oauth_creds.json not found and GEMINI_API_KEY not set; Gemini CLI will not work.")

        # Validate git remotes
        validate_remotes = _shell_call("_bridge_validate_git_remotes", str(worktree_path / ".git"))
        if validate_remotes.returncode != 0:
            log_error("Cannot enable credential isolation with embedded git credentials")
            sys.exit(1)

        # Set ALLOW_PR_OPERATIONS
        if allow_pr:
            os.environ["ALLOW_PR_OPERATIONS"] = "true"
            log_step("PR operations: allowed")
        else:
            os.environ["ALLOW_PR_OPERATIONS"] = ""
            log_step("PR operations: blocked (default)")

        # Generate sandbox ID
        seed = f"{container}:{name}:{int(datetime.now().timestamp() * 1e9)}"
        sandbox_id = _shell_call_capture("_bridge_generate_sandbox_id", seed)
        if not sandbox_id:
            log_error("Failed to generate sandbox identity (missing SHA-256 toolchain)")
            sys.exit(1)

        os.environ["SANDBOX_ID"] = sandbox_id
        log_step(f"Sandbox ID: {sandbox_id}")
        os.environ["REPOS_DIR"] = str(get_repos_dir())
    else:
        sandbox_id = ""

    # Start containers
    compose_up(
        worktree_path=str(worktree_path),
        claude_config_path=str(claude_config_path),
        container=container,
        override_file=str(override_file),
        isolate_credentials=isolate_credentials,
        repos_dir=str(get_repos_dir()) if isolate_credentials else "",
        sandbox_id=sandbox_id,
    )

    # Register with proxy
    if isolate_credentials:
        os.environ["SANDBOX_GATEWAY_ENABLED"] = "true"

        # Fix proxy worktree paths
        proxy_container = f"{container}-unified-proxy-1"
        username = os.environ.get("USER", "ubuntu")
        _shell_call("_bridge_fix_proxy_worktree_paths", proxy_container, username)

        # Extract repo spec
        repo_spec = repo_url
        repo_spec = repo_spec.removeprefix("https://github.com/")
        repo_spec = repo_spec.removeprefix("http://github.com/")
        repo_spec = repo_spec.removeprefix("git@github.com:")
        if repo_spec.endswith(".git"):
            repo_spec = repo_spec[:-4]

        metadata_json = {
            "repo": repo_spec,
            "allow_pr": allow_pr,
            "sandbox_branch": branch,
            "from_branch": from_branch or "",
        }

        try:
            setup_proxy_registration(container_id, metadata_json)
        except Exception as e:
            log_error(f"Failed to register container with unified-proxy: {e}")
            _shell_call("_bridge_compose_down", str(worktree_path), str(claude_config_path), container, str(override_file), "true", "true")
            click.echo()
            click.echo("Container registration failed. See error messages above for remediation.")
            click.echo("To create sandbox without credential isolation, use --no-isolate-credentials flag.")
            sys.exit(1)

    # Copy configs to container
    _shell_call(
        "_bridge_copy_configs_to_container",
        container_id,
        "0",
        runtime_enable_ssh,
        wd or "",
        "true" if isolate_credentials else "",
        from_branch or "",
        branch,
        repo_url,
    )

    # Copy files
    if copies:
        click.echo("Copying files into container...")
        for copy_spec in copies:
            parts = copy_spec.split(":", 1)
            if len(parts) != 2:
                continue
            src, dst = parts
            if not os.path.exists(src):
                click.echo(f"  Warning: Source '{src}' does not exist, skipping")
                continue

            click.echo(f"  {src} -> {dst}")
            if os.path.isdir(src):
                _shell_call("_bridge_copy_dir_to_container", container_id, src, dst)
            else:
                _shell_call("_bridge_copy_file_to_container", container_id, src, dst)

    # Install workspace permissions
    install_workspace_permissions(container_id)

    # Install pip requirements
    if pip_requirements:
        _shell_call("_bridge_install_pip_requirements", container_id, pip_requirements)

    # Apply network restrictions
    if network_mode:
        if network_mode == "limited":
            subprocess.run(
                ["docker", "exec", container_id, "sudo", "/usr/local/bin/network-firewall.sh"],
                check=False,
            )
        else:
            subprocess.run(
                ["docker", "exec", container_id, "sudo", "/usr/local/bin/network-mode", network_mode],
                check=False,
            )

    # Save last command
    save_last_cast_new(
        repo_url=repo_url,
        branch=branch,
        from_branch=from_branch or "",
        working_dir=wd or "",
        sparse_checkout=sparse,
        pip_requirements=pip_requirements or "",
        allow_pr=allow_pr,
        network_mode=network_mode or "",
        sync_ssh=sync_ssh,
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
            repo_url=repo_url,
            branch=branch,
            from_branch=from_branch or "",
            working_dir=wd or "",
            sparse_checkout=sparse,
            pip_requirements=pip_requirements or "",
            allow_pr=allow_pr,
            network_mode=network_mode or "",
            sync_ssh=sync_ssh,
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

    if not skip_terminal:
        _shell_call("_bridge_tmux_attach", name, wd or "")
