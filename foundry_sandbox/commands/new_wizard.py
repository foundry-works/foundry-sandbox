"""Guided wizard for sandbox creation.

Provides an interactive TUI-based wizard that walks users through
sandbox configuration step by step.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import click

from foundry_sandbox.constants import TIMEOUT_GIT_QUERY
from foundry_sandbox.tui import tui_choose, tui_confirm, tui_input


def _wizard_repo() -> tuple[str, str, str, str]:
    """Wizard step 1/7: Repository selection.

    Returns:
        Tuple of (repo_url, repo_root, repo_display, current_branch).
    """
    from foundry_sandbox.commands.new import _resolve_repo_input

    click.echo()
    click.echo("  Step 1/7: Repository")
    click.echo()

    # Check if current directory is a git repo
    current_result = subprocess.run(
        ["git", "-C", ".", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_GIT_QUERY,
    )

    if current_result.returncode == 0:
        current_repo_root = current_result.stdout.strip()
        origin_result = subprocess.run(
            ["git", "-C", current_repo_root, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_GIT_QUERY,
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
    from foundry_sandbox.commands.new import _get_local_branches

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
                    timeout=TIMEOUT_GIT_QUERY,
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
