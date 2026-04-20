"""sbx CLI wrapper for foundry-sandbox.

Wraps all Docker `sbx` CLI calls via subprocess. Provides the same interface
pattern as docker.py — commands call these functions, which handle subprocess
execution, error handling, and output parsing.

No Click or Pydantic imports at module level.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from foundry_sandbox.constants import get_sandbox_verbose
from foundry_sandbox.utils import log_warn


# ============================================================================
# Timeout Constants
# ============================================================================

TIMEOUT_SBX_QUERY: int = 30
TIMEOUT_SBX_LIFECYCLE: int = 120
TIMEOUT_SBX_EXEC: int = 60
TIMEOUT_SBX_SECRET: int = 15


# ============================================================================
# Internal Helpers
# ============================================================================


def _run_sbx(
    args: list[str],
    *,
    quiet: bool = False,
    check: bool = True,
    timeout: float | None = None,
    input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an sbx CLI command.

    Args:
        args: Command arguments (without the leading 'sbx').
        quiet: If True, suppress stdout and stderr.
        check: If True, raise CalledProcessError on non-zero exit.
        timeout: Optional timeout in seconds.
        input: Optional stdin input.

    Returns:
        CompletedProcess result.
    """
    cmd = ["sbx"] + args
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    kwargs: dict[str, Any] = {"check": check, "text": True}
    if timeout is not None:
        kwargs["timeout"] = timeout
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    else:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    if input is not None:
        kwargs["input"] = input

    return subprocess.run(cmd, **kwargs)


def find_sbx_binary() -> str | None:
    """Check if sbx CLI is available on PATH.

    Returns:
        Path to sbx binary, or None if not found.
    """
    return shutil.which("sbx")


# ============================================================================
# Sandbox Lifecycle
# ============================================================================


def sbx_create(
    name: str,
    agent: str,
    path: str | Path,
    *,
    branch: str | None = None,
    template: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Create a new sandbox.

    Args:
        name: Sandbox name.
        agent: Agent type (claude, codex, copilot, gemini, kiro, opencode, shell).
        path: Workspace path on host.
        branch: Optional branch name for git worktree.
        template: Optional template tag (e.g. 'foundry-git-wrapper:latest').

    Returns:
        CompletedProcess result.
    """
    args = ["create", "--name", name]
    if branch:
        args.extend(["--branch", branch])
    if template:
        args.extend(["--template", template])
    args.extend([agent, str(path)])
    return _run_sbx(args, timeout=TIMEOUT_SBX_LIFECYCLE)


def sbx_run(name: str) -> subprocess.CompletedProcess[str]:
    """Start a stopped sandbox (non-interactive).

    Args:
        name: Sandbox name.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["run", name], timeout=TIMEOUT_SBX_LIFECYCLE)


def sbx_stop(name: str) -> subprocess.CompletedProcess[str]:
    """Stop a running sandbox.

    Args:
        name: Sandbox name.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["stop", name], timeout=TIMEOUT_SBX_LIFECYCLE)


def sbx_rm(name: str) -> subprocess.CompletedProcess[str]:
    """Remove a sandbox.

    Args:
        name: Sandbox name.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["rm", name], timeout=TIMEOUT_SBX_LIFECYCLE)


def sbx_ls() -> list[dict[str, str]]:
    """List all sandboxes.

    Returns:
        List of sandbox info dicts with keys: name, status, agent, branch.
        Returns empty list on error.
    """
    try:
        result = _run_sbx(["ls", "--json"], timeout=TIMEOUT_SBX_QUERY, check=False)
        if result.returncode != 0:
            log_warn(f"sbx ls failed: {result.stderr.strip()}")
            return []
        return cast(list[dict[str, str]], json.loads(result.stdout))
    except (json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        log_warn(f"sbx ls parse error: {exc}")
        return []


def sbx_is_running(name: str) -> bool:
    """Check if a sandbox is currently running.

    Args:
        name: Sandbox name.

    Returns:
        True if the sandbox exists and is running.
    """
    sandboxes = sbx_ls()
    for sb in sandboxes:
        if sb.get("name") == name:
            return sb.get("status") == "running"
    return False


def sbx_sandbox_exists(name: str) -> bool:
    """Check if a sandbox exists (any status).

    Args:
        name: Sandbox name.

    Returns:
        True if the sandbox exists.
    """
    return any(sb.get("name") == name for sb in sbx_ls())


# ============================================================================
# Exec
# ============================================================================


def sbx_exec(
    name: str,
    cmd: list[str],
    *,
    user: str | None = None,
    env: dict[str, str] | None = None,
    quiet: bool = False,
    input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Execute a command in a sandbox.

    Args:
        name: Sandbox name.
        cmd: Command and arguments to execute.
        user: Optional user (e.g. 'root').
        env: Optional environment variables.
        quiet: If True, suppress output.
        input: Optional stdin input.

    Returns:
        CompletedProcess result.
    """
    args = ["exec", name]
    if user:
        args.extend(["-u", user])
    if env:
        for k, v in env.items():
            args.extend(["-e", f"{k}={v}"])
    args.append("--")
    args.extend(cmd)
    return _run_sbx(args, timeout=TIMEOUT_SBX_EXEC, quiet=quiet, input=input)


def sbx_exec_streaming(
    name: str,
    cmd: list[str],
    *,
    user: str | None = None,
    interactive: bool = False,
) -> subprocess.Popen[str]:
    """Execute a command with streaming I/O (for interactive use).

    Args:
        name: Sandbox name.
        cmd: Command and arguments to execute.
        user: Optional user (e.g. 'root').
        interactive: If True, allocate a pseudo-TTY (-it flag).

    Returns:
        Popen process with inherited stdio.
    """
    args = ["sbx", "exec", name]
    if interactive:
        args.append("-it")
    if user:
        args.extend(["-u", user])
    args.append("--")
    args.extend(cmd)

    if get_sandbox_verbose():
        print(f"+ {' '.join(args)}", file=sys.stderr)

    return subprocess.Popen(
        args,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        text=True,
    )


# ============================================================================
# Secrets
# ============================================================================


def sbx_secret_set(
    service: str,
    value: str,
    *,
    global_scope: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Store a secret on the host.

    Args:
        service: Service name (anthropic, github, openai, etc.).
        value: Secret value (read from stdin by sbx).
        global_scope: If True, make secret available to all sandboxes.

    Returns:
        CompletedProcess result.
    """
    args = ["secret", "set"]
    if global_scope:
        args.append("-g")
    args.append(service)
    return _run_sbx(args, input=value, timeout=TIMEOUT_SBX_SECRET)


# ============================================================================
# Network Policy
# ============================================================================

VALID_NETWORK_PROFILES = frozenset({"balanced", "allow-all", "deny-all"})


def sbx_policy_set_default(profile: str) -> subprocess.CompletedProcess[str]:
    """Set the default network policy profile.

    Args:
        profile: One of 'balanced', 'allow-all', 'deny-all'.

    Returns:
        CompletedProcess result.

    Raises:
        ValueError: If profile is not valid.
    """
    if profile not in VALID_NETWORK_PROFILES:
        raise ValueError(
            f"Invalid network profile {profile!r}; "
            f"must be one of: {', '.join(sorted(VALID_NETWORK_PROFILES))}"
        )
    return _run_sbx(["policy", "set-default", profile], timeout=TIMEOUT_SBX_QUERY)


def sbx_policy_allow(spec: str) -> subprocess.CompletedProcess[str]:
    """Add a network allow rule.

    Args:
        spec: Network specification (domain or CIDR).

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["policy", "allow", "network", spec], timeout=TIMEOUT_SBX_QUERY)


def sbx_policy_deny(spec: str) -> subprocess.CompletedProcess[str]:
    """Add a network deny rule.

    Args:
        spec: Network specification (domain or CIDR).

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["policy", "deny", "network", spec], timeout=TIMEOUT_SBX_QUERY)


# ============================================================================
# Templates
# ============================================================================


def sbx_template_save(name: str, tag: str) -> subprocess.CompletedProcess[str]:
    """Save a sandbox as a reusable template.

    Args:
        name: Sandbox name to save.
        tag: Template tag name.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["template", "save", name, tag], timeout=TIMEOUT_SBX_LIFECYCLE)


def sbx_template_load(tag: str) -> subprocess.CompletedProcess[str]:
    """Load a saved template.

    Args:
        tag: Template tag name.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["template", "load", tag], timeout=TIMEOUT_SBX_LIFECYCLE)


def sbx_template_ls() -> list[str]:
    """List available template tags.

    Returns:
        List of template tag strings. Empty list on error.
    """
    try:
        result = _run_sbx(
            ["template", "ls"], timeout=TIMEOUT_SBX_QUERY, check=False
        )
        if result.returncode != 0:
            return []
        return [
            line.strip()
            for line in result.stdout.strip().splitlines()
            if line.strip()
        ]
    except subprocess.TimeoutExpired:
        return []


# ============================================================================
# Diagnostics
# ============================================================================


def sbx_diagnose() -> subprocess.CompletedProcess[str]:
    """Run sbx diagnostics.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["diagnose"], timeout=TIMEOUT_SBX_QUERY)


def sbx_is_installed() -> bool:
    """Check if sbx CLI is installed and accessible.

    Returns:
        True if sbx binary is found on PATH.
    """
    return find_sbx_binary() is not None


def sbx_check_available() -> None:
    """Verify sbx is installed, exit with error if not.

    Raises:
        SystemExit: If sbx is not installed.
    """
    if not sbx_is_installed():
        print(
            "Error: Docker sbx CLI not found. Install with:\n"
            "  macOS:  brew install docker/tap/sbx\n"
            "  Windows: winget install Docker.sbx\n"
            "  Linux:  Download from https://github.com/docker/sbx-releases",
            file=sys.stderr,
        )
        raise SystemExit(1)
