"""sbx CLI wrapper for foundry-sandbox.

Wraps all Docker `sbx` CLI calls via subprocess. Provides the same interface
pattern as docker.py — commands call these functions, which handle subprocess
execution, error handling, and output parsing.

No Click or Pydantic imports at module level.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from foundry_sandbox.constants import get_sandbox_verbose
from foundry_sandbox.utils import log_info, log_section, log_warn


# ============================================================================
# Docker Desktop plugin detection
# ============================================================================

_DOCKER_PLUGIN_DIR_PATTERNS: list[str] = [
    os.path.expanduser("~/.docker/cli-plugins"),
    "/Applications/Docker.app/Contents/Resources/cli-plugins",
    "C:\\Program Files\\Docker\\Docker\\resources\\cli-plugins",
]

_STANDALONE_INSTALL_HINT = (
    "Install standalone sbx:\n"
    "  macOS:  brew install docker/tap/sbx\n"
    "  Windows: winget install Docker.sbx\n"
    "  Linux:  Download from https://github.com/docker/sbx-releases"
)


# ============================================================================
# Timeout Constants
# ============================================================================

TIMEOUT_SBX_QUERY: int = 30
TIMEOUT_SBX_LIFECYCLE: int = 120
TIMEOUT_SBX_EXEC: int = 60
TIMEOUT_SBX_SECRET: int = 15


# ============================================================================
# Version Pinning
# ============================================================================

SBX_MIN_VERSION = "0.26.0"  # minimum supported (tested on 0.26.1)
SBX_MAX_VERSION = "0.29.0"  # exclusive upper bound


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


def get_sbx_version() -> str | None:
    """Query the installed sbx CLI version.

    Returns:
        Version string (e.g. "0.26.1") or None on error.
    """
    if not shutil.which("sbx"):
        return None
    try:
        result = subprocess.run(
            ["sbx", "version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Output like "Client Version:  v0.26.1 abc123\nServer Version: ..."
        raw = result.stdout.strip().split("\n")[0]
        # Strip prefixes like "Client Version:  v" or "sbx " or bare version
        for prefix in ("Client Version:  v", "Client Version: v",
                        "sbx version ", "sbx "):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break
        # Drop anything after the version (commit hash, etc.)
        raw = raw.split()[0] if raw else ""
        return raw or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def check_sbx_version() -> None:
    """Verify installed sbx version is within the supported range.

    Raises:
        SystemExit: If version is outside [SBX_MIN_VERSION, SBX_MAX_VERSION).
    """
    version_str = get_sbx_version()
    if version_str is None:
        # sbx not installed — let sbx_check_available handle that
        return

    from foundry_sandbox.version_check import _parse_version

    try:
        parsed = _parse_version(version_str)
    except (ValueError, TypeError):
        log_warn(f"Could not parse sbx version: {version_str!r}")
        return

    if not parsed:
        log_warn(f"Could not parse sbx version: {version_str!r}")
        return

    min_parsed = _parse_version(SBX_MIN_VERSION)
    max_parsed = _parse_version(SBX_MAX_VERSION)

    if parsed < min_parsed:
        print(
            f"Error: sbx version {version_str} is too old.\n"
            f"  Supported range: >= {SBX_MIN_VERSION} and < {SBX_MAX_VERSION}\n"
            f"  Upgrade: https://github.com/docker/sbx-releases",
            file=sys.stderr,
        )
        raise SystemExit(1)

    if parsed >= max_parsed:
        print(
            f"Error: sbx version {version_str} has not been tested with foundry-sandbox.\n"
            f"  Supported range: >= {SBX_MIN_VERSION} and < {SBX_MAX_VERSION}\n"
            f"  Pin to an older version or update the supported range in foundry_sandbox/sbx.py.",
            file=sys.stderr,
        )
        raise SystemExit(1)


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
    cpus: str | None = None,
    memory: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Create a new sandbox.

    Args:
        name: Sandbox name.
        agent: Agent type (claude, codex, copilot, gemini, kiro, opencode, shell).
        path: Workspace path on host.
        branch: Optional branch name for git worktree.
        template: Optional template tag (e.g. 'foundry-git-wrapper:latest').
        cpus: Optional CPU limit (e.g. '2', '0.5').
        memory: Optional memory limit (e.g. '4g', '512m').

    Returns:
        CompletedProcess result.
    """
    args = ["create", "--name", name]
    if branch:
        args.extend(["--branch", branch])
    if template:
        args.extend(["--template", template])
    if cpus is not None:
        args.extend(["--cpus", cpus])
    if memory is not None:
        args.extend(["--memory", memory])
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
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            return cast(list[dict[str, str]], data.get("sandboxes", []))
        return cast(list[dict[str, str]], data)
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
    args = ["exec"]
    if user:
        args.extend(["-u", user])
    if env:
        for k, v in env.items():
            args.extend(["-e", f"{k}={v}"])
    args.append(name)
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
    args = ["sbx", "exec"]
    if interactive:
        args.append("-it")
    if user:
        args.extend(["-u", user])
    args.append(name)
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
# Pip helpers
# ============================================================================


def install_pip_requirements(name: str, requirements: str) -> None:
    """Install pip requirements inside an sbx sandbox."""
    log_info(f"Installing pip requirements: {requirements}")
    try:
        sbx_exec(name, ["pip", "install", "-r", requirements])
    except Exception as exc:
        log_warn(f"Failed to install pip requirements: {exc}")


def install_pip_packages(name: str, packages: list[str]) -> None:
    """Install named pip packages inside an sbx sandbox."""
    log_info(f"Installing pip packages: {packages}")
    try:
        sbx_exec(name, ["pip", "install", *packages])
    except Exception as exc:
        log_warn(f"Failed to install pip packages: {exc}")


def install_uv_requirements(name: str, requirements: str) -> None:
    """Install uv requirements inside an sbx sandbox."""
    log_info(f"Installing uv requirements: {requirements}")
    try:
        sbx_exec(name, ["uv", "pip", "install", "-r", requirements], user="root")
    except Exception as exc:
        log_warn(f"Failed to install uv requirements: {exc}")


def install_uv_packages(name: str, packages: list[str]) -> None:
    """Install named uv packages inside an sbx sandbox."""
    log_info(f"Installing uv packages: {packages}")
    try:
        sbx_exec(name, ["uv", "pip", "install", *packages], user="root")
    except Exception as exc:
        log_warn(f"Failed to install uv packages: {exc}")


def install_apt_packages(name: str, packages: list[str]) -> None:
    """Install apt packages inside an sbx sandbox."""
    if not packages:
        return
    log_info(f"Installing apt packages: {packages}")
    try:
        sbx_exec(name, ["apt-get", "update", "-qq"], user="root")
        sbx_exec(name, ["apt-get", "install", "-y", "-qq", "--", *packages], user="root")
    except Exception as exc:
        log_warn(f"Failed to install apt packages: {exc}")


def install_npm_packages(name: str, packages: list[str]) -> None:
    """Install npm packages globally inside an sbx sandbox."""
    if not packages:
        return
    log_info(f"Installing npm packages: {packages}")
    try:
        sbx_exec(name, ["npm", "install", "-g", *packages], user="root")
    except Exception as exc:
        log_warn(f"Failed to install npm packages: {exc}")


def bootstrap_packages(name: str, packages: dict[str, object]) -> None:
    """Run all package bootstrap steps in dependency order: apt -> pip -> uv -> npm."""
    if not packages:
        return
    log_section("Dependencies")
    apt_val = packages.get("apt")
    if apt_val and isinstance(apt_val, list):
        install_apt_packages(name, apt_val)
    pip_val = packages.get("pip")
    if pip_val:
        if isinstance(pip_val, list):
            install_pip_packages(name, pip_val)
        else:
            install_pip_requirements(name, str(pip_val))
    uv_val = packages.get("uv")
    if uv_val:
        if isinstance(uv_val, list):
            install_uv_packages(name, uv_val)
        else:
            install_uv_requirements(name, str(uv_val))
    npm_val = packages.get("npm")
    if npm_val and isinstance(npm_val, list):
        install_npm_packages(name, npm_val)


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


def sbx_template_rm(tag: str) -> subprocess.CompletedProcess[str]:
    """Remove a saved template.

    Args:
        tag: Template tag to remove.

    Returns:
        CompletedProcess result.
    """
    return _run_sbx(["template", "rm", tag], timeout=TIMEOUT_SBX_LIFECYCLE)


# ============================================================================
# Diagnostics
# ============================================================================


def sbx_diagnose(
    *, parse: bool = False,
) -> subprocess.CompletedProcess[str] | dict[str, Any]:
    """Run sbx diagnostics.

    Args:
        parse: If True, run ``sbx diagnose --json`` and return a parsed
            dict. If parsing fails, returns ``{"error": ..., "raw": ...}``.
            If False (default), return the raw CompletedProcess.

    Returns:
        Parsed dict when *parse* is True, otherwise CompletedProcess.
    """
    if not parse:
        return _run_sbx(["diagnose"], timeout=TIMEOUT_SBX_QUERY)

    result = _run_sbx(
        ["diagnose", "--json"], timeout=TIMEOUT_SBX_QUERY, check=False,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip() or f"exit code {result.returncode}", "raw": result.stdout}
    try:
        return cast(dict[str, Any], json.loads(result.stdout))
    except (json.JSONDecodeError, TypeError) as exc:
        return {"error": str(exc), "raw": result.stdout}


def sbx_is_installed() -> bool:
    """Check if sbx CLI is installed and accessible.

    Returns:
        True if sbx binary is found on PATH.
    """
    return find_sbx_binary() is not None


def _resolve_sbx_binary() -> str | None:
    """Resolve the real path of the sbx binary."""
    raw = shutil.which("sbx")
    if raw is None:
        return None
    return os.path.realpath(raw)


def _is_docker_plugin_path(binary_path: str) -> bool:
    """Check if the binary path is inside a Docker Desktop plugin directory."""
    normalized = os.path.normpath(binary_path).replace("\\", "/")
    for pattern in _DOCKER_PLUGIN_DIR_PATTERNS:
        prefix = os.path.normpath(pattern).replace("\\", "/") + "/"
        if normalized.startswith(prefix):
            return True
    return False


def _run_standalone_probe() -> bool:
    """Run a low-cost standalone-only probe (sbx template ls --help)."""
    try:
        result = subprocess.run(
            ["sbx", "template", "ls", "--help"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def sbx_check_available() -> None:
    """Verify sbx is installed, at a supported version, and is the standalone CLI.

    Raises:
        SystemExit: If sbx is not installed, version is out of range,
            or the binary is Docker Desktop's plugin shim.
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
    check_sbx_version()

    # Reject Docker Desktop's docker sandbox plugin shim.
    binary_path = _resolve_sbx_binary()
    if binary_path and _is_docker_plugin_path(binary_path):
        print(
            "Error: Detected Docker Desktop's 'docker sandbox' plugin instead "
            f"of standalone sbx (binary at {binary_path}). {_STANDALONE_INSTALL_HINT}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Probe: verify the binary actually behaves like the standalone CLI.
    if not _run_standalone_probe():
        print(
            "Error: sbx binary failed standalone probe (`sbx template ls --help`). "
            f"This may be Docker Desktop's 'docker sandbox' plugin. {_STANDALONE_INSTALL_HINT}",
            file=sys.stderr,
        )
        raise SystemExit(1)


# ============================================================================
# Workspace Info Parsing
# ============================================================================


def sbx_worktree_path(repo_root: str, sandbox_name: str, branch: str) -> str:
    """Compute the expected sbx worktree path.

    sbx creates worktrees at ``<repo_root>/.sbx/<name>-worktrees/<branch>/``.

    Args:
        repo_root: Absolute path to the repository root on host.
        sandbox_name: Sandbox name as known to sbx.
        branch: Branch name.

    Returns:
        Deterministic worktree path string.
    """
    return f"{repo_root}/.sbx/{sandbox_name}-worktrees/{branch}"


def sbx_get_workspace_info(sbx_create_stdout: str) -> dict[str, str]:
    """Extract worktree path and branch from ``sbx create`` stdout.

    sbx prints lines like::

        Worktree: /home/user/repo/.sbx/<name>-worktrees/<branch>
        Branch: <branch>

    Args:
        sbx_create_stdout: Raw stdout from ``sbx create``.

    Returns:
        Dict with ``worktree`` and ``branch`` keys (empty string if not found).

    Raises:
        ValueError: If stdout contains a Worktree line but it cannot be parsed.
    """
    info: dict[str, str] = {"worktree": "", "branch": ""}
    for line in sbx_create_stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Worktree:"):
            info["worktree"] = stripped[len("Worktree:"):].strip()
        elif stripped.startswith("Branch:"):
            info["branch"] = stripped[len("Branch:"):].strip()
    return info
