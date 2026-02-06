"""Git operations API with deny-by-default command allowlist and flag validation.

Provides validated, sandboxed git command execution. All commands are checked
against a strict allowlist before execution. Dangerous flags, config keys,
and path traversals are blocked.

Security model:
- Deny-by-default command allowlist (no command runs unless explicitly allowed)
- Per-operation flag blocklist (--git-dir, --work-tree, etc.)
- Exhaustive -c config key validation (never-allow checked before permitted prefixes)
- Path traversal prevention (realpath + startswith)
- Environment sanitization (all GIT_*/SSH_* vars cleared)
- Input/output size limits with truncation
- Per-sandbox concurrency control
"""

import asyncio
import base64
import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_STDIN_SIZE = 1 * 1024 * 1024       # 1MB decoded stdin
MAX_RESPONSE_SIZE = 10 * 1024 * 1024   # 10MB response truncation
MAX_REQUEST_BODY_SIZE = 256 * 1024     # 256KB request body
MAX_ARGS_COUNT = 256                    # Max number of args
MAX_ARG_LENGTH = 8 * 1024              # 8KB per arg
MAX_CONCURRENT_PER_SANDBOX = 4         # Max in-flight ops per sandbox
GIT_BINARY = "/usr/bin/git"
SUBPROCESS_TIMEOUT = 120               # 2 minutes

# ---------------------------------------------------------------------------
# Command Allowlist (deny-by-default)
# ---------------------------------------------------------------------------

# Working tree commands
_WORKING_TREE_CMDS = frozenset({
    "status", "add", "restore", "stash", "clean",
})

# Committing commands
_COMMIT_CMDS = frozenset({
    "commit", "cherry-pick", "merge", "rebase", "revert",
})

# Branching commands
_BRANCH_CMDS = frozenset({
    "branch", "checkout", "switch", "tag",
})

# History commands
_HISTORY_CMDS = frozenset({
    "diff", "show", "log", "blame", "shortlog",
    "describe", "name-rev",
})

# Remote commands
_REMOTE_CMDS = frozenset({
    "fetch", "pull", "push", "remote",
})

# Patch commands
_PATCH_CMDS = frozenset({
    "apply", "am", "format-patch",
})

# Notes (read-only enforced separately)
_NOTES_CMDS = frozenset({
    "notes",
})

# Config (restricted subcommands enforced separately)
_CONFIG_CMDS = frozenset({
    "config",
})

# Plumbing commands
_PLUMBING_CMDS = frozenset({
    "rev-parse", "symbolic-ref", "for-each-ref", "ls-tree",
    "ls-files", "ls-remote", "cat-file", "rev-list",
    "diff-tree", "diff-files", "diff-index",
})

ALLOWED_COMMANDS: FrozenSet[str] = (
    _WORKING_TREE_CMDS
    | _COMMIT_CMDS
    | _BRANCH_CMDS
    | _HISTORY_CMDS
    | _REMOTE_CMDS
    | _PATCH_CMDS
    | _NOTES_CMDS
    | _CONFIG_CMDS
    | _PLUMBING_CMDS
)

# ---------------------------------------------------------------------------
# Flag Blocklist (per-operation)
# ---------------------------------------------------------------------------

GLOBAL_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--git-dir",
    "--work-tree",
    "--exec",
    "--upload-pack",
    "--receive-pack",
})

# Per-command destructive flag blocking
_PUSH_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f", "--force-with-lease", "--force-if-includes",
})

_REBASE_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--interactive", "-i",
})

# Destructive variants for checkout/switch/branch/clean
_CHECKOUT_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f",
})

_SWITCH_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f", "--discard-changes",
})

_BRANCH_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f", "-D",
})

_CLEAN_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "-f", "--force", "-fd", "-fx", "-fxd", "-fX",
    "-d", "-x", "-X",
})

# Only --dry-run is allowed for clean
_CLEAN_ALLOWED_FLAGS: FrozenSet[str] = frozenset({
    "--dry-run", "-n",
})

COMMAND_BLOCKED_FLAGS: Dict[str, FrozenSet[str]] = {
    "push": _PUSH_BLOCKED_FLAGS,
    "rebase": _REBASE_BLOCKED_FLAGS,
    "checkout": _CHECKOUT_BLOCKED_FLAGS,
    "switch": _SWITCH_BLOCKED_FLAGS,
    "branch": _BRANCH_BLOCKED_FLAGS,
    "clean": _CLEAN_BLOCKED_FLAGS,
}

# ---------------------------------------------------------------------------
# Remote Subcommand Validation
# ---------------------------------------------------------------------------

REMOTE_ALLOWED_SUBCOMMANDS: FrozenSet[str] = frozenset({
    "-v", "show", "get-url",
})

REMOTE_BLOCKED_SUBCOMMANDS: FrozenSet[str] = frozenset({
    "add", "set-url", "remove", "rename",
})

# ---------------------------------------------------------------------------
# Config Key Validation (-c key=value)
# ---------------------------------------------------------------------------

# Never-allow list: checked FIRST, always rejected
CONFIG_NEVER_ALLOW: Tuple[str, ...] = (
    "alias.",
    "core.sshCommand",
    "core.pager",
    "core.editor",
    "core.hooksPath",
    "core.fsmonitor",
    "core.gitProxy",
    "core.askPass",
    "credential.",
    "http.",
    "remote.*.proxy",      # matched via special logic
    "remote.*.pushurl",    # matched via special logic
    "protocol.*.allow",    # matched via special logic
    "diff.*.textconv",     # matched via special logic
    "diff.*.command",      # matched via special logic
    "filter.",
    "merge.*.driver",      # matched via special logic
    "gpg.",
    "sendemail.",
    "browser.",
    "instaweb.",
    "difftool.*.cmd",      # matched via special logic
    "mergetool.*.cmd",     # matched via special logic
    "sequence.editor",
)

# Permitted prefixes: only checked if not in never-allow
CONFIG_PERMITTED_PREFIXES: Tuple[str, ...] = (
    "user.",
    "color.",
    "core.quotepath",
    "core.autocrlf",
    "core.eol",
    "core.whitespace",
    "diff.",
    "merge.",
    "format.",
    "log.",
    "pretty.",
    "column.",
    "pager.",
)

# ---------------------------------------------------------------------------
# Config Subcommand Validation
# ---------------------------------------------------------------------------

CONFIG_ALLOWED_FLAGS: FrozenSet[str] = frozenset({
    "--get", "--list", "--get-regexp",
    "--get-all", "--get-urlmatch",
    "-l",
})

# ---------------------------------------------------------------------------
# Environment Sanitization
# ---------------------------------------------------------------------------

# Vars to explicitly clear (set to empty string in subprocess env)
ENV_VARS_TO_CLEAR: Tuple[str, ...] = (
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EDITOR",
    "GIT_PAGER",
)

# Prefixes to strip from environment
ENV_PREFIX_STRIP: Tuple[str, ...] = (
    "GIT_",
    "SSH_",
)

# Minimal allowed env vars for git execution
ENV_ALLOWED: FrozenSet[str] = frozenset({
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TZ",
})

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class GitExecRequest:
    """Request to execute a git command."""

    args: List[str]
    cwd: Optional[str] = None
    stdin_b64: Optional[str] = None


@dataclass
class GitExecResponse:
    """Response from git command execution."""

    exit_code: int
    stdout: str
    stderr: str
    stdout_b64: Optional[str] = None
    truncated: bool = False

    def to_dict(self) -> dict:
        result = {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
        }
        if self.stdout_b64 is not None:
            result["stdout_b64"] = self.stdout_b64
        return result


@dataclass
class ValidationError:
    """Validation failure with reason."""

    reason: str
    field: Optional[str] = None

    def to_dict(self) -> dict:
        result = {"error": self.reason}
        if self.field:
            result["field"] = self.field
        return result


# ---------------------------------------------------------------------------
# Concurrency Control
# ---------------------------------------------------------------------------


class SandboxSemaphorePool:
    """Per-sandbox concurrency limiter using asyncio semaphores."""

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_PER_SANDBOX):
        self._semaphores: Dict[str, asyncio.Semaphore] = {}
        self._max = max_concurrent

    def get(self, sandbox_id: str) -> asyncio.Semaphore:
        if sandbox_id not in self._semaphores:
            self._semaphores[sandbox_id] = asyncio.Semaphore(self._max)
        return self._semaphores[sandbox_id]

    def cleanup(self, sandbox_id: str) -> None:
        self._semaphores.pop(sandbox_id, None)


# Module-level semaphore pool
_semaphore_pool = SandboxSemaphorePool()


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------


def validate_request(raw: dict) -> Tuple[Optional[GitExecRequest], Optional[ValidationError]]:
    """Parse and validate a raw request dict.

    Returns (request, None) on success, (None, error) on failure.
    """
    if not isinstance(raw, dict):
        return None, ValidationError("Request must be a JSON object")

    args = raw.get("args")
    if not isinstance(args, list) or len(args) == 0:
        return None, ValidationError("args must be a non-empty array", "args")

    if len(args) > MAX_ARGS_COUNT:
        return None, ValidationError(
            f"Too many arguments: {len(args)} > {MAX_ARGS_COUNT}", "args"
        )

    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            return None, ValidationError(
                f"args[{i}] must be a string", "args"
            )
        if len(arg) > MAX_ARG_LENGTH:
            return None, ValidationError(
                f"args[{i}] exceeds max length: {len(arg)} > {MAX_ARG_LENGTH}",
                "args",
            )

    cwd = raw.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        return None, ValidationError("cwd must be a string or null", "cwd")

    stdin_b64 = raw.get("stdin_b64")
    if stdin_b64 is not None:
        if not isinstance(stdin_b64, str):
            return None, ValidationError(
                "stdin_b64 must be a string or null", "stdin_b64"
            )
        try:
            decoded = base64.b64decode(stdin_b64)
        except Exception:
            return None, ValidationError(
                "stdin_b64 is not valid base64", "stdin_b64"
            )
        if len(decoded) > MAX_STDIN_SIZE:
            return None, ValidationError(
                f"Decoded stdin exceeds limit: {len(decoded)} > {MAX_STDIN_SIZE}",
                "stdin_b64",
            )

    return GitExecRequest(args=args, cwd=cwd, stdin_b64=stdin_b64), None


def validate_command(
    args: List[str],
    extra_allowed: Optional[Set[str]] = None,
) -> Optional[ValidationError]:
    """Validate git command args against allowlist and flag restrictions.

    Args:
        args: The git command arguments (without 'git' prefix).
        extra_allowed: Additional commands allowed per-sandbox from metadata.

    Returns:
        None if valid, ValidationError if blocked.
    """
    if not args:
        return ValidationError("Empty command")

    # Parse out any global flags and -c options before the subcommand
    idx = 0
    config_pairs: List[str] = []

    while idx < len(args):
        arg = args[idx]

        # Check global blocked flags
        flag_name = arg.split("=", 1)[0]
        if flag_name in GLOBAL_BLOCKED_FLAGS:
            return ValidationError(f"Blocked flag: {flag_name}")

        # Collect -c key=value pairs for later validation
        if arg == "-c" and idx + 1 < len(args):
            config_pairs.append(args[idx + 1])
            idx += 2
            continue
        elif arg.startswith("-c") and len(arg) > 2:
            # -ckey=value form
            config_pairs.append(arg[2:])
            idx += 1
            continue

        # Stop at first non-flag argument (the subcommand)
        if not arg.startswith("-"):
            break

        idx += 1

    if idx >= len(args):
        return ValidationError("No subcommand found")

    subcommand = args[idx]
    subcommand_args = args[idx + 1:]

    # Check subcommand against allowlist
    allowed = ALLOWED_COMMANDS
    if extra_allowed:
        allowed = allowed | frozenset(extra_allowed)

    if subcommand not in allowed:
        return ValidationError(f"Command not allowed: {subcommand}")

    # Validate -c config keys
    for pair in config_pairs:
        err = _validate_config_key(pair)
        if err:
            return err

    # Per-command flag validation
    err = _validate_command_flags(subcommand, subcommand_args)
    if err:
        return err

    # Remote subcommand validation
    if subcommand == "remote":
        err = _validate_remote_subcommand(subcommand_args)
        if err:
            return err

    # Config subcommand validation
    if subcommand == "config":
        err = _validate_config_subcommand(subcommand_args)
        if err:
            return err

    # Notes: only allow read-only operations
    if subcommand == "notes":
        err = _validate_notes_subcommand(subcommand_args)
        if err:
            return err

    # Clean: only allow --dry-run
    if subcommand == "clean":
        err = _validate_clean_flags(subcommand_args)
        if err:
            return err

    return None


def _validate_config_key(pair: str) -> Optional[ValidationError]:
    """Validate a -c key=value config override.

    Never-allow list is checked BEFORE permitted prefixes.
    """
    # Parse key from key=value
    key = pair.split("=", 1)[0] if "=" in pair else pair

    if not key:
        return ValidationError("Empty config key in -c option")

    # Check never-allow list FIRST
    for pattern in CONFIG_NEVER_ALLOW:
        if pattern.endswith("."):
            # Prefix match (e.g., "alias." matches "alias.anything")
            if key.startswith(pattern) or key == pattern.rstrip("."):
                return ValidationError(f"Blocked config key: {key}")
        elif "*" in pattern:
            # Wildcard pattern like "remote.*.proxy"
            if _matches_wildcard_config(key, pattern):
                return ValidationError(f"Blocked config key: {key}")
        else:
            # Exact match
            if key == pattern:
                return ValidationError(f"Blocked config key: {key}")

    # Check permitted prefixes
    for prefix in CONFIG_PERMITTED_PREFIXES:
        if key.startswith(prefix) or key == prefix.rstrip("."):
            return None

    return ValidationError(f"Config key not in permitted list: {key}")


def _matches_wildcard_config(key: str, pattern: str) -> bool:
    """Match a config key against a wildcard pattern like 'remote.*.proxy'.

    The '*' matches exactly one dotted segment.
    """
    parts = pattern.split(".")
    key_parts = key.split(".")

    if len(key_parts) != len(parts):
        return False

    for p, k in zip(parts, key_parts):
        if p == "*":
            continue
        if p != k:
            return False

    return True


def _validate_command_flags(
    subcommand: str, args: List[str]
) -> Optional[ValidationError]:
    """Check per-command blocked flags."""
    blocked = COMMAND_BLOCKED_FLAGS.get(subcommand)
    if not blocked:
        return None

    for arg in args:
        flag_name = arg.split("=", 1)[0]
        if flag_name in blocked:
            return ValidationError(
                f"Blocked flag for {subcommand}: {flag_name}"
            )

    return None


def _validate_remote_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git remote subcommands — explicit enumeration."""
    if not args:
        # bare 'git remote' lists remotes — allowed
        return None

    subcmd = args[0]

    if subcmd in REMOTE_BLOCKED_SUBCOMMANDS:
        return ValidationError(f"Remote subcommand not allowed: {subcmd}")

    if subcmd.startswith("-"):
        # Flags like -v are checked against allowed set
        if subcmd not in REMOTE_ALLOWED_SUBCOMMANDS:
            return ValidationError(f"Remote flag not allowed: {subcmd}")

    # Allow subcommands in the allowed set
    if subcmd in REMOTE_ALLOWED_SUBCOMMANDS:
        return None

    # Unknown subcommands are blocked by default
    return ValidationError(f"Remote subcommand not allowed: {subcmd}")


def _validate_config_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git config — only read-only operations allowed."""
    if not args:
        # bare 'git config' shows help — allowed
        return None

    # Check that at least one allowed flag is present
    has_allowed = False
    for arg in args:
        if arg in CONFIG_ALLOWED_FLAGS:
            has_allowed = True
            break

    if not has_allowed:
        return ValidationError(
            "Config command requires --get, --list, or --get-regexp"
        )

    return None


def _validate_notes_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git notes — only read-only operations allowed."""
    write_subcmds = {"add", "append", "copy", "edit", "merge", "remove", "prune"}
    if args and args[0] in write_subcmds:
        return ValidationError(f"Notes subcommand not allowed: {args[0]}")
    return None


def _validate_clean_flags(args: List[str]) -> Optional[ValidationError]:
    """Validate git clean — only --dry-run is allowed."""
    for arg in args:
        if arg.startswith("-") and arg not in _CLEAN_ALLOWED_FLAGS:
            return ValidationError(
                f"Clean only allows --dry-run/-n, got: {arg}"
            )
    return None


def validate_path(
    cwd: Optional[str], repo_root: str
) -> Tuple[str, Optional[ValidationError]]:
    """Validate and resolve working directory within repo root.

    Server-side repo root is authoritative. Client cwd is only used
    for relative subdirectory resolution within the repo root.

    Args:
        cwd: Client-requested working directory (relative to repo root).
        repo_root: Server-derived repo root path.

    Returns:
        (resolved_path, None) on success, ("", error) on failure.
    """
    if not repo_root:
        return "", ValidationError("No repo root configured")

    real_root = os.path.realpath(repo_root)

    if cwd is None or cwd in ("", ".", "/"):
        return real_root, None

    # Block path traversal
    if ".." in cwd.split(os.sep):
        return "", ValidationError("Path traversal (..) not allowed")

    # Resolve relative to repo root
    if os.path.isabs(cwd):
        # Absolute paths: must be within repo root
        resolved = os.path.realpath(cwd)
    else:
        resolved = os.path.realpath(os.path.join(real_root, cwd))

    if not resolved.startswith(real_root + os.sep) and resolved != real_root:
        return "", ValidationError(
            "Resolved path is outside repo root"
        )

    return resolved, None


def validate_path_args(args: List[str], repo_root: str) -> Optional[ValidationError]:
    """Check that path-like arguments don't contain traversal."""
    real_root = os.path.realpath(repo_root)

    for arg in args:
        # Skip flags
        if arg.startswith("-"):
            continue
        # Check for path traversal
        if ".." in arg.split(os.sep):
            return ValidationError(f"Path traversal (..) not allowed in arg: {arg}")
        # If it looks like a path (contains / or \), validate it
        if os.sep in arg or "/" in arg:
            resolved = os.path.realpath(os.path.join(real_root, arg))
            if not resolved.startswith(real_root + os.sep) and resolved != real_root:
                return ValidationError(f"Path outside repo root: {arg}")

    return None


# ---------------------------------------------------------------------------
# Environment Sanitization
# ---------------------------------------------------------------------------


def build_clean_env() -> Dict[str, str]:
    """Build a sanitized environment for git subprocess execution.

    Starts from an empty env and only copies allowed variables.
    All GIT_* and SSH_* vars are excluded.
    """
    clean = {}

    for key in ENV_ALLOWED:
        val = os.environ.get(key)
        if val is not None:
            clean[key] = val

    # Ensure PATH is always set
    if "PATH" not in clean:
        clean["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    return clean


# ---------------------------------------------------------------------------
# Git Execution
# ---------------------------------------------------------------------------


def execute_git(
    request: GitExecRequest,
    repo_root: str,
    metadata: Optional[dict] = None,
) -> Tuple[Optional[GitExecResponse], Optional[ValidationError]]:
    """Validate and execute a git command synchronously.

    Args:
        request: The parsed git exec request.
        repo_root: Server-derived repository root path.
        metadata: Container metadata for per-sandbox extensions.

    Returns:
        (response, None) on success, (None, error) on validation failure.
    """
    # Resolve extra allowed commands from metadata
    extra_allowed = None
    if metadata:
        git_meta = metadata.get("git", {})
        if isinstance(git_meta, dict):
            extra = git_meta.get("allowed_commands")
            if isinstance(extra, list):
                extra_allowed = set(extra)

    # Validate command
    err = validate_command(request.args, extra_allowed)
    if err:
        return None, err

    # Validate working directory
    resolved_cwd, err = validate_path(request.cwd, repo_root)
    if err:
        return None, err

    # Validate path args
    err = validate_path_args(request.args, repo_root)
    if err:
        return None, err

    # Decode stdin if provided
    stdin_data = None
    if request.stdin_b64:
        try:
            stdin_data = base64.b64decode(request.stdin_b64)
        except Exception:
            return None, ValidationError("Invalid base64 in stdin_b64")

    # Build command
    cmd = [GIT_BINARY] + request.args

    # Build clean environment
    env = build_clean_env()

    # Execute
    try:
        result = subprocess.run(
            cmd,
            cwd=resolved_cwd,
            input=stdin_data,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, ValidationError("Command timed out")
    except OSError as exc:
        logger.error("Git execution failed: %s", exc)
        return None, ValidationError(f"Execution error: {exc}")

    # Process stdout
    stdout_raw = result.stdout
    truncated = False

    if len(stdout_raw) > MAX_RESPONSE_SIZE:
        stdout_raw = stdout_raw[:MAX_RESPONSE_SIZE]
        truncated = True

    # Try UTF-8 decode, fall back to base64
    stdout_str = ""
    stdout_b64 = None
    try:
        stdout_str = stdout_raw.decode("utf-8")
    except UnicodeDecodeError:
        stdout_b64 = base64.b64encode(stdout_raw).decode("ascii")

    # Stderr is always best-effort UTF-8
    stderr_str = result.stderr.decode("utf-8", errors="replace")

    response = GitExecResponse(
        exit_code=result.returncode,
        stdout=stdout_str,
        stderr=stderr_str,
        stdout_b64=stdout_b64,
        truncated=truncated,
    )

    logger.info(
        "Git command executed: %s (exit=%d, truncated=%s)",
        " ".join(request.args),
        result.returncode,
        truncated,
    )

    return response, None


async def execute_git_async(
    request: GitExecRequest,
    repo_root: str,
    sandbox_id: str,
    metadata: Optional[dict] = None,
) -> Tuple[Optional[GitExecResponse], Optional[ValidationError]]:
    """Execute git command with per-sandbox concurrency control.

    Uses a non-blocking acquire to reject immediately when at capacity
    rather than queuing requests indefinitely.
    """
    semaphore = _semaphore_pool.get(sandbox_id)

    if semaphore.locked():
        return None, ValidationError(
            f"Too many concurrent operations for sandbox {sandbox_id}"
        )

    async with semaphore:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, execute_git, request, repo_root, metadata
        )
