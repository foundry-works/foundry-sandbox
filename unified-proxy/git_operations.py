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
import contextlib
import fcntl
import logging
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Generator, List, Optional, Set, Tuple

from git_policies import check_protected_branches
from branch_isolation import (
    GIT_BINARY,
    ValidationError,
    _get_subcommand,
    _get_subcommand_args,
    _GLOBAL_VALUE_FLAGS,
    validate_branch_isolation,
    validate_sha_reachability,
    _filter_ref_listing_output,
    _filter_stderr_branch_refs,
)

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("git_audit")

# ---------------------------------------------------------------------------
# Audit Logging
# ---------------------------------------------------------------------------

# Max bytes of stdout/stderr to include in audit log entries
AUDIT_OUTPUT_TRUNCATE = 1024

# Policy version for tracking audit schema changes
AUDIT_POLICY_VERSION = "1.0"


def audit_log(
    *,
    event: str,
    action: str,
    decision: str,
    command_args: Optional[List[str]] = None,
    sandbox_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    container_id: Optional[str] = None,
    request_id: Optional[str] = None,
    reason: Optional[str] = None,
    matched_rule: Optional[str] = None,
    exit_code: Optional[int] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
    component: str = "git_operations",
    **extra: Any,
) -> None:
    """Emit a structured audit log entry for a git operation.

    Sensitive data exclusion:
    - stdin_b64 is NEVER passed to this function
    - Authorization headers are NEVER passed
    - HMAC secrets are NEVER passed
    - stdout/stderr are truncated to AUDIT_OUTPUT_TRUNCATE bytes
    """
    entry: Dict[str, Any] = {
        "event": event,
        "component": component,
        "action": action,
        "decision": decision,
        "policy_version": AUDIT_POLICY_VERSION,
    }

    if request_id is None:
        request_id = str(uuid.uuid4())
    entry["request_id"] = request_id

    if container_id:
        entry["container_id"] = container_id
    if sandbox_id:
        entry["sandbox_id"] = sandbox_id
    if source_ip:
        entry["source_ip"] = source_ip
    if reason:
        entry["reason"] = reason
    if matched_rule:
        entry["matched_rule"] = matched_rule
    if command_args:
        # Avoid clobbering LogRecord.args (reserved field in logging).
        entry["command_args"] = command_args
    if exit_code is not None:
        entry["exit_code"] = exit_code

    # Truncate output fields
    if stdout is not None:
        entry["stdout"] = stdout[:AUDIT_OUTPUT_TRUNCATE]
        if len(stdout) > AUDIT_OUTPUT_TRUNCATE:
            entry["stdout_truncated"] = True
    if stderr is not None:
        entry["stderr"] = stderr[:AUDIT_OUTPUT_TRUNCATE]
        if len(stderr) > AUDIT_OUTPUT_TRUNCATE:
            entry["stderr_truncated"] = True

    if extra:
        entry.update(extra)

    log_fn = audit_logger.warning if decision == "deny" else audit_logger.info
    log_fn("git.%s", event, extra=entry)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_STDIN_SIZE = 1 * 1024 * 1024       # 1MB decoded stdin
MAX_RESPONSE_SIZE = 10 * 1024 * 1024   # 10MB response truncation
MAX_REQUEST_BODY_SIZE = 256 * 1024     # 256KB request body
MAX_ARGS_COUNT = 256                    # Max number of args
MAX_ARG_LENGTH = 8 * 1024              # 8KB per arg
MAX_CONCURRENT_PER_SANDBOX = 4         # Max in-flight ops per sandbox
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

# Sparse checkout (read-only subcommands enforced separately)
_SPARSE_CHECKOUT_CMDS = frozenset({
    "sparse-checkout",
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
    | _SPARSE_CHECKOUT_CMDS
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
    "core.sparseCheckout",
    "core.sparseCheckoutCone",
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

    # Check global blocked flags before parsing
    for arg in args:
        flag_name = arg.split("=", 1)[0]
        if flag_name in GLOBAL_BLOCKED_FLAGS:
            return ValidationError(f"Blocked flag: {flag_name}")
        # Stop scanning after first non-flag (subcommand)
        if not arg.startswith("-"):
            break

    # Extract subcommand and args using shared helper
    subcommand, subcommand_args, config_pairs = _get_subcommand_args(args)
    if subcommand is None:
        return ValidationError("No subcommand found")

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

    # Sparse checkout: only allow 'list'
    if subcommand == "sparse-checkout":
        err = _validate_sparse_checkout_subcommand(subcommand_args)
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


def _validate_sparse_checkout_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git sparse-checkout — only read-only 'list' subcommand allowed."""
    if not args:
        # bare 'git sparse-checkout' shows help — allowed
        return None

    subcmd = args[0]
    if subcmd != "list":
        return ValidationError(
            f"Sparse-checkout subcommand not allowed: {subcmd} (only 'list' is permitted)"
        )

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
        # Compatibility: wrapper may send /workspace absolute paths while
        # the proxy repo_root is mounted at /git-workspace.
        client_workspace_root = os.path.realpath(
            os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
        )
        if (
            resolved == client_workspace_root
            or resolved.startswith(client_workspace_root + os.sep)
        ):
            rel = os.path.relpath(resolved, client_workspace_root)
            resolved = os.path.realpath(os.path.join(real_root, rel))
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
    # Translate /workspace paths to repo_root (proxy mounts at /git-workspace)
    client_root = os.path.realpath(
        os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
    )

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
            # Translate client workspace paths to server repo root
            if os.path.isabs(arg) and (
                resolved == client_root
                or resolved.startswith(client_root + os.sep)
            ):
                rel = os.path.relpath(resolved, client_root)
                resolved = os.path.realpath(os.path.join(real_root, rel))
            if not resolved.startswith(real_root + os.sep) and resolved != real_root:
                return ValidationError(f"Path outside repo root: {arg}")

    return None


# ---------------------------------------------------------------------------
# Protected Branch Enforcement (push operations)
# ---------------------------------------------------------------------------

# SHA used by git_policies to detect creation/deletion operations.
_ZERO_SHA = "0" * 40

# Push options that consume the following argument.
_PUSH_OPTIONS_WITH_VALUE: FrozenSet[str] = frozenset({
    "--repo",
    "--receive-pack",
    "--exec",
    "--upload-pack",
    "--push-option",
    "-o",
})


def _has_push_flag(args: List[str], flag: str) -> bool:
    """Check if a push flag is present in args."""
    return any(arg == flag or arg.startswith(flag + "=") for arg in args)


def _is_wildcard_refspec(spec: str) -> bool:
    """Check if a push refspec uses wildcard patterns."""
    if spec.startswith("+"):
        spec = spec[1:]

    parts: List[str]
    if ":" in spec:
        src, dst = spec.split(":", 1)
        parts = [src, dst]
    else:
        parts = [spec]

    wildcard_chars = ("*", "?", "[")
    for part in parts:
        if any(ch in part for ch in wildcard_chars):
            return True
    return False


def _extract_push_positionals(args: List[str]) -> List[str]:
    """Extract positional args from push subcommand args.

    Returns [remote, refspec1, refspec2, ...] after stripping flags
    and options that consume values.
    """
    positionals: List[str] = []
    idx = 0

    while idx < len(args):
        arg = args[idx]

        # -- terminates options; everything after is positional
        if arg == "--":
            idx += 1
            positionals.extend(args[idx:])
            break

        if arg in _PUSH_OPTIONS_WITH_VALUE:
            idx += 2
            continue

        if any(
            arg.startswith(opt + "=")
            for opt in _PUSH_OPTIONS_WITH_VALUE
            if opt.startswith("--")
        ):
            idx += 1
            continue

        if arg.startswith("-o") and arg != "-o":
            idx += 1
            continue

        if arg.startswith("-"):
            idx += 1
            continue

        positionals.append(arg)
        idx += 1

    return positionals


def _parse_push_refspecs(args: List[str]) -> List[str]:
    """Extract target refnames from push command arguments.

    Parses push subcommand args (after 'push') to find refspecs and extracts
    destination refs.

    Returns a list of fully qualified refnames (refs/heads/<branch>).
    """
    refs: List[str] = []

    positionals = _extract_push_positionals(args)
    if len(positionals) <= 1:
        return refs

    for spec in positionals[1:]:
        refs.extend(_parse_single_refspec(spec))

    return refs


def _parse_single_refspec(spec: str) -> List[str]:
    """Parse a single refspec into target refnames.

    Refspec forms:
      "branch"          -> push local branch to refs/heads/branch
      "src:dst"         -> push src to dst
      ":branch"         -> delete remote branch (handled separately)
      "+src:dst"        -> force push (+ prefix ignored, force flag handled elsewhere)
      "refs/heads/main" -> fully qualified ref
    """
    # Strip force prefix
    if spec.startswith("+"):
        spec = spec[1:]

    if ":" in spec:
        src, dst = spec.split(":", 1)
        if not dst:
            return []
        if not src:
            # Deletion refspec — handled separately in check_push_protected_branches
            return []
        return [_qualify_ref(dst)]
    else:
        if not spec:
            return []
        # "HEAD" without explicit destination is ambiguous for policy checks.
        if spec == "HEAD":
            return []
        return [_qualify_ref(spec)]


def _qualify_ref(ref: str) -> str:
    """Ensure a ref is fully qualified (refs/heads/...)."""
    if ref.startswith("refs/"):
        return ref
    return f"refs/heads/{ref}"


def _extract_push_args(args: List[str]) -> Optional[List[str]]:
    """Extract push subcommand arguments from a full git args list.

    Skips global flags and -c options to find the subcommand.
    Returns the args after 'push' if the command is a push,
    or None if it's not a push command.
    """
    idx = 0
    while idx < len(args):
        arg = args[idx]
        # Skip -c key=value pairs
        if arg == "-c" and idx + 1 < len(args):
            idx += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            idx += 1
            continue
        # Skip other global flags
        if arg.startswith("-"):
            idx += 1
            continue
        # Found the subcommand
        if arg == "push":
            return args[idx + 1:]
        return None
    return None


def check_push_protected_branches(
    args: List[str],
    repo_root: str,
    metadata: Optional[dict] = None,
) -> Optional[ValidationError]:
    """Check if a push command targets protected branches.

    Parses push CLI arguments to extract target refspecs, then checks
    each against the protected branch policy using the shared validator
    from git_policies.py.

    To avoid bypasses from implicit push targets, this validator requires
    explicit refspecs for branch pushes and blocks broad push modes
    (--all, --mirror).

    Args:
        args: The push subcommand arguments (after the 'push' subcommand).
        repo_root: Repository root path (unused here but kept for consistency).
        metadata: Container metadata for policy configuration.

    Returns:
        None if allowed, ValidationError if a protected branch would be pushed to.
    """
    bare_repo_path = _resolve_bare_repo_path(repo_root)

    # Detect default branch from bare repo HEAD and inject into a shallow
    # copy of the metadata so that load_branch_policy() (which reads
    # metadata["git"]["protected_branches"]["patterns"]) can protect it.
    # We never mutate the caller's metadata dict.
    if bare_repo_path and metadata is not None:
        try:
            result = subprocess.run(
                [GIT_BINARY, "--git-dir", bare_repo_path,
                 "symbolic-ref", "HEAD"],
                capture_output=True, timeout=_SHA_CHECK_TIMEOUT,
            )
            if result.returncode == 0:
                head_ref = result.stdout.decode().strip()
                # e.g. "refs/heads/main" -> "main"
                if head_ref.startswith("refs/heads/"):
                    default_branch = head_ref[len("refs/heads/"):]
                    default_pattern = f"refs/heads/{default_branch}"
                    # Build the correct nested path that load_branch_policy reads
                    git_config = metadata.get("git", {})
                    if not isinstance(git_config, dict):
                        git_config = {}
                    pb_config = git_config.get("protected_branches", {})
                    if not isinstance(pb_config, dict):
                        pb_config = {}
                    patterns = list(pb_config.get("patterns", []))
                    if default_pattern not in patterns:
                        patterns.append(default_pattern)
                        # Shallow-copy the dict tree to avoid caller mutation
                        metadata = dict(metadata)
                        metadata["git"] = dict(git_config)
                        metadata["git"]["protected_branches"] = dict(pb_config)
                        metadata["git"]["protected_branches"]["patterns"] = patterns
        except (subprocess.TimeoutExpired, OSError):
            pass  # Best-effort; existing protected set still applies

    if _has_push_flag(args, "--all") or _has_push_flag(args, "--mirror"):
        return ValidationError(
            "Push modes --all and --mirror are not allowed; use explicit refspecs"
        )

    positionals = _extract_push_positionals(args)
    if not positionals:
        return ValidationError("Push command must include a remote")

    # Only a remote specified: this relies on implicit/default push targets.
    # Require explicit refspecs to ensure protected-branch enforcement applies.
    if len(positionals) == 1:
        if _has_push_flag(args, "--tags"):
            return None
        return ValidationError(
            "Push command must include explicit refspecs for policy enforcement"
        )

    refspecs = positionals[1:]
    for spec in refspecs:
        if _is_wildcard_refspec(spec):
            return ValidationError(
                "Wildcard push refspecs are not allowed; use explicit branch names"
            )

    # --delete mode uses plain ref names after remote.
    if _has_push_flag(args, "--delete"):
        for target in refspecs:
            qualified = _qualify_ref(target)
            block_reason = check_protected_branches(
                refname=qualified,
                old_sha="1" * 40,
                new_sha=_ZERO_SHA,  # Deletion
                bare_repo_path=bare_repo_path,
                metadata=metadata,
            )
            if block_reason:
                return ValidationError(block_reason)
        return None

    # Check regular push refspecs (treated as updates)
    refnames = _parse_push_refspecs(args)
    for refname in refnames:
        block_reason = check_protected_branches(
            refname=refname,
            old_sha="1" * 40,   # Non-zero: treat as update
            new_sha="2" * 40,   # Non-zero: treat as update
            bare_repo_path=bare_repo_path,
            metadata=metadata,
        )
        if block_reason:
            return ValidationError(block_reason)

    # Check deletion refspecs (":ref" form)
    saw_deletion = False
    for spec in refspecs:
        if spec.startswith("+"):
            spec = spec[1:]
        if ":" in spec:
            src, dst = spec.split(":", 1)
            if not src and dst:
                saw_deletion = True
                qualified = _qualify_ref(dst)
                block_reason = check_protected_branches(
                    refname=qualified,
                    old_sha="1" * 40,
                    new_sha=_ZERO_SHA,  # Deletion
                    bare_repo_path=bare_repo_path,
                    metadata=metadata,
                )
                if block_reason:
                    return ValidationError(block_reason)

    if not refnames and not saw_deletion and not _has_push_flag(args, "--tags"):
        return ValidationError(
            "Push refspecs could not be resolved; use explicit <src>:<dst> forms"
        )

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
# Fetch Locking
# ---------------------------------------------------------------------------

# Lock file name placed in bare repo directory
_FETCH_LOCK_FILENAME = ".foundry-fetch.lock"

# Default timeout and poll interval for fetch lock acquisition
_FETCH_LOCK_TIMEOUT = 30.0
_FETCH_LOCK_POLL_INTERVAL = 0.1


def _resolve_bare_repo_path(repo_root: str) -> Optional[str]:
    """Follow the worktree .git -> gitdir -> commondir chain to find the bare repo.

    Git worktrees have a ``.git`` *file* (not directory) that contains a
    ``gitdir:`` pointer to the worktree's gitdir directory.  That gitdir
    in turn has a ``commondir`` file pointing (absolute or relative) to the
    shared bare repo.

    Args:
        repo_root: The worktree's working directory root.

    Returns:
        Normalized absolute path to the bare repo directory, or None if
        the chain cannot be resolved.
    """
    try:
        dot_git = os.path.join(repo_root, ".git")

        # If .git is a directory, this IS the git dir (not a worktree)
        if os.path.isdir(dot_git):
            # Check for commondir inside .git
            commondir_file = os.path.join(dot_git, "commondir")
            if os.path.isfile(commondir_file):
                with open(commondir_file, "r") as f:
                    commondir = f.read().strip()
                if os.path.isabs(commondir):
                    return os.path.normpath(commondir)
                return os.path.normpath(os.path.join(dot_git, commondir))
            # No commondir — .git itself is the git dir
            return os.path.normpath(dot_git)

        # .git is a file — read gitdir pointer
        if not os.path.isfile(dot_git):
            return None

        with open(dot_git, "r") as f:
            content = f.read().strip()

        if not content.startswith("gitdir:"):
            return None

        gitdir = content[len("gitdir:"):].strip()
        if not os.path.isabs(gitdir):
            gitdir = os.path.join(repo_root, gitdir)
        gitdir = os.path.normpath(gitdir)

        if not os.path.isdir(gitdir):
            return None

        # Read commondir from gitdir
        commondir_file = os.path.join(gitdir, "commondir")
        if not os.path.isfile(commondir_file):
            # No commondir — gitdir itself is the bare repo
            return gitdir

        with open(commondir_file, "r") as f:
            commondir = f.read().strip()

        if os.path.isabs(commondir):
            bare_path = os.path.normpath(commondir)
        else:
            bare_path = os.path.normpath(os.path.join(gitdir, commondir))

        if not os.path.isdir(bare_path):
            return None

        return bare_path

    except (OSError, IOError):
        return None


@contextlib.contextmanager
def _fetch_lock(
    bare_repo_dir: str, timeout: float = _FETCH_LOCK_TIMEOUT,
) -> Generator[None, None, None]:
    """Acquire an exclusive file lock for fetch serialization.

    Creates ``.foundry-fetch.lock`` in the bare repo directory and holds
    an ``fcntl.flock`` exclusive lock for the duration of the context.

    Args:
        bare_repo_dir: Path to the bare repository directory.
        timeout: Maximum seconds to wait for the lock (default 30).

    Raises:
        TimeoutError: If the lock cannot be acquired within *timeout*.
    """
    lock_path = os.path.join(bare_repo_dir, _FETCH_LOCK_FILENAME)
    fd = None
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        deadline = time.monotonic() + timeout

        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break  # Lock acquired
            except (OSError, IOError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Could not acquire fetch lock within {timeout}s"
                    )
                time.sleep(_FETCH_LOCK_POLL_INTERVAL)

        yield

    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (OSError, IOError):
                pass
            os.close(fd)


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
    # Fail closed if sandbox branch identity is missing (legacy sandbox)
    if not (metadata and metadata.get("sandbox_branch")):
        return None, ValidationError(
            "Sandbox branch identity missing; recreate sandbox to enable isolation"
        )

    # Resolve extra allowed commands from metadata
    extra_allowed = None
    if metadata:
        git_meta = metadata.get("git", {})
        if isinstance(git_meta, dict):
            extra = git_meta.get("allowed_commands")
            if isinstance(extra, list):
                extra_allowed = set(extra)

    # Generate request ID for audit correlation
    req_id = str(uuid.uuid4())

    # Validate command
    err = validate_command(request.args, extra_allowed)
    if err:
        audit_log(
            event="command_blocked",
            action=" ".join(request.args[:3]),
            decision="deny",
            command_args=request.args,
            reason=err.reason,
            matched_rule="command_validation",
            request_id=req_id,
        )
        return None, err

    # Validate branch isolation
    err = validate_branch_isolation(request.args, metadata)
    if err:
        audit_log(
            event="branch_isolation_blocked",
            action=" ".join(request.args[:3]),
            decision="deny",
            command_args=request.args,
            reason=err.reason,
            matched_rule="branch_isolation",
            request_id=req_id,
        )
        return None, err

    # Validate SHA reachability (must follow branch isolation check)
    err = validate_sha_reachability(request.args, repo_root, metadata)
    if err:
        audit_log(
            event="sha_reachability_blocked",
            action=" ".join(request.args[:3]),
            decision="deny",
            command_args=request.args,
            reason=err.reason,
            matched_rule="sha_reachability",
            request_id=req_id,
        )
        return None, err

    # Validate working directory
    resolved_cwd, err = validate_path(request.cwd, repo_root)
    if err:
        audit_log(event="path_blocked", action=" ".join(request.args[:3]),
                  decision="deny", command_args=request.args, reason=err.reason,
                  matched_rule="path_validation", request_id=req_id)
        return None, err

    # Validate path args
    err = validate_path_args(request.args, repo_root)
    if err:
        audit_log(event="path_blocked", action=" ".join(request.args[:3]),
                  decision="deny", command_args=request.args, reason=err.reason,
                  matched_rule="path_arg_validation", request_id=req_id)
        return None, err

    # Check protected branches for push operations
    push_args = _extract_push_args(request.args)
    if push_args is not None:
        err = check_push_protected_branches(push_args, repo_root, metadata)
        if err:
            audit_log(event="push_blocked", action="push",
                      decision="deny", command_args=request.args, reason=err.reason,
                      matched_rule="protected_branch", request_id=req_id)
            return None, err

    # Decode stdin if provided
    stdin_data = None
    if request.stdin_b64:
        try:
            stdin_data = base64.b64decode(request.stdin_b64)
        except Exception:
            return None, ValidationError("Invalid base64 in stdin_b64")

    # Translate client-side paths (/workspace/...) to server-side (/git-workspace/...)
    client_root = os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
    real_repo = os.path.realpath(repo_root)
    translated_args = []
    for arg in request.args:
        if not arg.startswith("-") and os.path.isabs(arg):
            if arg == client_root or arg.startswith(client_root + "/"):
                arg = real_repo + arg[len(client_root):]
        translated_args.append(arg)

    # Build command
    cmd = [GIT_BINARY] + translated_args

    # Build clean environment
    env = build_clean_env()

    # Fetch locking: serialize concurrent fetch/pull per bare repo
    subcommand = _get_subcommand(request.args)
    fetch_lock_ctx: Optional[contextlib.AbstractContextManager] = None
    if subcommand in ("fetch", "pull"):
        # Check break-glass override
        allow_unlocked = os.environ.get("FOUNDRY_ALLOW_UNLOCKED_FETCH") == "1"
        bare_repo = _resolve_bare_repo_path(resolved_cwd)
        if bare_repo is None and not allow_unlocked:
            audit_log(
                event="fetch_lock_unavailable",
                action=subcommand,
                decision="deny",
                command_args=request.args,
                reason="Cannot resolve bare repo path for fetch locking",
                matched_rule="fetch_lock",
                request_id=req_id,
            )
            return None, ValidationError(
                "Cannot resolve bare repo for fetch locking; "
                "contact admin or set FOUNDRY_ALLOW_UNLOCKED_FETCH=1"
            )
        if bare_repo is not None:
            fetch_lock_ctx = _fetch_lock(bare_repo)
        elif allow_unlocked:
            audit_log(
                event="fetch_lock_bypassed",
                action=subcommand,
                decision="allow",
                command_args=request.args,
                reason="FOUNDRY_ALLOW_UNLOCKED_FETCH=1 override",
                matched_rule="fetch_lock_bypass",
                request_id=req_id,
            )

    # Execute (with optional fetch lock)
    try:
        ctx = fetch_lock_ctx or contextlib.nullcontext()
        with ctx:
            result = subprocess.run(
                cmd,
                cwd=resolved_cwd,
                input=stdin_data,
                capture_output=True,
                timeout=SUBPROCESS_TIMEOUT,
                env=env,
            )
    except TimeoutError as exc:
        audit_log(
            event="fetch_lock_timeout",
            action=subcommand or " ".join(request.args[:3]),
            decision="deny",
            command_args=request.args,
            reason=str(exc),
            matched_rule="fetch_lock",
            request_id=req_id,
        )
        return None, ValidationError(
            "Fetch lock timed out; another fetch may be in progress"
        )
    except subprocess.TimeoutExpired:
        audit_log(event="command_timeout", action=" ".join(request.args[:3]),
                  decision="deny", command_args=request.args, reason="Command timed out",
                  matched_rule="timeout", request_id=req_id)
        return None, ValidationError("Command timed out")
    except OSError as exc:
        logger.error("Git execution failed: %s", exc)
        audit_log(event="command_error", action=" ".join(request.args[:3]),
                  decision="deny", command_args=request.args, reason=str(exc),
                  matched_rule="os_error", request_id=req_id)
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

    # Translate proxy-side paths back to client-side paths in output
    # (e.g., /git-workspace → /workspace for rev-parse --show-toplevel)
    client_root = os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
    if repo_root and client_root and repo_root != client_root:
        real_repo = os.path.realpath(repo_root)
        if stdout_str:
            stdout_str = stdout_str.replace(real_repo, client_root)
        if stderr_str:
            stderr_str = stderr_str.replace(real_repo, client_root)

    # Apply branch isolation output filtering
    sandbox_branch = metadata.get("sandbox_branch") if metadata else None
    if sandbox_branch and stdout_str:
        stdout_str = _filter_ref_listing_output(stdout_str, request.args, sandbox_branch)
    if sandbox_branch and stderr_str:
        stderr_str = _filter_stderr_branch_refs(stderr_str, sandbox_branch)

    response = GitExecResponse(
        exit_code=result.returncode,
        stdout=stdout_str,
        stderr=stderr_str,
        stdout_b64=stdout_b64,
        truncated=truncated,
    )

    audit_log(
        event="command_executed",
        action=" ".join(request.args[:3]),
        decision="allow",
        command_args=request.args,
        exit_code=result.returncode,
        stdout=stdout_str or "",
        stderr=stderr_str,
        request_id=req_id,
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
