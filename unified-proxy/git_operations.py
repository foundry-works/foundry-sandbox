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

# Global flags that consume the next argument as their value.
# Used by _get_subcommand_args() to skip over value arguments.
_GLOBAL_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
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
# Branch Isolation Constants
# ---------------------------------------------------------------------------

WELL_KNOWN_BRANCHES: FrozenSet[str] = frozenset({
    "main", "master", "develop", "production",
})

WELL_KNOWN_BRANCH_PREFIXES: Tuple[str, ...] = (
    "release/", "hotfix/",
)

# Commands that accept ref arguments for reading (not switching branches)
_REF_READING_CMDS: FrozenSet[str] = frozenset({
    "log", "show", "diff", "blame", "cherry-pick", "merge", "rebase",
    "reset", "rev-list", "diff-tree", "rev-parse", "shortlog", "describe",
    "name-rev", "archive", "format-patch",
})

# Commands that enumerate refs
_REF_ENUM_CMDS: FrozenSet[str] = frozenset({
    "for-each-ref", "ls-remote", "show-ref",
})

# Flags that implicitly reference all branches/refs
_IMPLICIT_ALL_REF_FLAGS: FrozenSet[str] = frozenset({
    "--all", "--branches", "--remotes", "--glob",
})

# Flag prefixes that implicitly reference refs with patterns
_IMPLICIT_REF_FLAG_PREFIXES: Tuple[str, ...] = (
    "--branches=", "--remotes=", "--glob=",
)

# Ref-reading flags that consume the next argument as a value.
# This prevents option values (e.g. ``-n 5``) from being misclassified as refs.
_REF_READING_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-n", "--max-count", "--skip",
    "--since", "--until", "--after", "--before",
    "--author", "--committer", "--grep",
    "-G", "-S",
    "--date", "--format", "--pretty",
    "--decorate-refs", "--decorate-refs-exclude",
    "--output", "-o",
    "--word-diff-regex",
    "--find-object",
    "--min-parents", "--max-parents",
    "--diff-merges",
    "--relative", "--src-prefix", "--dst-prefix",
    "-L",
})

# Regex to strip revision suffixes (~N, ^N, @{...}) from ref names
_REV_SUFFIX_RE = re.compile(r"([~^]\d*|@\{[^}]*\})+$")

# Minimum length for a hex string to be treated as a SHA hash
_MIN_SHA_LENGTH = 12


def _strip_rev_suffixes(ref: str) -> str:
    """Strip trailing ~N, ^N, @{...} chains from a ref string.

    Examples:
        HEAD~3       -> HEAD
        main^^       -> main
        HEAD~2^3     -> HEAD
        main@{1}     -> main
        abc123~2^3   -> abc123
    """
    return _REV_SUFFIX_RE.sub("", ref)


def _is_allowed_branch_name(name: str, sandbox_branch: str) -> bool:
    """Check if a bare branch name is allowed for this sandbox.

    Allowed: the sandbox's own branch, well-known branches,
    and branches matching well-known prefixes.
    """
    if name == sandbox_branch:
        return True
    if name in WELL_KNOWN_BRANCHES:
        return True
    for prefix in WELL_KNOWN_BRANCH_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def _is_allowed_ref(ref: str, sandbox_branch: str) -> bool:
    """Check if a ref argument is allowed under branch isolation.

    Allows: HEAD, @{...} forms, own sandbox branch, well-known branches,
    tags, SHA hashes (>= 12 hex chars), range operators (checked recursively).
    Blocks: FETCH_HEAD, other sandbox branches, short hex strings.
    """
    # Handle range operators recursively
    for sep in ("...", ".."):
        if sep in ref:
            parts = ref.split(sep, 1)
            return all(_is_allowed_ref(p, sandbox_branch) for p in parts if p)

    # Strip revision suffixes
    base = _strip_rev_suffixes(ref)

    # FETCH_HEAD is always blocked (could contain cross-branch data)
    if base == "FETCH_HEAD":
        return False

    # HEAD and @{} forms are always allowed
    if base == "HEAD" or base.startswith("@{"):
        return True

    # Stash refs are allowed
    if base == "stash" or base.startswith("stash@{"):
        return True

    # Tags are always allowed (refs/tags/... or tag name checked by git)
    if base.startswith("refs/tags/") or base.startswith("tags/"):
        return True

    # Remote tracking refs: apply branch name isolation to the branch part
    for remote_prefix in ("refs/remotes/origin/", "origin/"):
        if base.startswith(remote_prefix):
            branch_name = base[len(remote_prefix):]
            return _is_allowed_branch_name(branch_name, sandbox_branch)

    # Full ref paths
    if base.startswith("refs/heads/"):
        branch_name = base[len("refs/heads/"):]
        return _is_allowed_branch_name(branch_name, sandbox_branch)

    # SHA hashes (hex strings of sufficient length) are always allowed
    if len(base) >= _MIN_SHA_LENGTH and all(c in "0123456789abcdefABCDEF" for c in base):
        return True

    # Bare branch names
    return _is_allowed_branch_name(base, sandbox_branch)


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


def _get_subcommand_args(
    args: List[str],
) -> Tuple[Optional[str], List[str], List[str]]:
    """Extract the git subcommand and its arguments from a full arg list.

    Handles global flags (-c key=val, -C <path>, --git-dir, --work-tree,
    --namespace) and the ``--`` global-options terminator.

    Args:
        args: Git command arguments (without the ``git`` prefix).

    Returns:
        (subcommand, subcommand_args, config_pairs) where subcommand is
        None if no subcommand was found.  config_pairs contains any
        ``-c key=value`` strings encountered before the subcommand.
    """
    idx = 0
    config_pairs: List[str] = []

    while idx < len(args):
        arg = args[idx]

        # '--' terminates global options; next arg is the subcommand
        if arg == "--":
            idx += 1
            break

        # Collect -c key=value pairs
        if arg == "-c" and idx + 1 < len(args):
            config_pairs.append(args[idx + 1])
            idx += 2
            continue
        elif arg.startswith("-c") and len(arg) > 2:
            # Compact -ckey=value form
            config_pairs.append(arg[2:])
            idx += 1
            continue

        # Skip global value flags and their argument
        if arg in _GLOBAL_VALUE_FLAGS and idx + 1 < len(args):
            idx += 2
            continue
        # Handle --flag=value form for global value flags
        flag_name = arg.split("=", 1)[0]
        if flag_name in _GLOBAL_VALUE_FLAGS and "=" in arg:
            idx += 1
            continue

        # First non-flag argument is the subcommand
        if not arg.startswith("-"):
            break

        idx += 1

    if idx >= len(args):
        return None, [], config_pairs

    return args[idx], args[idx + 1:], config_pairs


def _get_subcommand(args: List[str]) -> Optional[str]:
    """Return the git subcommand from *args*, or None."""
    subcmd, _, _ = _get_subcommand_args(args)
    return subcmd


# ---------------------------------------------------------------------------
# Branch Isolation Validator
# ---------------------------------------------------------------------------

# fetch/pull flags that consume the next argument as a value
_FETCH_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
    "-j", "--jobs", "--negotiation-tip", "--server-option", "-o",
    "--upload-pack", "--refmap", "--recurse-submodules-default",
    "--filter",
})

# checkout/switch flags that consume the next argument as a value
_CHECKOUT_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-b", "-B",       # checkout: create branch
    "-c", "-C",       # switch: create branch
    "--orphan",       # checkout: create orphan branch
    "--conflict",     # checkout: conflict style
    "--pathspec-from-file",
})

# checkout/switch flags that indicate branch creation (next arg is new branch name)
_BRANCH_CREATE_FLAGS: FrozenSet[str] = frozenset({
    "-b", "-B", "-c", "-C", "--orphan",
})


def validate_branch_isolation(
    args: List[str],
    metadata: Optional[dict],
) -> Optional[ValidationError]:
    """Validate git command args for branch isolation.

    Enforces that a sandbox can only access its own branch, well-known
    branches, tags, and SHA hashes.  Commands that enumerate refs
    (for-each-ref, ls-remote, show-ref, branch --list) return None here
    and are handled by output filtering instead.

    Args:
        args: Git command arguments (without ``git`` prefix).
        metadata: Container metadata dict (must contain ``sandbox_branch``).

    Returns:
        None if allowed, ValidationError if blocked.
    """
    if not metadata:
        return None
    sandbox_branch = metadata.get("sandbox_branch")
    if not sandbox_branch:
        return None

    subcommand, sub_args, _ = _get_subcommand_args(args)
    if subcommand is None:
        return None  # will be caught by validate_command

    # --- branch deletion guard ---
    if subcommand == "branch":
        delete_mode = False
        i = 0
        while i < len(sub_args):
            a = sub_args[i]
            if a in ("-d", "-D", "--delete"):
                delete_mode = True
            elif delete_mode and not a.startswith("-"):
                if not _is_allowed_branch_name(a, sandbox_branch):
                    return ValidationError(
                        f"Branch isolation: cannot delete branch '{a}'"
                    )
            i += 1
        return None  # branch listing handled by output filtering

    # --- ref enum commands (handled by output filtering) ---
    if subcommand in _REF_ENUM_CMDS:
        return None

    # --- checkout / switch ---
    if subcommand in ("checkout", "switch"):
        return _validate_checkout_isolation(sub_args, sandbox_branch)

    # --- fetch / pull ---
    if subcommand in ("fetch", "pull"):
        return _validate_fetch_isolation(sub_args, sandbox_branch)

    # --- worktree add ---
    if subcommand == "worktree" and sub_args and sub_args[0] == "add":
        return _validate_worktree_add_isolation(sub_args[1:], sandbox_branch)

    # --- bisect start ---
    if subcommand == "bisect" and sub_args and sub_args[0] == "start":
        for a in sub_args[1:]:
            if a == "--":
                break
            if not a.startswith("-") and not _is_allowed_ref(a, sandbox_branch):
                return ValidationError(
                    f"Branch isolation: ref '{a}' not allowed in bisect"
                )
        return None

    # --- reflog ---
    if subcommand == "reflog":
        # reflog show <ref> — check the ref
        reflog_args = sub_args
        if reflog_args and reflog_args[0] in ("show", "expire", "delete"):
            reflog_args = reflog_args[1:]
        for a in reflog_args:
            if a == "--":
                break
            if not a.startswith("-") and not _is_allowed_ref(a, sandbox_branch):
                return ValidationError(
                    f"Branch isolation: ref '{a}' not allowed in reflog"
                )
        return None

    # --- notes ---
    if subcommand == "notes":
        _NOTES_SUBCMDS = {
            "list", "add", "copy", "append", "edit", "show",
            "merge", "remove", "prune",
        }
        # Check --ref=<ref> flag value
        notes_args = list(sub_args)
        skip_next = False
        for a in sub_args:
            if skip_next:
                skip_next = False
                continue
            if a.startswith("--ref="):
                ref_val = a[len("--ref="):]
                if not _is_allowed_ref(ref_val, sandbox_branch):
                    return ValidationError(
                        f"Branch isolation: ref '{ref_val}' not allowed in notes"
                    )
            elif a == "--ref":
                skip_next = True  # next arg is the ref value, handled above

        # Check positional args (skip sub-subcommand and flags)
        positionals: List[str] = []
        seen_subcmd = False
        for a in sub_args:
            if a == "--":
                break
            if a.startswith("-"):
                continue
            if not seen_subcmd and a in _NOTES_SUBCMDS:
                seen_subcmd = True
                continue
            positionals.append(a)

        for a in positionals:
            if not _is_allowed_ref(a, sandbox_branch):
                return ValidationError(
                    f"Branch isolation: ref '{a}' not allowed in notes"
                )
        return None

    # --- ref-reading commands (log, show, diff, blame, etc.) ---
    if subcommand in _REF_READING_CMDS:
        return _validate_ref_reading_isolation(sub_args, sandbox_branch)

    return None


def _validate_checkout_isolation(
    sub_args: List[str], sandbox_branch: str,
) -> Optional[ValidationError]:
    """Validate checkout/switch args for branch isolation."""
    creating_branch = False
    skip_next = False
    positionals: List[str] = []
    start_point: Optional[str] = None

    i = 0
    while i < len(sub_args):
        a = sub_args[i]
        if a == "--":
            break  # rest are pathspecs
        if skip_next:
            skip_next = False
            i += 1
            continue

        if a in _BRANCH_CREATE_FLAGS:
            creating_branch = True
            # Next arg is the new branch name (skip it)
            skip_next = True
            i += 1
            continue

        if a in _CHECKOUT_VALUE_FLAGS:
            skip_next = True
            i += 1
            continue

        # Handle --flag=value form
        flag_name = a.split("=", 1)[0]
        if flag_name in _CHECKOUT_VALUE_FLAGS:
            if flag_name in _BRANCH_CREATE_FLAGS:
                creating_branch = True
            i += 1
            continue

        if not a.startswith("-"):
            positionals.append(a)

        i += 1

    if creating_branch:
        # When creating a branch, the start-point (if any) is the last positional
        if positionals:
            start_point = positionals[-1]
            if not _is_allowed_ref(start_point, sandbox_branch):
                return ValidationError(
                    f"Branch isolation: start-point '{start_point}' not allowed"
                )
    else:
        # Switching to a branch: first positional is the target
        if positionals:
            target = positionals[0]
            if not _is_allowed_ref(target, sandbox_branch):
                return ValidationError(
                    f"Branch isolation: cannot switch to '{target}'. "
                    f"If this is a file path, use -- to separate paths from refs."
                )

    return None


def _validate_fetch_isolation(
    sub_args: List[str], sandbox_branch: str,
) -> Optional[ValidationError]:
    """Validate fetch/pull args for branch isolation."""
    skip_next = False
    positionals: List[str] = []

    for i, a in enumerate(sub_args):
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue

        # Skip flags that consume the next argument
        if a in _FETCH_VALUE_FLAGS:
            skip_next = True
            continue
        # Handle --flag=value form
        if "=" in a and a.split("=", 1)[0] in _FETCH_VALUE_FLAGS:
            continue

        if not a.startswith("-"):
            positionals.append(a)

    # First positional is the remote name (always allowed), rest are refspecs
    for refspec in positionals[1:]:
        # Handle +src:dst refspec format
        spec = refspec.lstrip("+")
        src, _, dst = spec.partition(":")
        if src and not _is_allowed_ref(src, sandbox_branch):
            return ValidationError(
                f"Branch isolation: refspec source '{src}' not allowed"
            )
        if dst and not _is_allowed_ref(dst, sandbox_branch):
            return ValidationError(
                f"Branch isolation: refspec destination '{dst}' not allowed"
            )

    return None


def _validate_worktree_add_isolation(
    sub_args: List[str], sandbox_branch: str,
) -> Optional[ValidationError]:
    """Validate worktree add args for branch isolation."""
    skip_next = False
    positionals: List[str] = []

    for a in sub_args:
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if a in ("-b", "-B"):
            skip_next = True  # next is branch name (new, allowed)
            continue
        if not a.startswith("-"):
            positionals.append(a)

    # worktree add <path> [<commit-ish>]
    # First positional is path, second is commit-ish
    if len(positionals) >= 2:
        commit_ish = positionals[1]
        if not _is_allowed_ref(commit_ish, sandbox_branch):
            return ValidationError(
                f"Branch isolation: commit-ish '{commit_ish}' not allowed "
                f"in worktree add"
            )

    return None


def _validate_ref_reading_isolation(
    sub_args: List[str], sandbox_branch: str,
) -> Optional[ValidationError]:
    """Validate ref-reading command args for branch isolation.

    Blocks --all/--branches/--remotes/--glob flags and checks each
    positional ref argument.
    """
    for a in sub_args:
        if a == "--":
            break  # rest are pathspecs
        if a in _IMPLICIT_ALL_REF_FLAGS:
            return ValidationError(
                f"Branch isolation: flag '{a}' not allowed (exposes all branches)"
            )
        for prefix in _IMPLICIT_REF_FLAG_PREFIXES:
            if a.startswith(prefix):
                return ValidationError(
                    f"Branch isolation: flag '{a}' not allowed "
                    f"(exposes multiple branches)"
                )

    # Check positional ref args (before --), skipping known option values.
    skip_next = False
    for a in sub_args:
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if a in _REF_READING_VALUE_FLAGS:
            skip_next = True
            continue
        if "=" in a and a.split("=", 1)[0] in _REF_READING_VALUE_FLAGS:
            continue
        if a.startswith("-"):
            continue
        if not _is_allowed_ref(a, sandbox_branch):
            return ValidationError(
                f"Branch isolation: ref '{a}' not allowed. "
                f"If this is a file path, use -- to separate paths from refs."
            )

    return None


# ---------------------------------------------------------------------------
# SHA Reachability Enforcement
# ---------------------------------------------------------------------------

# Timeout for SHA reachability git subprocess calls (seconds).
_SHA_CHECK_TIMEOUT = 10

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _is_sha_like(token: str) -> bool:
    """Return True if *token* looks like a SHA hash (12-40 hex chars)."""
    return (
        _MIN_SHA_LENGTH <= len(token) <= 40
        and all(c in _HEX_CHARS for c in token)
    )


def _extract_sha_args(sub_args: List[str]) -> List[str]:
    """Collect SHA-like positional args from a ref-reading command.

    Handles range operators (``..``, ``...``) and strips revision
    suffixes before checking whether a token looks like a SHA.
    Stops at ``--`` (pathspec separator).
    """
    shas: List[str] = []
    for arg in sub_args:
        if arg == "--":
            break
        if arg.startswith("-"):
            continue
        # Expand range operators
        for sep in ("...", ".."):
            if sep in arg:
                parts = arg.split(sep, 1)
                for part in parts:
                    if part:
                        base = _strip_rev_suffixes(part)
                        if _is_sha_like(base):
                            shas.append(base)
                break
        else:
            base = _strip_rev_suffixes(arg)
            if _is_sha_like(base):
                shas.append(base)
    return shas


def _get_allowed_refs(bare_repo: str, sandbox_branch: str) -> List[str]:
    """Build the list of fully-qualified refs this sandbox may access.

    Includes the sandbox's own branch, well-known branches (matched via
    ``for-each-ref``), and all tags.

    Args:
        bare_repo: Path to the bare git repository.
        sandbox_branch: This sandbox's branch name.

    Returns:
        List of fully-qualified ref patterns for ``--stdin`` input.
    """
    refs: List[str] = [f"refs/heads/{sandbox_branch}"]

    # Well-known branches
    for name in WELL_KNOWN_BRANCHES:
        refs.append(f"refs/heads/{name}")

    # Well-known prefixes — enumerate matching refs via for-each-ref
    for prefix in WELL_KNOWN_BRANCH_PREFIXES:
        try:
            result = subprocess.run(
                [GIT_BINARY, "--git-dir", bare_repo,
                 "for-each-ref", "--format=%(refname)",
                 f"refs/heads/{prefix}"],
                capture_output=True, timeout=_SHA_CHECK_TIMEOUT,
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.decode().splitlines():
                    line = line.strip()
                    if line:
                        refs.append(line)
        except (subprocess.TimeoutExpired, OSError):
            pass

    # All tags
    refs.append("refs/tags/")

    return refs


def _check_sha_reachability(
    sha: str,
    bare_repo: str,
    allowed_refs: List[str],
    cache: dict,
) -> bool:
    """Check whether *sha* is reachable from any allowed ref.

    Strategy:
      1. Check tag containment first (single ``merge-base --is-ancestor``
         call against all tags is fast because tags share object storage).
      2. Check branch reachability via ``merge-base --is-ancestor`` with
         early exit on first match.

    Results are memoized in *cache* for the duration of a single request.

    Args:
        sha: The SHA hex string to verify.
        bare_repo: Path to the bare git repository.
        allowed_refs: Fully-qualified ref list from ``_get_allowed_refs``.
        cache: Per-request dict for memoization.

    Returns:
        True if reachable, False otherwise.
    """
    if sha in cache:
        return cache[sha]

    # Check each allowed ref (tags prefix handled specially)
    for ref in allowed_refs:
        if ref.endswith("/"):
            # Tag prefix — use for-each-ref to enumerate, then check
            try:
                result = subprocess.run(
                    [GIT_BINARY, "--git-dir", bare_repo,
                     "for-each-ref", "--format=%(refname)",
                     ref],
                    capture_output=True, timeout=_SHA_CHECK_TIMEOUT,
                )
                if result.returncode == 0 and result.stdout:
                    for tag_ref in result.stdout.decode().splitlines():
                        tag_ref = tag_ref.strip()
                        if not tag_ref:
                            continue
                        try:
                            r = subprocess.run(
                                [GIT_BINARY, "--git-dir", bare_repo,
                                 "merge-base", "--is-ancestor", sha, tag_ref],
                                capture_output=True, timeout=_SHA_CHECK_TIMEOUT,
                            )
                            if r.returncode == 0:
                                cache[sha] = True
                                return True
                        except (subprocess.TimeoutExpired, OSError):
                            continue
            except (subprocess.TimeoutExpired, OSError):
                pass
            continue

        # Branch ref — single merge-base check
        try:
            result = subprocess.run(
                [GIT_BINARY, "--git-dir", bare_repo,
                 "merge-base", "--is-ancestor", sha, ref],
                capture_output=True, timeout=_SHA_CHECK_TIMEOUT,
            )
            if result.returncode == 0:
                cache[sha] = True
                return True
        except (subprocess.TimeoutExpired, OSError):
            continue

    cache[sha] = False
    return False


def validate_sha_reachability(
    args: List[str],
    repo_root: str,
    metadata: Optional[dict],
) -> Optional[ValidationError]:
    """Validate that SHA arguments are reachable from allowed branches.

    Only applies to ref-reading commands (log, show, diff, etc.) when
    branch isolation is active.  Skips checks for shallow repos.

    Args:
        args: Git command arguments (without ``git`` prefix).
        repo_root: Server-side repository root path.
        metadata: Container metadata dict (must contain ``sandbox_branch``).

    Returns:
        None if allowed, ValidationError if a SHA is unreachable.
    """
    if not metadata:
        return None
    sandbox_branch = metadata.get("sandbox_branch")
    if not sandbox_branch:
        return None

    subcommand, sub_args, _ = _get_subcommand_args(args)
    if subcommand is None:
        return None

    # Only check ref-reading commands
    if subcommand not in _REF_READING_CMDS:
        return None

    # Extract SHA-like args
    shas = _extract_sha_args(sub_args)
    if not shas:
        return None

    # Resolve bare repo
    bare_repo = _resolve_bare_repo_path(repo_root)
    if not bare_repo:
        return None  # Cannot check — allow (fail open for resolution failure)

    # Shallow repo: skip checks (log warning)
    shallow_file = os.path.join(bare_repo, "shallow")
    if os.path.isfile(shallow_file):
        logger.warning(
            "SHA reachability check skipped: shallow repo at %s", bare_repo,
        )
        return None

    # Build allowed refs and check each SHA
    allowed_refs = _get_allowed_refs(bare_repo, sandbox_branch)
    cache: dict = {}

    for sha in shas:
        if not _check_sha_reachability(sha, bare_repo, allowed_refs, cache):
            return ValidationError(
                f"Branch isolation: SHA '{sha}' is not reachable from "
                f"allowed branches"
            )

    return None


# ---------------------------------------------------------------------------
# Output Filtering: Branch Listings
# ---------------------------------------------------------------------------

# Matches plain and verbose branch output lines:
#   "* main"  /  "  feature/x"  /  "  feature abc1234 commit msg"
#   "  feature   abc1234 [origin/feature] commit msg"  (verbose -vv)
# Groups: indicator (* or spaces), branch_name, rest (optional)
_BRANCH_LINE_RE = re.compile(
    r"^(?P<indicator>[* ] )"           # "* " or "  "
    r"(?P<branch>\S+)"                 # branch name
    r"(?P<rest>.*)$"                   # optional verbose info
)

# Matches remote branch lines from `git branch -a`:
#   "  remotes/origin/main"
#   "  remotes/origin/HEAD -> origin/main"
_REMOTE_BRANCH_LINE_RE = re.compile(
    r"^(?P<indent>\s+)"
    r"remotes/(?P<remote>[^/]+)/"
    r"(?P<branch>\S+)"
    r"(?P<rest>.*)$"
)


def _filter_branch_output(output: str, sandbox_branch: str) -> str:
    """Filter git branch output to hide other sandbox branches.

    Handles plain, verbose (-v/-vv), and remote (-a) branch listing formats.
    Drops lines where the branch is not allowed.
    Preserves current-branch indicator (*).
    Keeps unrecognized format lines (safe default).

    Args:
        output: Raw stdout from a ``git branch`` command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output with disallowed branches removed.
    """
    if not output:
        return output

    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")

        # Try remote branch pattern first (more specific)
        m = _REMOTE_BRANCH_LINE_RE.match(stripped)
        if m:
            branch_name = m.group("branch")
            rest = m.group("rest")
            # Handle symref format: "HEAD -> origin/main"
            if branch_name == "HEAD" and "->" in rest:
                # Always keep HEAD symref lines
                filtered_lines.append(line)
                continue
            if _is_allowed_branch_name(branch_name, sandbox_branch):
                filtered_lines.append(line)
            continue

        # Try local branch pattern
        m = _BRANCH_LINE_RE.match(stripped)
        if m:
            branch_name = m.group("branch")
            if _is_allowed_branch_name(branch_name, sandbox_branch):
                filtered_lines.append(line)
            continue

        # Unrecognized format — keep (safe default)
        filtered_lines.append(line)

    return "".join(filtered_lines)


# ---------------------------------------------------------------------------
# Output Filtering: Ref Enumerations
# ---------------------------------------------------------------------------

# Matches lines containing full ref paths (for-each-ref, show-ref, ls-remote)
# e.g. "abc123 refs/heads/feature" or "refs/heads/feature abc123 commit msg"
_REF_IN_LINE_RE = re.compile(r"refs/heads/([^\s]+)")


def _is_allowed_short_ref_token(token: str, sandbox_branch: str) -> bool:
    """Check whether a short/custom ref token from ref-enum output is allowed."""
    if not token:
        return True
    if token.startswith("("):
        return True
    if token.startswith("refs/tags/") or token.startswith("tags/"):
        return True
    if token.startswith("refs/heads/"):
        return _is_allowed_branch_name(token[len("refs/heads/"):], sandbox_branch)
    if token.startswith("refs/remotes/"):
        parts = token.split("/", 3)
        if len(parts) == 4:
            return _is_allowed_branch_name(parts[3], sandbox_branch)
        return True
    # First treat token as a branch name (supports slashed branch names like
    # "sandbox/alice" and "release/1.0").
    if _is_allowed_branch_name(token, sandbox_branch):
        return True
    # Then try remote-short form ("origin/main", "upstream/feature").
    if "/" in token:
        remote, _, branch = token.partition("/")
        if remote and branch:
            return _is_allowed_branch_name(branch, sandbox_branch)
    return False


def _filter_ref_enum_output(output: str, sandbox_branch: str) -> str:
    """Filter ref enumeration output (for-each-ref, ls-remote, show-ref).

    Two-pass filtering:
      Pass 1: Check refs/heads/<branch> patterns via _REF_IN_LINE_RE.
              Drop if branch not allowed. Tags always kept.
      Pass 2: For lines not matched by pass 1, check first whitespace-
              delimited token as a potential short refname (handles custom
              --format output like %(refname:short)).

    Args:
        output: Raw stdout from a ref enumeration command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output with disallowed branch refs removed.
    """
    if not output:
        return output

    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")
        if not stripped:
            filtered_lines.append(line)
            continue

        # Pass 1: Check for refs/heads/<branch> or refs/tags/ patterns
        ref_match = _REF_IN_LINE_RE.search(stripped)
        if ref_match:
            branch_name = ref_match.group(1)
            if _is_allowed_branch_name(branch_name, sandbox_branch):
                filtered_lines.append(line)
            continue

        # Check for tags — always keep
        if "refs/tags/" in stripped:
            filtered_lines.append(line)
            continue

        # Check for remote refs
        remote_match = re.search(r"refs/remotes/[^/]+/([^\s]+)", stripped)
        if remote_match:
            branch_name = remote_match.group(1)
            if _is_allowed_branch_name(branch_name, sandbox_branch):
                filtered_lines.append(line)
            continue

        # Pass 2: Check first token as potential short refname
        # This handles custom --format output like %(refname:short)
        tokens = stripped.split()
        if tokens:
            first_token = tokens[0]
            # If it looks like a SHA (hex, >= 12 chars), check second token
            if (
                len(first_token) >= _MIN_SHA_LENGTH
                and all(c in "0123456789abcdefABCDEF" for c in first_token)
            ):
                # SHA-prefixed line with optional ref token (custom format)
                if len(tokens) >= 2:
                    if _is_allowed_short_ref_token(tokens[1], sandbox_branch):
                        filtered_lines.append(line)
                else:
                    filtered_lines.append(line)
                continue

            # First token might be a short/custom ref token.
            if _is_allowed_short_ref_token(first_token, sandbox_branch):
                filtered_lines.append(line)
            continue

        # Unrecognized format — keep (safe default)
        filtered_lines.append(line)

    return "".join(filtered_lines)


# ---------------------------------------------------------------------------
# Output Filtering: Log Decorations
# ---------------------------------------------------------------------------

# Matches SHA-anchored decoration lines in git log output:
#   "abc1234 (HEAD -> main, tag: v1.0, origin/feature)"
_DECORATION_LINE_RE = re.compile(
    r"^(?P<prefix>[0-9a-fA-F]+\s+)"   # SHA + whitespace
    r"\((?P<decorations>[^)]+)\)"       # parenthesized decorations
    r"(?P<suffix>.*)$"                  # rest of line
)

# Matches custom %d format decorations (parenthesized):
#   " (HEAD -> main, tag: v1.0, origin/feature)"
_CUSTOM_D_RE = re.compile(
    r"\((?P<decorations>[^)]+)\)"
)

# Matches custom %D format decorations (bare, no parens):
#   "HEAD -> main, tag: v1.0, origin/feature"
# Used when the entire line is decorations (--format=%D)


def _is_decoration_ref_allowed(ref: str, sandbox_branch: str) -> bool:
    """Check if a single decoration ref should be kept.

    Always keeps: HEAD, HEAD -> branch (if branch allowed), tags,
    detached HEAD annotations.
    """
    ref = ref.strip()
    if not ref:
        return True

    # HEAD is always kept
    if ref == "HEAD":
        return True

    # "HEAD -> branch" form
    if ref.startswith("HEAD -> "):
        branch = ref[len("HEAD -> "):]
        return _is_allowed_branch_name(branch, sandbox_branch)

    # Tags are always kept
    if ref.startswith("tag: "):
        return True

    # Remote tracking refs: "origin/branch"
    if "/" in ref:
        parts = ref.split("/", 1)
        if len(parts) == 2:
            # Could be origin/branch
            branch_name = parts[1]
            return _is_allowed_branch_name(branch_name, sandbox_branch)

    # Bare branch name
    return _is_allowed_branch_name(ref, sandbox_branch)


def _filter_decoration_refs(decorations: str, sandbox_branch: str) -> Optional[str]:
    """Filter individual refs within a decoration string.

    Args:
        decorations: Comma-separated decoration refs (without parens).
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered decoration string, or None if all refs were removed.
    """
    refs = [r.strip() for r in decorations.split(",")]
    allowed = [r for r in refs if _is_decoration_ref_allowed(r, sandbox_branch)]
    if not allowed:
        return None
    return ", ".join(allowed)


def _filter_log_decorations(output: str, sandbox_branch: str) -> str:
    """Filter SHA-anchored decoration lines in git log output.

    Handles standard ``git log --decorate`` format where decorations
    appear in parentheses after the commit SHA.

    Args:
        output: Raw stdout from a ``git log`` command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output with disallowed branch refs removed from decorations.
    """
    if not output:
        return output

    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")

        m = _DECORATION_LINE_RE.match(stripped)
        if m:
            prefix = m.group("prefix")
            decorations = m.group("decorations")
            suffix = m.group("suffix")
            filtered = _filter_decoration_refs(decorations, sandbox_branch)
            if filtered:
                filtered_lines.append(
                    prefix + "(" + filtered + ")" + suffix
                    + (line[len(stripped):])  # preserve trailing newline
                )
            else:
                # All decorations removed — emit line without parens
                filtered_lines.append(
                    prefix.rstrip() + suffix
                    + (line[len(stripped):])
                )
            continue

        # Not a decoration line — keep as-is
        filtered_lines.append(line)

    return "".join(filtered_lines)


def _filter_custom_format_decorations(output: str, sandbox_branch: str) -> str:
    """Filter custom --format=%d/%D decoration output.

    Handles both %d (parenthesized) and %D (bare) formats.

    Args:
        output: Raw stdout from a ``git log --format`` command with %d or %D.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output with disallowed refs removed from decorations.
    """
    if not output:
        return output

    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")
        trailing = line[len(stripped):]

        # Try parenthesized format (%d): " (HEAD -> main, origin/feature)"
        m = _CUSTOM_D_RE.search(stripped)
        if m:
            decorations = m.group("decorations")
            filtered = _filter_decoration_refs(decorations, sandbox_branch)
            if filtered:
                new_line = (
                    stripped[:m.start()]
                    + "(" + filtered + ")"
                    + stripped[m.end():]
                )
                filtered_lines.append(new_line + trailing)
            else:
                # Remove empty decoration entirely
                new_line = stripped[:m.start()] + stripped[m.end():]
                filtered_lines.append(new_line.rstrip() + trailing)
            continue

        # Try bare format (%D): "HEAD -> main, origin/feature"
        # Only if line contains comma-separated ref-like tokens
        if "," in stripped or stripped.startswith("HEAD"):
            # Heuristic: if the line looks like a decoration list
            tokens = [t.strip() for t in stripped.split(",")]
            looks_like_refs = any(
                t.startswith("HEAD") or t.startswith("tag: ")
                or "/" in t or _is_allowed_branch_name(t, sandbox_branch)
                for t in tokens if t
            )
            if looks_like_refs:
                filtered = _filter_decoration_refs(stripped, sandbox_branch)
                if filtered:
                    filtered_lines.append(filtered + trailing)
                else:
                    filtered_lines.append(trailing)
                continue

        filtered_lines.append(line)

    return "".join(filtered_lines)


def _log_has_custom_decoration_format(args: List[str]) -> bool:
    """Detect if git log args use --format/--pretty with %d or %D."""
    for idx, arg in enumerate(args):
        for prefix in ("--format=", "--pretty=", "--pretty=format:"):
            if arg.startswith(prefix):
                fmt = arg[len(prefix):]
                if "%d" in fmt or "%D" in fmt:
                    return True
        # Also check --format <value> and --pretty <value>
        if arg in ("--format", "--pretty") and idx + 1 < len(args):
            fmt = args[idx + 1]
            if "%d" in fmt or "%D" in fmt:
                return True
    return False


def _log_has_source_flag(args: List[str]) -> bool:
    """Detect if git log args include --source."""
    return "--source" in args


def _filter_log_source_refs(output: str, sandbox_branch: str) -> str:
    """Redact disallowed branch refs from --source output.

    --source adds a ref name column to log output. Disallowed refs/heads/
    branch names are replaced with [redacted].

    Args:
        output: Raw stdout from a ``git log --source`` command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Output with disallowed source refs redacted.
    """
    if not output:
        return output

    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")
        trailing = line[len(stripped):]

        # --source output has ref as a tab-separated column, typically:
        # "abc1234\trefs/heads/branch\trest..."
        # or it appears as a space-separated token after the SHA
        new_stripped = re.sub(
            r"refs/heads/([^\s]+)",
            lambda m: (
                m.group(0)
                if _is_allowed_branch_name(m.group(1), sandbox_branch)
                else "refs/heads/[redacted]"
            ),
            stripped,
        )
        filtered_lines.append(new_stripped + trailing)

    return "".join(filtered_lines)


# ---------------------------------------------------------------------------
# Output Filtering: Dispatch
# ---------------------------------------------------------------------------


def _filter_ref_listing_output(
    output: str,
    args: List[str],
    sandbox_branch: str,
) -> str:
    """Dispatch to the appropriate output filter based on git subcommand.

    Called after git command execution for commands that enumerate refs.
    Routes to branch listing, ref enumeration, or log decoration filters.

    Args:
        output: Raw stdout from the git command.
        args: The original git command args (without 'git' prefix).
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output.
    """
    if not output or not sandbox_branch:
        return output

    subcommand, sub_args, _ = _get_subcommand_args(args)
    if subcommand is None:
        return output

    # Branch listing
    if subcommand == "branch":
        return _filter_branch_output(output, sandbox_branch)

    # Ref enumeration commands
    if subcommand in _REF_ENUM_CMDS:
        return _filter_ref_enum_output(output, sandbox_branch)

    # Log with decorations
    if subcommand == "log":
        if _log_has_source_flag(sub_args):
            output = _filter_log_source_refs(output, sandbox_branch)
        if _log_has_custom_decoration_format(sub_args):
            return _filter_custom_format_decorations(output, sandbox_branch)
        return _filter_log_decorations(output, sandbox_branch)

    return output


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

    # Detect default branch from bare repo HEAD and inject into metadata
    # so that check_protected_branches() can protect it.
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
                    # Ensure protected_branches includes the default branch
                    protected = metadata.get("protected_branches", [])
                    if isinstance(protected, list) and default_branch not in protected:
                        protected = list(protected) + [default_branch]
                        metadata["protected_branches"] = protected
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
_FETCH_LOCK_POLL_INTERVAL = 1.0


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
