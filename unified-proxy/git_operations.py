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

Command validation lives in git_command_validation.py.
Subprocess helpers live in git_subprocess.py.
This module re-exports both for backward compatibility.
"""

import asyncio
import base64
import contextlib
import logging
import os
import re
import subprocess
import uuid
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from git_policies import check_protected_branches
from branch_types import (
    GIT_BINARY,
    SHA_CHECK_TIMEOUT,
    ValidationError,
    get_subcommand,
    get_subcommand_args,
)
from branch_isolation import (
    resolve_bare_repo_path,
    validate_branch_isolation,
    validate_sha_reachability,
)
from branch_output_filter import (
    filter_ref_listing_output,
    filter_stderr_branch_refs,
)

# Re-export from git_command_validation for backward compatibility
from git_command_validation import (  # noqa: F401
    ALLOWED_COMMANDS,
    COMMAND_BLOCKED_FLAGS,
    CONFIG_ALLOWED_FLAGS,
    CONFIG_NEVER_ALLOW,
    CONFIG_PERMITTED_PREFIXES,
    GLOBAL_BLOCKED_FLAGS,
    GitExecRequest,
    GitExecResponse,
    MAX_ARG_LENGTH,
    MAX_ARGS_COUNT,
    MAX_CONCURRENT_PER_SANDBOX,
    MAX_REQUEST_BODY_SIZE,
    MAX_RESPONSE_SIZE,
    MAX_STDIN_SIZE,
    REMOTE_ALLOWED_SUBCOMMANDS,
    REMOTE_BLOCKED_SUBCOMMANDS,
    SUBPROCESS_TIMEOUT,
    _strip_clone_config_overrides,
    validate_clone_args,
    validate_command,
    validate_path,
    validate_path_args,
    validate_request,
)

# Re-export from git_subprocess for backward compatibility
from git_subprocess import (  # noqa: F401
    ENV_ALLOWED,
    ENV_PREFIX_STRIP,
    ENV_VARS_TO_CLEAR,
    _FETCH_LOCK_FILENAME,
    _FETCH_LOCK_POLL_INTERVAL,
    _FETCH_LOCK_TIMEOUT,
    _fetch_lock,
    _get_remote_names_from_config,
    _git_config_get,
    _git_config_get_all,
    _read_remote_urls_from_bare_config,
    _synthesize_remote_verbose_output,
    build_clean_env,
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
# Protected Branch Enforcement (push operations)
# ---------------------------------------------------------------------------

# SHA used by git_policies to detect creation/deletion operations.
_ZERO_SHA = "0" * 40

# Synthetic SHAs for policy checks where real SHAs are unavailable.
# Any non-zero SHA signals "existing ref" to check_protected_branches.
_SYNTHETIC_OLD_SHA = "1" * 40
_SYNTHETIC_NEW_SHA = "2" * 40

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


def _detect_default_branch(bare_repo_path: str) -> Optional[str]:
    """Detect the default branch name from a bare repo's HEAD symref.

    Runs ``git symbolic-ref HEAD`` against the bare repo and extracts
    the branch name from the ``refs/heads/`` prefix.

    Args:
        bare_repo_path: Path to the bare git repository.

    Returns:
        The branch name (e.g. ``"main"``), or None if detection fails.
    """
    try:
        result = subprocess.run(
            [GIT_BINARY, "--git-dir", bare_repo_path,
             "symbolic-ref", "HEAD"],
            capture_output=True, timeout=SHA_CHECK_TIMEOUT,
        )
        if result.returncode == 0:
            head_ref = result.stdout.decode().strip()
            if head_ref.startswith("refs/heads/"):
                return head_ref[len("refs/heads/"):]
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _inject_default_branch_protection(
    metadata: dict, default_branch: str,
) -> dict:
    """Return a shallow copy of *metadata* with the default branch added to protected patterns.

    Adds ``refs/heads/<default_branch>`` to
    ``metadata["git"]["protected_branches"]["patterns"]`` if not already present.
    Never mutates the caller's metadata dict.

    Args:
        metadata: Container metadata dict.
        default_branch: The default branch name to protect.

    Returns:
        A (possibly shallow-copied) metadata dict with the pattern added.
    """
    default_pattern = f"refs/heads/{default_branch}"
    git_config = metadata.get("git", {})
    if not isinstance(git_config, dict):
        git_config = {}
    pb_config = git_config.get("protected_branches", {})
    if not isinstance(pb_config, dict):
        pb_config = {}
    patterns = list(pb_config.get("patterns", []))
    if default_pattern not in patterns:
        patterns.append(default_pattern)
        metadata = dict(metadata)
        metadata["git"] = dict(git_config)
        metadata["git"]["protected_branches"] = dict(pb_config)
        metadata["git"]["protected_branches"]["patterns"] = patterns
    return metadata


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
    bare_repo_path = resolve_bare_repo_path(repo_root)

    # Detect default branch from bare repo HEAD and inject into metadata
    # so that load_branch_policy() protects it.  Best-effort: if detection
    # fails, the existing protected set still applies.
    if bare_repo_path and metadata is not None:
        default_branch = _detect_default_branch(bare_repo_path)
        if default_branch:
            metadata = _inject_default_branch_protection(metadata, default_branch)

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
                old_sha=_SYNTHETIC_OLD_SHA,
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
            old_sha=_SYNTHETIC_OLD_SHA,   # Non-zero: treat as update
            new_sha=_SYNTHETIC_NEW_SHA,   # Non-zero: treat as update
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
                    old_sha=_SYNTHETIC_OLD_SHA,
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
                extra_allowed = {
                    cmd for cmd in extra
                    if isinstance(cmd, str)
                    and re.fullmatch(r"[a-z][a-z0-9-]*", cmd)
                }

    # Generate request ID for audit correlation
    req_id = str(uuid.uuid4())

    args = request.args

    # Clone-specific validation (repo allowlist + destination allowlist)
    clone_allowed_roots = None
    clone_extra, clone_err = validate_clone_args(args, metadata)
    if clone_err:
        audit_log(
            event="clone_blocked",
            action="clone",
            decision="deny",
            command_args=args,
            reason=clone_err.reason,
            matched_rule="clone_validation",
            request_id=req_id,
        )
        return None, clone_err
    if clone_extra:
        clone_allowed_roots = clone_extra
        args = _strip_clone_config_overrides(args)

    # Validate command
    err = validate_command(args, extra_allowed)
    if err:
        audit_log(
            event="command_blocked",
            action=" ".join(args[:3]),
            decision="deny",
            command_args=args,
            reason=err.reason,
            matched_rule="command_validation",
            request_id=req_id,
        )
        return None, err

    # Validate branch isolation
    err = validate_branch_isolation(args, metadata)
    if err:
        audit_log(
            event="branch_isolation_blocked",
            action=" ".join(args[:3]),
            decision="deny",
            command_args=args,
            reason=err.reason,
            matched_rule="branch_isolation",
            request_id=req_id,
        )
        return None, err

    # Validate SHA reachability (must follow branch isolation check)
    err = validate_sha_reachability(args, repo_root, metadata)
    if err:
        audit_log(
            event="sha_reachability_blocked",
            action=" ".join(args[:3]),
            decision="deny",
            command_args=args,
            reason=err.reason,
            matched_rule="sha_reachability",
            request_id=req_id,
        )
        return None, err

    # Validate working directory
    resolved_cwd, err = validate_path(request.cwd, repo_root)
    if err:
        audit_log(event="path_blocked", action=" ".join(args[:3]),
                  decision="deny", command_args=args, reason=err.reason,
                  matched_rule="path_validation", request_id=req_id)
        return None, err

    # Validate path args
    err = validate_path_args(
        args, repo_root, extra_allowed_roots=clone_allowed_roots
    )
    if err:
        audit_log(event="path_blocked", action=" ".join(args[:3]),
                  decision="deny", command_args=args, reason=err.reason,
                  matched_rule="path_arg_validation", request_id=req_id)
        return None, err

    # Check protected branches for push operations
    push_args = _extract_push_args(args)
    if push_args is not None:
        err = check_push_protected_branches(push_args, repo_root, metadata)
        if err:
            audit_log(event="push_blocked", action="push",
                      decision="deny", command_args=args, reason=err.reason,
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
    for arg in args:
        if not arg.startswith("-") and os.path.isabs(arg):
            if arg == client_root or arg.startswith(client_root + "/"):
                arg = real_repo + arg[len(client_root):]
        translated_args.append(arg)

    # Build command — inject hook-disabling flags before client args.
    # core.hooksPath=/dev/null  -> disables all git hooks
    # core.fsmonitor=false      -> disables fs-monitor (can execute arbitrary commands)
    # Safe because CONFIG_NEVER_ALLOW blocks clients from sending either key.
    cmd = [
        GIT_BINARY,
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
    ] + translated_args

    # Build clean environment
    env = build_clean_env()

    # Fetch locking: serialize concurrent fetch/pull per bare repo
    subcommand = get_subcommand(args)
    fetch_lock_ctx: Optional[contextlib.AbstractContextManager] = None
    if subcommand in ("fetch", "pull"):
        # Check break-glass override
        allow_unlocked = os.environ.get("FOUNDRY_ALLOW_UNLOCKED_FETCH") == "1"
        bare_repo = resolve_bare_repo_path(resolved_cwd)
        if bare_repo is None and not allow_unlocked:
            audit_log(
                event="fetch_lock_unavailable",
                action=subcommand,
                decision="deny",
                command_args=args,
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
                command_args=args,
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
            action=subcommand or " ".join(args[:3]),
            decision="deny",
            command_args=args,
            reason=str(exc),
            matched_rule="fetch_lock",
            request_id=req_id,
        )
        return None, ValidationError(
            "Fetch lock timed out; another fetch may be in progress"
        )
    except subprocess.TimeoutExpired:
        audit_log(event="command_timeout", action=" ".join(args[:3]),
                  decision="deny", command_args=args, reason="Command timed out",
                  matched_rule="timeout", request_id=req_id)
        return None, ValidationError("Command timed out")
    except OSError as exc:
        logger.error("Git execution failed: %s", exc)
        audit_log(event="command_error", action=" ".join(args[:3]),
                  decision="deny", command_args=args, reason=str(exc),
                  matched_rule="os_error", request_id=req_id)
        return None, ValidationError(f"Execution error: {exc}")

    exit_code = result.returncode

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
    # (e.g., /git-workspace -> /workspace for rev-parse --show-toplevel)
    client_root = os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
    if repo_root and client_root and repo_root != client_root:
        real_repo = os.path.realpath(repo_root)
        if stdout_str:
            stdout_str = stdout_str.replace(real_repo, client_root)
        if stderr_str:
            stderr_str = stderr_str.replace(real_repo, client_root)

    # Fallback: synthesize remote output when empty or command failed
    if subcommand == "remote" and stdout_str.strip() == "":
        subcmd, sub_args, _ = get_subcommand_args(args)
        bare_repo = resolve_bare_repo_path(resolved_cwd)
        remotes_from_file = _read_remote_urls_from_bare_config(bare_repo)
        if sub_args and "get-url" in sub_args:
            idx = sub_args.index("get-url")
            remote_name = "origin"
            if idx + 1 < len(sub_args) and not sub_args[idx + 1].startswith("-"):
                remote_name = sub_args[idx + 1]
            url = _git_config_get(
                resolved_cwd, env, f"remote.{remote_name}.url", git_dir=bare_repo
            )
            if not url and remote_name in remotes_from_file:
                url = remotes_from_file[remote_name].get("url")
            if url:
                audit_log(
                    event="remote_output_synthesized",
                    action="remote get-url",
                    decision="allow",
                    command_args=args,
                    request_id=req_id,
                    reason="Synthesized get-url output from bare repo config",
                )
                stdout_str = url + "\n"
                stdout_b64 = None
                exit_code = 0
                stderr_str = ""
        if stdout_str.strip() == "" and (sub_args and "-v" in sub_args):
            synthesized = _synthesize_remote_verbose_output(
                resolved_cwd, env, git_dir=bare_repo
            )
            if synthesized:
                audit_log(
                    event="remote_output_synthesized",
                    action="remote -v",
                    decision="allow",
                    command_args=args,
                    request_id=req_id,
                    reason="Synthesized verbose remote output from bare repo config",
                )
                stdout_str = synthesized
                stdout_b64 = None
                exit_code = 0
                stderr_str = ""

    # Apply branch isolation output filtering
    sandbox_branch = metadata.get("sandbox_branch") if metadata else None
    base_branch = metadata.get("from_branch") if metadata else None
    if sandbox_branch and stdout_str:
        stdout_str = filter_ref_listing_output(
            stdout_str, args, sandbox_branch, base_branch
        )
    if sandbox_branch and stderr_str:
        stderr_str = filter_stderr_branch_refs(
            stderr_str, sandbox_branch, base_branch
        )

    response = GitExecResponse(
        exit_code=exit_code,
        stdout=stdout_str,
        stderr=stderr_str,
        stdout_b64=stdout_b64,
        truncated=truncated,
    )

    audit_log(
        event="command_executed",
        action=" ".join(args[:3]),
        decision="allow",
        command_args=args,
        exit_code=exit_code,
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

    # Single-threaded event loop: no await between check and acquire,
    # so no other coroutine can interleave.
    if semaphore.locked():
        return None, ValidationError(
            f"Too many concurrent operations for sandbox {sandbox_id}"
        )

    async with semaphore:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, execute_git, request, repo_root, metadata
        )
