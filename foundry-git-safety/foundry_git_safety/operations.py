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
import logging
import os
import re
import subprocess
import threading
import uuid
from typing import Any

from .branch_types import (
    GIT_BINARY,
    ValidationError,
    get_subcommand,
    get_subcommand_args,
)
from .branch_isolation import (
    normalize_pathspec_args,
    resolve_bare_repo_path,
    validate_branch_isolation,
    validate_sha_reachability,
)
from .branch_output_filter import (
    filter_ref_listing_output,
    filter_stderr_branch_refs,
)
from .command_validation import (
    GitExecRequest,
    GitExecResponse,
    MAX_CONCURRENT_PER_SANDBOX,
    MAX_RESPONSE_SIZE,
    SUBPROCESS_TIMEOUT,
    _strip_clone_config_overrides,
    validate_clone_args,
    validate_command,
    validate_path,
    validate_path_args,
)
from .commit_validation import check_commit_file_restrictions
from .push_validation import (
    check_push_file_restrictions,
    check_push_protected_branches,
    extract_push_args,
    normalize_push_args,
    strip_credential_config_overrides,
)
from .subprocess_env import (
    build_clean_env,
    remove_stale_config_locks,
    _fetch_lock,
    _git_config_get,
    _read_remote_urls_from_bare_config,
    _synthesize_remote_verbose_output,
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
    command_args: list[str] | None = None,
    sandbox_id: str | None = None,
    source_ip: str | None = None,
    container_id: str | None = None,
    request_id: str | None = None,
    reason: str | None = None,
    matched_rule: str | None = None,
    exit_code: int | None = None,
    stdout: str | None = None,
    stderr: str | None = None,
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
    entry: dict[str, Any] = {
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
    """Per-sandbox concurrency limiter using asyncio semaphores.

    Uses asyncio.Semaphore for async concurrency control in
    execute_git_async(). A threading.Lock protects dict access since
    the pool may be accessed from both the async event loop and
    Flask/Werkzeug handler threads.
    """

    def __init__(self, max_concurrent: int = MAX_CONCURRENT_PER_SANDBOX):
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._max = max_concurrent
        self._lock = threading.Lock()

    def get(self, sandbox_id: str) -> asyncio.Semaphore:
        with self._lock:
            if sandbox_id not in self._semaphores:
                self._semaphores[sandbox_id] = asyncio.Semaphore(self._max)
            return self._semaphores[sandbox_id]

    def cleanup(self, sandbox_id: str) -> None:
        with self._lock:
            self._semaphores.pop(sandbox_id, None)


# Module-level semaphore pool
_semaphore_pool = SandboxSemaphorePool()


# ---------------------------------------------------------------------------
# Git Execution
# ---------------------------------------------------------------------------

# Git output prefixes that reliably precede path segments.
_TRANSLATE_PREFIXES = (
    "M ", "A ", "D ", "R ", "C ", "U ",  # status short format
    "fatal: ", "error: ", "warning: ",    # git messages
    "# ",                                # comments (e.g. commit template)
)

# Subcommands whose output is known to contain repo paths.
_PATH_TRANSLATE_SUBCOMMANDS = frozenset({
    "rev-parse", "status", "diff", "log", "show", "ls-files",
    "ls-tree", "blame", "grep", "add", "reset", "checkout",
    "commit", "merge", "rebase", "stash", "remote", "fetch",
    "pull", "push", "branch", "worktree", "submodule",
})


def _translate_paths(text: str, real_repo: str, client_root: str) -> str:
    """Replace real repo root with client root on lines that look like git output.

    Only translates lines that either start with the repo path, contain the repo
    path after whitespace, or start with a known git output prefix (fatal:,
    error:, status codes, etc.). This avoids corrupting file content in commits
    or diffs that legitimately contains the repo path string.
    """
    lines = []
    for line in text.split("\n"):
        stripped = line.strip()
        should_translate = (
            stripped.startswith(real_repo)
            or f" {real_repo}" in line
            or f"\t{real_repo}" in line
            or any(stripped.startswith(p) for p in _TRANSLATE_PREFIXES)
        )
        if should_translate:
            line = line.replace(real_repo, client_root)
        lines.append(line)
    return "\n".join(lines)


def execute_git(
    request: GitExecRequest,
    repo_root: str,
    metadata: dict[str, Any] | None = None,
) -> tuple[GitExecResponse | None, ValidationError | None]:
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

    # Strip credential config overrides injected by tools like GitHub CLI.
    # The proxy manages credentials independently, so these are redundant.
    args, creds_stripped = strip_credential_config_overrides(args)
    if creds_stripped:
        audit_log(
            event="credential_config_stripped",
            action=" ".join(args[:3]) if args else "unknown",
            decision="allow",
            command_args=args,
            reason="Stripped -c credential.*=... overrides (proxy manages credentials)",
            matched_rule="credential_config_strip",
            request_id=req_id,
        )

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

    # Auto-expand bare push commands with the sandbox branch
    args, push_expanded = normalize_push_args(args, metadata)
    if push_expanded:
        audit_log(
            event="push_auto_expanded",
            action="push",
            decision="allow",
            command_args=args,
            reason="Bare push auto-expanded with sandbox branch",
            matched_rule="push_normalization",
            request_id=req_id,
        )

    # Auto-insert -- for ref-reading commands when args look like file paths
    args, pathspec_expanded = normalize_pathspec_args(args, metadata)
    if pathspec_expanded:
        audit_log(
            event="pathspec_auto_expanded",
            action=" ".join(args[:3]),
            decision="allow",
            command_args=args,
            reason="Auto-inserted -- before path-like arguments",
            matched_rule="pathspec_normalization",
            request_id=req_id,
        )

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
    push_args = extract_push_args(args)
    if push_args is not None:
        err = check_push_protected_branches(push_args, repo_root, metadata)
        if err:
            audit_log(event="push_blocked", action="push",
                      decision="deny", command_args=args, reason=err.reason,
                      matched_rule="protected_branch", request_id=req_id)
            return None, err

        # Check file restrictions for push operations
        err = check_push_file_restrictions(push_args, repo_root, metadata)
        if err:
            audit_log(event="push_blocked", action="push",
                      decision="deny", command_args=args, reason=err.reason,
                      matched_rule="file_restriction", request_id=req_id)
            return None, err

    # Check file restrictions for commit operations
    if get_subcommand(args) == "commit":
        err = check_commit_file_restrictions(repo_root, metadata)
        if err:
            audit_log(event="commit_blocked", action="commit",
                      decision="deny", command_args=args, reason=err.reason,
                      matched_rule="file_restriction", request_id=req_id)
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
    cmd = [
        GIT_BINARY,
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
    ] + translated_args

    # Build clean environment
    env = build_clean_env()

    # Fetch locking: serialize concurrent fetch/pull per bare repo
    subcommand = get_subcommand(args)
    fetch_lock_ctx: contextlib.AbstractContextManager | None = None
    if subcommand in ("fetch", "pull"):
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
                "Cannot resolve repository for fetch locking; "
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

    # Stale lock cleanup: remove config.lock before push -u
    if subcommand == "push":
        remove_stale_config_locks(resolved_cwd)

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

    # Translate proxy-side paths back to client-side paths in output.
    client_root = os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
    if repo_root and client_root and repo_root != client_root:
        real_repo = os.path.realpath(repo_root)
        if subcommand in _PATH_TRANSLATE_SUBCOMMANDS:
            if stdout_str:
                stdout_str = _translate_paths(stdout_str, real_repo, client_root)
            if stderr_str:
                stderr_str = _translate_paths(stderr_str, real_repo, client_root)

    # Fallback: synthesize remote output when empty or command failed
    if subcommand == "remote" and stdout_str.strip() == "":
        _, sub_args, _, _ = get_subcommand_args(args)
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
        if stdout_str.strip() == "" and (sub_args and ("-v" in sub_args or "--verbose" in sub_args)):
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
        request_id=req_id,
    )

    return response, None


async def execute_git_async(
    request: GitExecRequest,
    repo_root: str,
    sandbox_id: str,
    metadata: dict[str, Any] | None = None,
) -> tuple[GitExecResponse | None, ValidationError | None]:
    """Execute git command with per-sandbox concurrency control.

    Uses a non-blocking acquire to reject immediately when at capacity
    rather than queuing requests indefinitely.
    """
    semaphore = _semaphore_pool.get(sandbox_id)

    # Atomic non-blocking acquire: avoids race between check and acquire.
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=0)
    except asyncio.TimeoutError:
        return None, ValidationError(
            f"Too many concurrent operations for sandbox {sandbox_id}"
        )

    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, execute_git, request, repo_root, metadata
        )
    finally:
        semaphore.release()
