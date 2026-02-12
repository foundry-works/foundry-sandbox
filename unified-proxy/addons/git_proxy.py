"""
Git Proxy mitmproxy Addon

Handles git protocol operations with policy enforcement:
- Repo authorization: Container can only access repos in its metadata.repos list
- Branch deletion blocking: Prevents git push that would delete branches/tags
- Bot mode restrictions: In bot mode (auth_mode='bot'), pushes are restricted
  to sandbox/* branches only
- Push size limits: Rejects oversized pushes with 413 response

Security Model:
- Default deny: If no repos are configured, all git access is denied
- Deletion is never allowed: Branch and tag deletions are blocked
- Bot mode is restrictive: Only sandbox/* branches can be pushed

This addon runs AFTER container_identity (requires container config) and
BEFORE credential injection (git requests need auth before forwarding).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from io import BytesIO
from typing import Dict, List, Optional

from mitmproxy import http
from mitmproxy.flow import Flow

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config
import git_policies
from git_policies import check_protected_branches
from logging_config import get_logger
from pktline import PktLineRef, parse_pktline, read_pktline_prefix

logger = get_logger(__name__)

# Git path pattern: /<owner>/<repo>.git/<operation>
# Matches paths like: /octocat/hello-world.git/info/refs
GIT_PATH_PATTERN = re.compile(r"^/([^/]+)/([^/]+)\.git/(.+)$")

# Valid git operations (Smart HTTP protocol)
GIT_OPERATIONS = frozenset({"info/refs", "git-upload-pack", "git-receive-pack"})

# Metadata key for git operation info
GIT_METADATA_KEY = "git_operation"

# Push size limit (default: 100MB)
DEFAULT_MAX_PUSH_SIZE = 100 * 1024 * 1024

# Push rate limiting: per-container token bucket.
# Each push (git-receive-pack POST) consumes one token.
# This limits the rate at which restricted-path checks run,
# since each check creates a temp bare repo and spawns subprocesses.
PUSH_RATE_CAPACITY = int(os.environ.get("PUSH_RATE_CAPACITY", "10"))
PUSH_RATE_REFILL_PER_SEC = float(os.environ.get("PUSH_RATE_REFILL_PER_SEC", "1.0"))

# Sandbox branch pattern for bot mode
SANDBOX_BRANCH_PATTERN = re.compile(r"^refs/heads/sandbox/")

# Always-allowed repos for Claude plugin marketplaces (read-only)
# These are needed for installing plugins like pyright-lsp
ALLOWED_MARKETPLACES = frozenset({
    "anthropics/claude-plugins-official",
    "foundry-works/claude-foundry",
})


@dataclass
class GitOperation:
    """Represents a parsed git operation from the request."""

    owner: str
    repo: str
    operation: str
    is_write: bool
    refs: List[PktLineRef]
    push_size: int = 0
    pack_data: bytes = field(default=b"", repr=False)
    parse_error: Optional[str] = None

    def repo_path(self) -> str:
        """Return the owner/repo path."""
        return f"{self.owner}/{self.repo}"

    def to_dict(self) -> dict:
        """Convert to dictionary for metadata storage and logging."""
        data = {
            "owner": self.owner,
            "repo": self.repo,
            "operation": self.operation,
            "is_write": self.is_write,
            "push_size_bytes": self.push_size,
            "refs": [
                {
                    "refname": ref.refname,
                    "old_sha": ref.old_sha[:8],
                    "new_sha": ref.new_sha[:8] if not ref.is_deletion() else "(delete)",
                }
                for ref in self.refs
            ],
        }
        if self.parse_error:
            data["parse_error"] = self.parse_error
        return data


class GitProxyAddon:
    """Mitmproxy addon for git protocol handling with policy enforcement.

    This addon identifies git requests, validates them against container
    permissions, and enforces security policies (no deletions, bot mode
    branch restrictions, push size limits).
    """

    def __init__(self, max_push_size: int = DEFAULT_MAX_PUSH_SIZE):
        """Initialize the git proxy addon.

        Args:
            max_push_size: Maximum allowed push size in bytes (default 100MB).
        """
        self._max_push_size = max_push_size
        # Per-container push rate limiter: container_id -> (tokens, last_refill)
        self._push_buckets: Dict[str, list] = {}

    def load(self, loader):
        """Called when addon is loaded."""
        logger.info(f"Git proxy addon loaded (max_push_size={self._max_push_size})")

    def request(self, flow: http.HTTPFlow) -> None:
        """Process incoming request for git operations.

        This method:
        1. Identifies git requests by path pattern
        2. Checks repo authorization against container.repos
        3. Parses pkt-line data for push operations
        4. Enforces deletion blocking
        5. Enforces bot mode branch restrictions
        6. Enforces push size limits

        Args:
            flow: The mitmproxy HTTP flow.
        """
        # Parse git operation from path
        git_op = self._parse_git_request(flow)
        if git_op is None:
            # Not a git request - let it pass through
            return

        # Store git operation info in flow metadata for logging
        flow.metadata[GIT_METADATA_KEY] = git_op.to_dict()

        # Get container config (set by container_identity addon)
        container_config = get_container_config(flow)
        if container_config is None:
            # Container identity addon should have already denied the request
            # Log for debugging but don't create duplicate response
            logger.warning(
                f"Git request without container identity: "
                f"{git_op.owner}/{git_op.repo}"
            )
            return

        container_id = container_config.container_id
        metadata = container_config.metadata or {}

        # Check repo authorization
        # Support both "repo" (string) and "repos" (list) in metadata
        allowed_repos = metadata.get("repos", [])
        if not allowed_repos:
            # Fallback to singular "repo" field
            repo = metadata.get("repo")
            if repo:
                allowed_repos = [repo]
        if not self._is_repo_authorized(git_op, allowed_repos):
            self._deny_request(
                flow,
                f"Repository not authorized: {git_op.repo_path()}",
                container_id=container_id,
            )
            return

        # For write operations, apply additional checks
        if git_op.is_write:
            # Rate limit pushes to prevent resource exhaustion.
            # Each push triggers temp dir creation + subprocess spawning
            # for restricted-path checks, so rapid pushes are expensive.
            if self._check_push_rate_limit(container_id):
                self._deny_request(
                    flow,
                    "Push rate limit exceeded. Try again shortly.",
                    container_id=container_id,
                    status_code=429,
                )
                return

            # Fail closed on malformed push payloads.
            if git_op.parse_error:
                self._deny_request(
                    flow,
                    f"Malformed git push payload: {git_op.parse_error}",
                    container_id=container_id,
                )
                return

            # Check push size limit
            if git_op.push_size > self._max_push_size:
                self._deny_request(
                    flow,
                    f"Push size exceeds limit: {git_op.push_size} > {self._max_push_size}",
                    container_id=container_id,
                    status_code=413,
                )
                return

            # Check for branch deletions
            deletion_refs = [ref for ref in git_op.refs if ref.is_deletion()]
            if deletion_refs:
                ref_names = [ref.refname for ref in deletion_refs]
                self._deny_request(
                    flow,
                    f"Branch/tag deletion is not allowed: {', '.join(ref_names)}",
                    container_id=container_id,
                )
                return

            # Check protected branch enforcement (applies to all modes)
            bare_repo_path = metadata.get("bare_repo_path")
            for ref in git_op.refs:
                block_reason = check_protected_branches(
                    refname=ref.refname,
                    old_sha=ref.old_sha,
                    new_sha=ref.new_sha,
                    bare_repo_path=bare_repo_path,
                    metadata=metadata,
                )
                if block_reason:
                    self._deny_request(
                        flow,
                        block_reason,
                        container_id=container_id,
                    )
                    return

            # Check for restricted file paths (e.g., .github/workflows/)
            if bare_repo_path and os.path.isdir(bare_repo_path):
                restricted_msg = self._check_restricted_paths(
                    git_op.refs, bare_repo_path, git_op.pack_data,
                    git_policies.DEFAULT_RESTRICTED_PUSH_PATHS,
                )
                if restricted_msg:
                    self._deny_request(
                        flow,
                        restricted_msg,
                        container_id=container_id,
                    )
                    return
            else:
                # Fail closed if bare_repo_path is missing or invalid
                logger.warning(
                    "[restricted-path] check failed: bare_repo_path missing or invalid"
                )
                self._deny_request(
                    flow,
                    "Push blocked by security policy",
                    container_id=container_id,
                )
                return

            # Check bot mode restrictions
            auth_mode = metadata.get("auth_mode", "normal")
            if auth_mode == "bot":
                blocked = self._check_bot_mode_restrictions(git_op)
                if blocked:
                    self._deny_request(
                        flow,
                        blocked,
                        container_id=container_id,
                    )
                    return

        # Log the allowed git operation
        self._log_git_operation(git_op, container_id, allowed=True)

    def _parse_git_request(self, flow: http.HTTPFlow) -> Optional[GitOperation]:
        """Parse git operation from request path.

        Args:
            flow: The mitmproxy HTTP flow.

        Returns:
            GitOperation if this is a valid git request, None otherwise.
        """
        path = flow.request.path
        match = GIT_PATH_PATTERN.match(path)
        if not match:
            return None

        owner, repo, operation = match.groups()

        # Handle query string (e.g., info/refs?service=git-upload-pack)
        if "?" in operation:
            operation = operation.split("?")[0]

        # Validate operation
        if operation not in GIT_OPERATIONS:
            return None

        # Determine if this is a write operation
        is_write = operation == "git-receive-pack" and flow.request.method == "POST"

        # Parse pkt-line data for push operations
        refs: List[PktLineRef] = []
        push_size = 0
        pack_data = b""
        parse_error: Optional[str] = None

        if is_write:
            body = flow.request.content or b""
            push_size = len(body)

            # Parse pkt-line header to extract refs
            if not body:
                parse_error = "empty request body"
            else:
                stream = BytesIO(body)
                buf, pktline_end, err = read_pktline_prefix(stream)
                if err is not None:
                    parse_error = f"invalid pkt-line header ({err})"
                elif pktline_end is None:
                    parse_error = "invalid pkt-line header"
                else:
                    refs = parse_pktline(buf[:pktline_end])
                    if not refs:
                        parse_error = "no ref updates in pkt-line header"
                    # Extract pack data (everything after the pkt-line flush packet)
                    pack_data = body[pktline_end:] if pktline_end < len(body) else b""

        return GitOperation(
            owner=owner,
            repo=repo,
            operation=operation,
            is_write=is_write,
            refs=refs,
            push_size=push_size,
            pack_data=pack_data,
            parse_error=parse_error,
        )

    def _is_repo_authorized(
        self, git_op: GitOperation, allowed_repos: List[str]
    ) -> bool:
        """Check if the repository is in the container's allowed list.

        Args:
            git_op: The git operation being requested.
            allowed_repos: List of allowed repos in "owner/repo" format.

        Returns:
            True if the repo is authorized, False otherwise.
        """
        repo_path = git_op.repo_path()

        # Always allow read-only access to plugin marketplaces
        if not git_op.is_write and repo_path in ALLOWED_MARKETPLACES:
            return True

        if not allowed_repos:
            # No repos configured - deny all (default deny)
            return False

        return repo_path in allowed_repos

    def _check_bot_mode_restrictions(self, git_op: GitOperation) -> Optional[str]:
        """Check if push violates bot mode restrictions.

        In bot mode, pushes are only allowed to sandbox/* branches.

        Args:
            git_op: The git operation being requested.

        Returns:
            Error message if blocked, None if allowed.
        """
        for ref in git_op.refs:
            # Skip creation detection - only check the refname
            if not SANDBOX_BRANCH_PATTERN.match(ref.refname):
                return (
                    f"Bot mode: Push restricted to sandbox/* branches only. "
                    f"Attempted to push to: {ref.refname}"
                )
        return None

    def _check_push_rate_limit(self, container_id: str) -> bool:
        """Check if the container has exceeded its push rate limit.

        Uses a simple token bucket: each push consumes one token, tokens
        refill at PUSH_RATE_REFILL_PER_SEC, with max PUSH_RATE_CAPACITY.

        Args:
            container_id: The container making the push.

        Returns:
            True if the push should be rate-limited (blocked), False if allowed.
        """
        now = time.monotonic()
        bucket = self._push_buckets.get(container_id)

        if bucket is None:
            # First push from this container: full bucket minus one token
            self._push_buckets[container_id] = [PUSH_RATE_CAPACITY - 1, now]
            return False

        tokens, last_refill = bucket
        # Refill tokens based on elapsed time
        elapsed = now - last_refill
        tokens = min(PUSH_RATE_CAPACITY, tokens + elapsed * PUSH_RATE_REFILL_PER_SEC)

        if tokens < 1.0:
            # Not enough tokens — rate limited
            bucket[0] = tokens
            bucket[1] = now
            return True

        # Consume one token
        bucket[0] = tokens - 1
        bucket[1] = now
        return False

    def _make_clean_git_env(self, **extra) -> dict:
        """Build a minimal environment for git subprocesses in restricted-path checks.

        Uses only PATH (for finding the git binary) and HOME (required by git
        for config resolution). All GIT_* and SSH_* vars from the proxy's own
        environment are excluded to prevent interference (e.g., GIT_DIR,
        GIT_WORK_TREE, GIT_CONFIG_PARAMETERS could confuse the subprocess).
        """
        env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
        home = os.environ.get("HOME")
        if home:
            env["HOME"] = home
        env.update(extra)
        return env

    # THREADING: _check_restricted_paths is not thread-safe. It relies on
    # mitmproxy's default synchronous addon execution (no @concurrent decorator).
    # If concurrent execution is enabled, add a threading.Lock around the
    # entire method.
    def _check_restricted_paths(
        self,
        refs: List[PktLineRef],
        bare_repo_path: str,
        pack_data: bytes,
        restricted_paths: List[str],
    ) -> Optional[str]:
        """Check if a push modifies restricted file paths (e.g., .github/workflows/).

        Runs git diff-tree for each non-deletion ref in an isolated temporary bare
        repo whose alternate object store points at the real bare repo. When push
        pack data is present, it is unpacked into the temporary object store first.
        This also supports ref-only pushes with no pack payload (objects already on
        remote): diff-tree still runs and policy still applies. Fails closed on
        any error.

        Args:
            refs: List of ref updates from the push.
            bare_repo_path: Path to the bare git repository.
            pack_data: Raw pack data from the push request body.
            restricted_paths: List of path prefixes to block (no trailing slashes).

        Returns:
            None if allowed, generic error message if blocked or on any error.

        Note:
            The caller (request()) checks push size before calling this method.
            This defensive check ensures safety even if the call order is refactored.
        """
        # Defensive size check: reject oversized pack data even if the caller
        # didn't enforce the limit (e.g., due to future refactoring of request()).
        if len(pack_data) > self._max_push_size:
            logger.warning(
                f"[restricted-path] pack_data exceeds max push size "
                f"({len(pack_data)} > {self._max_push_size})"
            )
            return "Push blocked by security policy"

        GIT_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf899d69f82623700"
        ZERO_SHA = "0" * 40
        SUBPROCESS_TIMEOUT = 10

        # Normalize restricted paths (defensive against trailing slash misconfiguration)
        normalized_paths = [p.rstrip("/") for p in restricted_paths]

        tmp_dir = None
        try:
            tmp_dir = tempfile.mkdtemp(prefix="git-restricted-check-")

            # Initialize a temporary bare repo
            subprocess.run(
                ["git", "init", "--bare", tmp_dir],
                env=self._make_clean_git_env(),
                capture_output=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=True,
            )

            # Write alternates file so temp repo can resolve base objects from the real bare repo.
            #
            # TRUST BOUNDARY: The alternates file grants the temp repo read access
            # to all objects in the real bare repo's object store. If a pack parser
            # exploit compromises the temp repo, it could read (but not write) the
            # real repo's objects. This is an accepted tradeoff: the temp repo needs
            # access to resolve base objects for diff-tree, and the real bare repo
            # is already readable by the proxy process. The temp dir is cleaned up
            # in the finally block regardless of success or failure.
            objects_info_dir = os.path.join(tmp_dir, "objects", "info")
            os.makedirs(objects_info_dir, exist_ok=True)
            alternates_path = os.path.join(objects_info_dir, "alternates")
            with open(alternates_path, "w") as f:
                f.write(os.path.join(bare_repo_path, "objects") + "\n")

            # Unpack the pack data into the temp repo if present
            if pack_data:
                result = subprocess.run(
                    ["git", "unpack-objects"],
                    input=pack_data,
                    env=self._make_clean_git_env(
                        GIT_OBJECT_DIRECTORY=os.path.join(tmp_dir, "objects"),
                    ),
                    capture_output=True,
                    timeout=SUBPROCESS_TIMEOUT,
                    cwd=tmp_dir,
                )
                if result.returncode != 0:
                    logger.warning(
                        f"[restricted-path] git unpack-objects failed: "
                        f"{result.stderr.decode(errors='replace')[:200]}"
                    )
                    return "Push blocked by security policy"

            # Check each non-deletion ref for restricted path changes
            for ref in refs:
                if ref.new_sha == ZERO_SHA:
                    continue  # Skip deletions

                old_sha = ref.old_sha if ref.old_sha != ZERO_SHA else GIT_EMPTY_TREE_SHA

                diff_result = subprocess.run(
                    ["git", "--git-dir", tmp_dir, "diff-tree", "--name-only", "-r",
                     old_sha, ref.new_sha],
                    env=self._make_clean_git_env(),
                    capture_output=True,
                    timeout=SUBPROCESS_TIMEOUT,
                )
                if diff_result.returncode != 0:
                    logger.warning(
                        f"[restricted-path] git diff-tree failed for {ref.refname}: "
                        f"{diff_result.stderr.decode(errors='replace')[:200]}"
                    )
                    return "Push blocked by security policy"

                changed_files = diff_result.stdout.decode(errors="replace").strip().splitlines()
                for line in changed_files:
                    for restricted in normalized_paths:
                        if line == restricted or line.startswith(restricted + "/"):
                            logger.info(
                                f"[restricted-path] Blocked push modifying "
                                f"restricted path: {line} (matched {restricted})"
                            )
                            return "Push blocked by security policy"

            return None

        except subprocess.TimeoutExpired:
            logger.warning("[restricted-path] Subprocess timed out during restricted-path check")
            return "Push blocked by security policy"
        except Exception as exc:
            logger.warning(f"[restricted-path] Error during restricted-path check: {exc}")
            return "Push blocked by security policy"
        finally:
            if tmp_dir and os.path.isdir(tmp_dir):
                try:
                    shutil.rmtree(tmp_dir)
                except OSError as cleanup_err:
                    logger.warning(
                        f"[restricted-path] Failed to clean up temp dir "
                        f"{tmp_dir}: {cleanup_err}"
                    )

    def _log_git_operation(
        self, git_op: GitOperation, container_id: str, allowed: bool
    ) -> None:
        """Log a git operation with structured data.

        Args:
            git_op: The git operation.
            container_id: Container making the request.
            allowed: Whether the operation was allowed.
        """
        decision = "ALLOW" if allowed else "DENY"
        log_fn = logger.info if allowed else logger.warning

        log_fn(
            f"Git {decision}: {git_op.operation} {git_op.repo_path()} - "
            f"container={container_id} - "
            f"is_write={git_op.is_write} - "
            f"push_size_bytes={git_op.push_size} - "
            f"refs={len(git_op.refs)}"
        )

    def _deny_request(
        self,
        flow: http.HTTPFlow,
        reason: str,
        container_id: Optional[str] = None,
        status_code: int = 403,
    ) -> None:
        """Deny the request with an error response.

        Args:
            flow: The mitmproxy HTTP flow.
            reason: Human-readable reason for denial.
            container_id: Container ID for logging.
            status_code: HTTP status code (403, 413, 429).
        """
        # Log the denial with git operation info
        git_op_info = flow.metadata.get(GIT_METADATA_KEY, {})
        logger.warning(
            f"Git DENY: {reason} - "
            f"container={container_id or 'unknown'} - "
            f"repo={git_op_info.get('owner', '?')}/{git_op_info.get('repo', '?')} - "
            f"operation={git_op_info.get('operation', '?')}"
        )

        # Determine status message
        status_messages = {
            413: "Request Entity Too Large",
            429: "Too Many Requests",
        }
        status_message = status_messages.get(status_code, "Forbidden")

        # Create error response
        headers = {"Content-Type": "text/plain"}
        if status_code == 429:
            headers["Retry-After"] = "5"

        flow.response = http.Response.make(
            status_code,
            f"{status_message}: {reason}".encode(),
            headers,
        )


def get_git_operation(flow: Flow) -> Optional[dict]:
    """Helper function to get git operation info from flow metadata.

    This allows downstream addons to check git operation details.

    Args:
        flow: The mitmproxy flow.

    Returns:
        Git operation dict if available, None otherwise.
    """
    return flow.metadata.get(GIT_METADATA_KEY)


# Export addon class for mitmproxy
addons = [GitProxyAddon()]
