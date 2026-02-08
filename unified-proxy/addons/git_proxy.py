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
import sys
from dataclasses import dataclass
from io import BytesIO
from typing import List, Optional

from mitmproxy import ctx, http
from mitmproxy.flow import Flow

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config
from git_policies import check_protected_branches
from pktline import PktLineRef, parse_pktline, read_pktline_prefix

# Git path pattern: /<owner>/<repo>.git/<operation>
# Matches paths like: /octocat/hello-world.git/info/refs
GIT_PATH_PATTERN = re.compile(r"^/([^/]+)/([^/]+)\.git/(.+)$")

# Valid git operations (Smart HTTP protocol)
GIT_OPERATIONS = frozenset({"info/refs", "git-upload-pack", "git-receive-pack"})

# Metadata key for git operation info
GIT_METADATA_KEY = "git_operation"

# Push size limit (default: 100MB)
DEFAULT_MAX_PUSH_SIZE = 100 * 1024 * 1024

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

    def load(self, loader):
        """Called when addon is loaded."""
        ctx.log.info(f"Git proxy addon loaded (max_push_size={self._max_push_size})")

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
            ctx.log.warn(
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

        return GitOperation(
            owner=owner,
            repo=repo,
            operation=operation,
            is_write=is_write,
            refs=refs,
            push_size=push_size,
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
        log_fn = ctx.log.info if allowed else ctx.log.warn

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
            status_code: HTTP status code (403 for forbidden, 413 for too large).
        """
        # Log the denial with git operation info
        git_op_info = flow.metadata.get(GIT_METADATA_KEY, {})
        ctx.log.warn(
            f"Git DENY: {reason} - "
            f"container={container_id or 'unknown'} - "
            f"repo={git_op_info.get('owner', '?')}/{git_op_info.get('repo', '?')} - "
            f"operation={git_op_info.get('operation', '?')}"
        )

        # Determine status message
        if status_code == 413:
            status_message = "Request Entity Too Large"
        else:
            status_message = "Forbidden"

        # Create error response
        flow.response = http.Response.make(
            status_code,
            f"{status_message}: {reason}".encode(),
            {"Content-Type": "text/plain"},
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
