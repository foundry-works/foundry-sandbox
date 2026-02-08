"""
Policy Engine mitmproxy Addon

Centralized policy enforcement with documented evaluation order and comprehensive
logging. Acts as the coordination point for all policy decisions in the unified proxy.

Evaluation Order:
1. Identity verification (via container_identity addon)
2. Allowlist checks (domain/path allowlist from allowlist.yaml)
3. Blocklist checks (explicit denies, e.g., merge/release endpoints)
3b. Body inspection (PATCH PR/issue close via state:closed)
4. Rate limiting (via rate_limiter addon - future)
5. Circuit breaker (via circuit_breaker addon - future)

Default Deny:
- If no policy explicitly allows a request, it is denied
- Every request receives an explicit allow/deny decision with reason
- Allowlist is loaded from config/allowlist.yaml via config.py

Policy Decision Logging:
- All policy decisions are logged with structured data
- Decisions stored in flow.metadata for downstream use
- Includes: container_id, method, host, path, decision, reason

GitHub Security Policies:
- Blocks PUT /repos/*/pulls/*/merge (prevents merging PRs)
- Blocks POST /repos/*/releases (prevents creating releases)
- Blocks PATCH /repos/*/pulls/* with state:closed (prevents closing PRs)
- Blocks PATCH /repos/*/issues/* with state:closed (prevents closing issues)
"""

import json
import os
import posixpath
import re
import sys
from typing import Optional, List
from urllib.parse import unquote, urlparse

from mitmproxy import http, ctx
from mitmproxy.flow import Flow

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config
from config import (
    load_allowlist_config,
    AllowlistConfig,
    ConfigError,
    segment_match,
)

# Metadata key for policy decisions
POLICY_DECISION_KEY = "policy_decision"

# GitHub patterns for blocked operations
GITHUB_MERGE_PR_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/merge$")
GITHUB_CREATE_RELEASE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/releases$")
GITHUB_GIT_REFS_ROOT_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/git/refs$")
GITHUB_GIT_REFS_SUBPATH_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/git/refs/.+$")
# Defense-in-depth: also blocked in github-api-filter.py
GITHUB_AUTO_MERGE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$")
GITHUB_DELETE_REVIEW_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$")

# GitHub patterns for body-inspected PATCH operations
GITHUB_PATCH_PR_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+$")
GITHUB_PATCH_ISSUE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/issues/\d+$")
# Defense-in-depth: also blocked at GraphQL level in github-api-filter.py
GITHUB_PR_REVIEW_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$")

# Global allowlist configuration (loaded in load())
_allowlist_config: Optional[AllowlistConfig] = None


def normalize_path(raw_path: str) -> Optional[str]:
    """Normalize a URL path with strict security rules.

    Steps:
    1. Strip query string and fragment
    2. URL-decode once
    3. Reject if '%' still present (double-encoding prevention — legitimate
       GitHub API paths never contain percent-encoded characters)
    4. Collapse repeated slashes (// → /)
    5. Resolve .. segments via posixpath.normpath
    6. Strip trailing slash (except bare /)

    Note on mitmproxy interaction: mitmproxy may partially decode URLs before
    they reach addons. This function applies a full decode pass regardless,
    which is safe because decoding an already-decoded string is a no-op for
    legitimate paths. The double-encoding check catches attack payloads that
    survive mitmproxy's initial decode.

    Args:
        raw_path: The raw URL path (may include query string).

    Returns:
        Normalized path string, or None if the path is rejected
        (e.g., double-encoding detected).
    """
    # Step 1: Strip query string and fragment
    path = urlparse(raw_path).path

    # Step 2: URL-decode once
    path = unquote(path)

    # Step 3: Reject double-encoding (% remaining after decode)
    if "%" in path:
        return None

    # Step 4: Collapse repeated slashes
    while "//" in path:
        path = path.replace("//", "/")

    # Step 5: Resolve .. segments
    path = posixpath.normpath(path)

    # normpath turns empty path to '.', restore to '/'
    if path == ".":
        path = "/"

    # Ensure leading slash
    if not path.startswith("/"):
        path = "/" + path

    # Step 6: Strip trailing slash (except bare /)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    return path


def normalize_host(raw_host: str) -> str:
    """Normalize a host for policy comparisons."""
    return raw_host.rstrip(".").lower()


class PolicyDecision:
    """Represents a policy decision for a request."""

    def __init__(
        self,
        allowed: bool,
        reason: str,
        policy_type: str,
        container_id: Optional[str] = None,
    ):
        """Initialize a policy decision.

        Args:
            allowed: Whether the request is allowed.
            reason: Human-readable reason for the decision.
            policy_type: Type of policy that made the decision
                        (identity, allowlist, blocklist, rate_limit, circuit_breaker).
            container_id: Container ID making the request (if identified).
        """
        self.allowed = allowed
        self.reason = reason
        self.policy_type = policy_type
        self.container_id = container_id

    def to_dict(self) -> dict:
        """Convert to dictionary for metadata storage."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "policy_type": self.policy_type,
            "container_id": self.container_id,
        }


class PolicyEngine:
    """Mitmproxy addon for centralized policy enforcement.

    This addon coordinates all policy decisions and ensures that every
    request receives an explicit allow/deny decision with documented reasoning.
    Loads allowlist from config/allowlist.yaml and enforces default-deny.
    """

    def __init__(self, allowlist_path: Optional[str] = None):
        """Initialize the policy engine.

        Args:
            allowlist_path: Optional path to allowlist.yaml. If not provided,
                           uses default location or PROXY_ALLOWLIST_PATH env var.
        """
        self._allowlist_path = allowlist_path
        self._allowlist: Optional[AllowlistConfig] = None
        self._domains: List[str] = []

    def load(self, loader):
        """Called when addon is loaded."""
        global _allowlist_config

        # Try to load allowlist configuration
        try:
            self._allowlist = load_allowlist_config(self._allowlist_path)
            self._domains = self._allowlist.domains
            _allowlist_config = self._allowlist
            ctx.log.info(f"Policy engine loaded allowlist with {len(self._domains)} domains")
        except ConfigError as e:
            ctx.log.warn(f"Failed to load allowlist config: {e}")
            ctx.log.warn("Policy engine operating in default-deny mode (no allowlist)")
            self._domains = []
        except Exception as e:
            ctx.log.error(f"Unexpected error loading allowlist: {e}")
            self._domains = []

        ctx.log.info("Policy engine addon loaded (default-deny enabled)")

    def request(self, flow: http.HTTPFlow) -> None:
        """Evaluate policies for incoming request.

        Implements the documented evaluation order:
        1. Identity verification
        2. Domain allowlist checks
        2b. Endpoint path enforcement (segment-aware matching + blocked_paths)
        3. Blocklist checks (GitHub-specific operation blocks)
        3b. Body inspection (PATCH PR/issue close via state:closed)
        4. Rate limiting (future)
        5. Circuit breaker (future)

        Path normalization is applied once (URL decode, double-encoding
        rejection, slash collapsing, .. resolution, trailing slash strip)
        and used consistently across Steps 2b, 3, and 3b.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        method = flow.request.method
        raw_host = flow.request.pretty_host
        host = normalize_host(raw_host)
        path = flow.request.path

        # Step 1: Identity verification
        # Container identity addon runs before this, check if identity was verified
        container_config = get_container_config(flow)

        if container_config is None:
            # Identity verification failed - container_identity already denied request
            # Log for observability but don't create duplicate response
            decision = PolicyDecision(
                allowed=False,
                reason="Container identity verification failed",
                policy_type="identity",
                container_id=None,
            )
            self._log_decision(decision, method, raw_host, path)
            flow.metadata[POLICY_DECISION_KEY] = decision.to_dict()
            return

        container_id = container_config.container_id

        # Step 2: Allowlist checks (default-deny)
        if not self._is_domain_allowed(host):
            decision = PolicyDecision(
                allowed=False,
                reason=f"Domain '{raw_host}' not in allowlist",
                policy_type="allowlist",
                container_id=container_id,
            )
            self._log_decision(decision, method, raw_host, path)
            self._deny_request(flow, decision)
            return

        # Normalize path once for consistent use in Steps 2b and 3
        normalized_path = normalize_path(path)
        if normalized_path is None:
            decision = PolicyDecision(
                allowed=False,
                reason=f"Path rejected: double-encoding detected in request to {raw_host}",
                policy_type="endpoint_path",
                container_id=container_id,
            )
            self._log_decision(decision, method, raw_host, path)
            self._deny_request(flow, decision)
            return

        # Step 2b: Endpoint path enforcement (for hosts with endpoint config)
        endpoint_block = self._check_endpoint_paths(host, method, path)
        if endpoint_block:
            decision = PolicyDecision(
                allowed=False,
                reason=endpoint_block,
                policy_type="endpoint_path",
                container_id=container_id,
            )
            self._log_decision(decision, method, raw_host, path)
            self._deny_request(flow, decision)
            return

        # Step 3: Blocklist checks (uses normalized path for consistency)
        # Check GitHub security policies
        if self._is_github_request(host):
            github_block = self._check_github_blocklist(method, normalized_path)
            if github_block:
                decision = PolicyDecision(
                    allowed=False,
                    reason=github_block,
                    policy_type="blocklist",
                    container_id=container_id,
                )
                self._log_decision(decision, method, raw_host, path)
                self._deny_request(flow, decision)
                return

            # Step 3b: Body inspection for security-relevant PATCH endpoints
            content_type = flow.request.headers.get("content-type", "")
            content_encoding = flow.request.headers.get("content-encoding", "")
            body = flow.request.content
            body_block = self._check_github_body_policies(
                method, normalized_path, body, content_type, content_encoding
            )
            if body_block:
                decision = PolicyDecision(
                    allowed=False,
                    reason=body_block,
                    policy_type="body_policy",
                    container_id=container_id,
                )
                self._log_decision(decision, method, raw_host, path)
                self._deny_request(flow, decision)
                return

        # Step 4: Rate limiting (future)
        # Will integrate with rate_limiter addon when implemented

        # Step 5: Circuit breaker (future)
        # Will integrate with circuit_breaker addon when implemented

        # All checks passed - allow request
        decision = PolicyDecision(
            allowed=True,
            reason=f"Domain '{raw_host}' in allowlist, no blocking policies matched",
            policy_type="allowlist",
            container_id=container_id,
        )
        self._log_decision(decision, method, raw_host, path)
        flow.metadata[POLICY_DECISION_KEY] = decision.to_dict()

    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is in the allowlist.

        Supports:
        - Exact matches: "example.com"
        - Wildcard prefixes: "*.example.com" matches "api.example.com"

        Args:
            domain: The domain name to check. Must be pre-normalized via
                    normalize_host() (lowercase, trailing dot stripped).

        Returns:
            True if domain is allowed, False otherwise.
        """
        for pattern in self._domains:
            pattern_lower = pattern.lower()

            # Exact match
            if pattern_lower == domain:
                return True

            # Wildcard match: *.example.com matches api.example.com
            if pattern_lower.startswith("*."):
                base_domain = pattern_lower[2:]  # Remove "*."
                if domain.endswith("." + base_domain) or domain == base_domain:
                    return True

        return False

    def _check_endpoint_paths(
        self, host: str, method: str, raw_path: str
    ) -> Optional[str]:
        """Check endpoint path enforcement for hosts with endpoint config.

        For hosts that have http_endpoints entries in the allowlist, validates
        that the normalized request path matches at least one allowed path
        pattern using segment-aware matching. Then checks against blocked_paths.

        Hosts without endpoint entries use domain-level allowlisting only.

        Args:
            host: Request host.
            method: HTTP method.
            raw_path: Raw request path (may include query string).

        Returns:
            Block reason if request should be blocked, None if allowed.
        """
        if self._allowlist is None:
            return None

        # Find endpoint config for this host
        endpoint = None
        for ep in self._allowlist.http_endpoints:
            if normalize_host(ep.host) == host:
                endpoint = ep
                break

        # No endpoint config for this host — domain-level only
        if endpoint is None:
            return None

        # Normalize the path with strict security rules
        normalized = normalize_path(raw_path)
        if normalized is None:
            return (
                f"Path rejected: double-encoding detected in request to {host}"
            )

        # Enforce HTTP method allowlist for this host's endpoint config
        allowed_methods = {m.upper() for m in endpoint.methods}
        if method.upper() not in allowed_methods:
            return f"Method '{method}' not allowed for {host}"

        # Check if the path matches any allowed endpoint path pattern
        path_allowed = any(
            segment_match(pattern, normalized) for pattern in endpoint.paths
        )
        if not path_allowed:
            return (
                f"Path '{normalized}' not in allowed paths for {host}"
            )

        # Check against blocked paths
        for bp in self._allowlist.blocked_paths:
            if normalize_host(bp.host) == host and bp.matches(normalized):
                return (
                    f"Path '{normalized}' is blocked by policy for {host}"
                )

        return None

    def _is_github_request(self, host: str) -> bool:
        """Check if request is to GitHub API.

        Args:
            host: The request host.

        Returns:
            True if this is a GitHub API request.
        """
        return normalize_host(host) == "api.github.com"

    def _check_github_blocklist(self, method: str, path: str) -> Optional[str]:
        """Check GitHub-specific blocklist policies.

        Args:
            method: HTTP method.
            path: Request path.

        Returns:
            Block reason if request should be blocked, None otherwise.
        """
        # Block PR merge operations
        if method == "PUT" and GITHUB_MERGE_PR_PATTERN.match(path):
            return "GitHub PR merge operations are blocked by policy"

        # Block release creation
        if method == "POST" and GITHUB_CREATE_RELEASE_PATTERN.match(path):
            return "GitHub release creation is blocked by policy"

        # Block Git ref mutations (branch/tag create/update/delete via REST API)
        if method == "POST" and GITHUB_GIT_REFS_ROOT_PATTERN.match(path):
            return "GitHub git ref creation is blocked by policy"
        if method in {"PATCH", "DELETE"} and GITHUB_GIT_REFS_SUBPATH_PATTERN.match(path):
            return "GitHub git ref mutation is blocked by policy"

        # Block auto-merge enablement/disablement
        # Defense-in-depth: also blocked in github-api-filter.py
        if method in ("PUT", "DELETE") and GITHUB_AUTO_MERGE_PATTERN.match(path):
            return "GitHub auto-merge operations are blocked by policy"

        # Block review deletion (prevents removing blocking reviews)
        # Defense-in-depth: also blocked in github-api-filter.py
        if method == "DELETE" and GITHUB_DELETE_REVIEW_PATTERN.match(path):
            return "Deleting pull request reviews is blocked by policy"

        return None

    def _check_github_body_policies(
        self,
        method: str,
        path: str,
        body: Optional[bytes],
        content_type: str,
        content_encoding: str,
    ) -> Optional[str]:
        """Check GitHub body-level policies for PATCH and POST operations.

        Inspects request bodies on security-relevant endpoints to block
        PR close, issue close, and PR review approval operations while
        allowing reopens, edits, and non-approval review events.

        Args:
            method: HTTP method.
            path: Normalized request path.
            body: Raw request body bytes, or None if streaming.
            content_type: Content-Type header value.
            content_encoding: Content-Encoding header value.

        Returns:
            Block reason if request should be blocked, None otherwise.
        """
        # Only inspect PATCH and POST requests
        if method not in ("PATCH", "POST"):
            return None

        # POST: PR review approval check
        if method == "POST" and GITHUB_PR_REVIEW_PATTERN.match(path):
            # Reject compressed bodies
            if content_encoding:
                return (
                    "Compressed request bodies are not allowed for "
                    "security-relevant GitHub POST endpoints"
                )
            if not content_type or not content_type.lower().startswith("application/json"):
                return (
                    "Content-Type must be application/json for "
                    "security-relevant GitHub POST endpoints"
                )
            if body is None:
                return (
                    "Streaming request bodies are not allowed for "
                    "security-relevant GitHub POST endpoints"
                )
            body_str = body.lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body_str)
            except (json.JSONDecodeError, ValueError):
                return "Malformed JSON body in security-relevant GitHub POST request"
            if not isinstance(parsed, dict):
                return (
                    "Request body must be a JSON object for "
                    "security-relevant GitHub POST endpoints"
                )
            # Defense-in-depth: also blocked at GraphQL level in github-api-filter.py
            event = parsed.get("event")
            if event is not None and str(event).upper() == "APPROVE":
                return "Self-approving pull requests is blocked by policy"
            return None

        # Only inspect PR and issue endpoints
        if not (
            GITHUB_PATCH_PR_PATTERN.match(path)
            or GITHUB_PATCH_ISSUE_PATTERN.match(path)
        ):
            return None

        # Reject compressed bodies for these security-relevant endpoints
        if content_encoding:
            return (
                "Compressed request bodies are not allowed for "
                "security-relevant GitHub PATCH endpoints"
            )

        # Content-Type enforcement: require application/json
        if not content_type:
            return (
                "Content-Type header is required for "
                "security-relevant GitHub PATCH endpoints"
            )
        # Check that content-type starts with application/json
        # (may include charset parameter like "application/json; charset=utf-8")
        if not content_type.lower().startswith("application/json"):
            return (
                f"Content-Type must be application/json for "
                f"security-relevant GitHub PATCH endpoints, "
                f"got: {content_type}"
            )

        # Streaming mode: body not yet available
        if body is None:
            return (
                "Streaming request bodies are not allowed for "
                "security-relevant GitHub PATCH endpoints"
            )

        # Strip UTF-8 BOM if present
        body_str = body.lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")

        # Parse JSON body (fail closed on malformed JSON)
        try:
            parsed = json.loads(body_str)
        except (json.JSONDecodeError, ValueError):
            return (
                "Malformed JSON body in security-relevant GitHub PATCH request"
            )

        # Body must be a JSON object
        if not isinstance(parsed, dict):
            return (
                "Request body must be a JSON object for "
                "security-relevant GitHub PATCH endpoints"
            )

        # Block state:closed (PR close / issue close)
        state = parsed.get("state")
        if state is not None and str(state).lower() == "closed":
            if GITHUB_PATCH_PR_PATTERN.match(path):
                return "Closing pull requests via API is blocked by policy"
            else:
                return "Closing issues via API is blocked by policy"

        # Allow: state:open (reopen), no state (title/description edits), etc.
        return None

    def _log_decision(
        self,
        decision: PolicyDecision,
        method: str,
        host: str,
        path: str,
    ) -> None:
        """Log a policy decision with structured data.

        Args:
            decision: The policy decision.
            method: HTTP method.
            host: Request host.
            path: Request path.
        """
        log_level = "info" if decision.allowed else "warn"
        log_fn = getattr(ctx.log, log_level)

        decision_str = "ALLOW" if decision.allowed else "DENY"
        log_fn(
            f"Policy decision: {decision_str} - {method} {host}{path} - "
            f"container={decision.container_id or 'unknown'} - "
            f"policy={decision.policy_type} - "
            f"reason={decision.reason}"
        )

    def _deny_request(
        self,
        flow: http.HTTPFlow,
        decision: PolicyDecision,
    ) -> None:
        """Deny the request with a 403 Forbidden response.

        Args:
            flow: The mitmproxy HTTP flow.
            decision: The policy decision with denial reason.
        """
        # Store decision in metadata
        flow.metadata[POLICY_DECISION_KEY] = decision.to_dict()

        # Create 403 response
        flow.response = http.Response.make(
            403,
            b"Forbidden: Request denied by policy engine",
            {"Content-Type": "text/plain"},
        )


def get_policy_decision(flow: Flow) -> Optional[dict]:
    """Helper function to get policy decision from flow metadata.

    This allows downstream addons to check the policy decision.

    Args:
        flow: The mitmproxy flow.

    Returns:
        Policy decision dict if available, None otherwise.
    """
    return flow.metadata.get(POLICY_DECISION_KEY)


# Export addon class for mitmproxy
addons = [PolicyEngine()]
