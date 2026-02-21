"""
Policy Engine mitmproxy Addon

Centralized policy enforcement with documented evaluation order and comprehensive
logging. Acts as the coordination point for all policy decisions in the unified proxy.

Evaluation Order:
E. Early-exit merge blocking (unconditional, before all other checks)
0. IP literal check (block direct-IP requests before any policy evaluation)
1. Identity verification (via container_identity addon)
2. Allowlist checks (domain/path allowlist from allowlist.yaml)
3. Blocklist checks (explicit denies, e.g., release/ref-mutation endpoints)
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

GitHub security policy functions are imported from security_policies.py
(shared with github_gateway.py) to prevent pattern drift.
"""

import os
import re
import socket
import sys
from typing import Optional, List
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.flow import Flow

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config  # noqa: E402
from config import (  # noqa: E402
    HttpEndpointConfig,
    load_allowlist_config,
    AllowlistConfig,
    ConfigError,
    segment_match,
)
from logging_config import get_logger  # noqa: E402
from security_policies import (  # noqa: E402
    normalize_path,
    is_merge_request,
    check_github_blocklist,
    check_github_body_policies,
)

logger = get_logger(__name__)

# --- IP literal detection ---
# Patterns that identify IP-literal hostnames in various encodings.
# Any request where the host matches an IP-literal pattern is rejected
# before the domain allowlist lookup to prevent DNS filtering bypass.
_IP_LITERAL_PATTERNS = [
    re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"),  # Dotted decimal
    re.compile(r"^\["),                                   # IPv6 brackets
    re.compile(r"^0[0-7]+\.[0-9]"),                      # Octal prefix (digit after dot reduces false positives)
    re.compile(r"^0x[0-9a-fA-F]"),                        # Hex prefix
    re.compile(r"^[0-9]+$"),                              # Pure integer (any length)
]


def is_ip_literal(host: str) -> bool:
    """Check if a hostname is an IP literal in any encoding.

    Detects dotted decimal, octal, hex, pure integer, IPv6 bracket, and
    mixed-encoding IP addresses. Used to block direct-IP requests that
    bypass DNS-based domain filtering.

    Args:
        host: The hostname to check (should be pre-stripped of port).

    Returns:
        True if the host appears to be an IP literal.
    """
    # Fast path: regex catches common encodings
    if any(p.match(host) for p in _IP_LITERAL_PATTERNS):
        return True
    # Belt-and-suspenders: catch mixed encodings (e.g. 0x7f.0.0.01,
    # 1.0x0.0.1) that individual regex patterns miss. inet_aton handles
    # dotted-decimal, octal, hex, and mixed forms.
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        pass
    # Catch bare IPv6 addresses (::1, 2001:db8::1, ::ffff:127.0.0.1)
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


def normalize_host(raw_host: str) -> str:
    """Normalize a host for policy comparisons."""
    return raw_host.rstrip(".").lower()


# Metadata key for policy decisions
POLICY_DECISION_KEY = "policy_decision"

# Global allowlist configuration (loaded in load())
_allowlist_config: Optional[AllowlistConfig] = None


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
            logger.info(f"Policy engine loaded allowlist with {len(self._domains)} domains")
        except ConfigError as e:
            logger.warning(f"Failed to load allowlist config: {e}")
            logger.warning("Policy engine operating in default-deny mode (no allowlist)")
            self._domains = []
        except Exception as e:
            logger.error(f"Unexpected error loading allowlist: {e}")
            self._domains = []

        # Dynamically allow custom ANTHROPIC_BASE_URL host so the policy
        # engine doesn't block requests that the credential injector expects
        # to forward.
        self._add_anthropic_base_url_host()

        logger.info("Policy engine addon loaded (default-deny enabled)")

    def _add_anthropic_base_url_host(self) -> None:
        """Add ANTHROPIC_BASE_URL hostname to domain allowlist and endpoint config.

        When users set a custom ANTHROPIC_BASE_URL (e.g. a proxy or staging
        endpoint), the policy engine must allow requests to that host.
        The credential injector already handles this via _build_anthropic_hosts();
        this method mirrors that logic for the policy engine's domain allowlist
        and adds matching http_endpoints entries so path enforcement works too.
        """
        base_url = os.environ.get("ANTHROPIC_BASE_URL", "").strip()
        if not base_url:
            return

        parsed = urlparse(base_url)
        hostname = parsed.hostname
        if not hostname:
            return

        # Already in domain allowlist (e.g. api.anthropic.com)
        if self._is_domain_allowed(normalize_host(hostname)):
            return

        # Add to domain allowlist
        self._domains.append(hostname)
        logger.info(
            f"Added ANTHROPIC_BASE_URL host '{hostname}' to domain allowlist"
        )

        # Add http_endpoints entry mirroring the api.anthropic.com config
        # so endpoint path enforcement allows the same paths.
        if self._allowlist is not None:
            # Find the existing api.anthropic.com endpoint config to mirror
            anthropic_ep = None
            for ep in self._allowlist.http_endpoints:
                if normalize_host(ep.host) == "api.anthropic.com":
                    anthropic_ep = ep
                    break

            if anthropic_ep is not None:
                custom_ep = HttpEndpointConfig(
                    host=hostname,
                    methods=list(anthropic_ep.methods),
                    paths=list(anthropic_ep.paths),
                )
                self._allowlist.http_endpoints.append(custom_ep)
                logger.info(
                    f"Added http_endpoints entry for ANTHROPIC_BASE_URL host '{hostname}'"
                )

    def request(self, flow: http.HTTPFlow) -> None:
        """Evaluate policies for incoming request.

        Implements the documented evaluation order:
        E. Early-exit merge blocking (unconditional, before all other checks)
        0. IP literal check (block direct-IP requests)
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
        # Normalize method to uppercase for defense-in-depth.
        method = flow.request.method.upper()
        raw_host = flow.request.pretty_host
        path = flow.request.path

        # Step E: Early-exit merge blocking — unconditional check that runs
        # before identity verification, domain matching, or credential
        # injection.
        raw_content = flow.request.content
        body = raw_content if isinstance(raw_content, (bytes, bytearray)) else b""
        if is_merge_request(path, body):
            decision = PolicyDecision(
                allowed=False,
                reason="Merge operations are not permitted",
                policy_type="merge_block",
            )
            self._log_decision(decision, method, raw_host, path)
            self._deny_request(flow, decision)
            return

        # Step 0: IP literal check
        if is_ip_literal(raw_host):
            decision = PolicyDecision(
                allowed=False,
                reason="Direct IP access is not permitted",
                policy_type="ip_literal",
            )
            self._log_decision(decision, method, raw_host, path)
            self._deny_request(flow, decision)
            return

        host = normalize_host(raw_host)

        # Step 1: Identity verification
        container_config = get_container_config(flow)

        if container_config is None:
            decision = PolicyDecision(
                allowed=False,
                reason="Container identity verification failed",
                policy_type="identity",
                container_id=None,
            )
            self._log_decision(decision, method, raw_host, path)
            self._deny_request(flow, decision)
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
        endpoint_block = self._check_endpoint_paths(host, method, normalized_path)
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
        if self._is_github_request(host):
            github_block = check_github_blocklist(method, normalized_path)
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
            body_block = check_github_body_policies(
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
        # Step 5: Circuit breaker (future)

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
        self, host: str, method: str, path: str
    ) -> Optional[str]:
        """Check endpoint path enforcement for hosts with endpoint config.

        For hosts that have http_endpoints entries in the allowlist, validates
        that the request path matches at least one allowed path pattern using
        segment-aware matching. Then checks against blocked_paths.

        Hosts without endpoint entries use domain-level allowlisting only.

        Args:
            host: Request host.
            method: HTTP method.
            path: Normalized request path.

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

        # Enforce HTTP method allowlist for this host's endpoint config
        allowed_methods = {m.upper() for m in endpoint.methods}
        if method.upper() not in allowed_methods:
            return f"Method '{method}' not allowed for {host}"

        # Check if the path matches any allowed endpoint path pattern
        path_allowed = any(
            segment_match(pattern, path) for pattern in endpoint.paths
        )
        if not path_allowed:
            return (
                f"Path '{path}' not in allowed paths for {host}"
            )

        # Check against blocked paths
        for bp in self._allowlist.blocked_paths:
            if normalize_host(bp.host) == host and bp.matches(path):
                return (
                    f"Path '{path}' is blocked by policy for {host}"
                )

        return None

    def _is_github_request(self, host: str) -> bool:
        """Check if request is to GitHub API."""
        return normalize_host(host) == "api.github.com"

    def _log_decision(
        self,
        decision: PolicyDecision,
        method: str,
        host: str,
        path: str,
    ) -> None:
        """Log a policy decision with structured data."""
        log_level = "info" if decision.allowed else "warning"
        log_fn = getattr(logger, log_level)

        # Truncate path to prevent log injection/spam from crafted long paths
        safe_path = path[:200] if len(path) > 200 else path

        decision_str = "ALLOW" if decision.allowed else "DENY"
        log_fn(
            f"Policy decision: {decision_str} - {method} {host}{safe_path} - "
            f"container={decision.container_id or 'unknown'} - "
            f"policy={decision.policy_type} - "
            f"reason={decision.reason}"
        )

    def _deny_request(
        self,
        flow: http.HTTPFlow,
        decision: PolicyDecision,
    ) -> None:
        """Deny the request with a 403 Forbidden response."""
        # Store decision in metadata
        flow.metadata[POLICY_DECISION_KEY] = decision.to_dict()

        # Create 403 response with proxy-specific header for test distinguishability
        flow.response = http.Response.make(
            403,
            b"Forbidden: Request denied by policy engine",
            {"Content-Type": "text/plain", "X-Sandbox-Blocked": "true"},
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
