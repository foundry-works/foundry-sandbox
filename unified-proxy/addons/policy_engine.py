"""
Policy Engine mitmproxy Addon

Centralized policy enforcement with documented evaluation order and comprehensive
logging. Acts as the coordination point for all policy decisions in the unified proxy.

Evaluation Order:
1. Identity verification (via container_identity addon)
2. Allowlist checks (domain/path allowlist from allowlist.yaml)
3. Blocklist checks (explicit denies, e.g., merge/release endpoints)
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
"""

import os
import re
import sys
from typing import Optional, List

from mitmproxy import http, ctx
from mitmproxy.flow import Flow

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from addons.container_identity import get_container_config
from config import load_allowlist_config, AllowlistConfig, ConfigError

# Metadata key for policy decisions
POLICY_DECISION_KEY = "policy_decision"

# GitHub patterns for blocked operations
GITHUB_MERGE_PR_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+/merge$")
GITHUB_CREATE_RELEASE_PATTERN = re.compile(r"^/repos/[^/]+/[^/]+/releases$")

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
        2. Allowlist checks
        3. Blocklist checks
        4. Rate limiting (future)
        5. Circuit breaker (future)

        Args:
            flow: The mitmproxy HTTP flow.
        """
        method = flow.request.method
        host = flow.request.pretty_host
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
            self._log_decision(decision, method, host, path)
            flow.metadata[POLICY_DECISION_KEY] = decision.to_dict()
            return

        container_id = container_config.container_id

        # Step 2: Allowlist checks (default-deny)
        if not self._is_domain_allowed(host):
            decision = PolicyDecision(
                allowed=False,
                reason=f"Domain '{host}' not in allowlist",
                policy_type="allowlist",
                container_id=container_id,
            )
            self._log_decision(decision, method, host, path)
            self._deny_request(flow, decision)
            return

        # Step 3: Blocklist checks
        # Check GitHub security policies
        if self._is_github_request(host):
            github_block = self._check_github_blocklist(method, path)
            if github_block:
                decision = PolicyDecision(
                    allowed=False,
                    reason=github_block,
                    policy_type="blocklist",
                    container_id=container_id,
                )
                self._log_decision(decision, method, host, path)
                self._deny_request(flow, decision)
                return

        # Step 4: Rate limiting (future)
        # Will integrate with rate_limiter addon when implemented

        # Step 5: Circuit breaker (future)
        # Will integrate with circuit_breaker addon when implemented

        # All checks passed - allow request
        decision = PolicyDecision(
            allowed=True,
            reason=f"Domain '{host}' in allowlist, no blocking policies matched",
            policy_type="allowlist",
            container_id=container_id,
        )
        self._log_decision(decision, method, host, path)
        flow.metadata[POLICY_DECISION_KEY] = decision.to_dict()

    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is in the allowlist.

        Supports:
        - Exact matches: "example.com"
        - Wildcard prefixes: "*.example.com" matches "api.example.com"

        Args:
            domain: The domain name to check.

        Returns:
            True if domain is allowed, False otherwise.
        """
        # Normalize domain (remove trailing dot if present)
        domain = domain.rstrip(".").lower()

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

    def _is_github_request(self, host: str) -> bool:
        """Check if request is to GitHub API.

        Args:
            host: The request host.

        Returns:
            True if this is a GitHub API request.
        """
        return host == "api.github.com"

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
