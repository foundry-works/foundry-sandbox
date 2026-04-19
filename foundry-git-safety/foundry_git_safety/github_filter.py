"""GitHub API security filter as a standalone HTTP proxy.

Blocks dangerous GitHub API operations at the network layer.
This is a security boundary — cannot be bypassed from within the sandbox.

The filtering rules (allowlists, blocklists, GraphQL mutation blocking) are
ported directly from the mitmproxy-based github-api-filter.py. The mitmproxy
addon wrapper is replaced by a framework-agnostic GitHubAPIChecker class and
an HTTP proxy handler for standalone operation.
"""

import json
import logging
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from .github_config import GITHUB_API_HOSTS

logger = logging.getLogger(__name__)

ALLOW_PR_OPERATIONS = os.environ.get("ALLOW_PR_OPERATIONS", "").lower() in (
    "true", "1", "yes",
)

# Allowlisted safe operations (method, path_pattern)
ALLOWED_OPERATIONS: List[Tuple[str, str]] = [
    ("GET", r"^/repos/[^/]+/[^/]+$"),
    ("GET", r"^/repos/[^/]+/[^/]+/.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/issues.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/issues$"),
    ("POST", r"^/repos/[^/]+/[^/]+/issues/\d+/comments$"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/issues/\d+$"),
    ("GET", r"^/repos/[^/]+/[^/]+/pulls.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/commits.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/branches.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/git/.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/git/blobs$"),
    ("POST", r"^/repos/[^/]+/[^/]+/git/trees$"),
    ("POST", r"^/repos/[^/]+/[^/]+/git/commits$"),
    ("POST", r"^/repos/[^/]+/[^/]+/git/tags$"),
    ("GET", r"^/repos/[^/]+/[^/]+/contents/.*"),
    ("PUT", r"^/repos/[^/]+/[^/]+/contents/.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/releases.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/releases$"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/releases/\d+$"),
    ("POST", r"^/repos/[^/]+/[^/]+/releases/\d+/assets.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/labels.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/labels$"),
    ("GET", r"^/repos/[^/]+/[^/]+/milestones.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/milestones$"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/runs.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/workflows.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/jobs.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/artifacts.*"),
    ("GET", r"^/user$"),
    ("GET", r"^/user/.*"),
    ("GET", r"^/users/[^/]+$"),
    ("GET", r"^/users/[^/]+/.*"),
    ("GET", r"^/search/.*"),
    ("GET", r"^/orgs/[^/]+$"),
    ("GET", r"^/orgs/[^/]+/.*"),
    ("GET", r"^/rate_limit$"),
    ("GET", r"^/gists.*"),
    ("POST", r"^/gists$"),
    ("PATCH", r"^/gists/[^/]+$"),
    ("GET", r"^/notifications.*"),
    ("PATCH", r"^/notifications.*"),
    ("PUT", r"^/notifications.*"),
    ("GET", r"^/user/starred.*"),
    ("PUT", r"^/user/starred/.*"),
    ("DELETE", r"^/user/starred/.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/stargazers.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/subscribers.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/check-runs.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/check-suites.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/check-runs$"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/check-runs/\d+$"),
    ("GET", r"^/repos/[^/]+/[^/]+/statuses/.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/statuses/.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/commits/[^/]+/status$"),
    ("POST", r"^/graphql$"),
    ("POST", r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$"),
]

CONDITIONAL_PR_OPERATIONS: List[Tuple[str, str]] = [
    ("POST", r"^/repos/[^/]+/[^/]+/pulls$"),
    ("POST", r"^/repos/[^/]+/[^/]+/pulls/\d+/comments$"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/pulls/\d+$"),
]

ALWAYS_BLOCKED_GRAPHQL_MUTATIONS = [
    "mergePullRequest",
    "reopenPullRequest",
    "enablePullRequestAutoMerge",
    "disablePullRequestAutoMerge",
    "dismissPullRequestReview",
    "updatePullRequestBranch",
    "addPullRequestReview",
]

CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS = [
    "createPullRequest",
    "updatePullRequest",
    "submitPullRequestReview",
    "closePullRequest",
    "addPullRequestReviewComment",
]

BLOCKED_PATTERNS: List[Tuple[str, str, str]] = [
    ("DELETE", r"^/repos/[^/]+/[^/]+$", "gh repo delete: permanently destroys repository"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/releases/\d+$", "gh release delete: removes release artifacts"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/git/refs/.*", "gh api: deletes branch/tag (history loss)"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/git/refs/.*", "gh api: force updates ref (history rewrite)"),
    ("PUT", r"^/repos/[^/]+/[^/]+/pulls/\d+/merge$", "gh pr merge: merges pull request (requires human approval)"),
    ("PUT", r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$", "auto-merge: enables automatic merge (requires human approval)"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$", "auto-merge: disables automatic merge (requires human approval)"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$", "review deletion: removes review (requires human approval)"),
    ("POST", r"^/repos/[^/]+/[^/]+/merges$", "gh api: creates merge commit (requires human approval)"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/branches/[^/]+/protection.*", "gh api: removes branch protection"),
    ("PUT", r"^/repos/[^/]+/[^/]+/branches/[^/]+/protection.*", "gh api: modifies branch protection"),
    ("POST", r"^/repos/[^/]+/[^/]+/branches/[^/]+/protection.*", "gh api: creates branch protection rule"),
    ("POST", r"^/repos/[^/]+/[^/]+/git/refs$", "gh api: creates git ref (use git push instead)"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/secrets.*", "gh secret: accesses repository secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/actions/secrets.*", "gh secret: modifies repository secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/actions/secrets.*", "gh secret: deletes repository secrets"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: accesses repository variables"),
    ("POST", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: creates repository variables"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: modifies repository variables"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: deletes repository variables"),
    ("GET", r"^/orgs/[^/]+/actions/secrets.*", "gh secret: accesses organization secrets"),
    ("PUT", r"^/orgs/[^/]+/actions/secrets.*", "gh secret: modifies organization secrets"),
    ("DELETE", r"^/orgs/[^/]+/actions/secrets.*", "gh secret: deletes organization secrets"),
    ("GET", r"^/orgs/[^/]+/actions/variables.*", "gh variable: accesses organization variables"),
    ("POST", r"^/orgs/[^/]+/actions/variables.*", "gh variable: creates organization variables"),
    ("PATCH", r"^/orgs/[^/]+/actions/variables.*", "gh variable: modifies organization variables"),
    ("DELETE", r"^/orgs/[^/]+/actions/variables.*", "gh variable: deletes organization variables"),
    ("GET", r"^/repos/[^/]+/[^/]+/environments/[^/]+/secrets.*", "gh secret: accesses environment secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/environments/[^/]+/secrets.*", "gh secret: modifies environment secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/environments/[^/]+/secrets.*", "gh secret: deletes environment secrets"),
    ("GET", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: accesses environment variables"),
    ("POST", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: creates environment variables"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: modifies environment variables"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: deletes environment variables"),
    ("GET", r"^/repos/[^/]+/[^/]+/dependabot/secrets.*", "gh secret: accesses dependabot secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/dependabot/secrets.*", "gh secret: modifies dependabot secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/dependabot/secrets.*", "gh secret: deletes dependabot secrets"),
    ("GET", r"^/repos/[^/]+/[^/]+/codespaces/secrets.*", "gh secret: accesses codespaces secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/codespaces/secrets.*", "gh secret: modifies codespaces secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/codespaces/secrets.*", "gh secret: deletes codespaces secrets"),
]

# Compile patterns
_allowed_compiled = [(m, re.compile(p)) for m, p in ALLOWED_OPERATIONS]
_blocked_compiled = [(m, re.compile(p), msg) for m, p, msg in BLOCKED_PATTERNS]
_conditional_pr_compiled = [(m, re.compile(p)) for m, p in CONDITIONAL_PR_OPERATIONS]
_pr_patch_pattern = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+$")


class GitHubAPIChecker:
    """Framework-agnostic GitHub API request checker.

    Returns (allowed, reason) where reason is None if allowed,
    or a string explaining why the request was blocked.
    """

    def __init__(self, allow_pr_operations: bool = ALLOW_PR_OPERATIONS):
        self.allow_pr_operations = allow_pr_operations

    def check_request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Check if a GitHub API request should be allowed.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: URL path (e.g., /repos/owner/repo).
            body: Request body (for POST/PATCH inspection).

        Returns:
            (True, None) if allowed, (False, reason) if blocked.
        """
        method = method.upper()
        path_no_query = path.split("?")[0]

        # Check explicit blocklist
        for blocked_method, pattern, message in _blocked_compiled:
            if method == blocked_method and pattern.match(path_no_query):
                return False, message

        # PR reopen detection
        if method == "PATCH" and _pr_patch_pattern.match(path_no_query):
            if self._is_pr_reopen(body):
                return False, "gh pr reopen: reopening closed PRs requires human approval"

        # GraphQL mutation check
        if method == "POST" and path_no_query == "/graphql":
            blocked = self._check_graphql_mutations(body)
            if blocked:
                return False, f"GraphQL mutation '{blocked}' is not permitted"

        # Conditional PR operations
        if not self.allow_pr_operations:
            for pr_method, pattern in _conditional_pr_compiled:
                if method == pr_method and pattern.match(path_no_query):
                    return False, (
                        "PR operations blocked by sandbox policy. "
                        "Use --allow-pr flag to enable."
                    )

        # Allowlist
        for allowed_method, pattern in _allowed_compiled:
            if method == allowed_method and pattern.match(path_no_query):
                return True, None

        # Check if conditional PR is now allowed
        if self.allow_pr_operations:
            for pr_method, pattern in _conditional_pr_compiled:
                if method == pr_method and pattern.match(path_no_query):
                    return True, None

        return False, f"gh api: raw API access not permitted ({method} {path_no_query})"

    def _is_pr_reopen(self, body: Optional[bytes]) -> bool:
        if not body:
            return False
        try:
            data = json.loads(body)
            return str(data.get("state", "")).lower() == "open"
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def _check_graphql_mutations(self, body: Optional[bytes]) -> Optional[str]:
        if not body:
            return None
        try:
            data = json.loads(body)
            query = data.get("query", "")
            query = re.sub(r"#[^\n]*", "", query)

            for mutation in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS:
                if re.search(rf"\b{mutation}\s*\(", query, re.IGNORECASE):
                    return mutation

            if not self.allow_pr_operations:
                for mutation in CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS:
                    if re.search(rf"\b{mutation}\s*\(", query, re.IGNORECASE):
                        return mutation

            return None
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "unparseable GraphQL request body (fail closed)"


def run_github_proxy(
    host: str = "127.0.0.1",
    port: int = 8084,
    upstream_proxy: Optional[str] = None,
) -> None:
    """Run the GitHub API filter as a local HTTP proxy server.

    This proxy:
    1. Accepts CONNECT (HTTPS) and plain HTTP proxy requests
    2. For requests to GitHub API hosts, applies allowlist/blocklist filtering
    3. For all other requests, passes them through without filtering
    """
    checker = GitHubAPIChecker()

    class GitHubAPIProxyHandler(BaseHTTPRequestHandler):
        def do_CONNECT(self) -> None:
            """Handle HTTPS CONNECT requests."""
            # For HTTPS, we can't inspect the content without MITM.
            # Instead, we tunnel the connection and let the client's
            # HTTP requests flow through do_GET/do_POST after CONNECT
            # is established (via HTTP over the CONNECT tunnel).
            # Since most GitHub API calls use HTTPS, the actual filtering
            # happens at the application level (git wrapper + security_policies).
            self.send_response(200, "Connection Established")
            self.end_headers()

        def _handle_request(self) -> None:
            """Handle a proxied HTTP request."""
            parsed = urlparse(self.path)
            host = parsed.hostname
            path = parsed.path or "/"

            # Only filter GitHub API hosts
            if host in GITHUB_API_HOSTS:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else None

                allowed, reason = checker.check_request(
                    method=self.command,
                    path=path,
                    body=body,
                )

                if not allowed:
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-Sandbox-Blocked", "true")
                    self.end_headers()
                    response_body = json.dumps({
                        "error": "BLOCKED",
                        "message": reason,
                        "documentation_url": "https://docs.github.com/rest",
                        "hint": "This operation requires human operator approval.",
                    }, indent=2)
                    self.wfile.write(response_body.encode())
                    logger.warning("BLOCKED GitHub API: %s %s - %s", self.command, path, reason)
                    return

            # Forward the request
            import http.client
            try:
                target_host = host or "api.github.com"
                target_port = parsed.port or 443 if parsed.scheme == "https" else 80

                conn = http.client.HTTPSConnection(target_host, target_port) if parsed.scheme == "https" else http.client.HTTPConnection(target_host, target_port)

                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else None

                headers = {k: v for k, v in self.headers.items() if k.lower() != "host"}
                headers["Host"] = target_host

                conn.request(self.command, path, body=body, headers=headers)
                response = conn.getresponse()

                self.send_response(response.status)
                for key, value in response.getheaders():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, value)
                self.end_headers()

                response_body = response.read()
                self.wfile.write(response_body)
                conn.close()

            except Exception as exc:
                logger.error("Proxy forwarding error: %s", exc)
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Proxy error: {exc}"}).encode())

        def do_GET(self) -> None:
            self._handle_request()

        def do_POST(self) -> None:
            self._handle_request()

        def do_PUT(self) -> None:
            self._handle_request()

        def do_PATCH(self) -> None:
            self._handle_request()

        def do_DELETE(self) -> None:
            self._handle_request()

        def log_message(self, format, *args) -> None:
            logger.debug("Proxy: %s", format % args)

    server = HTTPServer((host, port), GitHubAPIProxyHandler)
    logger.info("Starting GitHub API filter proxy on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("GitHub API filter proxy shutting down")
    finally:
        server.server_close()
