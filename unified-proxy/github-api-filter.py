"""
GitHub API Security Filter - mitmproxy Addon

Blocks dangerous GitHub API operations at the network layer.
This is a security boundary - cannot be bypassed from within the sandbox.

Blocked operations:
- gh repo delete    → DELETE /repos/{owner}/{repo}
- gh release delete → DELETE /repos/{owner}/{repo}/releases/*
- gh api            → All api.github.com requests (use allowlist for safe ops)
- gh secret         → /repos/{owner}/{repo}/actions/secrets/*
- gh variable       → /repos/{owner}/{repo}/actions/variables/*

PR Operations (controlled by ALLOW_PR_OPERATIONS env var):
- Always blocked: merge, reopen (history protection)
- Conditionally blocked: create, comment, review, update, close
- Always allowed: read operations (view, list, checks)

Design: Allowlist approach - only explicitly permitted operations pass through.
This ensures gh api raw access is blocked while normal gh commands work.
"""

import json
import os
import re
from mitmproxy import http, ctx

# Import shared GitHub configuration
from github_config import GITHUB_API_HOSTS

# Check if PR operations are allowed (env var set by sandbox creation)
ALLOW_PR_OPERATIONS = os.environ.get("ALLOW_PR_OPERATIONS", "").lower() in ("true", "1", "yes")

# Allowlisted safe operations (method, path_pattern)
# Patterns use regex - be specific to avoid over-permitting
ALLOWED_OPERATIONS = [
    # --- Repository info (read-only) ---
    ("GET", r"^/repos/[^/]+/[^/]+$"),  # Get repo info
    ("GET", r"^/repos/[^/]+/[^/]+/.*"),  # Get repo sub-resources (broad read)

    # --- Issues ---
    ("GET", r"^/repos/[^/]+/[^/]+/issues.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/issues$"),  # Create issue
    ("POST", r"^/repos/[^/]+/[^/]+/issues/\d+/comments$"),  # Add comment
    ("PATCH", r"^/repos/[^/]+/[^/]+/issues/\d+$"),  # Update issue

    # --- Pull Requests (read-only always allowed) ---
    ("GET", r"^/repos/[^/]+/[^/]+/pulls.*"),
    # Note: PR write operations (create/comment/review/update) are conditionally allowed
    # based on ALLOW_PR_OPERATIONS env var - see CONDITIONAL_PR_OPERATIONS below
    # Note: PUT .../pulls/.../merge is ALWAYS blocked (history protection)

    # --- Commits & Branches ---
    ("GET", r"^/repos/[^/]+/[^/]+/commits.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/branches.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/git/.*"),  # Git data API (read)
    # Git data API - allow creating blobs, trees, commits (but NOT refs - those are blocked)
    ("POST", r"^/repos/[^/]+/[^/]+/git/blobs$"),  # Create blob
    ("POST", r"^/repos/[^/]+/[^/]+/git/trees$"),  # Create tree
    ("POST", r"^/repos/[^/]+/[^/]+/git/commits$"),  # Create commit object
    ("POST", r"^/repos/[^/]+/[^/]+/git/tags$"),  # Create tag object (annotated)
    # Note: POST /git/refs is intentionally NOT allowed (use git push instead)

    # --- Contents ---
    ("GET", r"^/repos/[^/]+/[^/]+/contents/.*"),
    ("PUT", r"^/repos/[^/]+/[^/]+/contents/.*"),  # Create/update file
    # Note: DELETE contents is intentionally not allowed

    # --- Releases (read + create, no delete) ---
    ("GET", r"^/repos/[^/]+/[^/]+/releases.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/releases$"),  # Create release
    ("PATCH", r"^/repos/[^/]+/[^/]+/releases/\d+$"),  # Update release
    ("POST", r"^/repos/[^/]+/[^/]+/releases/\d+/assets.*"),  # Upload release asset (uploads.github.com)
    # Note: DELETE releases is intentionally not allowed

    # --- Labels & Milestones ---
    ("GET", r"^/repos/[^/]+/[^/]+/labels.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/labels$"),
    ("GET", r"^/repos/[^/]+/[^/]+/milestones.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/milestones$"),

    # --- Actions (read-only, no secrets/variables) ---
    ("GET", r"^/repos/[^/]+/[^/]+/actions/runs.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/workflows.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/jobs.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/actions/artifacts.*"),
    # Note: secrets and variables endpoints are intentionally not allowed

    # --- User info ---
    ("GET", r"^/user$"),
    ("GET", r"^/user/.*"),
    ("GET", r"^/users/[^/]+$"),
    ("GET", r"^/users/[^/]+/.*"),

    # --- Search ---
    ("GET", r"^/search/.*"),

    # --- Organizations (read-only) ---
    ("GET", r"^/orgs/[^/]+$"),
    ("GET", r"^/orgs/[^/]+/.*"),

    # --- Rate limit ---
    ("GET", r"^/rate_limit$"),

    # --- Gists (read + create, no delete) ---
    ("GET", r"^/gists.*"),
    ("POST", r"^/gists$"),
    ("PATCH", r"^/gists/[^/]+$"),

    # --- Notifications ---
    ("GET", r"^/notifications.*"),
    ("PATCH", r"^/notifications.*"),
    ("PUT", r"^/notifications.*"),

    # --- Starring & Watching ---
    ("GET", r"^/user/starred.*"),
    ("PUT", r"^/user/starred/.*"),
    ("DELETE", r"^/user/starred/.*"),  # Unstarring is safe
    ("GET", r"^/repos/[^/]+/[^/]+/stargazers.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/subscribers.*"),

    # --- Check runs/suites (for CI integration) ---
    ("GET", r"^/repos/[^/]+/[^/]+/check-runs.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/check-suites.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/check-runs$"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/check-runs/\d+$"),

    # --- Statuses ---
    ("GET", r"^/repos/[^/]+/[^/]+/statuses/.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/statuses/.*"),
    ("GET", r"^/repos/[^/]+/[^/]+/commits/[^/]+/status$"),

    # --- GraphQL (allowed but mutations are filtered - see request handler) ---
    ("POST", r"^/graphql$"),
]

# Conditionally allowed PR operations (only when ALLOW_PR_OPERATIONS is set)
# These are blocked by default but can be enabled with --allow-pr flag
CONDITIONAL_PR_OPERATIONS = [
    ("POST", r"^/repos/[^/]+/[^/]+/pulls$"),  # Create PR
    ("POST", r"^/repos/[^/]+/[^/]+/pulls/\d+/comments$"),  # Add PR comment
    ("POST", r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$"),  # Add PR review
    ("PATCH", r"^/repos/[^/]+/[^/]+/pulls/\d+$"),  # Update PR (close, update title/body)
]

# GraphQL mutations that are always blocked (history protection)
ALWAYS_BLOCKED_GRAPHQL_MUTATIONS = [
    "mergePullRequest",
    "reopenPullRequest",
    "enablePullRequestAutoMerge",
    "disablePullRequestAutoMerge",
    "dismissPullRequestReview",
    "updatePullRequestBranch",  # Performs server-side merge; block conservatively
    # addPullRequestReview: blocked entirely because the regex-based mutation parser
    # cannot inspect GraphQL arguments (inline vs variables). APPROVE-only filtering
    # would require a GraphQL AST parser. REST reviews are NOT blocked — body
    # inspection in policy_engine.py selectively blocks only APPROVE events.
    # Collateral: GraphQL comment/request-changes reviews are blocked. All major
    # tools (gh, hub, Claude) use REST for reviews, so no functional impact.
    "addPullRequestReview",
]

# GraphQL mutations that are conditionally blocked (when ALLOW_PR_OPERATIONS is not set)
CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS = [
    "createPullRequest",
    "updatePullRequest",
    "submitPullRequestReview",
    "closePullRequest",
    "addPullRequestReviewComment",
]

# Explicitly blocked patterns (checked before allowlist for clear error messages)
# These return specific error messages explaining why they're blocked
BLOCKED_PATTERNS = [
    # Repository deletion
    ("DELETE", r"^/repos/[^/]+/[^/]+$", "gh repo delete: permanently destroys repository"),

    # Release deletion
    ("DELETE", r"^/repos/[^/]+/[^/]+/releases/\d+$", "gh release delete: removes release artifacts"),

    # =============================================================
    # Git History Protection - Block all operations that could
    # rewrite committed history or delete branches/refs
    # =============================================================

    # Branch/ref deletion via API
    ("DELETE", r"^/repos/[^/]+/[^/]+/git/refs/.*", "gh api: deletes branch/tag (history loss)"),

    # Force ref updates via API (can rewrite history)
    ("PATCH", r"^/repos/[^/]+/[^/]+/git/refs/.*", "gh api: force updates ref (history rewrite)"),

    # PR merge via API (creates merge commits, modifies branch)
    ("PUT", r"^/repos/[^/]+/[^/]+/pulls/\d+/merge$", "gh pr merge: merges pull request (requires human approval)"),

    # Defense-in-depth: also blocked in addons/policy_engine.py
    ("PUT", r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$", "auto-merge: enables automatic merge (requires human approval)"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$", "auto-merge: disables automatic merge (requires human approval)"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$", "review deletion: removes review (requires human approval)"),

    # Note: PR reopen is detected by checking PATCH request body for state: open
    # This is handled in the request() method, not here in static patterns

    # Merge commits via API
    ("POST", r"^/repos/[^/]+/[^/]+/merges$", "gh api: creates merge commit (requires human approval)"),

    # Branch protection manipulation (could weaken protections)
    ("DELETE", r"^/repos/[^/]+/[^/]+/branches/[^/]+/protection.*", "gh api: removes branch protection"),
    ("PUT", r"^/repos/[^/]+/[^/]+/branches/[^/]+/protection.*", "gh api: modifies branch protection"),
    ("POST", r"^/repos/[^/]+/[^/]+/branches/[^/]+/protection.*", "gh api: creates branch protection rule"),

    # Ref creation via API (could be used to create then force-update)
    ("POST", r"^/repos/[^/]+/[^/]+/git/refs$", "gh api: creates git ref (use git push instead)"),

    # Secrets access
    ("GET", r"^/repos/[^/]+/[^/]+/actions/secrets.*", "gh secret: accesses repository secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/actions/secrets.*", "gh secret: modifies repository secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/actions/secrets.*", "gh secret: deletes repository secrets"),

    # Variables access
    ("GET", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: accesses repository variables"),
    ("POST", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: creates repository variables"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: modifies repository variables"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/actions/variables.*", "gh variable: deletes repository variables"),

    # Org-level secrets/variables
    ("GET", r"^/orgs/[^/]+/actions/secrets.*", "gh secret: accesses organization secrets"),
    ("PUT", r"^/orgs/[^/]+/actions/secrets.*", "gh secret: modifies organization secrets"),
    ("DELETE", r"^/orgs/[^/]+/actions/secrets.*", "gh secret: deletes organization secrets"),
    ("GET", r"^/orgs/[^/]+/actions/variables.*", "gh variable: accesses organization variables"),
    ("POST", r"^/orgs/[^/]+/actions/variables.*", "gh variable: creates organization variables"),
    ("PATCH", r"^/orgs/[^/]+/actions/variables.*", "gh variable: modifies organization variables"),
    ("DELETE", r"^/orgs/[^/]+/actions/variables.*", "gh variable: deletes organization variables"),

    # Environment secrets/variables
    ("GET", r"^/repos/[^/]+/[^/]+/environments/[^/]+/secrets.*", "gh secret: accesses environment secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/environments/[^/]+/secrets.*", "gh secret: modifies environment secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/environments/[^/]+/secrets.*", "gh secret: deletes environment secrets"),
    ("GET", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: accesses environment variables"),
    ("POST", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: creates environment variables"),
    ("PATCH", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: modifies environment variables"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/environments/[^/]+/variables.*", "gh variable: deletes environment variables"),

    # Dependabot secrets
    ("GET", r"^/repos/[^/]+/[^/]+/dependabot/secrets.*", "gh secret: accesses dependabot secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/dependabot/secrets.*", "gh secret: modifies dependabot secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/dependabot/secrets.*", "gh secret: deletes dependabot secrets"),

    # Codespaces secrets
    ("GET", r"^/repos/[^/]+/[^/]+/codespaces/secrets.*", "gh secret: accesses codespaces secrets"),
    ("PUT", r"^/repos/[^/]+/[^/]+/codespaces/secrets.*", "gh secret: modifies codespaces secrets"),
    ("DELETE", r"^/repos/[^/]+/[^/]+/codespaces/secrets.*", "gh secret: deletes codespaces secrets"),
]

# Compile regex patterns for performance
_allowed_compiled = [(method, re.compile(pattern)) for method, pattern in ALLOWED_OPERATIONS]
_blocked_compiled = [(method, re.compile(pattern), msg) for method, pattern, msg in BLOCKED_PATTERNS]
_conditional_pr_compiled = [(method, re.compile(pattern)) for method, pattern in CONDITIONAL_PR_OPERATIONS]

# Regex to detect PR PATCH endpoint for reopen detection
_pr_patch_pattern = re.compile(r"^/repos/[^/]+/[^/]+/pulls/\d+$")


class GitHubAPIFilter:
    """mitmproxy addon that filters dangerous GitHub API operations."""

    def request(self, flow: http.HTTPFlow) -> None:
        """Check request against allowlist and block if not permitted."""
        host = flow.request.host

        # Only filter GitHub API requests
        if host not in GITHUB_API_HOSTS:
            return

        # Normalize method to uppercase for defense-in-depth.
        # HTTP methods are defined as case-sensitive uppercase per spec,
        # but a proxy-aware attacker could craft raw requests with
        # lowercase methods to bypass string comparisons.
        method = flow.request.method.upper()
        path = flow.request.path

        # Strip query string for pattern matching
        path_without_query = path.split("?")[0]

        # Check explicit blocklist first (for clear error messages)
        for blocked_method, pattern, message in _blocked_compiled:
            if method == blocked_method and pattern.match(path_without_query):
                ctx.log.warn(f"BLOCKED GitHub API: {method} {path} - {message}")
                self._block_request(flow, message)
                return

        # Check for PR reopen (PATCH to pulls endpoint with state: open)
        # This is always blocked regardless of ALLOW_PR_OPERATIONS
        if method == "PATCH" and _pr_patch_pattern.match(path_without_query):
            if self._is_pr_reopen(flow):
                ctx.log.warn(f"BLOCKED GitHub API: {method} {path} - PR reopen not allowed")
                self._block_request(flow, "gh pr reopen: reopening closed PRs requires human approval")
                return

        # Check GraphQL mutations
        if method == "POST" and path_without_query == "/graphql":
            blocked_mutation = self._check_graphql_mutations(flow)
            if blocked_mutation:
                ctx.log.warn(f"BLOCKED GitHub GraphQL: {blocked_mutation}")
                self._block_request(flow, f"GraphQL mutation '{blocked_mutation}' is not permitted")
                return

        # Check conditional PR operations (blocked by default, allowed with --allow-pr)
        if not ALLOW_PR_OPERATIONS:
            for pr_method, pattern in _conditional_pr_compiled:
                if method == pr_method and pattern.match(path_without_query):
                    ctx.log.warn(f"BLOCKED GitHub API (PR ops disabled): {method} {path}")
                    self._block_request(
                        flow,
                        f"PR operations blocked by sandbox policy. Use --allow-pr flag to enable."
                    )
                    return

        # Check allowlist
        for allowed_method, pattern in _allowed_compiled:
            if method == allowed_method and pattern.match(path_without_query):
                ctx.log.info(f"Allowed GitHub API: {method} {path}")
                return

        # Check if it's a conditional PR operation that's now allowed
        if ALLOW_PR_OPERATIONS:
            for pr_method, pattern in _conditional_pr_compiled:
                if method == pr_method and pattern.match(path_without_query):
                    ctx.log.info(f"Allowed GitHub API (PR ops enabled): {method} {path}")
                    return

        # Not in allowlist - block with generic message
        ctx.log.warn(f"BLOCKED GitHub API (not in allowlist): {method} {path}")
        self._block_request(
            flow,
            f"gh api: raw API access not permitted ({method} {path_without_query})"
        )

    def _is_pr_reopen(self, flow: http.HTTPFlow) -> bool:
        """Check if a PATCH request is attempting to reopen a PR."""
        try:
            content = flow.request.get_text()
            if not content:
                return False
            data = json.loads(content)
            # Check if state is being set to "open" (case-insensitive
            # for defense-in-depth, consistent with policy_engine.py's
            # APPROVE check which uses str(...).upper())
            return str(data.get("state", "")).lower() == "open"
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def _check_graphql_mutations(self, flow: http.HTTPFlow) -> str | None:
        """
        Check GraphQL request for blocked mutations.
        Returns the mutation name if blocked, None otherwise.
        """
        try:
            content = flow.request.get_text()
            if not content:
                return None
            data = json.loads(content)
            query = data.get("query", "")

            # Strip GraphQL comments before regex matching.
            # GraphQL supports `# comment` line comments, which could be
            # inserted between a mutation name and its opening `(` to
            # bypass the `\bmutation\s*\(` regex pattern.
            query = re.sub(r'#[^\n]*', '', query)

            # Check always-blocked mutations first
            for mutation in ALWAYS_BLOCKED_GRAPHQL_MUTATIONS:
                # Look for mutation keyword followed by the mutation name
                # Handles both "mutation { mutationName" and "mutation MutationName"
                if re.search(rf'\b{mutation}\s*\(', query, re.IGNORECASE):
                    return mutation

            # Check conditionally-blocked mutations if PR ops are disabled
            if not ALLOW_PR_OPERATIONS:
                for mutation in CONDITIONAL_BLOCKED_GRAPHQL_MUTATIONS:
                    if re.search(rf'\b{mutation}\s*\(', query, re.IGNORECASE):
                        return mutation

            return None
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fail closed: if we can't parse the body, block the request.
            # A crafted body that parses differently in Python vs. GitHub's
            # parser could exploit a fail-open here.
            return "unparseable GraphQL request body (fail closed)"

    def _block_request(self, flow: http.HTTPFlow, reason: str) -> None:
        """Return 403 Forbidden with explanation."""
        flow.response = http.Response.make(
            403,
            json.dumps({
                "error": "BLOCKED",
                "message": reason,
                "documentation_url": "https://docs.github.com/rest",
                "hint": "This operation requires human operator approval."
            }, indent=2).encode(),
            {
                "Content-Type": "application/json",
                "X-Sandbox-Blocked": "true",
            },
        )


addons = [GitHubAPIFilter()]
