"""
GitHub API Security Filter - mitmproxy Addon

Blocks dangerous GitHub API operations at the network layer.
This is a security boundary - cannot be bypassed from within the sandbox.

Blocked operations (matching shell-overrides.sh):
- gh repo delete    → DELETE /repos/{owner}/{repo}
- gh release delete → DELETE /repos/{owner}/{repo}/releases/*
- gh api            → All api.github.com requests (use allowlist for safe ops)
- gh secret         → /repos/{owner}/{repo}/actions/secrets/*
- gh variable       → /repos/{owner}/{repo}/actions/variables/*

Design: Allowlist approach - only explicitly permitted operations pass through.
This ensures gh api raw access is blocked while normal gh commands work.
"""

import json
import re
from mitmproxy import http, ctx

# GitHub API hosts
GITHUB_API_HOSTS = [
    "api.github.com",
    "uploads.github.com",  # For release asset uploads
]

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

    # --- Pull Requests ---
    ("GET", r"^/repos/[^/]+/[^/]+/pulls.*"),
    ("POST", r"^/repos/[^/]+/[^/]+/pulls$"),  # Create PR
    ("POST", r"^/repos/[^/]+/[^/]+/pulls/\d+/comments$"),  # Add PR comment
    ("POST", r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$"),  # Add PR review
    ("PATCH", r"^/repos/[^/]+/[^/]+/pulls/\d+$"),  # Update PR
    # Note: PUT .../pulls/.../merge is intentionally NOT allowed (history protection)

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

    # --- GraphQL (allowed but monitored - gh uses this heavily) ---
    ("POST", r"^/graphql$"),
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


class GitHubAPIFilter:
    """mitmproxy addon that filters dangerous GitHub API operations."""

    def request(self, flow: http.HTTPFlow) -> None:
        """Check request against allowlist and block if not permitted."""
        host = flow.request.host

        # Only filter GitHub API requests
        if host not in GITHUB_API_HOSTS:
            return

        method = flow.request.method
        path = flow.request.path

        # Strip query string for pattern matching
        path_without_query = path.split("?")[0]

        # Check explicit blocklist first (for clear error messages)
        for blocked_method, pattern, message in _blocked_compiled:
            if method == blocked_method and pattern.match(path_without_query):
                ctx.log.warn(f"BLOCKED GitHub API: {method} {path} - {message}")
                self._block_request(flow, message)
                return

        # Check allowlist
        for allowed_method, pattern in _allowed_compiled:
            if method == allowed_method and pattern.match(path_without_query):
                ctx.log.info(f"Allowed GitHub API: {method} {path}")
                return

        # Not in allowlist - block with generic message
        ctx.log.warn(f"BLOCKED GitHub API (not in allowlist): {method} {path}")
        self._block_request(
            flow,
            f"gh api: raw API access not permitted ({method} {path_without_query})"
        )

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
