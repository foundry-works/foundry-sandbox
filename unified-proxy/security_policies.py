"""Shared GitHub security policy enforcement.

Single source of truth for GitHub API security policies used by both
the GitHub API gateway (github_gateway.py) and the mitmproxy policy
engine (addons/policy_engine.py).

Policy layers:
  - Path normalization (URL decode, double-encoding rejection, slash collapsing)
  - Merge blocking (REST endpoints + GraphQL mutations)
  - Operation blocklist (release creation, ref mutations, webhooks, etc.)
  - Body inspection (PR/issue close, PR self-approval)
  - Dangerous endpoint blocklist (hooks, deploy keys, secrets, etc.)

Both consumers import from this module to prevent pattern drift.
"""

import json
import posixpath
import re
from typing import Optional
from urllib.parse import unquote, urlparse


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

def normalize_path(raw_path: str) -> Optional[str]:
    """Normalize a URL path with strict security rules.

    Steps:
    1. Strip query string and fragment
    2. URL-decode once
    3. Reject if '%' still present (double-encoding prevention)
    4. Collapse repeated slashes (// -> /)
    5. Resolve .. segments via posixpath.normpath
    6. Strip trailing slash (except bare /)

    Args:
        raw_path: The raw URL path (may include query string).

    Returns:
        Normalized path string, or None if the path is rejected
        (e.g., double-encoding detected).
    """
    path = urlparse(raw_path).path
    path = unquote(path)
    if "%" in path:
        return None
    path = posixpath.normpath(path)
    while "//" in path:
        path = path.replace("//", "/")
    if path == ".":
        path = "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


# ---------------------------------------------------------------------------
# Merge blocking (Step E — early-exit, unconditional)
# ---------------------------------------------------------------------------

# REST endpoints for PR merge operations.
# Uses search() in policy_engine (full path includes /repos/owner/repo prefix)
# and search() in github_gateway (path is relative to api.github.com).
_MERGE_PATH_PATTERNS = [
    re.compile(r"/pulls/\d+/merge$"),
    re.compile(r"/pulls/\d+/auto-merge$"),
]

# GraphQL mutation keywords for merge operations.
_MERGE_BODY_KEYWORDS = [
    b"mergePullRequest",
    b"enablePullRequestAutoMerge",
]


def is_merge_request(path: str, body: bytes) -> bool:
    """Check if a request is a merge operation (REST or GraphQL).

    For REST, checks if the path matches a merge endpoint pattern.
    For GraphQL (/graphql), parses the JSON body and checks only the
    ``query`` field for merge mutation keywords (not the entire body).
    This avoids false positives from PR descriptions that mention merge
    keywords.

    Args:
        path: The request path.
        body: The raw request body bytes.

    Returns:
        True if the request appears to be a merge operation.
    """
    if any(p.search(path) for p in _MERGE_PATH_PATTERNS):
        return True

    # GraphQL: only check the query/mutation field, not the full body.
    # This prevents false positives from PR descriptions or comments
    # that mention "mergePullRequest" as text.
    if body and path.rstrip("/").endswith("/graphql"):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                query_field = parsed.get("query", "")
                if isinstance(query_field, str):
                    query_bytes = query_field.encode("utf-8", errors="replace")
                    if any(kw in query_bytes for kw in _MERGE_BODY_KEYWORDS):
                        return True
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            # If we can't parse the body, fall back to substring scan
            # for safety (fail closed — block rather than allow).
            if any(kw in body for kw in _MERGE_BODY_KEYWORDS):
                return True

    return False


# ---------------------------------------------------------------------------
# GitHub REST blocklist (Step 3)
# ---------------------------------------------------------------------------

GITHUB_MERGE_PR_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/pulls/\d+/merge$"
)
GITHUB_CREATE_RELEASE_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/releases$"
)
GITHUB_GIT_REFS_ROOT_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/git/refs$"
)
GITHUB_GIT_REFS_SUBPATH_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/git/refs/.+$"
)
GITHUB_AUTO_MERGE_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/pulls/\d+/auto-merge$"
)
GITHUB_DELETE_REVIEW_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews/\d+$"
)
GITHUB_REPO_MERGES_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/merges$"
)

# Dangerous endpoints that must never be accessed (any method).
BLOCKED_PATH_PATTERNS = [
    re.compile(r"^/repos/[^/]+/[^/]+/hooks(/\d+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/keys(/\d+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/deploy_keys(/\d+)?$"),
    re.compile(
        r"^/repos/[^/]+/[^/]+/environments/[^/]+/deployment-branch-policy$"
    ),
    re.compile(r"^/repos/[^/]+/[^/]+/actions/secrets(/[^/]+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/actions/variables(/[^/]+)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/branches/.+/protection(/.*)?$"),
    re.compile(r"^/repos/[^/]+/[^/]+/branches/.+/rename$"),
]


def check_github_blocklist(method: str, path: str) -> Optional[str]:
    """Check GitHub-specific blocklist policies.

    Returns block reason if request should be blocked, None otherwise.
    """
    if method == "PUT" and GITHUB_MERGE_PR_PATTERN.fullmatch(path):
        return "GitHub PR merge operations are blocked by policy"

    if method == "POST" and GITHUB_CREATE_RELEASE_PATTERN.fullmatch(path):
        return "GitHub release creation is blocked by policy"

    if method == "POST" and GITHUB_REPO_MERGES_PATTERN.fullmatch(path):
        return "GitHub repo merge operations are blocked by policy"

    if method == "POST" and GITHUB_GIT_REFS_ROOT_PATTERN.fullmatch(path):
        return "GitHub git ref creation is blocked by policy"
    if method in {"PATCH", "DELETE"} and GITHUB_GIT_REFS_SUBPATH_PATTERN.fullmatch(path):
        return "GitHub git ref mutation is blocked by policy"

    if method in ("PUT", "DELETE") and GITHUB_AUTO_MERGE_PATTERN.fullmatch(path):
        return "GitHub auto-merge operations are blocked by policy"

    if method == "DELETE" and GITHUB_DELETE_REVIEW_PATTERN.fullmatch(path):
        return "Deleting pull request reviews is blocked by policy"

    for pattern in BLOCKED_PATH_PATTERNS:
        if pattern.fullmatch(path):
            return f"Path '{path}' is blocked by policy"

    return None


# ---------------------------------------------------------------------------
# Body inspection (Step 3b)
# ---------------------------------------------------------------------------

GITHUB_PATCH_PR_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/pulls/\d+$"
)
GITHUB_PATCH_ISSUE_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/issues/\d+$"
)
GITHUB_PR_REVIEW_PATTERN = re.compile(
    r"^/repos/[^/]+/[^/]+/pulls/\d+/reviews$"
)


def check_github_body_policies(
    method: str,
    path: str,
    body: Optional[bytes],
    content_type: str,
    content_encoding: str,
) -> Optional[str]:
    """Check GitHub body-level policies for PATCH and POST operations.

    Inspects request bodies on security-relevant endpoints to block
    PR close, issue close, and PR review approval operations.

    Returns block reason if request should be blocked, None otherwise.
    """
    if method not in ("PATCH", "POST"):
        return None

    # POST: PR review approval check
    if method == "POST" and GITHUB_PR_REVIEW_PATTERN.fullmatch(path):
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
        event = parsed.get("event")
        if event is not None and str(event).upper() == "APPROVE":
            return "Self-approving pull requests is blocked by policy"
        return None

    # PATCH: PR/issue close check
    if not (
        GITHUB_PATCH_PR_PATTERN.fullmatch(path)
        or GITHUB_PATCH_ISSUE_PATTERN.fullmatch(path)
    ):
        return None

    if content_encoding:
        return (
            "Compressed request bodies are not allowed for "
            "security-relevant GitHub PATCH endpoints"
        )
    if not content_type:
        return (
            "Content-Type header is required for "
            "security-relevant GitHub PATCH endpoints"
        )
    if not content_type.lower().startswith("application/json"):
        return (
            f"Content-Type must be application/json for "
            f"security-relevant GitHub PATCH endpoints, "
            f"got: {content_type}"
        )
    if body is None:
        return (
            "Streaming request bodies are not allowed for "
            "security-relevant GitHub PATCH endpoints"
        )

    body_str = body.lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")
    try:
        parsed = json.loads(body_str)
    except (json.JSONDecodeError, ValueError):
        return "Malformed JSON body in security-relevant GitHub PATCH request"

    if not isinstance(parsed, dict):
        return (
            "Request body must be a JSON object for "
            "security-relevant GitHub PATCH endpoints"
        )

    state = parsed.get("state")
    if state is not None and str(state).lower() == "closed":
        if GITHUB_PATCH_PR_PATTERN.fullmatch(path):
            return "Closing pull requests via API is blocked by policy"
        else:
            return "Closing issues via API is blocked by policy"

    return None
