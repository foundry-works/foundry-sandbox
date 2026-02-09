"""Self-merge prevention integration tests.

Verifies that the proxy blocks dangerous GitHub API operations that would
allow a sandbox to merge its own pull requests, approve its own reviews,
or enable auto-merge.  All tests execute ``curl`` inside a live sandbox
container via ``docker exec`` and assert that the proxy returns HTTP 403.

Security properties tested:
- PR merge via REST API is blocked (PUT /repos/*/pulls/*/merge)
- Auto-merge enablement via REST API is blocked (PUT /repos/*/pulls/*/auto-merge)
- PR review creation with APPROVE event is blocked (POST /repos/*/pulls/*/reviews)
- GraphQL mergePullRequest mutation is blocked (POST /graphql)

These tests mirror the shell-based checks in redteam-sandbox.sh section 23
("SELF-MERGE PREVENTION") but run as proper pytest cases with deterministic
pass/fail assertions.
"""

import json

import pytest

pytestmark = [
    pytest.mark.security,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]

PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"

# Dummy repo coordinates -- the proxy should block the operation before
# the request ever reaches GitHub, so the repo need not exist.
OWNER = "octocat"
REPO = "Hello-World"
PR_NUMBER = "1"
REVIEW_ID = "123"


def _curl_status_code(docker_exec, method, url, data=None, extra_headers=None):
    """Run curl inside the sandbox and return the HTTP status code as a string.

    Args:
        docker_exec: The docker_exec fixture callable.
        method: HTTP method (GET, POST, PUT, DELETE).
        url: Full URL to request.
        data: Optional JSON body string.
        extra_headers: Optional list of additional ``-H`` flag pairs.

    Returns:
        The HTTP status code as a string (e.g. ``"403"``), or the raw
        stdout if the curl command failed unexpectedly.
    """
    cmd = [
        "curl", "-s",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--max-time", "15",
        "-X", method,
        "-H", f"Authorization: token {PLACEHOLDER}",
        "-H", "Content-Type: application/json",
    ]

    if extra_headers:
        for hdr in extra_headers:
            cmd.extend(["-H", hdr])

    if data is not None:
        cmd.extend(["-d", data])

    cmd.append(url)

    result = docker_exec(*cmd)
    return result.stdout.strip()


class TestSelfMergePrevention:
    """Integration tests verifying the proxy blocks self-merge operations.

    Each test sends a curl request from inside the sandbox container to a
    GitHub API endpoint that would allow the sandbox to merge or approve
    its own pull requests.  The proxy must intercept these requests and
    return 403 Forbidden.
    """

    def test_gh_pr_merge_blocked(self, docker_exec):
        """PUT /repos/{owner}/{repo}/pulls/{number}/merge must return 403.

        This endpoint performs a PR merge via the REST API.  The proxy
        blocks it to prevent the sandbox from merging its own pull requests,
        which is the primary self-merge attack vector.

        Corresponds to redteam-sandbox.sh section 23, test 1.
        """
        url = (
            f"https://api.github.com/repos/{OWNER}/{REPO}"
            f"/pulls/{PR_NUMBER}/merge"
        )
        data = json.dumps({
            "commit_title": "self-merge test",
            "merge_method": "merge",
        })

        status = _curl_status_code(docker_exec, "PUT", url, data=data)

        assert status == "403", (
            f"Expected 403 for PUT .../pulls/{PR_NUMBER}/merge, got {status}. "
            "The proxy must block PR merge requests to prevent self-merge."
        )

    def test_auto_merge_enable_blocked(self, docker_exec):
        """PUT /repos/{owner}/{repo}/pulls/{number}/auto-merge must return 403.

        Enabling auto-merge allows a PR to be merged automatically once
        status checks pass.  The proxy blocks this to prevent the sandbox
        from scheduling its own PR for automatic merge.

        Corresponds to redteam-sandbox.sh section 23, test 2.
        """
        url = (
            f"https://api.github.com/repos/{OWNER}/{REPO}"
            f"/pulls/{PR_NUMBER}/auto-merge"
        )

        status = _curl_status_code(docker_exec, "PUT", url, data="{}")

        assert status == "403", (
            f"Expected 403 for PUT .../pulls/{PR_NUMBER}/auto-merge, got {status}. "
            "The proxy must block auto-merge enablement to prevent self-merge."
        )

    def test_pr_review_create_blocked(self, docker_exec):
        """POST /repos/{owner}/{repo}/pulls/{number}/reviews with APPROVE must return 403.

        Creating a review with ``event: APPROVE`` would let the sandbox
        approve its own pull request.  The proxy's policy engine inspects
        the request body and blocks approval reviews to prevent
        self-approval.

        Corresponds to redteam-sandbox.sh section 23, test 3.
        """
        url = (
            f"https://api.github.com/repos/{OWNER}/{REPO}"
            f"/pulls/{PR_NUMBER}/reviews"
        )
        data = json.dumps({
            "event": "APPROVE",
            "body": "Looks good",
        })

        status = _curl_status_code(docker_exec, "POST", url, data=data)

        assert status == "403", (
            f"Expected 403 for POST .../pulls/{PR_NUMBER}/reviews "
            f"(event=APPROVE), got {status}. "
            "The proxy must block self-approval reviews."
        )

    def test_graphql_merge_mutation_blocked(self, docker_exec):
        """GraphQL mergePullRequest mutation via POST /graphql must return 403.

        The ``mergePullRequest`` mutation is an alternative way to merge a
        PR.  The proxy's GitHub API filter addon matches this mutation name
        in the request body and blocks it, regardless of variables.

        Corresponds to redteam-sandbox.sh section 23, test 6 (analogous
        pattern -- the shell script tests updatePullRequestBranch; this
        test covers the more critical mergePullRequest mutation).
        """
        url = "https://api.github.com/graphql"
        data = json.dumps({
            "query": (
                "mutation { mergePullRequest(input: "
                '{pullRequestId: "PR_test123"}) '
                "{ pullRequest { id } } }"
            ),
        })

        status = _curl_status_code(docker_exec, "POST", url, data=data)

        assert status == "403", (
            f"Expected 403 for GraphQL mergePullRequest mutation, got {status}. "
            "The proxy must block GraphQL merge mutations to prevent self-merge."
        )
