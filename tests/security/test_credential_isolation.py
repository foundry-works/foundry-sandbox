"""Credential isolation tests for sandbox environments.

Verifies that real credentials are never exposed inside the sandbox:
- Environment variables contain only placeholders, not real keys
- API requests work transparently via the credential proxy
- Response headers do not leak injected credentials

These tests run commands inside a live sandbox container via ``docker exec``.
"""

import os

import pytest

pytestmark = [
    pytest.mark.security,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]

# Regex patterns that match real credential prefixes.
# If any env var value matches these, real credentials have leaked.
REAL_CREDENTIAL_PATTERNS = [
    r"^sk-ant-",          # Anthropic API keys
    r"^sk-proj-",         # OpenAI project keys
    r"^sk-[a-zA-Z0-9]{20,}",  # Generic OpenAI keys
    r"^ghp_",             # GitHub personal access tokens
    r"^ghs_",             # GitHub server-to-server tokens
    r"^gho_",             # GitHub OAuth tokens
    r"^AIza",             # Google/Gemini API keys
]

PLACEHOLDER = "CREDENTIAL_PROXY_PLACEHOLDER"


def test_no_real_credentials_in_env(docker_exec):
    """Environment variables inside the sandbox must not contain real credentials.

    Mirrors redteam-sandbox.sh (lines 44-78): scans all env vars for known
    credential prefixes (sk-ant-, ghp_, ghs_, sk-proj-, AIza, etc.).
    Only placeholders should be present.
    """
    import re

    result = docker_exec("env")
    assert result.returncode == 0, f"docker exec env failed: {result.stderr}"

    violations = []
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        for pattern in REAL_CREDENTIAL_PATTERNS:
            if re.match(pattern, value):
                violations.append(
                    f"{name} matches real credential pattern {pattern!r}"
                )

    assert not violations, (
        "Real credentials found in sandbox environment:\n"
        + "\n".join(f"  - {v}" for v in violations)
    )


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY")
    and not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"),
    reason="No API credentials available — proxy cannot inject credentials",
)
def test_api_requests_work_via_proxy(docker_exec, proxy_reachable):
    """API requests with placeholder credentials should succeed via the proxy.

    Mirrors redteam-sandbox.sh (lines 272-294): sends a request to the
    Anthropic API using the placeholder credential.  The proxy should
    inject the real key before forwarding.  We accept either a successful
    response (type=message) or an auth error that proves the request
    reached the API (as opposed to a connection failure).
    """
    result = docker_exec(
        "curl", "-s", "--max-time", "15",
        "-H", f"x-api-key: {PLACEHOLDER}",
        "-H", "anthropic-version: 2023-06-01",
        "-H", "content-type: application/json",
        "-d", '{"model":"claude-3-haiku-20240307","max_tokens":10,'
              '"messages":[{"role":"user","content":"hi"}]}',
        "https://api.anthropic.com/v1/messages",
    )

    body = result.stdout
    # Either the proxy injected real credentials and we got a response,
    # or the request reached the API and got an auth error — both prove
    # the proxy is forwarding traffic.
    api_reached = (
        '"type":"message"' in body
        or '"type": "message"' in body
        or "authentication_error" in body
        or "invalid_api_key" in body
    )
    assert api_reached, (
        "API request did not reach Anthropic (proxy may not be forwarding).\n"
        f"Response body: {body[:500]}"
    )


def test_credential_not_in_response_headers(docker_exec):
    """Response headers from proxied requests must not contain real credentials.

    Verifies the credential proxy strips injected credentials from
    responses so they cannot be observed by the sandboxed process.
    """
    import re

    result = docker_exec(
        "curl", "-sS", "--max-time", "15",
        "-D", "-",  # dump headers to stdout
        "-o", "/dev/null",
        "-H", f"x-api-key: {PLACEHOLDER}",
        "-H", "anthropic-version: 2023-06-01",
        "-H", "content-type: application/json",
        "-d", '{"model":"claude-3-haiku-20240307","max_tokens":10,'
              '"messages":[{"role":"user","content":"hi"}]}',
        "https://api.anthropic.com/v1/messages",
    )

    headers = result.stdout
    for pattern in REAL_CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, headers, re.MULTILINE)
        assert not matches, (
            f"Response headers contain real credential matching {pattern!r}:\n"
            f"{headers[:500]}"
        )
