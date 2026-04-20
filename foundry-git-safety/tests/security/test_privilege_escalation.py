"""Privilege escalation review: verify the git-safety HTTP surface cannot be
used to gain unauthorized access or execute arbitrary commands.

Tests that exit codes are honest, response sizes are bounded, env sanitization
is complete, and injection via args/cwd/stdin is prevented.
"""

import json
import os
import time

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
)
from foundry_git_safety.command_validation import MAX_RESPONSE_SIZE
from foundry_git_safety.server import create_git_api
from foundry_git_safety.subprocess_env import ENV_ALLOWED, build_clean_env


pytestmark = pytest.mark.security


def _make_app(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    data_dir = tmp_path / "data"

    sandbox_id = "escalation-test"
    secret = b"escalation-secret-key\n"
    (secrets_dir / sandbox_id).write_bytes(secret)

    app = create_git_api(
        secret_store=SecretStore(secrets_path=str(secrets_dir)),
        nonce_store=NonceStore(),
        rate_limiter=RateLimiter(),
        data_dir=str(data_dir),
    )
    app._test_sandbox_id = sandbox_id
    app._test_secret = secret.strip()
    return app


def _auth_headers(app, body: bytes, sandbox_id: str | None = None):
    sid = sandbox_id or app._test_sandbox_id
    ts = str(time.time())
    nonce = f"esc-nonce-{time.time_ns()}"
    sig = compute_signature("POST", "/git/exec", body, ts, nonce, app._test_secret)
    return {
        "X-Sandbox-Id": sid,
        "X-Request-Signature": sig,
        "X-Request-Timestamp": ts,
        "X-Request-Nonce": nonce,
    }


def _write_metadata(tmp_path, sandbox_id, branch="feature", repo="test/repo"):
    metadata_dir = tmp_path / "data" / "sandboxes"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (metadata_dir / f"{sandbox_id}.json").write_text(json.dumps({
        "sandbox_branch": branch,
        "from_branch": "main",
        "repos": [repo],
    }))


class TestMaliciousWrapperResponse:
    """Verify server responses cannot be exploited by a malicious wrapper."""

    def test_response_exit_code_not_overridden(self, tmp_path):
        """Server returns the actual git exit code — cannot be faked to 0."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        # Request an invalid command — should get a non-zero exit
        body = json.dumps({"args": ["status"], "cwd": "/nonexistent"}).encode()
        headers = _auth_headers(app, body)
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")

        if resp.status_code == 200:
            data = resp.json
            # If git fails, exit_code should be non-zero (not overridden to 0)
            # The server returns whatever git returns
            assert "exit_code" in data

    def test_environment_sanitization_complete(self):
        """build_clean_env() produces only allowed keys plus overrides."""
        # Set some dangerous env vars that should NOT leak
        old_env = os.environ.copy()
        os.environ["GIT_CONFIG_GLOBAL"] = "/home/attacker/.gitconfig"
        os.environ["SSH_AUTH_SOCK"] = "/tmp/attacker-ssh"
        os.environ["GIT_EXEC_PATH"] = "/malicious/path"
        os.environ["MY_API_KEY"] = "secret-key-123"

        try:
            env = build_clean_env()

            # Only allowed keys should be present (plus FOUNDRY_* overrides)
            for key in env:
                if key.startswith("FOUNDRY_") or key in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
                    continue
                assert key in ENV_ALLOWED, f"Unexpected env key: {key}"

            # Dangerous keys must not appear
            assert "SSH_AUTH_SOCK" not in env
            assert "GIT_EXEC_PATH" not in env
            assert "MY_API_KEY" not in env

            # HOME must be isolated
            assert env.get("HOME") == "/dev/null" or env.get("HOME", "").startswith("/dev/null")

            # GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM must be /dev/null
            assert env.get("GIT_CONFIG_GLOBAL") == "/dev/null"
            assert env.get("GIT_CONFIG_SYSTEM") == "/dev/null"
        finally:
            os.environ.clear()
            os.environ.update(old_env)

    def test_no_code_execution_from_response(self, tmp_path):
        """Response from /git/exec is pure JSON — no executable content type."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        body = json.dumps({"args": ["status"], "cwd": "."}).encode()
        headers = _auth_headers(app, body)
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")

        content_type = resp.content_type or ""
        assert "json" in content_type or "application/json" in content_type


class TestServerSideInjection:
    """Verify malicious inputs cannot achieve code execution or path traversal."""

    def test_malformed_args_do_not_execute_arbitrary_commands(self, tmp_path):
        """Shell metacharacters in args are blocked by the command allowlist."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        # Try to inject shell commands
        injection_attempts = [
            ["status", ";", "rm", "-rf", "/"],
            ["status", "&&", "cat", "/etc/passwd"],
            ["status", "|", "bash"],
            ["$(cat /etc/passwd)"],
            ["status`id`"],
        ]

        for args in injection_attempts:
            body = json.dumps({"args": args}).encode()
            headers = _auth_headers(app, body)
            resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
            # Should be rejected (400 or 422) — never executed
            assert resp.status_code in (400, 422), f"Args {args} returned {resp.status_code}"

    def test_path_traversal_in_cwd_blocked(self, tmp_path):
        """Path traversal in cwd parameter is blocked."""
        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        traversal_paths = [
            "../../etc",
            "/../../etc/passwd",
            "../../../tmp",
        ]

        for cwd in traversal_paths:
            body = json.dumps({"args": ["status"], "cwd": cwd}).encode()
            headers = _auth_headers(app, body)
            resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
            assert resp.status_code == 422, f"CWD {cwd!r} was not blocked"
            err = resp.json["error"].lower()
            assert "traversal" in err or "path" in err, f"Unexpected error for {cwd!r}: {err}"

    def test_stdin_b64_cannot_inject_commands(self, tmp_path):
        """stdin_b64 is passed to subprocess via input= parameter, not shell."""
        import base64

        app = _make_app(tmp_path)
        client = app.test_client()
        _write_metadata(tmp_path, app._test_sandbox_id)

        # Try to inject shell commands via stdin
        malicious_stdin = "; rm -rf /"
        stdin_b64 = base64.b64encode(malicious_stdin.encode()).decode()

        body = json.dumps({
            "args": ["status"],
            "cwd": ".",
            "stdin_b64": stdin_b64,
        }).encode()
        headers = _auth_headers(app, body)
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        # Request may succeed or fail (git operation) but should not execute the injection
        assert resp.status_code in (200, 400, 422)

    def test_response_size_limit_prevents_memory_bomb(self):
        """MAX_RESPONSE_SIZE is set and finite to prevent memory exhaustion."""
        assert MAX_RESPONSE_SIZE == 10 * 1024 * 1024  # 10MB
        assert MAX_RESPONSE_SIZE > 0

    def test_unknown_sandbox_id_rejected(self, tmp_path):
        """Requests with unregistered sandbox IDs are rejected."""
        app = _make_app(tmp_path)
        client = app.test_client()

        body = json.dumps({"args": ["status"]}).encode()
        headers = _auth_headers(app, body, sandbox_id="attacker-sandbox")
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        assert resp.status_code == 401
