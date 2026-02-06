"""Unit tests for git operations API.

Tests the git_operations.py and git_api.py modules covering:
- Command allowlist validation
- Flag validation (global and per-command)
- Config key validation (-c options)
- Path validation and traversal prevention
- Environment sanitization
- HMAC authentication
- Nonce replay protection
- Rate limiting
- Response handling (truncation, size limits)
- Remote subcommand validation
"""

import base64
import json
import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

# mitmproxy mocks and sys.path setup handled by conftest.py

# Import the modules under test
import git_operations
from git_operations import (
    ALLOWED_COMMANDS,
    CONFIG_NEVER_ALLOW,
    CONFIG_PERMITTED_PREFIXES,
    ENV_VARS_TO_CLEAR,
    GLOBAL_BLOCKED_FLAGS,
    MAX_ARGS_COUNT,
    MAX_REQUEST_BODY_SIZE,
    MAX_RESPONSE_SIZE,
    MAX_STDIN_SIZE,
    REMOTE_ALLOWED_SUBCOMMANDS,
    REMOTE_BLOCKED_SUBCOMMANDS,
    GitExecRequest,
    build_clean_env,
    check_push_protected_branches,
    execute_git,
    validate_command,
    validate_path,
    validate_request,
)

import git_api
from git_api import (
    CLOCK_WINDOW_SECONDS,
    MAX_REQUEST_BODY,
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
    create_git_api,
)


# ---------------------------------------------------------------------------
# Test Classes
# ---------------------------------------------------------------------------


class TestCommandAllowlist:
    """Tests for command allowlist validation."""

    def test_allowed_commands_pass_through(self):
        """Test that all allowlisted commands pass validation."""
        allowed_cmds = ["status", "add", "commit", "push", "pull", "fetch", "diff", "log"]

        for cmd in allowed_cmds:
            result = validate_command([cmd])
            assert result is None, f"Command {cmd} should be allowed but got: {result}"

    def test_non_allowlisted_commands_rejected(self):
        """Test that non-allowlisted commands are rejected (e.g., reset, rm)."""
        blocked_cmds = ["reset", "rm", "gc", "fsck", "filter-branch", "reflog"]

        for cmd in blocked_cmds:
            result = validate_command([cmd])
            assert result is not None, f"Command {cmd} should be blocked"
            assert "not allowed" in result.reason.lower()


class TestFlagValidation:
    """Tests for flag validation."""

    def test_git_dir_flag_blocked(self):
        """Test that --git-dir flag is blocked."""
        result = validate_command(["--git-dir=/tmp/evil", "status"])
        assert result is not None
        assert "blocked flag" in result.reason.lower()
        assert "--git-dir" in result.reason

    def test_force_flag_on_push_blocked(self):
        """Test that --force on push is blocked."""
        result = validate_command(["push", "--force", "origin", "main"])
        assert result is not None
        assert "blocked flag" in result.reason.lower()
        assert "push" in result.reason.lower()

    def test_interactive_rebase_blocked(self):
        """Test that interactive rebase is blocked."""
        result = validate_command(["rebase", "-i", "HEAD~3"])
        assert result is not None
        assert "blocked flag" in result.reason.lower()
        assert "rebase" in result.reason.lower()


class TestConfigKeyValidation:
    """Tests for -c config key validation."""

    def test_config_core_hooks_path_blocked(self):
        """Test that -c core.hooksPath=evil is blocked (never-allow)."""
        result = validate_command(["-c", "core.hooksPath=/tmp/evil", "status"])
        assert result is not None
        assert "blocked config key" in result.reason.lower()

    def test_config_alias_blocked(self):
        """Test that -c alias.st=!evil is blocked (never-allow)."""
        result = validate_command(["-c", "alias.st=!evil", "status"])
        assert result is not None
        assert "blocked config key" in result.reason.lower()

    def test_config_ssh_command_blocked(self):
        """Test that -c core.sshCommand=evil is blocked (never-allow)."""
        result = validate_command(["-c", "core.sshCommand=evil", "status"])
        assert result is not None
        assert "blocked config key" in result.reason.lower()

    def test_config_credential_helper_blocked(self):
        """Test that -c credential.helper=evil is blocked (never-allow)."""
        result = validate_command(["-c", "credential.helper=evil", "status"])
        assert result is not None
        assert "blocked config key" in result.reason.lower()

    def test_config_user_name_allowed(self):
        """Test that -c user.name=Test is allowed (permitted prefix)."""
        result = validate_command(["-c", "user.name=Test User", "status"])
        assert result is None

    def test_config_color_ui_allowed(self):
        """Test that -c color.ui=auto is allowed (permitted prefix)."""
        result = validate_command(["-c", "color.ui=auto", "status"])
        assert result is None


class TestPathValidation:
    """Tests for path validation and traversal prevention."""

    def test_path_traversal_blocked(self):
        """Test that path traversal (..) is blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result_path, error = validate_path("../../../etc", tmpdir)
            assert error is not None
            assert "traversal" in error.reason.lower()

    def test_symlink_escape_blocked(self):
        """Test that symlink in cwd subpath does not escape repo root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a directory structure
            subdir = os.path.join(tmpdir, "subdir")
            os.makedirs(subdir)

            # Create a symlink pointing outside repo root
            evil_link = os.path.join(subdir, "evil")
            os.symlink("/etc", evil_link)

            # Try to use the symlink path
            result_path, error = validate_path("subdir/evil", tmpdir)

            # Should be blocked because realpath resolves to /etc
            assert error is not None
            assert "outside repo root" in error.reason.lower()


class TestRequestValidation:
    """Tests for request body validation."""

    def test_decoded_stdin_over_1mb_rejected(self):
        """Test that decoded stdin over 1MB is rejected."""
        large_data = b"x" * (MAX_STDIN_SIZE + 1)
        encoded = base64.b64encode(large_data).decode("ascii")

        raw = {
            "args": ["status"],
            "stdin_b64": encoded,
        }

        request, error = validate_request(raw)
        assert error is not None
        assert "exceeds limit" in error.reason.lower()

    def test_max_args_count_enforced(self):
        """Test that max args count is enforced."""
        raw = {
            "args": ["arg"] * (MAX_ARGS_COUNT + 1),
        }

        request, error = validate_request(raw)
        assert error is not None
        assert "too many arguments" in error.reason.lower()


class TestEnvironmentSanitization:
    """Tests for environment sanitization."""

    def test_git_config_parameters_cleared(self):
        """Test that GIT_CONFIG_PARAMETERS env var is cleared."""
        os.environ["GIT_CONFIG_PARAMETERS"] = "'alias.st=!evil'"
        try:
            clean_env = build_clean_env()
            assert "GIT_CONFIG_PARAMETERS" not in clean_env
        finally:
            os.environ.pop("GIT_CONFIG_PARAMETERS", None)

    def test_git_dir_env_cleared(self):
        """Test that GIT_DIR env var is cleared."""
        os.environ["GIT_DIR"] = "/tmp/evil"
        try:
            clean_env = build_clean_env()
            assert "GIT_DIR" not in clean_env
        finally:
            os.environ.pop("GIT_DIR", None)

    def test_git_ssh_command_env_cleared(self):
        """Test that GIT_SSH_COMMAND env var is cleared."""
        os.environ["GIT_SSH_COMMAND"] = "evil"
        try:
            clean_env = build_clean_env()
            assert "GIT_SSH_COMMAND" not in clean_env
        finally:
            os.environ.pop("GIT_SSH_COMMAND", None)


class TestRemoteSubcommands:
    """Tests for git remote subcommand validation."""

    def test_git_remote_add_blocked(self):
        """Test that git remote add is blocked."""
        result = validate_command(["remote", "add", "origin", "https://evil.com/repo.git"])
        assert result is not None
        assert "not allowed" in result.reason.lower()

    def test_git_remote_set_url_blocked(self):
        """Test that git remote set-url is blocked."""
        result = validate_command(["remote", "set-url", "origin", "https://evil.com/repo.git"])
        assert result is not None
        assert "not allowed" in result.reason.lower()

    def test_git_remote_dash_v_allowed(self):
        """Test that git remote -v is allowed."""
        result = validate_command(["remote", "-v"])
        assert result is None


class TestHMACAuthentication:
    """Tests for HMAC authentication."""

    def test_unauthenticated_request_returns_401(self):
        """Test that unauthenticated request returns 401."""
        app = create_git_api()
        client = app.test_client()

        # Request without auth headers
        response = client.post(
            "/git/exec",
            data=json.dumps({"args": ["status"]}),
            content_type="application/json",
        )

        assert response.status_code == 401

    def test_spoofed_sandbox_id_returns_401(self):
        """Test that spoofed sandbox ID without valid HMAC returns 401."""
        # Create a custom secret store with a known secret
        secrets = SecretStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            secrets._path = tmpdir
            secret_file = os.path.join(tmpdir, "real-sandbox")
            with open(secret_file, "wb") as f:
                f.write(b"secret123")

            app = create_git_api(secret_store=secrets)
            client = app.test_client()

            # Try to use a different sandbox ID with wrong signature
            body = json.dumps({"args": ["status"]}).encode("utf-8")
            timestamp = str(time.time())
            nonce = "unique-nonce"

            # Compute signature for wrong sandbox
            wrong_sig = compute_signature(
                "POST", "/git/exec", body, timestamp, nonce, b"wrong-secret"
            )

            response = client.post(
                "/git/exec",
                data=body,
                headers={
                    "X-Sandbox-Id": "real-sandbox",
                    "X-Request-Signature": wrong_sig,
                    "X-Request-Timestamp": timestamp,
                    "X-Request-Nonce": nonce,
                },
            )

            assert response.status_code == 401

    def test_replayed_request_returns_401(self):
        """Test that replayed request (reused nonce) returns 401."""
        secrets = SecretStore()
        nonces = NonceStore()

        with tempfile.TemporaryDirectory() as tmpdir:
            secrets._path = tmpdir
            secret_file = os.path.join(tmpdir, "test-sandbox")
            with open(secret_file, "wb") as f:
                f.write(b"secret123")

            app = create_git_api(secret_store=secrets, nonce_store=nonces)
            client = app.test_client()

            # First request
            body = json.dumps({"args": ["status"]}).encode("utf-8")
            timestamp = str(time.time())
            nonce = "unique-nonce-123"

            sig = compute_signature(
                "POST", "/git/exec", body, timestamp, nonce, b"secret123"
            )

            response1 = client.post(
                "/git/exec",
                data=body,
                headers={
                    "X-Sandbox-Id": "test-sandbox",
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": timestamp,
                    "X-Request-Nonce": nonce,
                },
            )

            # May fail due to no repo_root, but should get past nonce check
            # If it's 401, it must be for a different reason (not nonce)
            assert response1.status_code != 401 or b"nonce" not in response1.data.lower()

            # Replay the same request with same nonce
            response2 = client.post(
                "/git/exec",
                data=body,
                headers={
                    "X-Sandbox-Id": "test-sandbox",
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": timestamp,
                    "X-Request-Nonce": nonce,  # Same nonce!
                },
            )

            assert response2.status_code == 401
            assert b"replayed" in response2.data.lower() or b"duplicate" in response2.data.lower()


class TestRateLimiting:
    """Tests for rate limiting."""

    def test_rate_limiting_keyed_on_authenticated_identity(self):
        """Test that rate limiting returns 429 keyed on authenticated identity."""
        limiter = RateLimiter(burst=2, sustained=1, global_ceiling=1000)

        # Consume tokens for sandbox1
        allowed, retry = limiter.check_sandbox_rate("sandbox1")
        assert allowed is True

        allowed, retry = limiter.check_sandbox_rate("sandbox1")
        assert allowed is True

        # Third request should be denied
        allowed, retry = limiter.check_sandbox_rate("sandbox1")
        assert allowed is False
        assert retry > 0

        # But sandbox2 should still have tokens
        allowed, retry = limiter.check_sandbox_rate("sandbox2")
        assert allowed is True

    def test_global_rate_ceiling_enforced(self):
        """Test that global rate ceiling is enforced."""
        limiter = RateLimiter(burst=1000, sustained=1000, global_ceiling=5)

        # Make 5 requests
        for i in range(5):
            allowed, retry = limiter.check_global_rate()
            assert allowed is True, f"Request {i+1} should be allowed"

        # 6th request should be denied
        allowed, retry = limiter.check_global_rate()
        assert allowed is False
        assert retry > 0


class TestResponseHandling:
    """Tests for response handling."""

    def test_response_truncation_at_10mb(self):
        """Test that response is truncated at 10MB."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock subprocess.run to return large stdout
            large_output = b"x" * (MAX_RESPONSE_SIZE + 1000)

            with patch("git_operations.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=large_output,
                    stderr=b"",
                )

                request = GitExecRequest(args=["log"])
                response, error = execute_git(request, tmpdir)

                assert error is None
                assert response.truncated is True
                # Output should be truncated
                assert len(response.stdout) + len(response.stdout_b64 or "") <= MAX_RESPONSE_SIZE

    def test_server_side_repo_root_used(self):
        """Test that server-side repo root derivation ignores client cwd."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a git repo
            os.system(f"cd {tmpdir} && git init >/dev/null 2>&1")

            # Client requests cwd of "evil/path"
            request = GitExecRequest(args=["status"], cwd="evil/path")

            with patch("git_operations.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=b"On branch main",
                    stderr=b"",
                )

                response, error = execute_git(request, tmpdir)

                # Should call subprocess with resolved cwd (not client's cwd)
                called_cwd = mock_run.call_args[1]["cwd"]
                # Should be within repo root
                assert called_cwd.startswith(tmpdir)


class TestGitApiMetadataLookup:
    """Tests for metadata lookup behavior in git API."""

    def test_metadata_lookup_falls_back_to_client_ip(self):
        """When sandbox_id is not a registry container_id, lookup falls back to source IP."""
        secrets = SecretStore()

        with tempfile.TemporaryDirectory() as tmpdir:
            secrets._path = tmpdir
            secret_file = os.path.join(tmpdir, "sandbox-123")
            with open(secret_file, "wb") as f:
                f.write(b"secret123")

            registry_instance = MagicMock()
            registry_instance.get_by_container_id.return_value = None
            registry_instance.get_by_ip.return_value = MagicMock(
                metadata={"repo_root": "/git-workspace/from-ip", "allow_pr": True}
            )

            mock_git_response = MagicMock()
            mock_git_response.to_dict.return_value = {
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "truncated": False,
            }

            with patch("registry.ContainerRegistry", return_value=registry_instance):
                with patch(
                    "git_operations.execute_git",
                    return_value=(mock_git_response, None),
                ) as mock_execute:
                    app = create_git_api(secret_store=secrets)
                    client = app.test_client()

                    body = json.dumps({"args": ["status"], "cwd": "."}).encode("utf-8")
                    timestamp = str(time.time())
                    nonce = "nonce-meta-ip"
                    sig = compute_signature(
                        "POST",
                        "/git/exec",
                        body,
                        timestamp,
                        nonce,
                        b"secret123",
                    )

                    response = client.post(
                        "/git/exec",
                        data=body,
                        headers={
                            "X-Sandbox-Id": "sandbox-123",
                            "X-Request-Signature": sig,
                            "X-Request-Timestamp": timestamp,
                            "X-Request-Nonce": nonce,
                        },
                        environ_base={"REMOTE_ADDR": "172.20.0.9"},
                    )

                    assert response.status_code == 200
                    registry_instance.get_by_container_id.assert_called_with(
                        "sandbox-123"
                    )
                    registry_instance.get_by_ip.assert_called_with("172.20.0.9")

                    _, repo_root_arg, metadata_arg = mock_execute.call_args[0]
                    assert repo_root_arg == "/git-workspace/from-ip"
                    assert metadata_arg == {
                        "repo_root": "/git-workspace/from-ip",
                        "allow_pr": True,
                    }


class TestProtectedBranchPushValidation:
    """Tests for protected-branch enforcement in push argument parsing."""

    def test_push_without_refspec_is_rejected(self):
        """Implicit push targets must be rejected to prevent bypasses."""
        err = check_push_protected_branches(["origin"], "/tmp", metadata=None)
        assert err is not None
        assert "explicit refspecs" in err.reason.lower()

    def test_push_all_is_rejected(self):
        """--all push mode is too broad for deterministic policy checks."""
        err = check_push_protected_branches(["--all", "origin"], "/tmp", metadata=None)
        assert err is not None
        assert "--all" in err.reason

    def test_push_mirror_is_rejected(self):
        """--mirror push mode is too broad for deterministic policy checks."""
        err = check_push_protected_branches(
            ["--mirror", "origin"], "/tmp", metadata=None
        )
        assert err is not None
        assert "--mirror" in err.reason

    def test_push_main_refspec_is_rejected(self):
        """Explicit push to protected branch should be blocked."""
        err = check_push_protected_branches(["origin", "main"], "/tmp", metadata=None)
        assert err is not None
        assert "protected branch" in err.reason.lower()

    def test_push_non_protected_branch_is_allowed(self):
        """Explicit push to non-protected branch should be allowed."""
        err = check_push_protected_branches(
            ["origin", "feature/test"], "/tmp", metadata=None
        )
        assert err is None

    def test_push_wildcard_refspec_is_rejected(self):
        """Wildcard refspecs are rejected to prevent broad push bypasses."""
        err = check_push_protected_branches(
            ["origin", "refs/heads/*:refs/heads/*"], "/tmp", metadata=None
        )
        assert err is not None
        assert "wildcard" in err.reason.lower()

    def test_execute_git_blocks_implicit_push_before_subprocess(self):
        """Implicit push should be denied before running git subprocess."""
        request = GitExecRequest(args=["push", "origin"])
        with patch("git_operations.subprocess.run") as mock_run:
            response, err = execute_git(request, "/tmp", metadata=None)
            assert response is None
            assert err is not None
            assert "explicit refspecs" in err.reason.lower()
            mock_run.assert_not_called()

    def test_execute_git_blocks_wildcard_refspec_before_subprocess(self):
        """Wildcard refspec push should be denied before running git subprocess."""
        request = GitExecRequest(args=["push", "origin", "refs/heads/*:refs/heads/*"])
        with patch("git_operations.subprocess.run") as mock_run:
            response, err = execute_git(request, "/tmp", metadata=None)
            assert response is None
            assert err is not None
            assert "wildcard" in err.reason.lower()
            mock_run.assert_not_called()

    def test_push_tags_only_is_allowed(self):
        """Push with only --tags and a remote should be allowed (no branch refspecs)."""
        err = check_push_protected_branches(
            ["origin", "--tags"], "/tmp", metadata=None
        )
        assert err is None

    def test_push_delete_protected_branch_is_rejected(self):
        """Deleting a protected branch via --delete should be blocked."""
        err = check_push_protected_branches(
            ["--delete", "origin", "main"], "/tmp", metadata=None
        )
        assert err is not None
        assert "protected branch" in err.reason.lower()

    def test_push_delete_non_protected_branch_is_allowed(self):
        """Deleting a non-protected branch via --delete should be allowed."""
        err = check_push_protected_branches(
            ["--delete", "origin", "feature/old"], "/tmp", metadata=None
        )
        assert err is None

    def test_push_with_double_dash_treats_remaining_as_positional(self):
        """Arguments after -- should be treated as positional (remote + refspec)."""
        err = check_push_protected_branches(
            ["--", "origin", "feature/test"], "/tmp", metadata=None
        )
        assert err is None


class TestRequestSizeLimits:
    """Tests for request size limits."""

    def test_max_request_body_size_enforced(self):
        """Test that max request body size is enforced."""
        secrets = SecretStore()

        with tempfile.TemporaryDirectory() as tmpdir:
            secrets._path = tmpdir
            secret_file = os.path.join(tmpdir, "test-sandbox")
            with open(secret_file, "wb") as f:
                f.write(b"secret123")

            app = create_git_api(secret_store=secrets)
            client = app.test_client()

            # Create oversized body
            large_body = b"x" * (MAX_REQUEST_BODY + 1)

            timestamp = str(time.time())
            nonce = "nonce-123"
            sig = compute_signature(
                "POST", "/git/exec", large_body, timestamp, nonce, b"secret123"
            )

            response = client.post(
                "/git/exec",
                data=large_body,
                headers={
                    "X-Sandbox-Id": "test-sandbox",
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": timestamp,
                    "X-Request-Nonce": nonce,
                },
            )

            assert response.status_code == 413


# ---------------------------------------------------------------------------
# Additional Edge Case Tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Additional edge case tests."""

    def test_empty_command_rejected(self):
        """Test that empty command list is rejected."""
        result = validate_command([])
        assert result is not None
        assert "empty" in result.reason.lower()

    def test_config_wildcard_pattern_matching(self):
        """Test that wildcard config patterns like remote.*.proxy are blocked."""
        result = validate_command(["-c", "remote.origin.proxy=http://evil.com", "status"])
        assert result is not None
        assert "blocked config key" in result.reason.lower()

    def test_path_validation_with_absolute_path(self):
        """Test that absolute paths are validated against repo root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Try to use absolute path outside repo
            result_path, error = validate_path("/etc/passwd", tmpdir)
            assert error is not None
            assert "outside repo root" in error.reason.lower()

    def test_path_validation_maps_workspace_absolute_path(self):
        """Absolute /workspace paths are translated to repo_root for compatibility."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result_path, error = validate_path("/workspace/src", tmpdir)
            assert error is None
            assert result_path == os.path.realpath(os.path.join(tmpdir, "src"))

    def test_nonce_store_ttl_expiration(self):
        """Test that expired nonces are cleaned up."""
        nonces = NonceStore(ttl=1, max_per_sandbox=100)

        # Store a nonce
        assert nonces.check_and_store("sandbox1", "nonce1") is True

        # Wait for TTL expiration
        time.sleep(1.1)

        # Same nonce should be allowed again after expiration
        assert nonces.check_and_store("sandbox1", "nonce1") is True

    def test_nonce_store_lru_eviction(self):
        """Test that LRU eviction works when cache is full."""
        nonces = NonceStore(ttl=3600, max_per_sandbox=3)

        # Fill the cache
        assert nonces.check_and_store("sandbox1", "nonce1") is True
        assert nonces.check_and_store("sandbox1", "nonce2") is True
        assert nonces.check_and_store("sandbox1", "nonce3") is True

        # Add one more - should evict oldest
        assert nonces.check_and_store("sandbox1", "nonce4") is True

        # nonce1 should be evicted, so we can use it again
        assert nonces.check_and_store("sandbox1", "nonce1") is True

    def test_token_bucket_refill(self):
        """Test that token bucket refills over time."""
        limiter = RateLimiter(burst=1, sustained=60, global_ceiling=1000)  # 1 token/sec

        # Consume the only token
        allowed, retry = limiter.check_sandbox_rate("sandbox1")
        assert allowed is True

        # Immediate retry should fail
        allowed, retry = limiter.check_sandbox_rate("sandbox1")
        assert allowed is False

        # Wait for refill
        time.sleep(1.1)

        # Should have a new token
        allowed, retry = limiter.check_sandbox_rate("sandbox1")
        assert allowed is True

    def test_clock_window_validation(self):
        """Test that requests outside clock window are rejected."""
        secrets = SecretStore()

        with tempfile.TemporaryDirectory() as tmpdir:
            secrets._path = tmpdir
            secret_file = os.path.join(tmpdir, "test-sandbox")
            with open(secret_file, "wb") as f:
                f.write(b"secret123")

            app = create_git_api(secret_store=secrets)
            client = app.test_client()

            body = json.dumps({"args": ["status"]}).encode("utf-8")
            # Use timestamp from the past (outside window)
            old_timestamp = str(time.time() - CLOCK_WINDOW_SECONDS - 10)
            nonce = "nonce-old"

            sig = compute_signature(
                "POST", "/git/exec", body, old_timestamp, nonce, b"secret123"
            )

            response = client.post(
                "/git/exec",
                data=body,
                headers={
                    "X-Sandbox-Id": "test-sandbox",
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": old_timestamp,
                    "X-Request-Nonce": nonce,
                },
            )

            assert response.status_code == 401
            assert b"clock window" in response.data.lower() or b"timestamp" in response.data.lower()

    def test_health_endpoint(self):
        """Test that health endpoint returns 200."""
        app = create_git_api()
        client = app.test_client()

        response = client.get("/health")
        assert response.status_code == 200
        assert b"ok" in response.data.lower()

    def test_invalid_json_body_returns_400(self):
        """Test that invalid JSON body returns 400."""
        secrets = SecretStore()

        with tempfile.TemporaryDirectory() as tmpdir:
            secrets._path = tmpdir
            secret_file = os.path.join(tmpdir, "test-sandbox")
            with open(secret_file, "wb") as f:
                f.write(b"secret123")

            app = create_git_api(secret_store=secrets)
            client = app.test_client()

            body = b"not-json"
            timestamp = str(time.time())
            nonce = "nonce-123"

            sig = compute_signature(
                "POST", "/git/exec", body, timestamp, nonce, b"secret123"
            )

            response = client.post(
                "/git/exec",
                data=body,
                headers={
                    "X-Sandbox-Id": "test-sandbox",
                    "X-Request-Signature": sig,
                    "X-Request-Timestamp": timestamp,
                    "X-Request-Nonce": nonce,
                },
            )

            assert response.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
