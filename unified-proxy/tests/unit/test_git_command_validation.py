"""Unit tests for git_command_validation module.

Tests input validation, command allowlisting, flag blocking,
config key validation, clone validation, and path validation.
"""

import base64
import os
from unittest.mock import patch

import pytest

from git_command_validation import (
    ALLOWED_COMMANDS,
    ALLOWED_MARKETPLACES,
    GLOBAL_BLOCKED_FLAGS,
    MAX_ARG_LENGTH,
    MAX_ARGS_COUNT,
    MAX_STDIN_SIZE,
    validate_clone_args,
    validate_command,
    validate_path,
    validate_request,
)


class TestValidateRequest:
    """Tests for validate_request function."""

    def test_valid_request(self):
        """Test a valid request with args."""
        req, err = validate_request({"args": ["status"]})
        assert err is None
        assert req is not None
        assert req.args == ["status"]

    def test_non_dict_input(self):
        """Test non-dict input is rejected."""
        req, err = validate_request("not a dict")
        assert req is None
        assert "JSON object" in err.reason

    def test_empty_args(self):
        """Test empty args list is rejected."""
        req, err = validate_request({"args": []})
        assert req is None
        assert "non-empty" in err.reason

    def test_missing_args(self):
        """Test missing args key is rejected."""
        req, err = validate_request({})
        assert req is None
        assert "non-empty" in err.reason

    def test_args_count_limit(self):
        """Test args count exceeding MAX_ARGS_COUNT is rejected."""
        args = ["status"] + ["--verbose"] * MAX_ARGS_COUNT
        req, err = validate_request({"args": args})
        assert req is None
        assert "Too many arguments" in err.reason

    def test_arg_length_limit(self):
        """Test individual arg exceeding MAX_ARG_LENGTH is rejected."""
        long_arg = "x" * (MAX_ARG_LENGTH + 1)
        req, err = validate_request({"args": ["commit", "-m", long_arg]})
        assert req is None
        assert "max length" in err.reason

    def test_non_string_arg(self):
        """Test non-string arg is rejected."""
        req, err = validate_request({"args": ["status", 123]})
        assert req is None
        assert "must be a string" in err.reason

    def test_valid_base64_stdin(self):
        """Test valid base64 stdin is accepted."""
        data = base64.b64encode(b"hello").decode()
        req, err = validate_request({"args": ["commit"], "stdin_b64": data})
        assert err is None
        assert req.stdin_b64 == data

    def test_invalid_base64_stdin(self):
        """Test invalid base64 stdin is rejected."""
        req, err = validate_request({"args": ["commit"], "stdin_b64": "not-valid-base64!!!"})
        assert req is None
        assert "not valid base64" in err.reason

    def test_stdin_size_limit(self):
        """Test stdin exceeding MAX_STDIN_SIZE is rejected."""
        data = base64.b64encode(b"x" * (MAX_STDIN_SIZE + 1)).decode()
        req, err = validate_request({"args": ["commit"], "stdin_b64": data})
        assert req is None
        assert "exceeds limit" in err.reason

    def test_cwd_type_validation(self):
        """Test cwd must be string or null."""
        req, err = validate_request({"args": ["status"], "cwd": 123})
        assert req is None
        assert "cwd must be a string" in err.reason

    def test_cwd_null_accepted(self):
        """Test null cwd is accepted."""
        req, err = validate_request({"args": ["status"], "cwd": None})
        assert err is None
        assert req.cwd is None


class TestValidateCommand:
    """Tests for validate_command function."""

    @pytest.mark.parametrize("cmd", ["status", "commit", "push", "fetch", "log"])
    def test_allowed_commands_pass(self, cmd):
        """Test allowed commands pass validation."""
        err = validate_command([cmd])
        assert err is None

    @pytest.mark.parametrize("cmd", ["gc", "reflog"])
    def test_blocked_commands_rejected(self, cmd):
        """Test disallowed commands are rejected."""
        err = validate_command([cmd])
        assert err is not None
        assert "not allowed" in err.reason

    def test_empty_args(self):
        """Test empty args list is rejected."""
        err = validate_command([])
        assert err is not None
        assert "Empty command" in err.reason

    @pytest.mark.parametrize("flag", ["--git-dir", "--work-tree", "--exec"])
    def test_global_blocked_flags(self, flag):
        """Test global blocked flags are rejected."""
        err = validate_command(["status", flag])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_push_force_blocked(self):
        """Test push --force is blocked."""
        err = validate_command(["push", "--force"])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_push_force_with_lease_blocked(self):
        """Test push --force-with-lease is blocked."""
        err = validate_command(["push", "--force-with-lease"])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_checkout_force_blocked(self):
        """Test checkout --force is blocked."""
        err = validate_command(["checkout", "--force"])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_clean_fd_blocked(self):
        """Test clean -fd is blocked."""
        err = validate_command(["clean", "-fd"])
        assert err is not None

    def test_clean_dry_run_allowed(self):
        """Test clean --dry-run is allowed."""
        err = validate_command(["clean", "--dry-run"])
        assert err is None

    def test_branch_d_blocked(self):
        """Test branch -D is blocked."""
        err = validate_command(["branch", "-D"])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_remote_v_allowed(self):
        """Test remote -v is allowed."""
        err = validate_command(["remote", "-v"])
        assert err is None

    def test_remote_show_allowed(self):
        """Test remote show is allowed."""
        err = validate_command(["remote", "show", "origin"])
        assert err is None

    def test_remote_get_url_allowed(self):
        """Test remote get-url is allowed."""
        err = validate_command(["remote", "get-url", "origin"])
        assert err is None

    def test_remote_add_blocked(self):
        """Test remote add is blocked."""
        err = validate_command(["remote", "add", "evil", "url"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_remote_set_url_blocked(self):
        """Test remote set-url is blocked."""
        err = validate_command(["remote", "set-url", "origin", "url"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_remote_remove_blocked(self):
        """Test remote remove is blocked."""
        err = validate_command(["remote", "remove", "origin"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_config_get_allowed(self):
        """Test config --get is allowed."""
        err = validate_command(["config", "--get", "user.name"])
        assert err is None

    def test_config_bare_blocked(self):
        """Test bare config (write) is blocked."""
        err = validate_command(["config", "user.name", "test"])
        assert err is not None
        assert "--get" in err.reason

    def test_notes_list_allowed(self):
        """Test notes list is allowed."""
        err = validate_command(["notes", "list"])
        assert err is None

    def test_notes_add_blocked(self):
        """Test notes add is blocked."""
        err = validate_command(["notes", "add"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_sparse_checkout_list_allowed(self):
        """Test sparse-checkout list is allowed."""
        err = validate_command(["sparse-checkout", "list"])
        assert err is None

    def test_sparse_checkout_set_blocked(self):
        """Test sparse-checkout set is blocked."""
        err = validate_command(["sparse-checkout", "set"])
        assert err is not None
        assert "not allowed" in err.reason


class TestConfigKeyValidation:
    """Tests for config key validation via -c flag."""

    def test_never_allow_alias(self):
        """Test alias.* keys are always blocked."""
        err = validate_command(["-c", "alias.co=checkout", "status"])
        assert err is not None
        assert "Blocked config key" in err.reason

    def test_never_allow_credential(self):
        """Test credential.* keys are always blocked."""
        err = validate_command(["-c", "credential.helper=store", "status"])
        assert err is not None
        assert "Blocked config key" in err.reason

    def test_never_allow_ssh_command(self):
        """Test core.sshCommand is always blocked."""
        err = validate_command(["-c", "core.sshCommand=ssh -o something", "status"])
        assert err is not None
        assert "Blocked config key" in err.reason

    def test_permitted_user_keys(self):
        """Test user.* keys are permitted."""
        err = validate_command(["-c", "user.name=Test", "status"])
        assert err is None

    def test_permitted_color_keys(self):
        """Test color.* keys are permitted."""
        err = validate_command(["-c", "color.ui=auto", "status"])
        assert err is None

    def test_wildcard_remote_proxy_blocked(self):
        """Test remote.origin.proxy is blocked via wildcard."""
        err = validate_command(["-c", "remote.origin.proxy=http://evil", "status"])
        assert err is not None
        assert "Blocked config key" in err.reason

    def test_unpermitted_key_rejected(self):
        """Test keys not in permitted or never-allow lists are rejected."""
        err = validate_command(["-c", "some.unknown.key=value", "status"])
        assert err is not None
        assert "not in permitted list" in err.reason


class TestCloneValidation:
    """Tests for clone argument validation."""

    def test_https_github_url_allowed(self):
        """Test HTTPS GitHub URL is allowed when repo is authorized."""
        extra, err = validate_clone_args(
            ["clone", "https://github.com/owner/repo"],
            metadata={"repos": ["owner/repo"]},
        )
        assert err is None
        assert extra is not None

    def test_non_https_blocked(self):
        """Test non-HTTPS URLs are blocked."""
        extra, err = validate_clone_args(
            ["clone", "git@github.com:owner/repo.git"],
            metadata={"repos": ["owner/repo"]},
        )
        assert err is not None
        assert "not allowed" in err.reason

    def test_credentials_in_url_blocked(self):
        """Test URLs with embedded credentials are blocked."""
        extra, err = validate_clone_args(
            ["clone", "https://user:pass@github.com/owner/repo"],
            metadata={"repos": ["owner/repo"]},
        )
        assert err is not None
        assert "not allowed" in err.reason

    def test_unauthorized_repo_blocked(self):
        """Test unauthorized repos are blocked."""
        extra, err = validate_clone_args(
            ["clone", "https://github.com/evil/malware"],
            metadata={"repos": ["owner/repo"]},
        )
        assert err is not None
        assert "not authorized" in err.reason

    def test_marketplace_repo_always_allowed(self):
        """Test marketplace repos are always allowed."""
        for marketplace in ALLOWED_MARKETPLACES:
            owner, repo = marketplace.split("/")
            extra, err = validate_clone_args(
                ["clone", f"https://github.com/{owner}/{repo}"],
            )
            assert err is None, f"Marketplace {marketplace} should be allowed"


class TestPathValidation:
    """Tests for path validation."""

    def test_path_within_repo_allowed(self):
        """Test path within repo root is allowed."""
        with patch("git_command_validation.os.path.realpath", side_effect=lambda p: p):
            resolved, err = validate_path("subdir", "/repo")
            assert err is None
            assert "subdir" in resolved

    def test_traversal_blocked(self):
        """Test .. path traversal is blocked."""
        resolved, err = validate_path("../outside", "/repo")
        assert err is not None
        assert "traversal" in err.reason

    def test_absolute_path_within_root(self):
        """Test absolute path within repo root is allowed."""
        with patch("git_command_validation.os.path.realpath", side_effect=lambda p: p):
            with patch.dict(os.environ, {"GIT_CLIENT_WORKSPACE_ROOT": "/workspace"}):
                resolved, err = validate_path("/repo/subdir", "/repo")
                assert err is None

    def test_absolute_path_outside_root(self):
        """Test absolute path outside repo root is blocked."""
        with patch("git_command_validation.os.path.realpath", side_effect=lambda p: p):
            with patch.dict(os.environ, {"GIT_CLIENT_WORKSPACE_ROOT": "/workspace"}):
                resolved, err = validate_path("/etc/passwd", "/repo")
                assert err is not None
                assert "outside repo root" in err.reason

    def test_null_cwd_defaults_to_root(self):
        """Test null cwd defaults to repo root."""
        with patch("git_command_validation.os.path.realpath", side_effect=lambda p: p):
            resolved, err = validate_path(None, "/repo")
            assert err is None
            assert resolved == "/repo"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
