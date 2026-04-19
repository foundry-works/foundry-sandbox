"""Tests for foundry_git_safety.command_validation."""

import base64
import os
from unittest.mock import patch

import pytest

from foundry_git_safety.command_validation import (
    ALLOWED_COMMANDS,
    ALLOWED_MARKETPLACES,
    COMMAND_BLOCKED_FLAGS,
    GLOBAL_BLOCKED_FLAGS,
    MAX_ARG_LENGTH,
    MAX_ARGS_COUNT,
    MAX_STDIN_SIZE,
    GitExecRequest,
    GitExecResponse,
    validate_clone_args,
    validate_command,
    validate_path,
    validate_path_args,
    validate_request,
)
from foundry_git_safety.branch_types import ValidationError


# ---------------------------------------------------------------------------
# TestValidateRequest
# ---------------------------------------------------------------------------


class TestValidateRequest:
    """Tests for validate_request(raw) -> (GitExecRequest | None, ValidationError | None)."""

    def test_valid_minimal_request(self):
        req, err = validate_request({"args": ["status"]})
        assert err is None
        assert req is not None
        assert req.args == ["status"]
        assert req.cwd is None
        assert req.stdin_b64 is None

    def test_valid_full_request(self):
        stdin = base64.b64encode(b"hello").decode()
        raw = {"args": ["commit", "-m", "test"], "cwd": "/tmp/repo", "stdin_b64": stdin}
        req, err = validate_request(raw)
        assert err is None
        assert req is not None
        assert req.args == ["commit", "-m", "test"]
        assert req.cwd == "/tmp/repo"
        assert req.stdin_b64 == stdin

    def test_non_dict_rejected(self):
        req, err = validate_request("not a dict")
        assert req is None
        assert err is not None
        assert "JSON object" in err.reason

    def test_non_dict_list_rejected(self):
        req, err = validate_request([1, 2, 3])
        assert req is None
        assert err is not None

    def test_empty_args_rejected(self):
        req, err = validate_request({"args": []})
        assert req is None
        assert err is not None
        assert "non-empty" in err.reason

    def test_missing_args_rejected(self):
        req, err = validate_request({})
        assert req is None
        assert err is not None

    def test_args_not_list_rejected(self):
        req, err = validate_request({"args": "status"})
        assert req is None
        assert err is not None

    def test_too_many_args(self):
        raw = {"args": ["x"] * (MAX_ARGS_COUNT + 1)}
        req, err = validate_request(raw)
        assert req is None
        assert err is not None
        assert "Too many arguments" in err.reason

    def test_max_args_passes(self):
        raw = {"args": ["x"] * MAX_ARGS_COUNT}
        req, err = validate_request(raw)
        assert err is None
        assert req is not None
        assert len(req.args) == MAX_ARGS_COUNT

    def test_non_string_arg_rejected(self):
        req, err = validate_request({"args": ["status", 123]})
        assert req is None
        assert err is not None
        assert "args[1]" in err.reason

    def test_oversized_arg_rejected(self):
        raw = {"args": ["x" * (MAX_ARG_LENGTH + 1)]}
        req, err = validate_request(raw)
        assert req is None
        assert err is not None
        assert "exceeds max length" in err.reason

    def test_max_length_arg_passes(self):
        raw = {"args": ["x" * MAX_ARG_LENGTH]}
        req, err = validate_request(raw)
        assert err is None
        assert req is not None

    def test_invalid_cwd_type_rejected(self):
        req, err = validate_request({"args": ["status"], "cwd": 123})
        assert req is None
        assert err is not None
        assert "cwd" in err.reason

    def test_none_cwd_accepted(self):
        req, err = validate_request({"args": ["status"], "cwd": None})
        assert err is None
        assert req is not None
        assert req.cwd is None

    def test_invalid_stdin_b64_rejected(self):
        req, err = validate_request({"args": ["status"], "stdin_b64": "!!!not-base64!!!"})
        assert req is None
        assert err is not None
        assert "base64" in err.reason

    def test_oversized_stdin_rejected(self):
        # Create stdin that decodes to more than MAX_STDIN_SIZE
        payload = b"x" * (MAX_STDIN_SIZE + 1)
        stdin = base64.b64encode(payload).decode()
        req, err = validate_request({"args": ["status"], "stdin_b64": stdin})
        assert req is None
        assert err is not None
        assert "stdin" in err.reason.lower()

    def test_non_string_stdin_b64_rejected(self):
        req, err = validate_request({"args": ["status"], "stdin_b64": 42})
        assert req is None
        assert err is not None


# ---------------------------------------------------------------------------
# TestValidateCommand
# ---------------------------------------------------------------------------


class TestValidateCommand:
    """Tests for validate_command(args, extra_allowed=None)."""

    # -- Allowed commands pass with minimal safe args --

    # Commands that need specific sub-args to pass validation
    _CMD_SPECIAL_ARGS = {
        "config": ["--list"],
        "remote": ["-v"],
        "notes": ["list"],
        "sparse-checkout": ["list"],
        "clean": ["-n"],
    }

    @pytest.mark.parametrize("cmd", sorted(ALLOWED_COMMANDS))
    def test_allowed_command_passes(self, cmd):
        args = self._CMD_SPECIAL_ARGS.get(cmd, ["--help"])
        err = validate_command([cmd] + args)
        assert err is None, f"Allowed command {cmd!r} should pass"

    def test_extra_allowed_command_passes(self):
        err = validate_command(["my-custom-cmd"], extra_allowed={"my-custom-cmd"})
        assert err is None

    def test_extra_allowed_does_not_pollute_base_set(self):
        # Without extra_allowed, custom cmd should be blocked
        err = validate_command(["my-custom-cmd"])
        assert err is not None

    # -- Unknown/blocked commands --

    def test_unknown_command_blocked(self):
        err = validate_command(["foobar"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_empty_args_blocked(self):
        err = validate_command([])
        assert err is not None

    # -- Global blocked flags --

    def test_git_dir_blocked(self):
        err = validate_command(["--git-dir", "/tmp", "status"])
        assert err is not None
        assert "--git-dir" in err.reason

    def test_work_tree_blocked(self):
        err = validate_command(["--work-tree", "/tmp", "status"])
        assert err is not None
        assert "--work-tree" in err.reason

    def test_exec_blocked(self):
        err = validate_command(["--exec", "/tmp", "status"])
        assert err is not None
        assert "--exec" in err.reason

    # -- rev-parse exemption for --git-dir / --work-tree --

    def test_rev_parse_git_dir_allowed(self):
        err = validate_command(["rev-parse", "--git-dir"])
        assert err is None

    def test_rev_parse_work_tree_allowed(self):
        err = validate_command(["rev-parse", "--work-tree"])
        assert err is None

    def test_rev_parse_exec_still_blocked(self):
        err = validate_command(["rev-parse", "--exec"])
        assert err is not None
        assert "--exec" in err.reason

    # -- Per-command blocked flags from COMMAND_BLOCKED_FLAGS --

    def test_push_force_blocked(self):
        err = validate_command(["push", "--force", "origin", "main"])
        assert err is not None
        assert "push" in err.reason

    def test_push_force_with_lease_blocked(self):
        err = validate_command(["push", "--force-with-lease"])
        assert err is not None

    def test_rebase_interactive_blocked(self):
        err = validate_command(["rebase", "-i", "HEAD~3"])
        assert err is not None
        assert "rebase" in err.reason

    def test_checkout_force_blocked(self):
        err = validate_command(["checkout", "--force", "main"])
        assert err is not None
        assert "checkout" in err.reason

    def test_switch_force_blocked(self):
        err = validate_command(["switch", "--force", "main"])
        assert err is not None

    def test_branch_D_blocked(self):
        err = validate_command(["branch", "-D", "feature"])
        assert err is not None
        assert "branch" in err.reason

    def test_clean_force_blocked(self):
        err = validate_command(["clean", "-f"])
        assert err is not None
        assert "clean" in err.reason.lower() or "dry-run" in err.reason

    def test_clean_dry_run_allowed(self):
        err = validate_command(["clean", "--dry-run"])
        assert err is None

    def test_clean_n_allowed(self):
        err = validate_command(["clean", "-n"])
        assert err is None

    # -- Combined short flags expansion --

    def test_combined_short_flags_branch(self):
        # -fD should be caught as -f and -D
        err = validate_command(["branch", "-fD", "feature"])
        assert err is not None

    # -- remote subcommand validation --

    def test_remote_verbose_allowed(self):
        err = validate_command(["remote", "-v"])
        assert err is None

    def test_remote_add_blocked(self):
        err = validate_command(["remote", "add", "origin", "url"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_remote_set_url_blocked(self):
        err = validate_command(["remote", "set-url", "origin", "url"])
        assert err is not None

    # -- config subcommand validation --

    def test_config_get_allowed(self):
        err = validate_command(["config", "--get", "user.name"])
        assert err is None

    def test_config_set_blocked(self):
        # Setting config (no --get/--list flag) should be blocked
        err = validate_command(["config", "user.name", "Alice"])
        assert err is not None
        assert "Config" in err.reason

    # -- notes subcommand validation --

    def test_notes_list_allowed(self):
        err = validate_command(["notes", "list"])
        assert err is None

    def test_notes_add_blocked(self):
        err = validate_command(["notes", "add", "-m", "x", "HEAD"])
        assert err is not None

    # -- sparse-checkout subcommand validation --

    def test_sparse_checkout_list_allowed(self):
        err = validate_command(["sparse-checkout", "list"])
        assert err is None

    def test_sparse_checkout_set_blocked(self):
        err = validate_command(["sparse-checkout", "set", "src/"])
        assert err is not None

    # -- No subcommand found --

    def test_only_flags_no_subcommand(self):
        err = validate_command(["-c", "user.name=Bob"])
        assert err is not None


# ---------------------------------------------------------------------------
# TestValidatePath
# ---------------------------------------------------------------------------


class TestValidatePath:
    """Tests for validate_path(cwd, repo_root)."""

    def test_path_within_repo_root_passes(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        resolved_repo = str(repo.resolve())
        result, err = validate_path("subdir", resolved_repo)
        assert err is None
        assert resolved_repo in result

    def test_path_traversal_blocked(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _, err = validate_path("../../etc/passwd", str(repo.resolve()))
        assert err is not None
        assert "traversal" in err.reason.lower()

    def test_absolute_path_within_root(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        subdir = repo / "subdir"
        subdir.mkdir()
        resolved_repo = str(repo.resolve())
        result, err = validate_path(str(subdir.resolve()), resolved_repo)
        assert err is None
        assert resolved_repo in result

    def test_none_cwd_returns_repo_root(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        resolved_repo = str(repo.resolve())
        result, err = validate_path(None, resolved_repo)
        assert err is None
        assert result == resolved_repo

    def test_empty_cwd_returns_repo_root(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        resolved_repo = str(repo.resolve())
        result, err = validate_path("", resolved_repo)
        assert err is None
        assert result == resolved_repo

    def test_dot_cwd_returns_repo_root(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        resolved_repo = str(repo.resolve())
        result, err = validate_path(".", resolved_repo)
        assert err is None
        assert result == resolved_repo

    def test_no_repo_root(self):
        _, err = validate_path("subdir", "")
        assert err is not None
        assert "repo root" in err.reason.lower()

    def test_absolute_path_outside_root_blocked(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        _, err = validate_path(str(other.resolve()), str(repo.resolve()))
        assert err is not None
        assert "outside" in err.reason.lower()

    def test_client_workspace_translated(self, tmp_path):
        """Absolute paths under GIT_CLIENT_WORKSPACE_ROOT are mapped to repo_root."""
        repo = tmp_path / "repo"
        repo.mkdir()
        real_root = str(repo.resolve())

        # Simulate client workspace at an arbitrary location
        fake_workspace = str(tmp_path / "workspace")
        with patch.dict(os.environ, {"GIT_CLIENT_WORKSPACE_ROOT": fake_workspace}):
            # The fake workspace itself should map to repo root
            result, err = validate_path(fake_workspace, real_root)
            assert err is None
            assert result == real_root


# ---------------------------------------------------------------------------
# TestValidatePathArgs
# ---------------------------------------------------------------------------


class TestValidatePathArgs:
    """Tests for validate_path_args(args, repo_root, extra_allowed_roots=None)."""

    def test_flags_skipped(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        err = validate_path_args(
            ["--format=%H", "HEAD"], str(repo.resolve())
        )
        assert err is None

    def test_path_traversal_in_arg_blocked(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        err = validate_path_args(
            ["../../etc/passwd"], str(repo.resolve())
        )
        assert err is not None
        assert "traversal" in err.reason.lower()

    def test_absolute_path_outside_roots_blocked(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        err = validate_path_args(
            [str(other.resolve())], str(repo.resolve())
        )
        assert err is not None
        assert "outside" in err.reason.lower()

    def test_relative_path_within_root_passes(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        err = validate_path_args(
            ["src/main.py"], str(repo.resolve())
        )
        assert err is None

    def test_extra_allowed_roots(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        extra = tmp_path / "extra"
        extra.mkdir()
        err = validate_path_args(
            [str(extra.resolve())],
            str(repo.resolve()),
            extra_allowed_roots=[str(extra.resolve())],
        )
        assert err is None

    def test_plain_name_no_slash_passes(self, tmp_path):
        """Args without any path separator are not treated as paths."""
        repo = tmp_path / "repo"
        repo.mkdir()
        err = validate_path_args(["HEAD"], str(repo.resolve()))
        assert err is None


# ---------------------------------------------------------------------------
# TestValidateCloneArgs
# ---------------------------------------------------------------------------


class TestValidateCloneArgs:
    """Tests for validate_clone_args(args, metadata)."""

    def test_valid_https_github_url_authorized(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "https://github.com/owner/repo"]
        roots, err = validate_clone_args(args, metadata)
        assert err is None
        assert roots is not None
        assert len(roots) == 2  # plugin_cache_root, plugin_marketplaces_root

    def test_valid_https_with_git_suffix(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "https://github.com/owner/repo.git"]
        roots, err = validate_clone_args(args, metadata)
        assert err is None
        assert roots is not None

    def test_non_https_rejected(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "git@github.com:owner/repo.git"]
        _, err = validate_clone_args(args, metadata)
        assert err is not None
        assert "https" in err.reason.lower()

    def test_non_github_rejected(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "https://gitlab.com/owner/repo"]
        _, err = validate_clone_args(args, metadata)
        assert err is not None

    def test_unauthorized_repo_rejected(self):
        metadata = {"repos": ["other/repo"]}
        args = ["clone", "https://github.com/owner/repo"]
        _, err = validate_clone_args(args, metadata)
        assert err is not None
        assert "not authorized" in err.reason.lower()

    def test_credentials_in_url_rejected(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "https://user:pass@github.com/owner/repo"]
        _, err = validate_clone_args(args, metadata)
        assert err is not None

    def test_token_in_url_rejected(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "https://ghp_token@github.com/owner/repo"]
        _, err = validate_clone_args(args, metadata)
        assert err is not None

    def test_marketplace_repo_allowed(self):
        """ALLOWED_MARKETPLACES repos pass even without metadata authorization."""
        repo = next(iter(ALLOWED_MARKETPLACES))
        owner, name = repo.split("/")
        args = ["clone", f"https://github.com/{owner}/{name}"]
        roots, err = validate_clone_args(args, metadata=None)
        assert err is None
        assert roots is not None

    def test_non_clone_command_returns_none_none(self):
        args = ["status"]
        roots, err = validate_clone_args(args, metadata=None)
        assert roots is None
        assert err is None

    def test_clone_no_url_rejected(self):
        args = ["clone"]
        _, err = validate_clone_args(args, metadata=None)
        assert err is not None
        assert "requires a repository URL" in err.reason

    def test_clone_with_branch_option(self):
        metadata = {"repos": ["owner/repo"]}
        args = ["clone", "-b", "main", "https://github.com/owner/repo"]
        roots, err = validate_clone_args(args, metadata)
        assert err is None
        assert roots is not None

    def test_single_repo_metadata(self):
        """Metadata with single 'repo' key (not 'repos') is accepted."""
        metadata = {"repo": "owner/repo"}
        args = ["clone", "https://github.com/owner/repo"]
        roots, err = validate_clone_args(args, metadata)
        assert err is None


# ---------------------------------------------------------------------------
# TestGitExecResponse
# ---------------------------------------------------------------------------


class TestGitExecResponse:
    """Tests for GitExecResponse dataclass."""

    def test_to_dict_without_stdout_b64(self):
        resp = GitExecResponse(exit_code=0, stdout="out", stderr="err")
        d = resp.to_dict()
        assert d == {
            "exit_code": 0,
            "stdout": "out",
            "stderr": "err",
            "truncated": False,
        }
        assert "stdout_b64" not in d

    def test_to_dict_with_stdout_b64(self):
        resp = GitExecResponse(
            exit_code=1, stdout="out", stderr="err", stdout_b64="base64val"
        )
        d = resp.to_dict()
        assert d["stdout_b64"] == "base64val"
        assert d["truncated"] is False

    def test_to_dict_truncated(self):
        resp = GitExecResponse(
            exit_code=0, stdout="x" * 100, stderr="", truncated=True
        )
        d = resp.to_dict()
        assert d["truncated"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
