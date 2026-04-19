"""Tests for foundry_git_safety.push_validation."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.push_validation import (
    _extract_push_positionals,
    _parse_push_refspecs,
    _qualify_ref,
    check_push_file_restrictions,
    check_push_protected_branches,
    extract_push_args,
    normalize_push_args,
    strip_credential_config_overrides,
)
from foundry_git_safety.config import ConfigError, FileRestrictionsData


# ---------------------------------------------------------------------------
# TestExtractPushArgs
# ---------------------------------------------------------------------------


class TestExtractPushArgs:
    """Tests for extract_push_args(args)."""

    def test_extracts_push_subcommand_args(self):
        """Returns args after 'push' when push is the subcommand."""
        result = extract_push_args(["push", "origin", "main"])
        assert result == ["origin", "main"]

    def test_non_push_returns_none(self):
        """Returns None when the subcommand is not 'push'."""
        result = extract_push_args(["commit", "-m", "msg"])
        assert result is None

    def test_handles_minus_c_before_push(self):
        """Skips -c key=value pairs to find push subcommand."""
        result = extract_push_args(
            ["-c", "user.name=Bot", "push", "origin", "main"]
        )
        assert result == ["origin", "main"]

    def test_handles_combined_minus_c_before_push(self):
        """Skips -ckey=value combined form to find push subcommand."""
        result = extract_push_args(
            ["-cuser.name=Bot", "push", "origin", "feature"]
        )
        # Returns args after "push" (which are origin and feature)
        assert result == ["origin", "feature"]

    def test_push_with_global_flags_returns_none(self):
        """-C <path> is not handled by _find_push_index; returns None.

        Note: _find_push_index only handles -c flags, not -C or other
        global value flags. The caller (execute_git) normalizes args
        before reaching this point.
        """
        result = extract_push_args(
            ["-C", "/some/path", "push", "origin", "main"]
        )
        assert result is None


# ---------------------------------------------------------------------------
# TestStripCredentialConfigOverrides
# ---------------------------------------------------------------------------


class TestStripCredentialConfigOverrides:
    """Tests for strip_credential_config_overrides(args)."""

    def test_strips_credential_helper(self):
        """Strips -c credential.helper=... from args."""
        args = ["-c", "credential.helper=store", "push", "origin"]
        result, changed = strip_credential_config_overrides(args)
        assert changed is True
        assert result == ["push", "origin"]

    def test_preserves_non_credential_config(self):
        """Keeps -c key=value pairs that are not credential-related."""
        args = ["-c", "user.name=Bot", "push", "origin"]
        result, changed = strip_credential_config_overrides(args)
        assert changed is False
        assert result == ["-c", "user.name=Bot", "push", "origin"]

    def test_original_list_not_mutated(self):
        """The original args list is not modified."""
        args = ["-c", "credential.helper=store", "push"]
        original = list(args)
        strip_credential_config_overrides(args)
        assert args == original

    def test_strips_combined_form_credential(self):
        """Strips -ccredential.helper=store combined form."""
        args = ["-ccredential.helper=store", "push", "origin"]
        result, changed = strip_credential_config_overrides(args)
        assert changed is True
        assert result == ["push", "origin"]

    def test_strips_bare_credential_key(self):
        """Strips -c credential (bare key without value assignment)."""
        args = ["-c", "credential", "push"]
        result, changed = strip_credential_config_overrides(args)
        assert changed is True
        assert result == ["push"]


# ---------------------------------------------------------------------------
# TestNormalizePushArgs
# ---------------------------------------------------------------------------


class TestNormalizePushArgs:
    """Tests for normalize_push_args(args, metadata)."""

    def test_bare_push_expanded_with_sandbox_branch(self):
        """git push -> git push origin <sandbox_branch> when metadata has branch."""
        metadata = {"sandbox_branch": "sbx-123"}
        args = ["push"]
        result, expanded = normalize_push_args(args, metadata)
        assert expanded is True
        assert result == ["push", "origin", "sbx-123"]

    def test_push_with_remote_expanded(self):
        """git push origin -> git push origin <sandbox_branch>."""
        metadata = {"sandbox_branch": "sbx-456"}
        args = ["push", "origin"]
        result, expanded = normalize_push_args(args, metadata)
        assert expanded is True
        assert result == ["push", "origin", "sbx-456"]

    def test_push_with_refspecs_unchanged(self):
        """git push origin main is not modified (already has refspecs)."""
        metadata = {"sandbox_branch": "sbx-789"}
        args = ["push", "origin", "main"]
        result, expanded = normalize_push_args(args, metadata)
        assert expanded is False
        assert result == args

    def test_no_metadata_returns_unchanged(self):
        """Without metadata (or missing sandbox_branch), args are unchanged."""
        args = ["push"]
        result, expanded = normalize_push_args(args, None)
        assert expanded is False
        assert result == args

    def test_metadata_without_sandbox_branch(self):
        """Metadata dict without sandbox_branch key returns unchanged."""
        metadata = {"sandbox_id": "abc"}
        args = ["push"]
        result, expanded = normalize_push_args(args, metadata)
        assert expanded is False
        assert result == args

    def test_push_all_not_expanded(self):
        """git push --all is not expanded (broad mode handled by validation)."""
        metadata = {"sandbox_branch": "sbx-branch"}
        args = ["push", "--all"]
        result, expanded = normalize_push_args(args, metadata)
        assert expanded is False
        assert result == args

    def test_push_mirror_not_expanded(self):
        """git push --mirror is not expanded."""
        metadata = {"sandbox_branch": "sbx-branch"}
        args = ["push", "--mirror"]
        result, expanded = normalize_push_args(args, metadata)
        assert expanded is False
        assert result == args


# ---------------------------------------------------------------------------
# TestQualifyRef
# ---------------------------------------------------------------------------


class TestQualifyRef:
    """Tests for _qualify_ref(ref)."""

    def test_bare_name_gets_prefix(self):
        """A bare branch name gets the refs/heads/ prefix."""
        assert _qualify_ref("main") == "refs/heads/main"

    def test_already_qualified_passes_through(self):
        """An already-qualified ref passes through unchanged."""
        assert _qualify_ref("refs/heads/main") == "refs/heads/main"

    def test_tags_ref_passes_through(self):
        """A refs/tags/ ref passes through unchanged."""
        assert _qualify_ref("refs/tags/v1.0") == "refs/tags/v1.0"


# ---------------------------------------------------------------------------
# TestExtractPushPositionals
# ---------------------------------------------------------------------------


class TestExtractPushPositionals:
    """Tests for _extract_push_positionals(args)."""

    def test_remote_and_refspecs(self):
        """Extracts remote followed by refspec positional args."""
        result = _extract_push_positionals(["origin", "main"])
        assert result == ["origin", "main"]

    def test_flags_skipped(self):
        """Flags like --force, --verbose are skipped."""
        result = _extract_push_positionals(["--force", "origin", "main"])
        assert result == ["origin", "main"]

    def test_double_dash_terminator(self):
        """Everything after -- is treated as positional."""
        result = _extract_push_positionals(["--force", "--", "origin", "main"])
        assert result == ["origin", "main"]

    def test_option_with_value_skipped(self):
        """Options that consume a value (--repo, -o, etc.) skip the value."""
        result = _extract_push_positionals(
            ["--repo", "upstream", "origin", "main"]
        )
        assert result == ["origin", "main"]

    def test_push_option_with_equals_skipped(self):
        """--push-option=value combined form is skipped."""
        result = _extract_push_positionals(
            ["--push-option=ci.skip", "origin", "main"]
        )
        assert result == ["origin", "main"]

    def test_short_o_combined_form_skipped(self):
        """-oCi.skip combined form is skipped."""
        result = _extract_push_positionals(["-oCi.skip", "origin", "main"])
        assert result == ["origin", "main"]


# ---------------------------------------------------------------------------
# TestParsePushRefspecs
# ---------------------------------------------------------------------------


class TestParsePushRefspecs:
    """Tests for _parse_push_refspecs(args)."""

    def test_bare_branch_qualified(self):
        """A bare branch name is qualified to refs/heads/<branch>."""
        result = _parse_push_refspecs(["origin", "feature-branch"])
        assert result == ["refs/heads/feature-branch"]

    def test_src_colon_dst_returns_dst(self):
        """src:dst refspec returns the qualified dst."""
        result = _parse_push_refspecs(["origin", "HEAD:refs/heads/release"])
        assert result == ["refs/heads/release"]

    def test_deletion_refspec_returns_empty(self):
        """Deletion refspec (:branch) returns an empty list."""
        result = _parse_push_refspecs(["origin", ":main"])
        assert result == []

    def test_head_skipped(self):
        """HEAD without explicit destination is skipped (ambiguous)."""
        result = _parse_push_refspecs(["origin", "HEAD"])
        assert result == []

    def test_multiple_refspecs(self):
        """Multiple refspecs are all parsed and qualified."""
        result = _parse_push_refspecs(["origin", "main", "feature"])
        assert result == ["refs/heads/main", "refs/heads/feature"]

    def test_only_remote_no_refspecs(self):
        """Only a remote with no refspecs returns empty list."""
        result = _parse_push_refspecs(["origin"])
        assert result == []

    def test_force_prefix_stripped(self):
        """+ prefix on a refspec is stripped before qualification."""
        result = _parse_push_refspecs(["origin", "+main"])
        assert result == ["refs/heads/main"]


# ---------------------------------------------------------------------------
# TestCheckPushProtectedBranches
# ---------------------------------------------------------------------------


class TestCheckPushProtectedBranches:
    """Tests for check_push_protected_branches(args, repo_root, metadata)."""

    def test_push_to_main_blocked(self):
        """Push to main (a protected branch) is blocked."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["origin", "main"], "/fake/repo"
            )
        assert err is not None
        assert "protected" in err.reason.lower() or "main" in err.reason.lower()

    def test_push_to_own_branch_allowed(self):
        """Push to a non-protected feature branch is allowed."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["origin", "feature/my-thing"], "/fake/repo"
            )
        assert err is None

    def test_all_flag_blocked(self):
        """--all push mode is blocked."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["--all"], "/fake/repo"
            )
        assert err is not None
        assert "--all" in err.reason

    def test_mirror_flag_blocked(self):
        """--mirror push mode is blocked."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["--mirror"], "/fake/repo"
            )
        assert err is not None
        assert "--mirror" in err.reason

    def test_deletion_of_protected_branch_blocked(self):
        """Deleting a protected branch via :refspec is blocked."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["origin", ":main"], "/fake/repo"
            )
        assert err is not None
        assert "deletion" in err.reason.lower() or "protected" in err.reason.lower()

    def test_push_only_remote_blocked(self):
        """Push with only a remote (no refspecs) is blocked.

        Requires explicit refspecs for policy enforcement.
        """
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["origin"], "/fake/repo"
            )
        assert err is not None
        assert "refspec" in err.reason.lower() or "explicit" in err.reason.lower()

    def test_wildcard_refspec_blocked(self):
        """Wildcard push refspecs are blocked."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["origin", "feature/*"], "/fake/repo"
            )
        assert err is not None
        assert "wildcard" in err.reason.lower()

    def test_delete_flag_with_protected_branch_blocked(self):
        """--delete flag targeting a protected branch is blocked."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["--delete", "origin", "main"], "/fake/repo"
            )
        assert err is not None

    def test_tags_flag_with_only_remote_allowed(self):
        """--tags with only a remote is allowed (tag-only push)."""
        with patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ):
            err = check_push_protected_branches(
                ["--tags", "origin"], "/fake/repo"
            )
        assert err is None


# ---------------------------------------------------------------------------
# TestCheckPushFileRestrictions
# ---------------------------------------------------------------------------


class TestCheckPushFileRestrictions:
    """Tests for check_push_file_restrictions(args, repo_root, metadata)."""

    def test_blocked_file_triggers_block(self):
        """A changed file matching a blocked pattern blocks the push."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b".github/workflows/ci.yml\n"
        mock_result.stderr = b""

        with patch(
            "foundry_git_safety.push_validation.get_file_restrictions_config",
            return_value=config,
        ), patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ), patch(
            "foundry_git_safety.push_validation.subprocess.run",
            return_value=mock_result,
        ):
            err = check_push_file_restrictions(
                ["origin", "main"], "/fake/repo",
                metadata={"sandbox_branch": "feature-x"},
            )
        assert err is not None
        assert "blocked" in err.reason.lower()

    def test_config_error_fails_closed(self):
        """When get_file_restrictions_config raises ConfigError, push is blocked.

        Unlike commit-time validation, push-time validation fails closed.
        """
        with patch(
            "foundry_git_safety.push_validation.get_file_restrictions_config",
            side_effect=ConfigError("config missing"),
        ):
            err = check_push_file_restrictions(
                ["origin", "main"], "/fake/repo"
            )
        assert err is not None
        assert "fail-closed" in err.reason or "config" in err.reason.lower()

    def test_diff_failure_fails_closed(self):
        """When the diff subprocess fails, push is blocked (fail-closed)."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 128
        mock_result.stdout = b""
        mock_result.stderr = b"fatal: bad revision"

        with patch(
            "foundry_git_safety.push_validation.get_file_restrictions_config",
            return_value=config,
        ), patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ), patch(
            "foundry_git_safety.push_validation.subprocess.run",
            return_value=mock_result,
        ):
            err = check_push_file_restrictions(
                ["origin", "main"], "/fake/repo",
                metadata={"sandbox_branch": "feature-x"},
            )
        assert err is not None
        assert "fail-closed" in err.reason

    def test_clean_files_pass(self):
        """Changed files not matching any blocked pattern allow the push."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = b"src/main.py\nREADME.md\n"
        mock_result.stderr = b""

        with patch(
            "foundry_git_safety.push_validation.get_file_restrictions_config",
            return_value=config,
        ), patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ), patch(
            "foundry_git_safety.push_validation.subprocess.run",
            return_value=mock_result,
        ):
            err = check_push_file_restrictions(
                ["origin", "main"], "/fake/repo",
                metadata={"sandbox_branch": "feature-x"},
            )
        assert err is None

    def test_no_positionals_returns_none(self):
        """When no positional args are found, returns None."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        with patch(
            "foundry_git_safety.push_validation.get_file_restrictions_config",
            return_value=config,
        ):
            err = check_push_file_restrictions(
                ["--force"], "/fake/repo"
            )
        assert err is None

    def test_diff_exception_fails_closed(self):
        """When subprocess.run raises an exception, push is blocked."""
        config = FileRestrictionsData(
            blocked_patterns=[".github/workflows/*"],
            warned_patterns=[],
            warn_action="log",
        )
        with patch(
            "foundry_git_safety.push_validation.get_file_restrictions_config",
            return_value=config,
        ), patch(
            "foundry_git_safety.push_validation.resolve_bare_repo_path",
            return_value=None,
        ), patch(
            "foundry_git_safety.push_validation.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=30),
        ):
            err = check_push_file_restrictions(
                ["origin", "main"], "/fake/repo",
                metadata={"sandbox_branch": "feature-x"},
            )
        assert err is not None
        assert "fail-closed" in err.reason


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
