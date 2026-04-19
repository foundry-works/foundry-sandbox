"""Tests for foundry_git_safety.branch_types."""

import pytest

from foundry_git_safety.branch_types import (
    WELL_KNOWN_BRANCHES,
    WELL_KNOWN_BRANCH_PREFIXES,
    REF_ENUM_CMDS,
    ValidationError,
    _is_allowed_branch_name,
    _is_sha_like,
    _normalize_base_branch,
    get_subcommand,
    get_subcommand_args,
)


# ---------------------------------------------------------------------------
# ValidationError
# ---------------------------------------------------------------------------


class TestValidationError:
    """Tests for the ValidationError dataclass."""

    def test_construction(self):
        err = ValidationError(reason="something broke")
        assert err.reason == "something broke"
        assert err.field is None

    def test_to_dict_without_field(self):
        err = ValidationError(reason="bad value")
        d = err.to_dict()
        assert d == {"error": "bad value"}
        assert "field" not in d

    def test_to_dict_with_field(self):
        err = ValidationError(reason="invalid", field="branch")
        d = err.to_dict()
        assert d == {"error": "invalid", "field": "branch"}


# ---------------------------------------------------------------------------
# get_subcommand_args
# ---------------------------------------------------------------------------


class TestGetSubcommandArgs:
    """Tests for get_subcommand_args()."""

    def test_plain_command(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["checkout", "main"]
        )
        assert subcmd == "checkout"
        assert subcmd_args == ["main"]
        assert config_pairs == []
        assert idx == 0

    def test_c_key_val(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["-c", "user.name=Test", "commit", "-m", "msg"]
        )
        assert subcmd == "commit"
        assert subcmd_args == ["-m", "msg"]
        assert config_pairs == ["user.name=Test"]
        assert idx == 2

    def test_compact_c_key_val(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["-cuser.email=bot@example.com", "push"]
        )
        assert subcmd == "push"
        assert subcmd_args == []
        assert config_pairs == ["user.email=bot@example.com"]
        assert idx == 1

    def test_git_dir_equals_path(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["--git-dir=/repo/.git", "status"]
        )
        assert subcmd == "status"
        assert subcmd_args == []
        assert config_pairs == []
        assert idx == 1

    def test_work_tree_value(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["--work-tree", "/src", "log"]
        )
        assert subcmd == "log"
        assert subcmd_args == []
        assert config_pairs == []
        assert idx == 2

    def test_double_dash_terminator(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["--", "stash", "list"]
        )
        assert subcmd == "stash"
        assert subcmd_args == ["list"]
        assert config_pairs == []
        assert idx == 1

    def test_multiple_global_flags(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            [
                "-c", "core.bare=false",
                "--git-dir=/repo/.git",
                "--work-tree", "/src",
                "diff",
                "--stat",
            ]
        )
        assert subcmd == "diff"
        assert subcmd_args == ["--stat"]
        assert config_pairs == ["core.bare=false"]
        assert idx == 5

    def test_C_path(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["-C", "/home/user/repo", "log", "--oneline"]
        )
        assert subcmd == "log"
        assert subcmd_args == ["--oneline"]
        assert config_pairs == []
        assert idx == 2

    def test_no_subcommand_all_flags(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args(
            ["-C", "/repo", "--version"]
        )
        # --version is not a GLOBAL_VALUE_FLAG, but it starts with '-'
        # so the loop skips it and idx reaches the end
        assert subcmd is None
        assert subcmd_args == []
        assert config_pairs == []

    def test_empty_args(self):
        subcmd, subcmd_args, config_pairs, idx = get_subcommand_args([])
        assert subcmd is None
        assert subcmd_args == []
        assert config_pairs == []
        assert idx == 0


# ---------------------------------------------------------------------------
# get_subcommand
# ---------------------------------------------------------------------------


class TestGetSubcommand:
    """Tests for get_subcommand()."""

    def test_returns_subcommand(self):
        assert get_subcommand(["clone", "https://example.com/repo.git"]) == "clone"

    def test_returns_none_for_flags_only(self):
        assert get_subcommand(["-C", "/repo", "--version"]) is None

    def test_empty_args(self):
        assert get_subcommand([]) is None


# ---------------------------------------------------------------------------
# _is_sha_like
# ---------------------------------------------------------------------------


class TestIsShaLike:
    """Tests for _is_sha_like()."""

    def test_12_char_pass(self):
        assert _is_sha_like("abc123def456") is True

    def test_40_char_pass(self):
        assert _is_sha_like("a" * 40) is True

    def test_11_char_fail(self):
        assert _is_sha_like("abc123def45") is False

    def test_non_hex_fail(self):
        assert _is_sha_like("abcdefghijklmn") is False

    def test_empty_fail(self):
        assert _is_sha_like("") is False


# ---------------------------------------------------------------------------
# _normalize_base_branch
# ---------------------------------------------------------------------------


class TestNormalizeBaseBranch:
    """Tests for _normalize_base_branch()."""

    def test_refs_heads_main(self):
        assert _normalize_base_branch("refs/heads/main") == "main"

    def test_refs_remotes_origin_main(self):
        assert _normalize_base_branch("refs/remotes/origin/main") == "main"

    def test_origin_main(self):
        assert _normalize_base_branch("origin/main") == "main"

    def test_bare_name_passthrough(self):
        assert _normalize_base_branch("develop") == "develop"

    def test_empty_returns_none(self):
        assert _normalize_base_branch("") is None
        assert _normalize_base_branch(None) is None


# ---------------------------------------------------------------------------
# _is_allowed_branch_name
# ---------------------------------------------------------------------------


class TestIsAllowedBranchName:
    """Tests for _is_allowed_branch_name()."""

    def test_own_branch(self):
        assert _is_allowed_branch_name("feature/x", "feature/x") is True

    def test_well_known_branch(self):
        assert _is_allowed_branch_name("main", "feature/x") is True

    def test_well_known_prefix_same_prefix(self):
        """release/* branches visible from a release/* sandbox."""
        assert _is_allowed_branch_name("release/v1.0", "release/my-fix") is True

    def test_well_known_prefix_cross_prefix_blocked(self):
        """release/* branches NOT visible from a non-release sandbox."""
        assert _is_allowed_branch_name("release/v1.0", "feature/x") is False

    def test_hotfix_prefix_same_prefix(self):
        """hotfix/* branches visible from a hotfix/* sandbox."""
        assert _is_allowed_branch_name("hotfix/urgent-fix", "hotfix/my-hotfix") is True

    def test_unknown_blocked(self):
        assert _is_allowed_branch_name("other/branch", "feature/x") is False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    """Tests for module-level constants."""

    def test_well_known_branches(self):
        assert WELL_KNOWN_BRANCHES == frozenset({
            "main", "master", "develop", "production",
        })

    def test_ref_enum_cmds(self):
        assert REF_ENUM_CMDS == frozenset({
            "for-each-ref", "ls-remote", "show-ref",
        })


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
