"""Security invariant tests for git branch isolation and protection.

Validates that critical security properties of branch isolation, protected
branch enforcement, and cross-sandbox visibility filtering are maintained.

Security Properties Tested:
- Branch isolation is deny-by-default and fail-closed
- Protected branch push protections enforced
- Branch/tag deletion blocking enforced
- Cross-sandbox branch visibility filtering intact

These tests exercise the unified-proxy branch_isolation and git_policies
modules directly, without mitmproxy or network dependencies.
"""

import os
import re
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup -- unified-proxy lives outside the normal test package tree
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from branch_isolation import (
    ValidationError,
    _filter_branch_output,
    _filter_ref_enum_output,
    _filter_log_decorations,
    _is_allowed_branch_name,
    _is_allowed_ref,
    filter_stderr_branch_refs,
    validate_branch_isolation,
    WELL_KNOWN_BRANCHES,
    WELL_KNOWN_BRANCH_PREFIXES,
)
from git_policies import (
    ZERO_SHA,
    DEFAULT_PROTECTED_PATTERNS,
    check_protected_branches,
    load_branch_policy,
)

# foundry_sandbox is in the repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from foundry_sandbox.git_worktree import cleanup_sandbox_branch

# ---------------------------------------------------------------------------
# Module markers
# ---------------------------------------------------------------------------

pytestmark = [
    pytest.mark.security,
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SANDBOX_BRANCH = "sandbox/test-abc123"
OTHER_SANDBOX_BRANCH = "sandbox/other-def456"
BASE_BRANCH = "main"


def _make_metadata(sandbox_branch=SANDBOX_BRANCH, from_branch=BASE_BRANCH, **extra):
    """Build a standard metadata dict for testing."""
    meta = {
        "sandbox_branch": sandbox_branch,
        "from_branch": from_branch,
    }
    meta.update(extra)
    return meta


# ============================================================================
# 1. Branch Isolation Deny-by-Default Tests
# ============================================================================


class TestBranchIsolationDenyByDefault:
    """Verify that branch isolation denies access when metadata is incomplete.

    Security invariant: when sandbox_branch is missing or empty, ALL
    branch operations MUST be denied.  This prevents a misconfigured
    sandbox from escaping isolation.
    """

    def test_missing_sandbox_branch_blocks_all_operations(self):
        """Metadata present but no sandbox_branch must block everything."""
        metadata = {"from_branch": "main"}
        # Any git command that references a branch should be blocked
        commands = [
            ["log", "main"],
            ["checkout", "feature/x"],
            ["push", "origin", "some-branch"],
            ["branch", "-d", "some-branch"],
            ["diff", "main..develop"],
        ]
        for args in commands:
            result = validate_branch_isolation(args, metadata)
            assert result is not None, (
                f"Expected denial for {args} with missing sandbox_branch"
            )
            assert "missing sandbox_branch" in result.reason.lower() or \
                   "sandbox_branch" in result.reason, (
                f"Error should mention sandbox_branch, got: {result.reason}"
            )

    def test_none_metadata_allows_passthrough(self):
        """When metadata is None (no isolation context), validation passes.

        This is the pre-sandbox state where branch isolation is not active.
        The proxy handles this case by not enforcing isolation.
        """
        result = validate_branch_isolation(["log", "main"], None)
        assert result is None, (
            "None metadata should pass through (isolation not active)"
        )

    def test_empty_string_sandbox_branch_blocks_all(self):
        """Empty string sandbox_branch must be treated as missing."""
        metadata = {"sandbox_branch": "", "from_branch": "main"}
        result = validate_branch_isolation(["log", "main"], metadata)
        assert result is not None, (
            "Empty string sandbox_branch should be denied"
        )

    def test_none_sandbox_branch_blocks_all(self):
        """None sandbox_branch value must be treated as missing."""
        metadata = {"sandbox_branch": None, "from_branch": "main"}
        result = validate_branch_isolation(["log", "main"], metadata)
        assert result is not None, (
            "None sandbox_branch should be denied"
        )

    def test_whitespace_only_sandbox_branch_blocks_all(self):
        """Whitespace-only sandbox_branch must be treated as missing."""
        # Python's falsy check on "  " is False (truthy), but leading/trailing
        # whitespace in a branch name is not valid.  The system should handle
        # this by either rejecting it or treating it as the literal branch name.
        metadata = {"sandbox_branch": "   ", "from_branch": "main"}
        # Even if it's not treated as missing, accessing another branch should
        # be blocked because "   " won't match any real branch.
        result = validate_branch_isolation(["log", "some-other-branch"], metadata)
        # Either it's blocked as missing or as a non-matching branch
        # The key security property is that cross-branch access is denied.
        # We accept either outcome as long as another branch can't be accessed.
        if result is None:
            # If validation passed, then "some-other-branch" would need to be
            # allowed. Let's verify it's actually blocked for a real ref.
            result2 = validate_branch_isolation(
                ["checkout", OTHER_SANDBOX_BRANCH], metadata
            )
            assert result2 is not None, (
                "Cross-sandbox access must be denied even with whitespace sandbox_branch"
            )

    def test_cross_sandbox_access_denied(self):
        """A sandbox must not access another sandbox's branch."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["checkout", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None, (
            f"Access to {OTHER_SANDBOX_BRANCH} from {SANDBOX_BRANCH} must be denied"
        )

    def test_cross_sandbox_log_denied(self):
        """Reading log from another sandbox's branch must be denied."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["log", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None, (
            f"Log of {OTHER_SANDBOX_BRANCH} from {SANDBOX_BRANCH} must be denied"
        )

    def test_cross_sandbox_diff_denied(self):
        """Diff referencing another sandbox branch must be denied."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["diff", f"{SANDBOX_BRANCH}..{OTHER_SANDBOX_BRANCH}"], metadata
        )
        assert result is not None, (
            "Diff range including other sandbox branch must be denied"
        )

    def test_cross_sandbox_push_denied(self):
        """Push to another sandbox's branch must be denied."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["push", "origin", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None, (
            f"Push to {OTHER_SANDBOX_BRANCH} must be denied"
        )

    def test_own_branch_always_allowed(self):
        """A sandbox can always access its own branch."""
        metadata = _make_metadata()
        # Checkout own branch
        result = validate_branch_isolation(
            ["checkout", SANDBOX_BRANCH], metadata
        )
        assert result is None, (
            f"Checkout of own branch {SANDBOX_BRANCH} should be allowed"
        )

    def test_well_known_branches_allowed(self):
        """Well-known branches (main, master, develop, production) are accessible."""
        metadata = _make_metadata()
        for branch in WELL_KNOWN_BRANCHES:
            result = validate_branch_isolation(
                ["log", branch], metadata
            )
            assert result is None, (
                f"Well-known branch '{branch}' should be accessible"
            )

    def test_well_known_prefixes_allowed(self):
        """Branches with well-known prefixes (release/*, hotfix/*) are accessible."""
        metadata = _make_metadata()
        for prefix in WELL_KNOWN_BRANCH_PREFIXES:
            branch = f"{prefix}v1.0"
            result = validate_branch_isolation(
                ["log", branch], metadata
            )
            assert result is None, (
                f"Well-known prefix branch '{branch}' should be accessible"
            )

    def test_base_branch_allowed(self):
        """The sandbox's configured base branch is always accessible."""
        metadata = _make_metadata(from_branch="feature/base")
        result = validate_branch_isolation(
            ["log", "feature/base"], metadata
        )
        assert result is None, (
            "Base branch should be accessible"
        )


# ============================================================================
# 2. Branch Isolation Fail-Closed Tests
# ============================================================================


class TestBranchIsolationFailClosed:
    """Verify that branch isolation fails closed on edge cases.

    Security invariant: unknown or ambiguous input must be blocked,
    never allowed through.
    """

    def test_short_hex_treated_as_branch_name(self):
        """Hex strings shorter than 12 chars must be treated as branch names.

        A short hex string could be a branch name disguised as a SHA.
        The system must not allow it as a SHA bypass.
        """
        metadata = _make_metadata()
        # "abc123" is 6 chars of hex - could be a branch name
        short_hex = "abc123"
        assert not _is_allowed_ref(short_hex, SANDBOX_BRANCH), (
            f"Short hex '{short_hex}' should NOT be treated as SHA and allowed"
        )

    def test_11_char_hex_treated_as_branch(self):
        """11-char hex string is below the 12-char SHA threshold."""
        metadata = _make_metadata()
        hex_11 = "a" * 11
        assert not _is_allowed_ref(hex_11, SANDBOX_BRANCH), (
            "11-char hex should be treated as branch name and denied"
        )

    def test_12_char_hex_treated_as_sha(self):
        """12-char hex string meets the SHA threshold and is allowed."""
        metadata = _make_metadata()
        hex_12 = "a" * 12
        assert _is_allowed_ref(hex_12, SANDBOX_BRANCH), (
            "12-char hex should be treated as SHA and allowed"
        )

    def test_40_char_hex_treated_as_sha(self):
        """Full 40-char SHA is always allowed."""
        metadata = _make_metadata()
        sha_40 = "a" * 40
        assert _is_allowed_ref(sha_40, SANDBOX_BRANCH), (
            "40-char SHA should be allowed"
        )

    def test_fetch_head_always_blocked(self):
        """FETCH_HEAD is always blocked (could contain cross-branch data)."""
        metadata = _make_metadata()
        assert not _is_allowed_ref("FETCH_HEAD", SANDBOX_BRANCH), (
            "FETCH_HEAD must always be blocked"
        )

    def test_head_always_allowed(self):
        """HEAD is always allowed."""
        assert _is_allowed_ref("HEAD", SANDBOX_BRANCH), (
            "HEAD must always be allowed"
        )

    def test_tags_always_allowed(self):
        """Tag refs are always allowed."""
        assert _is_allowed_ref("refs/tags/v1.0.0", SANDBOX_BRANCH)
        assert _is_allowed_ref("tags/v2.0", SANDBOX_BRANCH)

    def test_stash_always_allowed(self):
        """Stash refs are always allowed."""
        assert _is_allowed_ref("stash", SANDBOX_BRANCH)

    def test_implicit_all_ref_flags_blocked(self):
        """Flags like --all, --branches, --remotes are blocked on ref-reading commands."""
        metadata = _make_metadata()
        blocked_flags = ["--all", "--branches", "--remotes", "--glob"]
        for flag in blocked_flags:
            result = validate_branch_isolation(
                ["log", flag], metadata
            )
            assert result is not None, (
                f"Flag '{flag}' should be blocked (exposes all branches)"
            )

    def test_fetch_all_blocked(self):
        """fetch --all is blocked (exposes all branches)."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["fetch", "--all"], metadata
        )
        assert result is not None, (
            "fetch --all must be blocked"
        )

    def test_push_all_blocked(self):
        """push --all is blocked (affects all branches)."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["push", "--all"], metadata
        )
        assert result is not None, (
            "push --all must be blocked"
        )

    def test_push_mirror_blocked(self):
        """push --mirror is blocked (affects all branches)."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["push", "--mirror"], metadata
        )
        assert result is not None, (
            "push --mirror must be blocked"
        )

    def test_error_messages_dont_leak_sandbox_names(self):
        """Error messages must not reveal other sandbox branch names."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["checkout", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None
        # The error should mention the ref but should not contain internal
        # sandbox identifiers beyond what the user already provided.
        # It should not reveal the list of other sandboxes.
        assert "other sandbox" not in result.reason.lower(), (
            "Error should not mention other sandboxes"
        )

    def test_remote_tracking_ref_isolation(self):
        """Remote tracking refs for other sandbox branches must be denied."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["log", f"refs/remotes/origin/{OTHER_SANDBOX_BRANCH}"], metadata
        )
        assert result is not None, (
            "Remote tracking ref to other sandbox branch must be denied"
        )

    def test_refs_heads_isolation(self):
        """Full refs/heads/ path for other sandbox branch must be denied."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["log", f"refs/heads/{OTHER_SANDBOX_BRANCH}"], metadata
        )
        assert result is not None, (
            "refs/heads/ of other sandbox branch must be denied"
        )

    def test_range_operator_both_sides_checked(self):
        """Both sides of .. and ... range operators must be validated."""
        metadata = _make_metadata()
        # Left side bad
        result = validate_branch_isolation(
            ["log", f"{OTHER_SANDBOX_BRANCH}..{SANDBOX_BRANCH}"], metadata
        )
        assert result is not None, "Bad left side of range must be caught"

        # Right side bad
        result = validate_branch_isolation(
            ["log", f"{SANDBOX_BRANCH}..{OTHER_SANDBOX_BRANCH}"], metadata
        )
        assert result is not None, "Bad right side of range must be caught"

        # Both sides allowed
        result = validate_branch_isolation(
            ["log", f"{SANDBOX_BRANCH}..main"], metadata
        )
        assert result is None, "Both sides allowed should pass"

    def test_rev_suffix_stripping(self):
        """Revision suffixes (~N, ^N) must be stripped before checking."""
        metadata = _make_metadata()
        # Own branch with suffix should be allowed
        assert _is_allowed_ref(f"{SANDBOX_BRANCH}~3", SANDBOX_BRANCH)
        assert _is_allowed_ref(f"{SANDBOX_BRANCH}^2", SANDBOX_BRANCH)
        assert _is_allowed_ref(f"main~5", SANDBOX_BRANCH)

        # Other sandbox branch with suffix should still be denied
        assert not _is_allowed_ref(f"{OTHER_SANDBOX_BRANCH}~3", SANDBOX_BRANCH)


# ============================================================================
# 3. Protected Branch Push Protection Tests
# ============================================================================


class TestProtectedBranchPushProtection:
    """Verify that protected branches cannot be modified or deleted.

    Security invariant: protected branches (main, master, production,
    release/*) cannot be directly pushed to, force-pushed, or deleted.
    """

    def test_direct_push_to_main_blocked(self):
        """Direct push to refs/heads/main must be blocked."""
        result = check_protected_branches(
            "refs/heads/main", "a" * 40, "b" * 40
        )
        assert result is not None, "Direct push to main must be blocked"
        assert "not allowed" in result.lower()

    def test_direct_push_to_master_blocked(self):
        """Direct push to refs/heads/master must be blocked."""
        result = check_protected_branches(
            "refs/heads/master", "a" * 40, "b" * 40
        )
        assert result is not None, "Direct push to master must be blocked"

    def test_direct_push_to_production_blocked(self):
        """Direct push to refs/heads/production must be blocked."""
        result = check_protected_branches(
            "refs/heads/production", "a" * 40, "b" * 40
        )
        assert result is not None, "Direct push to production must be blocked"

    def test_direct_push_to_release_wildcard_blocked(self):
        """Direct push to refs/heads/release/* must be blocked."""
        release_branches = [
            "refs/heads/release/v1.0",
            "refs/heads/release/v2.0.1",
            "refs/heads/release/2024-01",
        ]
        for refname in release_branches:
            result = check_protected_branches(
                refname, "a" * 40, "b" * 40
            )
            assert result is not None, (
                f"Direct push to {refname} must be blocked"
            )

    def test_deletion_of_main_blocked(self):
        """Deletion of main (new_sha = ZERO_SHA) must be blocked."""
        result = check_protected_branches(
            "refs/heads/main", "a" * 40, ZERO_SHA
        )
        assert result is not None, "Deletion of main must be blocked"
        assert "deletion" in result.lower()

    def test_deletion_of_master_blocked(self):
        """Deletion of master must be blocked."""
        result = check_protected_branches(
            "refs/heads/master", "a" * 40, ZERO_SHA
        )
        assert result is not None, "Deletion of master must be blocked"

    def test_deletion_of_production_blocked(self):
        """Deletion of production must be blocked."""
        result = check_protected_branches(
            "refs/heads/production", "a" * 40, ZERO_SHA
        )
        assert result is not None, "Deletion of production must be blocked"

    def test_deletion_of_release_branches_blocked(self):
        """Deletion of release/* branches must be blocked."""
        result = check_protected_branches(
            "refs/heads/release/v1.0", "a" * 40, ZERO_SHA
        )
        assert result is not None, "Deletion of release branch must be blocked"

    def test_force_push_to_protected_blocked(self):
        """Force push (update) to protected branch must be blocked.

        Force push is detected as an update (neither old_sha nor new_sha
        is ZERO_SHA) to a protected branch.
        """
        for refname in DEFAULT_PROTECTED_PATTERNS:
            # Replace wildcards with a concrete name for testing
            concrete_ref = refname.replace("*", "v1.0")
            result = check_protected_branches(
                concrete_ref, "a" * 40, "b" * 40
            )
            assert result is not None, (
                f"Force push to {concrete_ref} must be blocked"
            )

    def test_non_protected_branch_push_allowed(self):
        """Push to a non-protected branch should be allowed."""
        non_protected = [
            "refs/heads/feature/my-feature",
            "refs/heads/sandbox/test-123",
            "refs/heads/bugfix/fix-123",
            "refs/heads/develop",  # Not in default protected patterns
        ]
        for refname in non_protected:
            result = check_protected_branches(
                refname, "a" * 40, "b" * 40
            )
            assert result is None, (
                f"Push to non-protected {refname} should be allowed"
            )

    def test_creation_of_protected_branch_blocked(self):
        """Creation (old_sha = ZERO_SHA) of a protected branch must be blocked.

        Exception: initial bootstrap creation of main may be allowed once
        via lock file, but subsequent creations are blocked.
        """
        # master doesn't have the bootstrap exception
        result = check_protected_branches(
            "refs/heads/master", ZERO_SHA, "b" * 40
        )
        assert result is not None, (
            "Creation of protected branch master must be blocked"
        )

    def test_policy_disabled_allows_all(self):
        """When policy is explicitly disabled, all operations are allowed."""
        metadata = {
            "git": {
                "protected_branches": {
                    "enabled": False,
                    "patterns": DEFAULT_PROTECTED_PATTERNS,
                }
            }
        }
        result = check_protected_branches(
            "refs/heads/main", "a" * 40, "b" * 40, metadata=metadata
        )
        assert result is None, (
            "Disabled policy should allow all operations"
        )

    def test_custom_patterns_override_defaults(self):
        """Custom patterns from metadata override default patterns."""
        metadata = {
            "git": {
                "protected_branches": {
                    "enabled": True,
                    "patterns": ["refs/heads/custom-protected"],
                }
            }
        }
        # Default protected branch should now be allowed
        result = check_protected_branches(
            "refs/heads/main", "a" * 40, "b" * 40, metadata=metadata
        )
        assert result is None, (
            "main should not be protected when custom patterns don't include it"
        )

        # Custom protected branch should be blocked
        result = check_protected_branches(
            "refs/heads/custom-protected", "a" * 40, "b" * 40, metadata=metadata
        )
        assert result is not None, (
            "Custom protected branch should be blocked"
        )

    def test_zero_sha_is_exactly_40_zeros(self):
        """Verify ZERO_SHA is exactly 40 zero characters."""
        assert len(ZERO_SHA) == 40
        assert all(c == "0" for c in ZERO_SHA)

    def test_main_bootstrap_creation_with_lock_file(self):
        """Bootstrap creation of main is allowed exactly once via lock file."""
        with tempfile.TemporaryDirectory() as bare_repo:
            # First creation should succeed (lock file doesn't exist)
            result = check_protected_branches(
                "refs/heads/main", ZERO_SHA, "b" * 40,
                bare_repo_path=bare_repo,
            )
            assert result is None, (
                "First bootstrap creation of main should be allowed"
            )

            # Second creation should fail (lock file exists)
            result = check_protected_branches(
                "refs/heads/main", ZERO_SHA, "c" * 40,
                bare_repo_path=bare_repo,
            )
            assert result is not None, (
                "Second creation of main must be blocked (bootstrap completed)"
            )
            assert "bootstrap" in result.lower()


# ============================================================================
# 4. Branch/Tag Deletion Blocking Tests
# ============================================================================


class TestBranchTagDeletionBlocking:
    """Verify that branch and tag deletion is properly controlled.

    Security invariant: delete operations on non-owned branches must
    be blocked, and cleanup_sandbox_branch must refuse to delete
    protected patterns.
    """

    def test_branch_delete_non_owned_blocked(self):
        """git branch -d/-D on non-owned branch must be blocked."""
        metadata = _make_metadata()
        for flag in ["-d", "-D", "--delete"]:
            result = validate_branch_isolation(
                ["branch", flag, OTHER_SANDBOX_BRANCH], metadata
            )
            assert result is not None, (
                f"Deletion of non-owned branch with {flag} must be blocked"
            )

    def test_branch_delete_own_branch_allowed(self):
        """git branch -d on own branch should be allowed."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["branch", "-d", SANDBOX_BRANCH], metadata
        )
        assert result is None, (
            "Deletion of own branch should be allowed"
        )

    def test_branch_delete_well_known_allowed(self):
        """git branch -d on well-known branch should be allowed (policy check is separate)."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["branch", "-d", "main"], metadata
        )
        # Branch isolation allows this because main is a well-known branch.
        # The actual deletion would be caught by check_protected_branches.
        assert result is None, (
            "Branch isolation allows deletion of well-known branches "
            "(protected branch policy enforces the actual block)"
        )

    def test_push_delete_refspec_non_owned_blocked(self):
        """push origin :branch (delete refspec) for non-owned branch must be blocked."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["push", "origin", f":{OTHER_SANDBOX_BRANCH}"], metadata
        )
        assert result is not None, (
            "Delete refspec for non-owned branch must be blocked"
        )

    def test_push_delete_refspec_own_branch_allowed(self):
        """push origin :branch for own branch should be allowed."""
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["push", "origin", f":{SANDBOX_BRANCH}"], metadata
        )
        assert result is None, (
            "Delete refspec for own branch should be allowed"
        )

    def test_cleanup_sandbox_branch_refuses_main(self):
        """cleanup_sandbox_branch must refuse to delete 'main'."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
                cleanup_sandbox_branch("main", bare_path)
                # Should never call branch -D for protected branches
                for call in mock_run.call_args_list:
                    cmd = call[0][0] if call[0] else call.kwargs.get("args", [])
                    if "-D" in cmd:
                        assert "main" not in cmd, (
                            "cleanup_sandbox_branch must not delete 'main'"
                        )

    def test_cleanup_sandbox_branch_refuses_master(self):
        """cleanup_sandbox_branch must refuse to delete 'master'."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
                cleanup_sandbox_branch("master", bare_path)
                for call in mock_run.call_args_list:
                    cmd = call[0][0] if call[0] else call.kwargs.get("args", [])
                    if "-D" in cmd:
                        assert "master" not in cmd

    def test_cleanup_sandbox_branch_refuses_develop(self):
        """cleanup_sandbox_branch must refuse to delete 'develop'."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
                cleanup_sandbox_branch("develop", bare_path)
                for call in mock_run.call_args_list:
                    cmd = call[0][0] if call[0] else call.kwargs.get("args", [])
                    if "-D" in cmd:
                        assert "develop" not in cmd

    def test_cleanup_sandbox_branch_refuses_production(self):
        """cleanup_sandbox_branch must refuse to delete 'production'."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
                cleanup_sandbox_branch("production", bare_path)
                for call in mock_run.call_args_list:
                    cmd = call[0][0] if call[0] else call.kwargs.get("args", [])
                    if "-D" in cmd:
                        assert "production" not in cmd

    def test_cleanup_sandbox_branch_refuses_release(self):
        """cleanup_sandbox_branch must refuse to delete 'release/*'."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
                cleanup_sandbox_branch("release/v1.0", bare_path)
                for call in mock_run.call_args_list:
                    cmd = call[0][0] if call[0] else call.kwargs.get("args", [])
                    if "-D" in cmd:
                        assert "release/v1.0" not in cmd

    def test_cleanup_sandbox_branch_refuses_hotfix(self):
        """cleanup_sandbox_branch must refuse to delete 'hotfix/*'."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
                cleanup_sandbox_branch("hotfix/urgent-fix", bare_path)
                for call in mock_run.call_args_list:
                    cmd = call[0][0] if call[0] else call.kwargs.get("args", [])
                    if "-D" in cmd:
                        assert "hotfix/urgent-fix" not in cmd

    def test_cleanup_sandbox_branch_allows_ephemeral(self):
        """cleanup_sandbox_branch should allow deleting ephemeral sandbox branches."""
        with tempfile.TemporaryDirectory() as bare_path:
            with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
                # First call: worktree list (no match), second call: branch -D
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout="", stderr=""),
                    MagicMock(returncode=0, stdout="", stderr=""),
                ]
                cleanup_sandbox_branch("sandbox/ephemeral-123", bare_path)
                # The second call should be the deletion
                assert mock_run.call_count == 2
                delete_call = mock_run.call_args_list[1]
                cmd = delete_call[0][0]
                assert "-D" in cmd
                assert "sandbox/ephemeral-123" in cmd

    def test_cleanup_sandbox_branch_empty_inputs(self):
        """cleanup_sandbox_branch with empty inputs does nothing."""
        with patch("foundry_sandbox.git_worktree.subprocess.run") as mock_run:
            cleanup_sandbox_branch("", "/some/path")
            mock_run.assert_not_called()

            cleanup_sandbox_branch("branch", "")
            mock_run.assert_not_called()

    def test_protected_branch_deletion_via_push(self):
        """Deletion of protected branches via push must be blocked."""
        for pattern in DEFAULT_PROTECTED_PATTERNS:
            concrete_ref = pattern.replace("*", "v1.0")
            result = check_protected_branches(
                concrete_ref, "a" * 40, ZERO_SHA
            )
            assert result is not None, (
                f"Deletion of {concrete_ref} via push must be blocked"
            )
            assert "deletion" in result.lower()


# ============================================================================
# 5. Cross-Sandbox Branch Visibility Filtering Tests
# ============================================================================


class TestCrossSandboxVisibilityFiltering:
    """Verify that output filtering hides other sandbox branches.

    Security invariant: git command output must be filtered to remove
    references to other sandbox branches while preserving visibility
    of own branch, well-known branches, and tags.
    """

    # --- _filter_branch_output tests ---

    def test_filter_branch_hides_other_sandbox(self):
        """_filter_branch_output must hide other sandbox branches."""
        output = (
            "* sandbox/test-abc123\n"
            "  main\n"
            "  sandbox/other-def456\n"
            "  develop\n"
        )
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert SANDBOX_BRANCH in filtered
        assert "main" in filtered

    def test_filter_branch_preserves_own_branch(self):
        """Own sandbox branch must always be visible."""
        output = f"* {SANDBOX_BRANCH}\n"
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered

    def test_filter_branch_preserves_well_known(self):
        """Well-known branches must remain visible."""
        lines = []
        for branch in WELL_KNOWN_BRANCHES:
            lines.append(f"  {branch}\n")
        output = "".join(lines)
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        for branch in WELL_KNOWN_BRANCHES:
            assert branch in filtered, (
                f"Well-known branch '{branch}' must remain visible"
            )

    def test_filter_branch_preserves_release_prefix(self):
        """Branches with well-known prefixes must remain visible."""
        output = "  release/v1.0\n  hotfix/fix-1\n  sandbox/other-xyz\n"
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        assert "release/v1.0" in filtered
        assert "hotfix/fix-1" in filtered
        assert "sandbox/other-xyz" not in filtered

    def test_filter_branch_verbose_format(self):
        """Verbose branch output (-v) must also be filtered."""
        output = (
            f"* {SANDBOX_BRANCH}   abc1234 commit message\n"
            f"  {OTHER_SANDBOX_BRANCH} def5678 other commit\n"
            "  main                abc1234 main commit\n"
        )
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert "main" in filtered

    def test_filter_branch_empty_output(self):
        """Empty output returns empty."""
        assert _filter_branch_output("", SANDBOX_BRANCH) == ""

    def test_filter_branch_drops_unrecognized_format(self):
        """Unrecognized format lines are dropped (fail-closed)."""
        # A line that doesn't match any known branch format
        output = "WEIRD_FORMAT_LINE_NO_INDICATOR\n"
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        assert "WEIRD_FORMAT_LINE_NO_INDICATOR" not in filtered

    def test_filter_branch_remote_format(self):
        """Remote branch listing (-a) must filter other sandbox branches."""
        output = (
            f"  remotes/origin/{SANDBOX_BRANCH}\n"
            f"  remotes/origin/{OTHER_SANDBOX_BRANCH}\n"
            "  remotes/origin/main\n"
            "  remotes/origin/HEAD -> origin/main\n"
        )
        filtered = _filter_branch_output(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert "main" in filtered
        assert "HEAD" in filtered

    # --- _filter_ref_enum_output tests ---

    def test_filter_ref_enum_hides_other_sandbox(self):
        """_filter_ref_enum_output must hide other sandbox branch refs."""
        output = (
            f"abc1234 refs/heads/{SANDBOX_BRANCH}\n"
            f"def5678 refs/heads/{OTHER_SANDBOX_BRANCH}\n"
            "ghi9012 refs/heads/main\n"
            "jkl3456 refs/tags/v1.0\n"
        )
        filtered = _filter_ref_enum_output(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert "main" in filtered
        assert "refs/tags/v1.0" in filtered

    def test_filter_ref_enum_preserves_tags(self):
        """Tag refs must always remain visible."""
        output = (
            "abc1234 refs/tags/v1.0\n"
            "def5678 refs/tags/v2.0\n"
            "ghi9012 refs/tags/release-candidate\n"
        )
        filtered = _filter_ref_enum_output(output, SANDBOX_BRANCH)
        assert "refs/tags/v1.0" in filtered
        assert "refs/tags/v2.0" in filtered
        assert "refs/tags/release-candidate" in filtered

    def test_filter_ref_enum_preserves_own_branch(self):
        """Own sandbox branch must remain visible in ref enumeration."""
        output = f"abc1234 refs/heads/{SANDBOX_BRANCH}\n"
        filtered = _filter_ref_enum_output(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered

    def test_filter_ref_enum_preserves_well_known(self):
        """Well-known branch refs must remain visible."""
        lines = []
        for i, branch in enumerate(WELL_KNOWN_BRANCHES):
            sha = f"{chr(ord('a') + i) * 7}"
            lines.append(f"{sha}0000 refs/heads/{branch}\n")
        output = "".join(lines)
        filtered = _filter_ref_enum_output(output, SANDBOX_BRANCH)
        for branch in WELL_KNOWN_BRANCHES:
            assert branch in filtered, (
                f"Well-known branch '{branch}' must remain visible in ref enum"
            )

    def test_filter_ref_enum_empty_output(self):
        """Empty output returns empty."""
        assert _filter_ref_enum_output("", SANDBOX_BRANCH) == ""

    def test_filter_ref_enum_remote_refs(self):
        """Remote refs for other sandbox branches must be hidden."""
        output = (
            f"abc1234 refs/remotes/origin/{SANDBOX_BRANCH}\n"
            f"def5678 refs/remotes/origin/{OTHER_SANDBOX_BRANCH}\n"
            "ghi9012 refs/remotes/origin/main\n"
        )
        filtered = _filter_ref_enum_output(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert "main" in filtered

    # --- _filter_log_decorations tests ---

    def test_filter_log_decorations_hides_other_sandbox(self):
        """Log decorations must hide other sandbox branch names."""
        output = (
            f"abc1234 (HEAD -> {SANDBOX_BRANCH}, "
            f"origin/{OTHER_SANDBOX_BRANCH}, "
            f"tag: v1.0, main)\n"
        )
        filtered = _filter_log_decorations(output, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert "tag: v1.0" in filtered
        assert "main" in filtered

    def test_filter_log_decorations_preserves_head(self):
        """HEAD decoration must always be preserved."""
        output = f"abc1234 (HEAD -> {SANDBOX_BRANCH})\n"
        filtered = _filter_log_decorations(output, SANDBOX_BRANCH)
        assert "HEAD" in filtered

    def test_filter_log_decorations_preserves_tags(self):
        """Tag decorations must always be preserved."""
        output = "abc1234 (tag: v1.0, tag: v2.0)\n"
        filtered = _filter_log_decorations(output, SANDBOX_BRANCH)
        assert "tag: v1.0" in filtered
        assert "tag: v2.0" in filtered

    def test_filter_log_decorations_removes_all_disallowed(self):
        """When all decorations are disallowed, parens are removed."""
        output = f"abc1234 (origin/{OTHER_SANDBOX_BRANCH})\n"
        filtered = _filter_log_decorations(output, SANDBOX_BRANCH)
        assert OTHER_SANDBOX_BRANCH not in filtered

    def test_filter_log_decorations_non_decoration_lines_preserved(self):
        """Non-decoration lines must pass through unchanged."""
        output = "    This is a commit message\n    With multiple lines\n"
        filtered = _filter_log_decorations(output, SANDBOX_BRANCH)
        assert filtered == output

    def test_filter_log_decorations_empty_output(self):
        """Empty output returns empty."""
        assert _filter_log_decorations("", SANDBOX_BRANCH) == ""

    # --- filter_stderr_branch_refs tests ---

    def test_stderr_redacts_other_sandbox_refs(self):
        """Stderr output must redact other sandbox branch refs."""
        stderr = (
            f"error: pathspec 'refs/heads/{OTHER_SANDBOX_BRANCH}' "
            f"did not match any files\n"
        )
        filtered = filter_stderr_branch_refs(stderr, SANDBOX_BRANCH)
        assert OTHER_SANDBOX_BRANCH not in filtered
        assert "<redacted>" in filtered

    def test_stderr_preserves_own_branch_in_ref_context(self):
        """Stderr output must preserve own sandbox branch in refs/heads/ context.

        The first regex pass (_STDERR_REF_RE) extracts the branch name from
        refs/heads/<branch> and checks it against _is_allowed_branch_name.
        The own sandbox branch should be preserved by the first pass.
        Note: the second pass (_STDERR_BARE_BRANCH_RE) may still redact the
        full 'refs/heads/...' token in single quotes since it treats the
        whole path as a bare branch name.
        """
        # Use a non-quoted context to avoid the bare_branch second pass
        stderr = (
            f"hint: refs/heads/{SANDBOX_BRANCH} was updated\n"
        )
        filtered = filter_stderr_branch_refs(stderr, SANDBOX_BRANCH)
        assert SANDBOX_BRANCH in filtered

    def test_stderr_preserves_well_known_refs_unquoted(self):
        """Stderr output must preserve well-known branch refs in unquoted context."""
        stderr = "hint: refs/heads/main was updated\n"
        filtered = filter_stderr_branch_refs(stderr, SANDBOX_BRANCH)
        assert "main" in filtered
        assert "<redacted>" not in filtered

    def test_stderr_redacts_bare_branch_in_quotes(self):
        """Bare branch names in quotes must be redacted if not allowed."""
        stderr = (
            f"error: pathspec '{OTHER_SANDBOX_BRANCH}' "
            f"did not match any files\n"
        )
        filtered = filter_stderr_branch_refs(stderr, SANDBOX_BRANCH)
        assert OTHER_SANDBOX_BRANCH not in filtered

    def test_stderr_empty_input(self):
        """Empty stderr returns empty."""
        assert filter_stderr_branch_refs("", SANDBOX_BRANCH) == ""

    def test_stderr_none_sandbox_branch(self):
        """None sandbox_branch returns stderr unchanged."""
        stderr = "some error message\n"
        # The function checks `not sandbox_branch` and returns early
        assert filter_stderr_branch_refs(stderr, "") == stderr

    def test_stderr_remote_refs_redacted(self):
        """Remote branch refs in stderr must be redacted."""
        stderr = (
            f"hint: refs/remotes/origin/{OTHER_SANDBOX_BRANCH} "
            f"was not found\n"
        )
        filtered = filter_stderr_branch_refs(stderr, SANDBOX_BRANCH)
        assert OTHER_SANDBOX_BRANCH not in filtered


# ============================================================================
# 6. _is_allowed_branch_name and _is_allowed_ref Unit Tests
# ============================================================================


class TestIsAllowedBranchName:
    """Direct tests for the branch name allowlist function."""

    def test_own_branch_allowed(self):
        assert _is_allowed_branch_name(SANDBOX_BRANCH, SANDBOX_BRANCH)

    def test_other_sandbox_denied(self):
        assert not _is_allowed_branch_name(OTHER_SANDBOX_BRANCH, SANDBOX_BRANCH)

    def test_well_known_branches_allowed(self):
        for branch in WELL_KNOWN_BRANCHES:
            assert _is_allowed_branch_name(branch, SANDBOX_BRANCH), (
                f"Well-known branch '{branch}' should be allowed"
            )

    def test_release_prefix_allowed(self):
        assert _is_allowed_branch_name("release/v1.0", SANDBOX_BRANCH)
        assert _is_allowed_branch_name("release/2024-01-15", SANDBOX_BRANCH)

    def test_hotfix_prefix_allowed(self):
        assert _is_allowed_branch_name("hotfix/urgent", SANDBOX_BRANCH)

    def test_arbitrary_branch_denied(self):
        assert not _is_allowed_branch_name("feature/someone-else", SANDBOX_BRANCH)
        assert not _is_allowed_branch_name("bugfix/random", SANDBOX_BRANCH)

    def test_base_branch_allowed(self):
        assert _is_allowed_branch_name(
            "feature/base", SANDBOX_BRANCH, base_branch="feature/base"
        )

    def test_base_branch_none_ignored(self):
        assert not _is_allowed_branch_name(
            "feature/random", SANDBOX_BRANCH, base_branch=None
        )


class TestIsAllowedRef:
    """Direct tests for the ref allowlist function."""

    def test_head_allowed(self):
        assert _is_allowed_ref("HEAD", SANDBOX_BRANCH)

    def test_at_forms_with_head_prefix_allowed(self):
        """HEAD@{N} forms are allowed (HEAD is always allowed, @{} is suffix)."""
        assert _is_allowed_ref("HEAD@{1}", SANDBOX_BRANCH)
        assert _is_allowed_ref("HEAD@{upstream}", SANDBOX_BRANCH)

    def test_tags_allowed(self):
        assert _is_allowed_ref("refs/tags/v1.0", SANDBOX_BRANCH)
        assert _is_allowed_ref("tags/v2.0", SANDBOX_BRANCH)

    def test_stash_allowed(self):
        assert _is_allowed_ref("stash", SANDBOX_BRANCH)

    def test_fetch_head_blocked(self):
        assert not _is_allowed_ref("FETCH_HEAD", SANDBOX_BRANCH)

    def test_own_branch_allowed(self):
        assert _is_allowed_ref(SANDBOX_BRANCH, SANDBOX_BRANCH)

    def test_other_sandbox_blocked(self):
        assert not _is_allowed_ref(OTHER_SANDBOX_BRANCH, SANDBOX_BRANCH)

    def test_refs_heads_own_allowed(self):
        assert _is_allowed_ref(f"refs/heads/{SANDBOX_BRANCH}", SANDBOX_BRANCH)

    def test_refs_heads_other_blocked(self):
        assert not _is_allowed_ref(
            f"refs/heads/{OTHER_SANDBOX_BRANCH}", SANDBOX_BRANCH
        )

    def test_remote_tracking_own_allowed(self):
        assert _is_allowed_ref(
            f"refs/remotes/origin/{SANDBOX_BRANCH}", SANDBOX_BRANCH
        )

    def test_remote_tracking_other_blocked(self):
        assert not _is_allowed_ref(
            f"refs/remotes/origin/{OTHER_SANDBOX_BRANCH}", SANDBOX_BRANCH
        )

    def test_sha_like_12_chars_allowed(self):
        assert _is_allowed_ref("a" * 12, SANDBOX_BRANCH)

    def test_sha_like_40_chars_allowed(self):
        assert _is_allowed_ref("a" * 40, SANDBOX_BRANCH)

    def test_short_hex_6_chars_blocked_if_not_branch(self):
        """6-char hex string is not a recognized branch and is too short for SHA."""
        assert not _is_allowed_ref("abcdef", SANDBOX_BRANCH)

    def test_range_operator_double_dot(self):
        """Both sides of '..' checked."""
        assert _is_allowed_ref(f"{SANDBOX_BRANCH}..main", SANDBOX_BRANCH)
        assert not _is_allowed_ref(
            f"{OTHER_SANDBOX_BRANCH}..main", SANDBOX_BRANCH
        )

    def test_range_operator_triple_dot(self):
        """Both sides of '...' checked."""
        assert _is_allowed_ref(f"main...{SANDBOX_BRANCH}", SANDBOX_BRANCH)
        assert not _is_allowed_ref(
            f"main...{OTHER_SANDBOX_BRANCH}", SANDBOX_BRANCH
        )


# ============================================================================
# 7. Integration: Validate Branch Isolation for Various Git Commands
# ============================================================================


class TestBranchIsolationIntegration:
    """Integration tests verifying branch isolation across git subcommands."""

    def test_checkout_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["checkout", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_switch_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["switch", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_fetch_other_sandbox_refspec_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["fetch", "origin", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_push_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["push", "origin", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_log_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["log", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_show_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["show", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_diff_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["diff", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_blame_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["blame", OTHER_SANDBOX_BRANCH, "--", "file.txt"], metadata
        )
        assert result is not None

    def test_cherry_pick_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["cherry-pick", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_merge_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["merge", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_rebase_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["rebase", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_worktree_add_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["worktree", "add", "/tmp/wt", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_bisect_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["bisect", "start", OTHER_SANDBOX_BRANCH, SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_tag_creation_with_other_sandbox_commit_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["tag", "my-tag", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_notes_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["notes", "show", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_reflog_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["reflog", "show", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_archive_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["archive", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_format_patch_other_sandbox_blocked(self):
        metadata = _make_metadata()
        result = validate_branch_isolation(
            ["format-patch", OTHER_SANDBOX_BRANCH], metadata
        )
        assert result is not None

    def test_branch_listing_passthrough(self):
        """Branch listing is handled by output filtering, not input validation."""
        metadata = _make_metadata()
        result = validate_branch_isolation(["branch"], metadata)
        assert result is None, (
            "Branch listing should pass through (handled by output filtering)"
        )

    def test_ref_enum_passthrough(self):
        """Ref enum commands pass through (handled by output filtering)."""
        metadata = _make_metadata()
        for cmd in ["for-each-ref", "ls-remote", "show-ref"]:
            result = validate_branch_isolation([cmd], metadata)
            assert result is None, (
                f"{cmd} should pass through (handled by output filtering)"
            )

    def test_own_branch_operations_allowed(self):
        """All operations on own branch should be allowed."""
        metadata = _make_metadata()
        allowed_commands = [
            ["checkout", SANDBOX_BRANCH],
            ["log", SANDBOX_BRANCH],
            ["push", "origin", SANDBOX_BRANCH],
            ["diff", f"main..{SANDBOX_BRANCH}"],
            ["merge", "main"],  # merging a well-known branch
            ["rebase", "main"],
        ]
        for args in allowed_commands:
            result = validate_branch_isolation(args, metadata)
            assert result is None, (
                f"Operation {args} on own/well-known branch should be allowed"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
