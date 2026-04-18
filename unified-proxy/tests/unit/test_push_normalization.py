"""
Unit tests for push auto-expansion in git_operations.

Tests cover _normalize_push_args which auto-expands bare ``git push``
commands with the sandbox branch when the proxy has metadata.
"""

import sys
from unittest import mock

# git_operations imports mitmproxy indirectly via git_policies; ensure mocks
# are in place before import.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.flow"):
    if mod not in sys.modules:
        sys.modules[mod] = mock.MagicMock()

from git_operations import _normalize_push_args

BRANCH = "sandbox/test-branch"
META = {"sandbox_branch": BRANCH}


# ---------------------------------------------------------------------------
# Bare push → appends origin + branch
# ---------------------------------------------------------------------------


class TestBarePush:
    """git push (no remote, no refspec) → appends origin + sandbox branch."""

    def test_bare_push(self):
        args, expanded = _normalize_push_args(["push"], META)
        assert args == ["push", "origin", BRANCH]
        assert expanded is True


# ---------------------------------------------------------------------------
# Push with remote only → appends branch
# ---------------------------------------------------------------------------


class TestPushRemoteOnly:
    """git push origin (remote, no refspec) → appends sandbox branch."""

    def test_push_origin(self):
        args, expanded = _normalize_push_args(["push", "origin"], META)
        assert args == ["push", "origin", BRANCH]
        assert expanded is True

    def test_push_upstream(self):
        args, expanded = _normalize_push_args(["push", "upstream"], META)
        assert args == ["push", "upstream", BRANCH]
        assert expanded is True


# ---------------------------------------------------------------------------
# Push with flags + remote only → appends branch
# ---------------------------------------------------------------------------


class TestPushFlagsRemoteOnly:
    """git push -u origin (flags + remote, no refspec) → appends branch."""

    def test_push_u_origin(self):
        args, expanded = _normalize_push_args(["push", "-u", "origin"], META)
        assert args == ["push", "-u", "origin", BRANCH]
        assert expanded is True

    def test_push_force_origin(self):
        args, expanded = _normalize_push_args(["push", "--force", "origin"], META)
        assert args == ["push", "--force", "origin", BRANCH]
        assert expanded is True


# ---------------------------------------------------------------------------
# Push with refspec → unchanged
# ---------------------------------------------------------------------------


class TestPushWithRefspec:
    """git push origin feat → already has refspec, no expansion."""

    def test_push_origin_branch(self):
        args, expanded = _normalize_push_args(["push", "origin", "feat"], META)
        assert args == ["push", "origin", "feat"]
        assert expanded is False

    def test_push_origin_src_dst(self):
        original = ["push", "origin", f"{BRANCH}:{BRANCH}"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False


# ---------------------------------------------------------------------------
# Broad push modes → unchanged (handled by existing validation)
# ---------------------------------------------------------------------------


class TestBroadPushModes:
    """--tags, --all, --mirror should not be modified."""

    def test_push_tags_origin(self):
        original = ["push", "--tags", "origin"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False

    def test_push_all(self):
        original = ["push", "--all"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False

    def test_push_mirror(self):
        original = ["push", "--mirror"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False


# ---------------------------------------------------------------------------
# Global -c flags before push → expansion still works
# ---------------------------------------------------------------------------


class TestGlobalFlags:
    """Global -c flags before 'push' should be handled correctly."""

    def test_c_flag_bare_push(self):
        args, expanded = _normalize_push_args(["-c", "k=v", "push"], META)
        assert args == ["-c", "k=v", "push", "origin", BRANCH]
        assert expanded is True

    def test_c_flag_push_origin(self):
        args, expanded = _normalize_push_args(
            ["-c", "k=v", "push", "origin"], META
        )
        assert args == ["-c", "k=v", "push", "origin", BRANCH]
        assert expanded is True

    def test_compact_c_flag(self):
        args, expanded = _normalize_push_args(["-ck=v", "push"], META)
        assert args == ["-ck=v", "push", "origin", BRANCH]
        assert expanded is True


# ---------------------------------------------------------------------------
# No metadata / no sandbox_branch → unchanged
# ---------------------------------------------------------------------------


class TestNoMetadata:
    """Without metadata or sandbox_branch, args pass through unchanged."""

    def test_none_metadata(self):
        original = ["push"]
        args, expanded = _normalize_push_args(original, None)
        assert args is original
        assert expanded is False

    def test_empty_metadata(self):
        original = ["push"]
        args, expanded = _normalize_push_args(original, {})
        assert args is original
        assert expanded is False

    def test_no_sandbox_branch(self):
        original = ["push"]
        args, expanded = _normalize_push_args(original, {"other_key": "val"})
        assert args is original
        assert expanded is False


# ---------------------------------------------------------------------------
# Non-push command → unchanged
# ---------------------------------------------------------------------------


class TestNonPushCommand:
    """Non-push commands should never be modified."""

    def test_status(self):
        original = ["status"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False

    def test_commit(self):
        original = ["commit", "-m", "msg"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False

    def test_fetch(self):
        original = ["fetch", "origin"]
        args, expanded = _normalize_push_args(original, META)
        assert args is original
        assert expanded is False


# ---------------------------------------------------------------------------
# Original args list is not mutated
# ---------------------------------------------------------------------------


class TestNoMutation:
    """Verify the original args list is never mutated by expansion."""

    def test_bare_push_no_mutation(self):
        original = ["push"]
        original_copy = list(original)
        args, expanded = _normalize_push_args(original, META)
        assert expanded is True
        assert original == original_copy  # original unchanged
        assert args is not original  # new list returned

    def test_push_origin_no_mutation(self):
        original = ["push", "origin"]
        original_copy = list(original)
        args, expanded = _normalize_push_args(original, META)
        assert expanded is True
        assert original == original_copy
        assert args is not original
