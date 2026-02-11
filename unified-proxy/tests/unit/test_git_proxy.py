"""Unit tests for the git proxy addon.

Tests repo authorization, bot mode restrictions, and related git proxy
policy enforcement logic.
"""

import pytest

from addons.git_proxy import (
    GitProxyAddon,
    GitOperation,
    ALLOWED_MARKETPLACES,
    SANDBOX_BRANCH_PATTERN,
    DEFAULT_MAX_PUSH_SIZE,
)
from pktline import PktLineRef


class TestRepoAuthorization:
    def test_allowed_repo_passes(self):
        addon = GitProxyAddon()
        op = GitOperation(owner="org", repo="myrepo", operation="info/refs",
                         is_write=False, refs=[])
        assert addon._is_repo_authorized(op, ["org/myrepo"]) is True

    def test_disallowed_repo_fails(self):
        addon = GitProxyAddon()
        op = GitOperation(owner="org", repo="secret", operation="info/refs",
                         is_write=False, refs=[])
        assert addon._is_repo_authorized(op, ["org/myrepo"]) is False

    def test_marketplace_repo_allowed_for_read(self):
        addon = GitProxyAddon()
        op = GitOperation(owner="anthropics", repo="claude-plugins-official",
                         operation="git-upload-pack", is_write=False, refs=[])
        assert addon._is_repo_authorized(op, []) is True

    def test_marketplace_repo_blocked_for_write(self):
        addon = GitProxyAddon()
        op = GitOperation(owner="anthropics", repo="claude-plugins-official",
                         operation="git-receive-pack", is_write=True, refs=[])
        assert addon._is_repo_authorized(op, []) is False


class TestBotModeRestrictions:
    def test_sandbox_branch_allowed(self):
        addon = GitProxyAddon()
        op = GitOperation(owner="o", repo="r", operation="git-receive-pack",
                         is_write=True, refs=[PktLineRef(
                             old_sha="0"*40, new_sha="a"*40,
                             refname="refs/heads/sandbox/my-feature")])
        assert addon._check_bot_mode_restrictions(op) is None

    def test_non_sandbox_branch_blocked(self):
        addon = GitProxyAddon()
        op = GitOperation(owner="o", repo="r", operation="git-receive-pack",
                         is_write=True, refs=[PktLineRef(
                             old_sha="0"*40, new_sha="a"*40,
                             refname="refs/heads/main")])
        result = addon._check_bot_mode_restrictions(op)
        assert result is not None
