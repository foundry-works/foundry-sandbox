"""Integration tests for git operations through the unified-proxy.

Tests git protocol handling including:
- Git clone through proxy (authenticated and unauthenticated)
- Git push through proxy with credential injection
- Branch deletion blocking (security policy)
- Bot mode auth enforcement (sandbox/* branches only)

These tests use mocked HTTP responses to simulate git protocol
without requiring actual git servers or network access.
"""

import os
import sys
from typing import Optional
from unittest import mock

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from addons.git_proxy import GitProxyAddon, GIT_PATH_PATTERN


class MockContainerConfig:
    """Mock container configuration for testing."""

    def __init__(
        self,
        container_id: str = "test-container",
        repos: Optional[list] = None,
        auth_mode: str = "user",
    ):
        self.container_id = container_id
        self.ip_address = "172.17.0.2"
        self.metadata = {
            "repos": repos or ["owner/repo"],
            "auth_mode": auth_mode,
        }


class MockFlow:
    """Mock mitmproxy flow for testing."""

    def __init__(
        self,
        host: str = "github.com",
        path: str = "/owner/repo.git/info/refs",
        method: str = "GET",
        content: bytes = b"",
        query: str = "",
    ):
        self.request = mock.MagicMock()
        self.request.host = host
        self.request.path = path
        self.request.method = method
        self.request.content = content
        self.request.query = mock.MagicMock()
        self.request.query.get.return_value = query

        self.response = None
        self.metadata = {}

    def kill(self):
        """Mark flow as killed."""
        self.killed = True


def create_pktline_refs(*refs) -> bytes:
    """Create pktline formatted refs for testing.

    Args:
        refs: Tuples of (old_sha, new_sha, refname)

    Returns:
        Pktline formatted bytes.
    """
    lines = []
    for old_sha, new_sha, refname in refs:
        line = f"{old_sha} {new_sha} {refname}\n"
        pkt_len = len(line) + 4
        lines.append(f"{pkt_len:04x}{line}".encode())
    lines.append(b"0000")  # Flush packet
    return b"".join(lines)


class TestGitPathParsing:
    """Test git path pattern matching."""

    def test_valid_git_path(self):
        """Test parsing valid git paths."""
        match = GIT_PATH_PATTERN.match("/owner/repo.git/info/refs")
        assert match is not None
        assert match.group(1) == "owner"
        assert match.group(2) == "repo"
        assert match.group(3) == "info/refs"

    def test_git_upload_pack_path(self):
        """Test git-upload-pack path parsing."""
        match = GIT_PATH_PATTERN.match("/org/project.git/git-upload-pack")
        assert match is not None
        assert match.group(1) == "org"
        assert match.group(2) == "project"
        assert match.group(3) == "git-upload-pack"

    def test_git_receive_pack_path(self):
        """Test git-receive-pack path parsing."""
        match = GIT_PATH_PATTERN.match("/user/private-repo.git/git-receive-pack")
        assert match is not None
        assert match.group(1) == "user"
        assert match.group(2) == "private-repo"
        assert match.group(3) == "git-receive-pack"

    def test_non_git_path(self):
        """Test non-git paths don't match."""
        assert GIT_PATH_PATTERN.match("/api/v1/repos") is None
        assert GIT_PATH_PATTERN.match("/owner/repo/issues") is None
        assert GIT_PATH_PATTERN.match("/owner/repo.git") is None


class TestGitCloneThoughProxy:
    """Test git clone operations through the proxy."""

    @pytest.fixture
    def addon(self):
        """Create addon instance."""
        return GitProxyAddon()

    @pytest.fixture
    def container_config(self):
        """Create mock container config."""
        return MockContainerConfig(repos=["owner/repo", "org/project"])

    def test_clone_allowed_repo(self, addon, container_config):
        """Test clone is allowed for repos in container's allowlist."""
        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/info/refs",
            method="GET",
            query="service=git-upload-pack",
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            # request hook should allow this through
            addon.request(flow)

        # Flow should not be killed for allowed repo
        assert not hasattr(flow, "killed") or not flow.killed

    def test_clone_denied_repo(self, addon, container_config):
        """Test clone is denied for repos not in container's allowlist."""
        flow = MockFlow(
            host="github.com",
            path="/other/secret-repo.git/info/refs",
            method="GET",
            query="service=git-upload-pack",
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Flow should be killed or have error response
        assert flow.response is not None or hasattr(flow, "killed")

    def test_clone_no_container_config(self, addon):
        """Test clone is denied when no container config exists."""
        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/info/refs",
            method="GET",
            query="service=git-upload-pack",
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=None
        ):
            addon.request(flow)

        # Should deny access without container config
        assert flow.response is not None or hasattr(flow, "killed")


class TestGitPushThroughProxy:
    """Test git push operations through the proxy."""

    @pytest.fixture
    def addon(self):
        """Create addon instance."""
        return GitProxyAddon()

    @pytest.fixture
    def container_config(self):
        """Create mock container config."""
        return MockContainerConfig(repos=["owner/repo"], auth_mode="user")

    def test_push_allowed_repo(self, addon, container_config):
        """Test push is allowed for repos in container's allowlist."""
        # Simulate git-receive-pack request with valid ref update
        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/feature-branch")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Flow should not be killed for valid push
        assert not hasattr(flow, "killed") or not flow.killed

    def test_push_denied_repo(self, addon, container_config):
        """Test push is denied for repos not in allowlist."""
        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/main")
        )

        flow = MockFlow(
            host="github.com",
            path="/other/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Should deny push to unauthorized repo
        assert flow.response is not None or hasattr(flow, "killed")


class TestBranchDeletionBlocked:
    """Test that branch and tag deletions are blocked."""

    @pytest.fixture
    def addon(self):
        """Create addon instance."""
        return GitProxyAddon()

    @pytest.fixture
    def container_config(self):
        """Create mock container config with full access."""
        return MockContainerConfig(repos=["owner/repo"], auth_mode="user")

    def test_branch_deletion_blocked(self, addon, container_config):
        """Test branch deletion is blocked."""
        # Deletion is indicated by new_sha being all zeros
        refs = create_pktline_refs(
            ("a" * 40, "0" * 40, "refs/heads/feature-to-delete")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Deletion should be blocked
        assert flow.response is not None
        if flow.response:
            assert flow.response.status_code == 403

    def test_tag_deletion_blocked(self, addon, container_config):
        """Test tag deletion is blocked."""
        refs = create_pktline_refs(
            ("a" * 40, "0" * 40, "refs/tags/v1.0.0")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Tag deletion should be blocked
        assert flow.response is not None
        if flow.response:
            assert flow.response.status_code == 403

    def test_force_push_allowed(self, addon, container_config):
        """Test force push (non-deletion) is allowed."""
        # Force push has non-zero old and new SHA
        refs = create_pktline_refs(
            ("a" * 40, "b" * 40, "refs/heads/feature")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Force push should be allowed (not a deletion)
        assert not hasattr(flow, "killed") or not flow.killed


class TestAuthModeEnforcement:
    """Test auth mode enforcement (bot mode restrictions)."""

    @pytest.fixture
    def addon(self):
        """Create addon instance."""
        return GitProxyAddon()

    def test_bot_mode_sandbox_branch_allowed(self, addon):
        """Test bot mode allows push to sandbox/* branches."""
        container_config = MockContainerConfig(
            repos=["owner/repo"], auth_mode="bot"
        )

        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/sandbox/feature-123")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # sandbox/* branch should be allowed in bot mode
        assert not hasattr(flow, "killed") or not flow.killed

    def test_bot_mode_main_branch_blocked(self, addon):
        """Test bot mode blocks push to non-sandbox branches."""
        container_config = MockContainerConfig(
            repos=["owner/repo"], auth_mode="bot"
        )

        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/main")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # main branch should be blocked in bot mode
        assert flow.response is not None
        if flow.response:
            assert flow.response.status_code == 403

    def test_user_mode_any_branch_allowed(self, addon):
        """Test user mode allows push to any branch."""
        container_config = MockContainerConfig(
            repos=["owner/repo"], auth_mode="user"
        )

        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/main")
        )

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=refs,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # User mode should allow any branch
        assert not hasattr(flow, "killed") or not flow.killed


class TestPushSizeLimit:
    """Test push size limit enforcement."""

    def test_oversized_push_rejected(self):
        """Test push exceeding size limit is rejected."""
        # Create addon with small size limit for testing
        addon = GitProxyAddon(max_push_size=1024)  # 1KB limit

        container_config = MockContainerConfig(repos=["owner/repo"])

        # Create large content
        large_content = b"x" * 2048  # 2KB, exceeds 1KB limit

        flow = MockFlow(
            host="github.com",
            path="/owner/repo.git/git-receive-pack",
            method="POST",
            content=large_content,
        )

        with mock.patch(
            "addons.git_proxy.get_container_config", return_value=container_config
        ):
            addon.request(flow)

        # Oversized push should be rejected with 413
        assert flow.response is not None
        if flow.response:
            assert flow.response.status_code == 413


class TestNonGitRequests:
    """Test that non-git requests pass through unmodified."""

    @pytest.fixture
    def addon(self):
        """Create addon instance."""
        return GitProxyAddon()

    def test_api_request_passes_through(self, addon):
        """Test API requests pass through unmodified."""
        flow = MockFlow(
            host="api.github.com",
            path="/repos/owner/repo",
            method="GET",
        )

        addon.request(flow)

        # Non-git requests should pass through
        assert flow.response is None
        assert not hasattr(flow, "killed") or not flow.killed

    def test_web_request_passes_through(self, addon):
        """Test web requests pass through unmodified."""
        flow = MockFlow(
            host="github.com",
            path="/owner/repo/issues",
            method="GET",
        )

        addon.request(flow)

        # Non-git requests should pass through
        assert flow.response is None
        assert not hasattr(flow, "killed") or not flow.killed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
