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
import subprocess
import sys
from typing import Optional
from unittest import mock

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from addons.git_proxy import GitProxyAddon, GIT_PATH_PATTERN
from pktline import PktLineRef, ZERO_SHA


class MockContainerConfig:
    """Mock container configuration for testing."""

    def __init__(
        self,
        container_id: str = "test-container",
        repos: Optional[list] = None,
        auth_mode: str = "user",
        bare_repo_path: str = "/tmp",
    ):
        self.container_id = container_id
        self.ip_address = "172.17.0.2"
        self.metadata = {
            "repos": repos or ["owner/repo"],
            "auth_mode": auth_mode,
            "bare_repo_path": bare_repo_path,
        }


class MockResponse:
    """Mock HTTP response with status_code attribute."""

    def __init__(self, status_code: int, body: bytes = b"", headers: Optional[dict] = None):
        self.status_code = status_code
        self.content = body
        self.headers = headers or {}


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
        self.killed = False

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


@pytest.fixture(autouse=True)
def bypass_restricted_path_check(monkeypatch, request):
    """Integration tests here focus on auth/policy flow, not pack path scanning."""
    if "TestRestrictedPathIntegration" in request.node.nodeid:
        return
    monkeypatch.setattr(
        GitProxyAddon,
        "_check_restricted_paths",
        lambda self, refs, bare_repo_path, pack_data, restricted_paths: None,
    )


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
        assert not flow.killed
        assert flow.response is None

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

        # Flow should have error response (403 Forbidden)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_clone_no_container_config(self, addon):
        """Test clone passes through when no container config exists.

        Note: The git_proxy addon logs and returns early when there's no
        container config. It relies on the container_identity addon to have
        already denied the request. This test verifies that git_proxy doesn't
        crash and doesn't create a duplicate response.
        """
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

        # Addon returns early - no response set (container_identity handles it)
        # Just verify no crash and no duplicate response
        assert not flow.killed


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
        assert not flow.killed
        assert flow.response is None

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
        assert flow.response is not None
        assert flow.response.status_code == 403


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
        assert not flow.killed
        assert flow.response is None


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
        assert not flow.killed
        assert flow.response is None

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
        assert flow.response.status_code == 403

    def test_user_mode_any_branch_allowed(self, addon):
        """Test user mode allows push to non-protected branches."""
        container_config = MockContainerConfig(
            repos=["owner/repo"], auth_mode="user"
        )

        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/feature/test")
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
        assert not flow.killed
        assert flow.response is None


class TestPushSizeLimit:
    """Test push size limit enforcement."""

    def test_oversized_push_rejected(self):
        """Test push exceeding size limit is rejected."""
        # Create addon with small size limit for testing
        addon = GitProxyAddon(max_push_size=1024)  # 1KB limit

        container_config = MockContainerConfig(repos=["owner/repo"])

        # Create large content (exceeds 1KB limit)
        # Need valid pktline header first, then large payload
        refs = create_pktline_refs(
            ("0" * 40, "a" * 40, "refs/heads/feature")
        )
        large_content = refs + b"x" * 2048  # Total exceeds 1KB

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
        assert not flow.killed

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
        assert not flow.killed


class TestRestrictedPathIntegration:
    """Integration test for _check_restricted_paths using real git operations.

    Unlike the unit tests (which mock subprocess.run), this creates a real
    git repo, commits a file under .github/workflows/, generates pack data,
    and verifies _check_restricted_paths blocks it.
    """

    @pytest.fixture
    def git_env(self):
        """Clean git environment for subprocess calls."""
        return {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@test.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@test.com",
        }

    @pytest.fixture
    def bare_repo(self, tmp_path, git_env):
        """Create a bare git repo with an initial commit."""
        bare = tmp_path / "bare.git"
        work = tmp_path / "work"

        subprocess.run(
            ["git", "init", "--bare", str(bare)],
            env=git_env, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "clone", str(bare), str(work)],
            env=git_env, capture_output=True, check=True,
        )

        # Initial commit so main branch exists
        readme = work / "README.md"
        readme.write_text("init\n")
        subprocess.run(
            ["git", "add", "README.md"],
            cwd=str(work), env=git_env, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "init"],
            cwd=str(work), env=git_env, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "push", "origin", "HEAD"],
            cwd=str(work), env=git_env, capture_output=True, check=True,
        )

        return bare, work

    def test_restricted_path_blocks_workflow_push(self, bare_repo, git_env):
        """A push containing .github/workflows/ changes must be blocked."""
        bare, work = bare_repo

        # Get current HEAD sha (will be old_sha)
        old_sha_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(work), env=git_env, capture_output=True, text=True, check=True,
        )
        old_sha = old_sha_result.stdout.strip()

        # Commit a workflow file
        wf_dir = work / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "evil.yml").write_text("name: evil\n")
        subprocess.run(
            ["git", "add", ".github/workflows/evil.yml"],
            cwd=str(work), env=git_env, capture_output=True, check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "add workflow"],
            cwd=str(work), env=git_env, capture_output=True, check=True,
        )

        new_sha_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(work), env=git_env, capture_output=True, text=True, check=True,
        )
        new_sha = new_sha_result.stdout.strip()

        # Generate pack data: git pack-objects of the new commit
        pack_result = subprocess.run(
            ["git", "pack-objects", "--stdout", "--revs"],
            input=f"{new_sha}\n^{old_sha}\n".encode(),
            cwd=str(work), env=git_env, capture_output=True, check=True,
        )
        pack_data = pack_result.stdout

        # Build the ref update
        refs = [PktLineRef(old_sha=old_sha, new_sha=new_sha, refname="refs/heads/main")]

        addon = GitProxyAddon()
        result = addon._check_restricted_paths(
            refs=refs,
            bare_repo_path=str(bare),
            pack_data=pack_data,
            restricted_paths=[".github/workflows", ".github/actions"],
        )

        assert result is not None, (
            "_check_restricted_paths should block push with .github/workflows/ changes"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
