"""Unit tests for git proxy mitmproxy addon.

Tests the GitProxyAddon class which handles git protocol operations with
policy enforcement including repo authorization, deletion blocking, bot mode
restrictions, and push size limits.

Note: These tests use mock objects for mitmproxy types since mitmproxy_rs
cannot be loaded in sandboxed environments. The mocking approach ensures
we test the actual business logic without requiring the full mitmproxy runtime.
"""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Add unified-proxy to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))


# Mock mitmproxy before importing git_proxy
class MockHeaders(dict):
    """Mock mitmproxy Headers class."""

    def get(self, key, default=None):
        return super().get(key, default)


class MockRequest:
    """Mock mitmproxy Request class."""

    def __init__(self, path="/", method="GET", content=None, headers=None):
        self.path = path
        self.method = method
        self.content = content
        self.headers = MockHeaders(headers or {})
        self.pretty_host = "github.com"


class MockResponse:
    """Mock mitmproxy Response class."""

    def __init__(self, status_code, content, headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}

    @classmethod
    def make(cls, status_code, content, headers=None):
        return cls(status_code, content, headers)


class MockClientConn:
    """Mock mitmproxy client connection."""

    def __init__(self, peername):
        self.peername = peername


class MockHTTPFlow:
    """Mock mitmproxy HTTPFlow class."""

    def __init__(self, source_ip, path="/", method="GET", content=None, headers=None):
        if source_ip is None:
            self.client_conn = MockClientConn(None)
        else:
            self.client_conn = MockClientConn((source_ip, 12345))
        self.request = MockRequest(path, method, content, headers)
        self.response = None
        self.metadata = {}


class MockCtxLog:
    """Mock mitmproxy ctx.log with proper tracking."""

    def __init__(self):
        self.calls = []

    def info(self, msg):
        self.calls.append(("info", msg))

    def warn(self, msg):
        self.calls.append(("warn", msg))

    def debug(self, msg):
        self.calls.append(("debug", msg))

    def error(self, msg):
        self.calls.append(("error", msg))

    def reset(self):
        self.calls.clear()

    def was_called_with_level(self, level):
        return any(call[0] == level for call in self.calls)

    def get_messages(self, level=None):
        if level:
            return [call[1] for call in self.calls if call[0] == level]
        return [call[1] for call in self.calls]


class MockCtx:
    """Mock mitmproxy ctx module."""

    def __init__(self):
        self.log = MockCtxLog()


# Create mock modules BEFORE any mitmproxy import
mock_mitmproxy = MagicMock()

# Create http mock with our Response class
mock_http = MagicMock()
mock_http.Response = MockResponse
mock_http.HTTPFlow = MockHTTPFlow

# Create ctx mock
mock_ctx = MockCtx()

# Create flow mock
mock_flow = MagicMock()
mock_flow.Flow = MockHTTPFlow

# Install mocks into sys.modules BEFORE importing git_proxy
sys.modules["mitmproxy"] = mock_mitmproxy
sys.modules["mitmproxy.http"] = mock_http
sys.modules["mitmproxy.ctx"] = mock_ctx
sys.modules["mitmproxy.flow"] = mock_flow

# Add addons path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))

# Import git_proxy - it will use our mocked mitmproxy
import git_proxy

# Ensure the module uses our mock ctx
git_proxy.ctx = mock_ctx
git_proxy.http = mock_http

# Import pktline for creating test data
from pktline import ZERO_SHA

# Import registry for creating container configs
from registry import ContainerConfig


# Constants from the module
GIT_METADATA_KEY = "git_operation"


@pytest.fixture(autouse=True)
def reset_mock_ctx():
    """Reset mock ctx before each test.

    Uses git_proxy.ctx (not local mock_ctx) to handle cross-file mock
    interference when pytest runs multiple test files in the same process.
    """
    git_proxy.ctx = mock_ctx
    mock_ctx.log.reset()
    yield


def create_container_config(
    container_id="test-container",
    ip_address="172.17.0.2",
    repos=None,
    auth_mode="normal",
    **kwargs,
):
    """Create a ContainerConfig with given repos and auth_mode in metadata."""
    import time

    metadata = {"repos": repos or [], "auth_mode": auth_mode}
    metadata.update(kwargs)

    return ContainerConfig(
        container_id=container_id,
        ip_address=ip_address,
        registered_at=time.time(),
        last_seen=time.time(),
        ttl_seconds=86400,
        metadata=metadata,
    )


def create_pktline_data(refs):
    """Create pkt-line data for a push operation.

    Args:
        refs: List of (old_sha, new_sha, refname) tuples.

    Returns:
        bytes: Encoded pkt-line data with flush packet.
    """
    data = b""
    for i, (old_sha, new_sha, refname) in enumerate(refs):
        # First ref includes capabilities
        caps = "report-status" if i == 0 else ""
        if caps:
            content = f"{old_sha} {new_sha} {refname}\0{caps}\n"
        else:
            content = f"{old_sha} {new_sha} {refname}\n"
        length = len(content) + 4
        data += f"{length:04x}".encode() + content.encode()
    data += b"0000"  # Flush packet
    return data


def create_git_flow(
    path,
    method="GET",
    content=None,
    container_config=None,
):
    """Create a mock git flow with optional container config."""
    flow = MockHTTPFlow("172.17.0.2", path, method, content)
    if container_config:
        flow.metadata["container_config"] = container_config
    return flow


class TestGitRequestIdentification:
    """Tests for git request path pattern matching."""

    def test_identifies_info_refs(self):
        """Test that info/refs path is identified as git request."""
        addon = git_proxy.GitProxyAddon()
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs",
            container_config=create_container_config(repos=["octocat/hello-world"]),
        )

        addon.request(flow)

        # Should have git operation metadata
        assert GIT_METADATA_KEY in flow.metadata
        assert flow.metadata[GIT_METADATA_KEY]["owner"] == "octocat"
        assert flow.metadata[GIT_METADATA_KEY]["repo"] == "hello-world"
        assert flow.metadata[GIT_METADATA_KEY]["operation"] == "info/refs"

    def test_identifies_git_upload_pack(self):
        """Test that git-upload-pack path is identified."""
        addon = git_proxy.GitProxyAddon()
        flow = create_git_flow(
            "/anthropic/claude.git/git-upload-pack",
            container_config=create_container_config(repos=["anthropic/claude"]),
        )

        addon.request(flow)

        assert GIT_METADATA_KEY in flow.metadata
        assert flow.metadata[GIT_METADATA_KEY]["operation"] == "git-upload-pack"

    def test_non_git_path_passes_through(self):
        """Test that non-git paths are not processed."""
        addon = git_proxy.GitProxyAddon()
        flow = MockHTTPFlow("172.17.0.2", "/api/v1/users")

        addon.request(flow)

        # Should not have git operation metadata
        assert GIT_METADATA_KEY not in flow.metadata
        # And no response set
        assert flow.response is None


class TestRepoAuthorization:
    """Tests for repository authorization."""

    def test_clone_authorized_repo_succeeds(self):
        """Test that cloning an authorized repo succeeds."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world", "anthropic/claude"]
        )
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs",
            container_config=container,
        )

        addon.request(flow)

        # No response means request proceeds
        assert flow.response is None

    def test_clone_unauthorized_repo_returns_403(self):
        """Test that cloning an unauthorized repo returns 403."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["anthropic/claude"])
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs",
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"not authorized" in flow.response.content.lower()

    def test_empty_repos_denies_all(self):
        """Test that empty repos list denies all access (default deny)."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=[])
        flow = create_git_flow(
            "/any/repo.git/info/refs",
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_no_container_config_logs_warning(self):
        """Test that request without container config logs warning."""
        addon = git_proxy.GitProxyAddon()
        flow = create_git_flow("/octocat/hello-world.git/info/refs")
        # No container_config set

        addon.request(flow)

        # Should log warning but not set response (container_identity should have denied)
        assert mock_ctx.log.was_called_with_level("warn")


class TestBranchDeletionBlocking:
    """Tests for branch/tag deletion blocking."""

    def test_branch_deletion_returns_403(self):
        """Test that push with branch deletion returns 403."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        # Create push with deletion (new_sha = ZERO_SHA)
        refs = [("a" * 40, ZERO_SHA, "refs/heads/old-branch")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"deletion" in flow.response.content.lower()

    def test_tag_deletion_returns_403(self):
        """Test that push with tag deletion returns 403."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        refs = [("a" * 40, ZERO_SHA, "refs/tags/v1.0.0")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_normal_push_succeeds(self):
        """Test that normal push (update) succeeds."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        refs = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # No response means success
        assert flow.response is None

    def test_branch_creation_succeeds(self):
        """Test that branch creation succeeds."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        refs = [(ZERO_SHA, "b" * 40, "refs/heads/new-feature")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is None


class TestBotModeRestrictions:
    """Tests for bot mode push restrictions."""

    def test_bot_mode_push_to_main_returns_403(self):
        """Test that bot mode push to main branch returns 403.

        Note: Protected branch enforcement runs before bot mode restrictions,
        so the error message references protected branches rather than bot mode.
        """
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            auth_mode="bot",
        )

        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"protected branch" in flow.response.content.lower()

    def test_bot_mode_push_to_feature_returns_403(self):
        """Test that bot mode push to feature branch returns 403."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            auth_mode="bot",
        )

        refs = [("a" * 40, "b" * 40, "refs/heads/feature/cool-thing")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_bot_mode_push_to_sandbox_succeeds(self):
        """Test that bot mode push to sandbox/* branch succeeds."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            auth_mode="bot",
        )

        refs = [("a" * 40, "b" * 40, "refs/heads/sandbox/test-branch")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # No response means success
        assert flow.response is None

    def test_bot_mode_push_to_nested_sandbox_succeeds(self):
        """Test that bot mode push to sandbox/user/feature succeeds."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            auth_mode="bot",
        )

        refs = [("a" * 40, "b" * 40, "refs/heads/sandbox/user/feature")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is None

    def test_normal_mode_push_to_feature_succeeds(self):
        """Test that normal mode push to feature branch succeeds."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            auth_mode="normal",
        )

        refs = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is None


class TestPushSizeLimits:
    """Tests for push size limit enforcement."""

    def test_push_size_limit_returns_413(self):
        """Test that push exceeding size limit returns 413."""
        # Create addon with small limit for testing
        addon = git_proxy.GitProxyAddon(max_push_size=100)
        container = create_container_config(repos=["octocat/hello-world"])

        # Create content larger than limit
        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        content = create_pktline_data(refs)
        # Add padding to exceed limit
        content += b"x" * 200

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 413
        assert b"too large" in flow.response.content.lower()

    def test_push_within_limit_succeeds(self):
        """Test that push within size limit succeeds."""
        addon = git_proxy.GitProxyAddon(max_push_size=10000)
        container = create_container_config(repos=["octocat/hello-world"])

        refs = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is None


class TestLogging:
    """Tests for git operation logging."""

    def test_allowed_operation_logs_info(self):
        """Test that allowed operations are logged at info level."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs",
            container_config=container,
        )

        addon.request(flow)

        assert mock_ctx.log.was_called_with_level("info")
        messages = mock_ctx.log.get_messages("info")
        assert any("ALLOW" in msg for msg in messages)

    def test_denied_operation_logs_warn(self):
        """Test that denied operations are logged at warn level."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=[])  # Empty = denied
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs",
            container_config=container,
        )

        addon.request(flow)

        assert mock_ctx.log.was_called_with_level("warn")
        messages = mock_ctx.log.get_messages("warn")
        assert any("DENY" in msg for msg in messages)

    def test_push_logs_include_refs(self):
        """Test that push operation logs include ref information."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        content = create_pktline_data(refs)

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Check metadata has ref info
        git_op = flow.metadata.get(GIT_METADATA_KEY, {})
        assert git_op.get("refs") is not None
        assert len(git_op.get("refs", [])) == 1
        assert git_op["refs"][0]["refname"] == "refs/heads/main"


class TestHelperFunction:
    """Tests for the get_git_operation helper function."""

    def test_get_git_operation_returns_info(self):
        """Test that get_git_operation returns git operation info."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs",
            container_config=container,
        )

        addon.request(flow)

        git_op = git_proxy.get_git_operation(flow)
        assert git_op is not None
        assert git_op["owner"] == "octocat"
        assert git_op["repo"] == "hello-world"

    def test_get_git_operation_returns_none_for_non_git(self):
        """Test that get_git_operation returns None for non-git flows."""
        flow = MockHTTPFlow("172.17.0.2", "/api/users")

        git_op = git_proxy.get_git_operation(flow)
        assert git_op is None


class TestQueryStringHandling:
    """Tests for query string handling in git paths."""

    def test_info_refs_with_query_string(self):
        """Test that info/refs with service query string works."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        flow = create_git_flow(
            "/octocat/hello-world.git/info/refs?service=git-upload-pack",
            container_config=container,
        )

        addon.request(flow)

        assert GIT_METADATA_KEY in flow.metadata
        assert flow.metadata[GIT_METADATA_KEY]["operation"] == "info/refs"
        assert flow.response is None


class TestProtectedBranchEnforcement:
    """Tests for protected branch enforcement via git_policies.py."""

    def test_push_update_to_main_blocked(self):
        """Test that push update to refs/heads/main is blocked."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"protected branch" in flow.response.content.lower()

    def test_push_update_to_feature_allowed(self):
        """Test that push update to refs/heads/feature-x is allowed."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        refs = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is None

    def test_push_update_to_release_wildcard_blocked(self):
        """Test that push update to refs/heads/release/v2.0 is blocked (wildcard)."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        refs = [("a" * 40, "b" * 40, "refs/heads/release/v2.0")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_custom_protected_branch_from_metadata_blocked(self):
        """Test that custom protected branch from metadata is blocked."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            git={"protected_branches": {"patterns": ["refs/heads/staging"]}},
        )
        refs = [("a" * 40, "b" * 40, "refs/heads/staging")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_branch_creation_protected_blocked(self):
        """Test that branch creation on protected branch is blocked (no bootstrap)."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        refs = [(ZERO_SHA, "b" * 40, "refs/heads/master")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"creation" in flow.response.content.lower()

    def test_bootstrap_creation_succeeds_then_blocked(self):
        """Test bootstrap creation to refs/heads/main succeeds once then blocked."""
        import tempfile
        addon = git_proxy.GitProxyAddon()

        with tempfile.TemporaryDirectory() as tmpdir:
            container = create_container_config(
                repos=["octocat/hello-world"],
                git={"protected_branches": {"bare_repo_path": tmpdir}},
            )
            # Note: bare_repo_path is not passed through git_proxy flow metadata,
            # so bootstrap requires the git_policies module directly.
            # Test the module directly for bootstrap lock behavior.
            from git_policies import check_protected_branches

            # First creation succeeds
            result = check_protected_branches(
                "refs/heads/main", ZERO_SHA, "b" * 40, bare_repo_path=tmpdir,
            )
            assert result is None

            # Second creation blocked
            result = check_protected_branches(
                "refs/heads/main", ZERO_SHA, "c" * 40, bare_repo_path=tmpdir,
            )
            assert result is not None
            assert "bootstrap already completed" in result

    def test_branch_deletion_main_blocked(self):
        """Test that branch deletion of refs/heads/main is blocked."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])
        refs = [("a" * 40, ZERO_SHA, "refs/heads/main")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403
        # Blocked by deletion check (runs before protected branch check)
        assert b"deletion" in flow.response.content.lower()

    def test_disabled_enforcement_allows_push_to_main(self):
        """Test that enabled:false disables protected branch enforcement."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            git={"protected_branches": {"enabled": False}},
        )
        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is None

    def test_default_enabled_for_normal_mode(self):
        """Test that protected branches are enabled by default in normal mode."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            auth_mode="normal",
        )
        refs = [("a" * 40, "b" * 40, "refs/heads/production")]
        content = create_pktline_data(refs)
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST", content=content, container_config=container,
        )
        addon.request(flow)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_lock_file_permanent_no_orphan_cleanup(self):
        """Test that lock file is permanent (no automatic orphan cleanup)."""
        import os
        import tempfile
        from git_policies import check_protected_branches

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create bootstrap lock
            result = check_protected_branches(
                "refs/heads/main", ZERO_SHA, "b" * 40, bare_repo_path=tmpdir,
            )
            assert result is None

            lock_path = os.path.join(tmpdir, "foundry-bootstrap.lock")
            assert os.path.exists(lock_path)

            # Lock persists - subsequent attempts always blocked
            for _ in range(3):
                result = check_protected_branches(
                    "refs/heads/main", ZERO_SHA, "c" * 40, bare_repo_path=tmpdir,
                )
                assert result is not None
            assert os.path.exists(lock_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
