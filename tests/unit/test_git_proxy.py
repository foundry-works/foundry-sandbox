"""Unit tests for git proxy mitmproxy addon.

Tests the GitProxyAddon class which handles git protocol operations with
policy enforcement including repo authorization, deletion blocking, bot mode
restrictions, and push size limits.

Note: These tests use mock objects for mitmproxy types since mitmproxy_rs
cannot be loaded in sandboxed environments. The mocking approach ensures
we test the actual business logic without requiring the full mitmproxy runtime.
"""

import os
import shutil
import sys
from unittest.mock import MagicMock

import pytest

# Add unified-proxy to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))


# Mock mitmproxy before importing git_proxy
from tests.mocks import (
    MockHeaders, MockResponse, MockClientConn, MockCtxLog,
)


class MockRequest:
    """Mock mitmproxy Request class."""

    def __init__(self, path="/", method="GET", content=None, headers=None):
        self.path = path
        self.method = method
        self.content = content
        self.headers = MockHeaders(headers or {})
        self.pretty_host = "github.com"


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


# Create test-specific mock objects for git_proxy tests.
# NOTE: We do NOT overwrite sys.modules["mitmproxy"] here because conftest.py
# already installs proper mitmproxy mocks. Overwriting the top-level module
# entry would pollute the global module cache and break other test files
# that import mitmproxy-based addons later in the session.
mock_http = MagicMock()
mock_http.Response = MockResponse
mock_http.HTTPFlow = MockHTTPFlow

mock_logger = MockCtxLog()

# Add addons path and import git_proxy (uses conftest mitmproxy mocks)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))
import git_proxy

# Replace the module-level mitmproxy references with our test-specific mocks
git_proxy.logger = mock_logger
git_proxy.http = mock_http

# Import pktline for creating test data
from pktline import ZERO_SHA

# Import registry for creating container configs
from registry import ContainerConfig


# Constants from the module
GIT_METADATA_KEY = "git_operation"
@pytest.fixture(autouse=True)
def reset_mock_ctx():
    """Reset mock logger before each test.

    Uses git_proxy.logger (not local mock_logger) to handle cross-file mock
    interference when pytest runs multiple test files in the same process.
    """
    git_proxy.logger = mock_logger
    yield


@pytest.fixture(autouse=True)
def bypass_restricted_path_check_for_non_restricted_tests(monkeypatch, request, tmp_path):
    """Stub restricted-path enforcement outside TestRestrictedPathsCheck.

    Most unit tests in this module target auth/branch/size behavior and are not
    exercising pack/diff subprocess logic. Keep those tests focused while the
    dedicated restricted-path test class validates _check_restricted_paths().
    """
    if "TestRestrictedPathsCheck" in request.node.nodeid:
        return
    monkeypatch.setattr(
        git_proxy.GitProxyAddon,
        "_check_restricted_paths",
        lambda self, refs, bare_repo_path, pack_data, restricted_paths: None,
    )


DEFAULT_TEST_BARE_REPO = None  # Set per-test via _test_bare_repo fixture


@pytest.fixture(autouse=True)
def _test_bare_repo(tmp_path, request):
    """Provide a per-test bare repo directory using pytest's tmp_path.

    Avoids side effects from writing to /tmp/foundry-test-bare.git which
    persists across test runs and could leak into other tests.
    """
    global DEFAULT_TEST_BARE_REPO
    if "TestRestrictedPathsCheck" in request.node.nodeid:
        yield  # TestRestrictedPathsCheck manages its own paths
        return
    bare = str(tmp_path / "foundry-test-bare.git")
    os.makedirs(bare, exist_ok=True)
    DEFAULT_TEST_BARE_REPO = bare
    yield
    DEFAULT_TEST_BARE_REPO = None


def create_container_config(
    container_id="test-container",
    ip_address="172.17.0.2",
    repos=None,
    auth_mode="normal",
    bare_repo_path="__default__",
    **kwargs,
):
    """Create a ContainerConfig with given repos and auth_mode in metadata."""
    import time

    if bare_repo_path == "__default__":
        bare_repo_path = DEFAULT_TEST_BARE_REPO

    metadata = {"repos": repos or [], "auth_mode": auth_mode}
    if bare_repo_path is not None:
        metadata["bare_repo_path"] = bare_repo_path
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
        assert mock_logger.was_called_with_level("warn")


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


class TestMalformedPushPayload:
    """Tests that malformed push payloads fail closed."""

    def test_invalid_pktline_header_is_denied(self):
        """Non-hex pkt-line prefix should be denied."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=b"XXXXnot-a-pktline",
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"malformed git push payload" in flow.response.content.lower()

    def test_push_without_ref_updates_is_denied(self):
        """Pkt-line stream with no ref updates should be denied."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["octocat/hello-world"])

        # Valid pkt-line framing + flush, but payload is not a ref-update line.
        # parse_pktline() should return no refs.
        content = b"0008NAK\n0000"
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"malformed git push payload" in flow.response.content.lower()


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

        assert mock_logger.was_called_with_level("info")
        messages = mock_logger.get_messages("info")
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

        assert mock_logger.was_called_with_level("warn")
        messages = mock_logger.get_messages("warn")
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
        git_proxy.GitProxyAddon()

        with tempfile.TemporaryDirectory() as tmpdir:
            create_container_config(
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


class TestRestrictedPathsCheck:
    """Tests for restricted file path blocking on pushes.

    These tests verify _check_restricted_paths() which inspects pack data
    to block pushes modifying .github/workflows/ or .github/actions/.
    Tests mock subprocess.run since the method shells out to git.
    """

    def _make_addon_and_flow(
        self, refs_data, bare_repo_path="/fake/bare", include_pack_data=True
    ):
        """Create addon + flow with container metadata including bare_repo_path."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["octocat/hello-world"],
            bare_repo_path=bare_repo_path,
        )
        content = create_pktline_data(refs_data)
        if include_pack_data:
            # Append fake pack data so pack_data is non-empty
            content += b"PACK" + b"\x00" * 20
        flow = create_git_flow(
            "/octocat/hello-world.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )
        return addon, flow

    def _mock_subprocess_success(self, diff_output="src/main.py\n"):
        """Return a side_effect function for subprocess.run that simulates success.

        git init -> success, git unpack-objects -> success, git diff-tree -> diff_output.
        """
        def side_effect(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = b""
            result.stderr = b""
            if "diff-tree" in cmd:
                result.stdout = diff_output.encode()
            return result

        return side_effect

    def _mock_subprocess_with_diff(self, diff_output):
        """Return a side_effect that returns specific diff-tree output."""
        return self._mock_subprocess_success(diff_output)

    @pytest.fixture(autouse=True)
    def _patch_fs(self, monkeypatch, tmp_path):
        """Patch filesystem operations used by _check_restricted_paths."""
        self._tmp_dir = str(tmp_path / "git-restricted-check-test")
        os.makedirs(self._tmp_dir, exist_ok=True)
        # Create objects/info dir so the code can write alternates
        os.makedirs(os.path.join(self._tmp_dir, "objects", "info"), exist_ok=True)

        # Patch at the module where it's imported, not the global tempfile.
        # This is robust against import style changes in git_proxy.py.
        monkeypatch.setattr(
            "git_proxy.tempfile.mkdtemp",
            lambda prefix="": self._tmp_dir,
        )
        # Patch shutil.rmtree to track cleanup calls
        self._rmtree_calls = []
        original_rmtree = shutil.rmtree

        def tracking_rmtree(path, **kwargs):
            self._rmtree_calls.append(path)
            # Actually clean up
            if os.path.isdir(path):
                original_rmtree(path, **kwargs)

        monkeypatch.setattr("shutil.rmtree", tracking_rmtree)

    def test_blocked_push_workflow_file(self, monkeypatch):
        """Push containing .github/workflows/ci.yml change is blocked."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        monkeypatch.setattr(
            "subprocess.run",
            self._mock_subprocess_with_diff(".github/workflows/ci.yml\n"),
        )
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_blocked_push_actions_file(self, monkeypatch):
        """Push containing .github/actions/custom/action.yml change is blocked."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        monkeypatch.setattr(
            "subprocess.run",
            self._mock_subprocess_with_diff(".github/actions/custom/action.yml\n"),
        )
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_allowed_push_normal_file(self, monkeypatch):
        """Push containing only src/main.py change is allowed."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        monkeypatch.setattr(
            "subprocess.run",
            self._mock_subprocess_with_diff("src/main.py\n"),
        )
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        # No response means allowed
        assert flow.response is None

    def test_blocked_push_new_branch_with_workflow(self, monkeypatch):
        """Branch creation containing a workflow file is blocked."""
        refs_data = [(ZERO_SHA, "b" * 40, "refs/heads/new-feature")]
        addon, flow = self._make_addon_and_flow(refs_data)

        monkeypatch.setattr(
            "subprocess.run",
            self._mock_subprocess_with_diff(".github/workflows/deploy.yml\nsrc/app.py\n"),
        )
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_allowed_push_branch_deletion(self, monkeypatch):
        """Branch deletion is not inspected for restricted paths (no files to check)."""
        refs_data = [("a" * 40, ZERO_SHA, "refs/heads/old-branch")]
        addon, flow = self._make_addon_and_flow(refs_data)

        # subprocess should not be called for diff-tree on deletions,
        # but the deletion will be blocked by the deletion check first
        monkeypatch.setattr("subprocess.run", self._mock_subprocess_success())
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        # Blocked by deletion check, not restricted paths
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"deletion" in flow.response.content.lower()

    def test_fail_closed_on_diff_error(self, monkeypatch):
        """If git diff-tree fails, push is blocked."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        call_count = [0]

        def diff_fails(cmd, **kwargs):
            call_count[0] += 1
            result = MagicMock()
            result.returncode = 0
            result.stdout = b""
            result.stderr = b""
            if "diff-tree" in cmd:
                result.returncode = 128
                result.stderr = b"fatal: bad object"
            return result

        monkeypatch.setattr("subprocess.run", diff_fails)
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_fail_closed_on_unpack_error(self, monkeypatch):
        """If git unpack-objects fails, push is blocked."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        call_count = [0]

        def unpack_fails(cmd, **kwargs):
            call_count[0] += 1
            result = MagicMock()
            result.returncode = 0
            result.stdout = b""
            result.stderr = b""
            if "unpack-objects" in cmd:
                result.returncode = 1
                result.stderr = b"fatal: unpack failed"
            return result

        monkeypatch.setattr("subprocess.run", unpack_fails)
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_temp_dir_cleanup(self, monkeypatch):
        """Temporary object store is cleaned up even on failure."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        def exploding_subprocess(cmd, **kwargs):
            result = MagicMock()
            result.returncode = 0
            result.stdout = b""
            result.stderr = b""
            if "diff-tree" in cmd:
                raise RuntimeError("Simulated explosion")
            return result

        monkeypatch.setattr("subprocess.run", exploding_subprocess)
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        # Push should be blocked (fail closed)
        assert flow.response is not None
        assert flow.response.status_code == 403
        # Temp dir should have been cleaned up
        assert len(self._rmtree_calls) > 0
        assert self._tmp_dir in self._rmtree_calls

    def test_error_message_is_generic(self, monkeypatch):
        """Returned error message does not contain file paths or restricted path names."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data)

        monkeypatch.setattr(
            "subprocess.run",
            self._mock_subprocess_with_diff(".github/workflows/ci.yml\n"),
        )
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        error_msg = flow.response.content.decode()
        # Must not leak specific file paths or restricted path patterns
        assert ".github/workflows" not in error_msg
        assert ".github/actions" not in error_msg
        assert "ci.yml" not in error_msg
        # Should use the generic message
        assert "security policy" in error_msg.lower()

    def test_missing_bare_repo_path_blocks(self, monkeypatch):
        """Missing bare_repo_path should fail closed."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data, bare_repo_path=None)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        error_msg = flow.response.content.decode()
        assert "security policy" in error_msg.lower()

    def test_invalid_bare_repo_path_blocks(self, monkeypatch):
        """Non-directory bare_repo_path should fail closed."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(
            refs_data, bare_repo_path="/not/a/real/bare-repo.git"
        )

        monkeypatch.setattr("os.path.isdir", lambda p: False)
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403
        error_msg = flow.response.content.decode()
        assert "security policy" in error_msg.lower()

    def test_empty_pack_data_still_checked(self, monkeypatch):
        """Empty pack_data should still run restricted-path check."""
        refs_data = [("a" * 40, "b" * 40, "refs/heads/feature-x")]
        addon, flow = self._make_addon_and_flow(refs_data, include_pack_data=False)

        monkeypatch.setattr(
            "subprocess.run",
            self._mock_subprocess_with_diff(".github/workflows/ci.yml\n"),
        )
        monkeypatch.setattr("os.path.isdir", lambda p: True)

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_defensive_size_check_blocks_oversized_pack(self, monkeypatch):
        """Pack data exceeding max_push_size is blocked defensively.

        _check_restricted_paths has its own size guard independent of the
        caller's size check in request(), ensuring safety even if the call
        order is refactored.
        """
        addon = git_proxy.GitProxyAddon(max_push_size=100)
        refs = [git_proxy.PktLineRef("a" * 40, "b" * 40, "refs/heads/feature-x")]
        oversized_pack = b"x" * 200

        monkeypatch.setattr("os.path.isdir", lambda p: True)

        result = addon._check_restricted_paths(
            refs, "/fake/bare", oversized_pack,
            [".github/workflows"],
        )

        assert result is not None
        assert "security policy" in result.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
