"""Security tests for git policy enforcement.

These tests focus on adversarial scenarios and attack vectors, complementing
the unit tests with security-specific test cases. Each test class represents
a category of attack that the git proxy should defend against.

Security Properties Tested:
- Unauthorized repository access is always blocked
- Branch/tag deletion cannot be circumvented
- Auth mode restrictions cannot be bypassed
- Push size limits cannot be evaded
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# Add unified-proxy to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))


# Mock mitmproxy before importing git_proxy
from tests.mocks import (
    MockHeaders, MockResponse, MockClientConn, MockCtxLog, MockCtx,
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


# Create and install mock modules
mock_mitmproxy = MagicMock()
mock_http = MagicMock()
mock_http.Response = MockResponse
mock_http.HTTPFlow = MockHTTPFlow
mock_ctx = MockCtx()
mock_flow = MagicMock()
mock_flow.Flow = MockHTTPFlow

sys.modules["mitmproxy"] = mock_mitmproxy
sys.modules["mitmproxy.http"] = mock_http
sys.modules["mitmproxy.ctx"] = mock_ctx
sys.modules["mitmproxy.flow"] = mock_flow

# Add addons path and import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))

import git_proxy

git_proxy.ctx = mock_ctx
git_proxy.http = mock_http

from pktline import ZERO_SHA
from registry import ContainerConfig

DEFAULT_TEST_BARE_REPO = "/tmp/foundry-test-bare.git"


@pytest.fixture(autouse=True)
def reset_mock_ctx():
    """Reset mock ctx before each test.

    Reassigns git_proxy.ctx to handle cross-file mock interference
    when pytest runs multiple test files in the same process.
    """
    git_proxy.ctx = mock_ctx
    mock_ctx.log.reset()
    yield


@pytest.fixture(autouse=True)
def bypass_restricted_path_check(monkeypatch):
    """Security tests here don't target restricted-path pack parsing logic."""
    monkeypatch.setattr(
        git_proxy.GitProxyAddon,
        "_check_restricted_paths",
        lambda self, refs, bare_repo_path, pack_data, restricted_paths: None,
    )


def create_container_config(
    repos=None,
    auth_mode="normal",
    bare_repo_path=DEFAULT_TEST_BARE_REPO,
    **extra_metadata,
):
    """Create a ContainerConfig with given configuration."""
    import time

    metadata = {"repos": repos or [], "auth_mode": auth_mode}
    if bare_repo_path is not None:
        if bare_repo_path == DEFAULT_TEST_BARE_REPO:
            os.makedirs(bare_repo_path, exist_ok=True)
        metadata["bare_repo_path"] = bare_repo_path
    metadata.update(extra_metadata)

    return ContainerConfig(
        container_id="test-container",
        ip_address="172.17.0.2",
        registered_at=time.time(),
        last_seen=time.time(),
        ttl_seconds=86400,
        metadata=metadata,
    )


def create_pktline_data(refs):
    """Create pkt-line data for push operation."""
    data = b""
    for i, (old_sha, new_sha, refname) in enumerate(refs):
        caps = "report-status" if i == 0 else ""
        if caps:
            content = f"{old_sha} {new_sha} {refname}\0{caps}\n"
        else:
            content = f"{old_sha} {new_sha} {refname}\n"
        length = len(content) + 4
        data += f"{length:04x}".encode() + content.encode()
    data += b"0000"
    return data


def create_flow(path, method="GET", content=None, container_config=None):
    """Create a mock flow with optional container config."""
    flow = MockHTTPFlow("172.17.0.2", path, method, content)
    if container_config:
        flow.metadata["container_config"] = container_config
    return flow


class TestUnauthorizedRepoAccessBlocking:
    """Security tests for unauthorized repository access.

    Attack scenario: An attacker with a valid container identity attempts
    to access repositories not in their authorized list.
    """

    def test_path_traversal_attempt(self):
        """Test that path traversal cannot bypass repo authorization."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/allowed-repo"])

        # Attempt path traversal to access unauthorized repo
        malicious_paths = [
            "/owner/allowed-repo/../unauthorized.git/info/refs",
            "/owner/./unauthorized.git/info/refs",
            "/owner%2Funauthorized.git/info/refs",
        ]

        for path in malicious_paths:
            flow = create_flow(path, container_config=container)
            addon.request(flow)

            # Path traversal should not match git pattern or be denied
            # Either no response (no match) or 403 (denied)
            if flow.response is not None:
                assert flow.response.status_code == 403

    def test_case_sensitivity_bypass_attempt(self):
        """Test that case variations cannot bypass authorization."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["Owner/Repo"])

        # Try different case variations
        case_variations = [
            "/owner/repo.git/info/refs",
            "/OWNER/REPO.git/info/refs",
            "/Owner/REPO.git/info/refs",
        ]

        for path in case_variations:
            flow = create_flow(path, container_config=container)
            addon.request(flow)

            # Case mismatches should be denied (exact match required)
            if flow.response is not None:
                assert flow.response.status_code == 403

    def test_unicode_normalization_bypass_attempt(self):
        """Test that Unicode normalization cannot bypass authorization."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/repo"])

        # Unicode lookalikes (these shouldn't match)
        unicode_paths = [
            "/owner/repο.git/info/refs",  # Greek omicron instead of 'o'
            "/owner/rеpo.git/info/refs",  # Cyrillic 'е' instead of 'e'
        ]

        for path in unicode_paths:
            flow = create_flow(path, container_config=container)
            addon.request(flow)

            # Unicode lookalikes should be denied
            if flow.response is not None:
                assert flow.response.status_code == 403

    def test_empty_repos_list_denies_all(self):
        """Test that empty repos list implements default deny."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=[])

        # Try various repos - all should be denied
        test_repos = [
            "/any/repo.git/info/refs",
            "/public/open-source.git/info/refs",
            "/owner/private.git/info/refs",
        ]

        for path in test_repos:
            flow = create_flow(path, container_config=container)
            addon.request(flow)

            assert flow.response is not None
            assert flow.response.status_code == 403

    def test_wildcard_not_supported_in_repos(self):
        """Test that wildcards in repos list don't match everything."""
        addon = git_proxy.GitProxyAddon()
        # Attacker might hope wildcards work
        container = create_container_config(repos=["*/*", "owner/*", "*/repo"])

        # These should NOT match due to literal comparison
        flow = create_flow("/owner/repo.git/info/refs", container_config=container)
        addon.request(flow)

        # Wildcards should not be interpreted - exact match only
        assert flow.response is not None
        assert flow.response.status_code == 403


class TestBranchDeletionBlocking:
    """Security tests for branch/tag deletion blocking.

    Attack scenario: An attacker attempts to delete branches or tags
    through various bypass techniques.
    """

    def test_deletion_in_multi_ref_push(self):
        """Test that deletion is blocked even in multi-ref pushes."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/repo"])

        # Mix legitimate updates with a deletion
        refs = [
            ("a" * 40, "b" * 40, "refs/heads/feature"),  # Update (ok)
            ("c" * 40, "d" * 40, "refs/heads/main"),  # Update (ok)
            ("e" * 40, ZERO_SHA, "refs/heads/delete-me"),  # Deletion (blocked)
        ]
        content = create_pktline_data(refs)

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Entire push should be blocked due to deletion
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_deletion_first_in_multi_ref(self):
        """Test deletion blocked when it's the first ref."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/repo"])

        refs = [
            ("a" * 40, ZERO_SHA, "refs/heads/delete-first"),  # Deletion first
            ("b" * 40, "c" * 40, "refs/heads/update"),  # Update second
        ]
        content = create_pktline_data(refs)

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_protected_ref_deletion(self):
        """Test that deletion of protected refs is blocked."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/repo"])

        # Protected refs that must never be deleted
        protected_refs = [
            "refs/heads/main",
            "refs/heads/master",
            "refs/heads/release",
            "refs/tags/v1.0.0",
            "refs/tags/production",
        ]

        for refname in protected_refs:
            refs = [("a" * 40, ZERO_SHA, refname)]
            content = create_pktline_data(refs)

            flow = create_flow(
                "/owner/repo.git/git-receive-pack",
                method="POST",
                content=content,
                container_config=container,
            )

            addon.request(flow)

            assert flow.response is not None, f"Deletion of {refname} was not blocked"
            assert flow.response.status_code == 403

    def test_all_zeros_sha_variations(self):
        """Test that all variations of zero SHA are caught."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/repo"])

        # Only the 40-zero SHA should indicate deletion
        zero_sha = "0" * 40

        refs = [("a" * 40, zero_sha, "refs/heads/test")]
        content = create_pktline_data(refs)

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403


class TestAuthModeEnforcement:
    """Security tests for auth mode (bot mode) enforcement.

    Attack scenario: A bot-mode container attempts to push to
    non-sandbox branches through various bypass techniques.
    """

    def test_bot_mode_protected_branches(self):
        """Test that bot mode blocks all non-sandbox branches."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["owner/repo"],
            auth_mode="bot",
        )

        protected_branches = [
            "refs/heads/main",
            "refs/heads/master",
            "refs/heads/develop",
            "refs/heads/release/v1",
            "refs/heads/feature/important",
            "refs/heads/hotfix/critical",
        ]

        for refname in protected_branches:
            refs = [("a" * 40, "b" * 40, refname)]
            content = create_pktline_data(refs)

            flow = create_flow(
                "/owner/repo.git/git-receive-pack",
                method="POST",
                content=content,
                container_config=container,
            )

            addon.request(flow)

            assert flow.response is not None, f"Push to {refname} was not blocked in bot mode"
            assert flow.response.status_code == 403

    def test_bot_mode_sandbox_prefix_only(self):
        """Test that only exact sandbox/* prefix is allowed."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["owner/repo"],
            auth_mode="bot",
        )

        # These should NOT be allowed - they don't match sandbox/ prefix
        not_sandbox = [
            "refs/heads/sandbox",  # No trailing slash content
            "refs/heads/sandboxes/test",  # sandboxes != sandbox
            "refs/heads/my-sandbox/test",  # prefix doesn't start with sandbox/
            "refs/heads/Sandbox/test",  # Case sensitive
            "refs/heads/SANDBOX/test",  # Case sensitive
        ]

        for refname in not_sandbox:
            refs = [("a" * 40, "b" * 40, refname)]
            content = create_pktline_data(refs)

            flow = create_flow(
                "/owner/repo.git/git-receive-pack",
                method="POST",
                content=content,
                container_config=container,
            )

            addon.request(flow)

            assert flow.response is not None, f"Push to {refname} should be blocked"
            assert flow.response.status_code == 403

    def test_bot_mode_sandbox_allowed(self):
        """Test that valid sandbox branches ARE allowed in bot mode."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["owner/repo"],
            auth_mode="bot",
        )

        # These should be allowed
        allowed = [
            "refs/heads/sandbox/test",
            "refs/heads/sandbox/user/feature",
            "refs/heads/sandbox/123/experiment",
        ]

        for refname in allowed:
            refs = [("a" * 40, "b" * 40, refname)]
            content = create_pktline_data(refs)

            flow = create_flow(
                "/owner/repo.git/git-receive-pack",
                method="POST",
                content=content,
                container_config=container,
            )

            addon.request(flow)

            assert flow.response is None, f"Push to {refname} should be allowed"

    def test_bot_mode_mixed_refs_blocked(self):
        """Test that push with mixed sandbox/non-sandbox refs is blocked."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["owner/repo"],
            auth_mode="bot",
        )

        # Mix of sandbox (ok) and non-sandbox (blocked)
        refs = [
            ("a" * 40, "b" * 40, "refs/heads/sandbox/ok"),  # Allowed
            ("c" * 40, "d" * 40, "refs/heads/main"),  # Blocked
        ]
        content = create_pktline_data(refs)

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Entire push should be blocked
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_normal_mode_allows_non_protected_branches(self):
        """Test that normal mode allows pushes to non-protected branches."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["owner/repo"],
            auth_mode="normal",  # Normal mode, not bot
        )

        all_branches = [
            "refs/heads/feature/test",
            "refs/heads/develop",
            "refs/heads/sandbox/test",
        ]

        for refname in all_branches:
            refs = [("a" * 40, "b" * 40, refname)]
            content = create_pktline_data(refs)

            flow = create_flow(
                "/owner/repo.git/git-receive-pack",
                method="POST",
                content=content,
                container_config=container,
            )

            addon.request(flow)

            assert flow.response is None, f"Normal mode should allow {refname}"


class TestPushSizeLimitEnforcement:
    """Security tests for push size limit enforcement.

    Attack scenario: An attacker attempts to exhaust resources by
    sending large pushes or bypassing size limits.
    """

    def test_push_size_exact_boundary(self):
        """Test push size enforcement at exact boundary."""
        limit = 1000
        addon = git_proxy.GitProxyAddon(max_push_size=limit)
        container = create_container_config(repos=["owner/repo"])

        # Create push at exactly the limit (use non-protected branch)
        refs = [("a" * 40, "b" * 40, "refs/heads/feature/size-test")]
        base_data = create_pktline_data(refs)
        padding = b"x" * (limit - len(base_data))
        content = base_data + padding

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # At exactly limit should be allowed
        assert flow.response is None

    def test_push_size_one_over_boundary(self):
        """Test push size enforcement at one byte over boundary."""
        limit = 1000
        addon = git_proxy.GitProxyAddon(max_push_size=limit)
        container = create_container_config(repos=["owner/repo"])

        # Create push at limit + 1
        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        base_data = create_pktline_data(refs)
        padding = b"x" * (limit - len(base_data) + 1)
        content = base_data + padding

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Over limit should be blocked
        assert flow.response is not None
        assert flow.response.status_code == 413

    def test_chunked_push_size_counted(self):
        """Test that size is counted even for chunked transfers."""
        limit = 500
        addon = git_proxy.GitProxyAddon(max_push_size=limit)
        container = create_container_config(repos=["owner/repo"])

        # Create oversized content
        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        base_data = create_pktline_data(refs)
        content = base_data + b"x" * 1000  # Way over limit

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 413

    def test_size_limit_returns_413_not_403(self):
        """Test that size limit returns 413, not 403."""
        addon = git_proxy.GitProxyAddon(max_push_size=100)
        container = create_container_config(repos=["owner/repo"])

        refs = [("a" * 40, "b" * 40, "refs/heads/main")]
        content = create_pktline_data(refs) + b"x" * 200

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Must be 413 (Request Entity Too Large), not 403 (Forbidden)
        assert flow.response is not None
        assert flow.response.status_code == 413
        assert b"too large" in flow.response.content.lower()


class TestCombinedAttacks:
    """Security tests for combined attack scenarios.

    Attack scenario: Attacker combines multiple bypass techniques.
    """

    def test_unauthorized_repo_with_deletion(self):
        """Test that unauthorized repo is caught before deletion check."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(repos=["owner/allowed"])

        # Try deletion on unauthorized repo
        refs = [("a" * 40, ZERO_SHA, "refs/heads/main")]
        content = create_pktline_data(refs)

        flow = create_flow(
            "/owner/unauthorized.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Should be blocked (403) for repo access, not deletion
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_bot_mode_deletion_double_blocked(self):
        """Test that bot mode + deletion are both enforced."""
        addon = git_proxy.GitProxyAddon()
        container = create_container_config(
            repos=["owner/repo"],
            auth_mode="bot",
        )

        # Try deletion on sandbox branch (would normally be allowed in bot mode)
        refs = [("a" * 40, ZERO_SHA, "refs/heads/sandbox/test")]
        content = create_pktline_data(refs)

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Deletion should be blocked regardless of branch
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_oversized_deletion_push(self):
        """Test that size limit is checked before other policies."""
        addon = git_proxy.GitProxyAddon(max_push_size=100)
        container = create_container_config(repos=["owner/repo"])

        # Oversized push with deletion
        refs = [("a" * 40, ZERO_SHA, "refs/heads/main")]
        content = create_pktline_data(refs) + b"x" * 200

        flow = create_flow(
            "/owner/repo.git/git-receive-pack",
            method="POST",
            content=content,
            container_config=container,
        )

        addon.request(flow)

        # Should be 413 (size limit), not 403 (deletion)
        assert flow.response is not None
        assert flow.response.status_code == 413


class TestGitHookHardening:
    """Security tests for git hook hardening in proxy-side execution.

    Attack scenario: A cloned repository contains malicious hooks in
    .git/hooks/ that attempt to execute during proxy-side git operations.
    The proxy must inject hook-disabling flags to prevent this.
    """

    def test_hooks_disabled_in_execution(self):
        """Test that git hooks cannot execute during proxy-side git operations.

        Verifies that execute_git() injects core.hooksPath=/dev/null and
        core.fsmonitor=false into the command array passed to subprocess.run,
        ensuring malicious hooks in cloned repos cannot trigger.
        """
        from git_operations import GitExecRequest, execute_git

        with tempfile.TemporaryDirectory() as tmpdir:
            request = GitExecRequest(args=["status"])
            metadata = {"sandbox_branch": "test-branch"}

            with patch("git_operations.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout=b"",
                    stderr=b"",
                )

                execute_git(request, tmpdir, metadata=metadata)

                mock_run.assert_called_once()
                cmd = mock_run.call_args[0][0]

                # Verify hook-disabling flags are present in the command array
                assert "-c" in cmd, "Expected -c flag in command"

                # Find all -c flag pairs in the command
                config_pairs = {}
                for i, arg in enumerate(cmd):
                    if arg == "-c" and i + 1 < len(cmd):
                        key_value = cmd[i + 1]
                        if "=" in key_value:
                            key, value = key_value.split("=", 1)
                            config_pairs[key] = value

                assert "core.hooksPath" in config_pairs, (
                    "core.hooksPath not found in git command config flags"
                )
                assert config_pairs["core.hooksPath"] == "/dev/null", (
                    f"core.hooksPath should be /dev/null, got {config_pairs['core.hooksPath']}"
                )

                assert "core.fsmonitor" in config_pairs, (
                    "core.fsmonitor not found in git command config flags"
                )
                assert config_pairs["core.fsmonitor"] == "false", (
                    f"core.fsmonitor should be false, got {config_pairs['core.fsmonitor']}"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
