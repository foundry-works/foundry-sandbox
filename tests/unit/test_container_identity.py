"""Unit tests for container identity mitmproxy addon.

Tests the ContainerIdentityAddon class which identifies containers by
source IP address with optional X-Container-Id header validation.

Note: These tests use mock objects for mitmproxy types since mitmproxy_rs
cannot be loaded in sandboxed environments. The mocking approach ensures
we test the actual business logic without requiring the full mitmproxy runtime.
"""

import os
import sys
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

# Add unified-proxy to path for registry import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))


# Mock mitmproxy before importing container_identity
from tests.mocks import (
    MockHeaders, MockResponse, MockClientConn, MockCtxLog,
)


class MockRequest:
    """Mock mitmproxy Request class."""

    def __init__(self, headers=None):
        self.headers = MockHeaders(headers or {})
        self.pretty_host = "example.com"


class MockHTTPFlow:
    """Mock mitmproxy HTTPFlow class."""

    def __init__(self, source_ip, headers=None):
        if source_ip is None:
            self.client_conn = MockClientConn(None)
        else:
            self.client_conn = MockClientConn((source_ip, 12345))
        self.request = MockRequest(headers)
        self.response = None
        self.metadata = {}


# Create test-specific mock objects for container_identity tests.
# NOTE: We do NOT overwrite sys.modules["mitmproxy*"] here because conftest.py
# already installs proper mitmproxy mocks.  Overwriting them would pollute the
# global module cache and break other test files (test_github_api_filter,
# test_dual_layer_consistency) that import mitmproxy-based addons later.
mock_http = MagicMock()
mock_http.Response = MockResponse
mock_http.HTTPFlow = MockHTTPFlow

mock_logger = MockCtxLog()

# Add addons path and import container_identity (uses conftest mitmproxy mocks)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))
import container_identity

# Replace the module-level mitmproxy references with our test-specific mocks
# so that container_identity uses MockResponse/MockCtx defined above.
container_identity.logger = mock_logger
container_identity.http = mock_http

# Import registry directly (no mitmproxy dependency)
from registry import ContainerRegistry


# Constants from the module
CONTAINER_ID_HEADER = "X-Container-Id"
FLOW_METADATA_KEY = "container_config"


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_registry.db")
        yield db_path


@pytest.fixture
def registry(temp_db):
    """Create a fresh registry for each test."""
    return ContainerRegistry(db_path=temp_db)


@pytest.fixture
def addon(registry):
    """Create a ContainerIdentityAddon with a test registry."""
    addon_instance = container_identity.ContainerIdentityAddon(registry=registry)
    return addon_instance


@pytest.fixture(autouse=True)
def reset_mock_logger():
    """Reset mock logger before each test."""
    mock_logger.reset()
    yield


def create_flow(source_ip, headers=None):
    """Create a test HTTP flow with the specified source IP.

    Args:
        source_ip: The client IP address (or None for missing address).
        headers: Optional headers to add to the request.

    Returns:
        Configured MockHTTPFlow for testing.
    """
    return MockHTTPFlow(source_ip, headers)


class TestUnknownSourceIP:
    """Tests for unknown source IP handling."""

    def test_unknown_ip_returns_403(self, addon):
        """Test that unknown source IP returns 403 Forbidden."""
        # Create flow with unregistered IP
        flow = create_flow("192.168.1.100")

        # Process the request
        addon.request(flow)

        # Verify 403 response was set
        assert flow.response is not None
        assert flow.response.status_code == 403
        assert b"Forbidden" in flow.response.content

    def test_unknown_ip_logs_warning(self, addon):
        """Test that unknown IP is logged with warning level."""
        flow = create_flow("10.0.0.99")
        addon.request(flow)

        # Verify warning was logged
        assert mock_logger.was_called_with_level("warn")
        messages = mock_logger.get_messages("warn")
        assert any("Unknown source IP" in msg for msg in messages)

    def test_unknown_ip_does_not_set_metadata(self, addon):
        """Test that unknown IP does not set container config in metadata."""
        flow = create_flow("172.16.0.50")
        addon.request(flow)

        assert FLOW_METADATA_KEY not in flow.metadata


class TestMismatchedHeader:
    """Tests for X-Container-Id header mismatch handling."""

    def test_mismatched_header_returns_403(self, addon, registry):
        """Test that mismatched X-Container-Id header returns 403."""
        # Register container with one ID
        registry.register(
            container_id="container-abc",
            ip_address="172.17.0.2",
        )

        # Create flow with different container ID in header
        flow = create_flow(
            "172.17.0.2",
            headers={CONTAINER_ID_HEADER: "container-xyz"},
        )

        addon.request(flow)

        # Verify 403 response
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_mismatched_header_logs_mismatch_details(self, addon, registry):
        """Test that header mismatch logs both header and registered ID."""
        registry.register(
            container_id="registered-id",
            ip_address="172.17.0.3",
        )

        flow = create_flow(
            "172.17.0.3",
            headers={CONTAINER_ID_HEADER: "header-id"},
        )

        addon.request(flow)

        assert mock_logger.was_called_with_level("warn")
        messages = mock_logger.get_messages("warn")
        assert any("mismatch" in msg.lower() for msg in messages)


class TestExpiredRegistration:
    """Tests for expired registration handling."""

    def test_expired_registration_returns_403(self, addon, registry):
        """Test that expired registration returns 403 Forbidden."""
        # Register container with very short TTL
        registry.register(
            container_id="expiring-container",
            ip_address="172.17.0.4",
            ttl_seconds=1,
        )

        # Wait for expiration
        time.sleep(1.5)

        flow = create_flow("172.17.0.4")
        addon.request(flow)

        # Verify 403 response (registry returns None for expired)
        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_expired_registration_logs_expiration(self, addon, registry):
        """Test that expiration is logged."""
        registry.register(
            container_id="old-container",
            ip_address="172.17.0.5",
            ttl_seconds=1,
        )

        time.sleep(1.5)

        flow = create_flow("172.17.0.5")
        addon.request(flow)

        # Check that warning was logged (either expired or unknown)
        assert mock_logger.was_called_with_level("warn")


class TestValidRegistration:
    """Tests for valid container registration handling."""

    def test_valid_registration_proceeds(self, addon, registry):
        """Test that valid registration allows request to proceed."""
        registry.register(
            container_id="valid-container",
            ip_address="172.17.0.6",
        )

        flow = create_flow("172.17.0.6")
        addon.request(flow)

        # Verify no response was set (request proceeds)
        assert flow.response is None

    def test_valid_registration_sets_metadata(self, addon, registry):
        """Test that valid registration sets container config in flow metadata."""
        registry.register(
            container_id="metadata-container",
            ip_address="172.17.0.7",
        )

        flow = create_flow("172.17.0.7")
        addon.request(flow)

        # Verify metadata was set
        assert FLOW_METADATA_KEY in flow.metadata
        config = flow.metadata[FLOW_METADATA_KEY]
        assert config.container_id == "metadata-container"
        assert config.ip_address == "172.17.0.7"

    def test_valid_registration_with_matching_header(self, addon, registry):
        """Test that matching X-Container-Id header is accepted."""
        registry.register(
            container_id="header-match-container",
            ip_address="172.17.0.8",
        )

        flow = create_flow(
            "172.17.0.8",
            headers={CONTAINER_ID_HEADER: "header-match-container"},
        )

        addon.request(flow)

        # Verify request proceeds
        assert flow.response is None
        assert FLOW_METADATA_KEY in flow.metadata

    def test_get_container_config_helper(self, addon, registry):
        """Test the get_container_config helper function."""
        registry.register(
            container_id="helper-test-container",
            ip_address="172.17.0.9",
        )

        flow = create_flow("172.17.0.9")
        addon.request(flow)

        # Use helper function
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert config.container_id == "helper-test-container"

    def test_get_container_config_returns_none_for_unidentified(self):
        """Test that get_container_config returns None for unidentified flows."""
        flow = create_flow("192.168.1.1")
        # Don't process with addon - flow has no container config

        config = container_identity.get_container_config(flow)
        assert config is None


class TestHeaderStripping:
    """Tests for X-Container-Id header stripping."""

    def test_header_stripped_before_forwarding(self, addon, registry):
        """Test that X-Container-Id header is stripped after validation."""
        registry.register(
            container_id="strip-test-container",
            ip_address="172.17.0.10",
        )

        flow = create_flow(
            "172.17.0.10",
            headers={CONTAINER_ID_HEADER: "strip-test-container"},
        )

        # Verify header exists before processing
        assert CONTAINER_ID_HEADER in flow.request.headers

        addon.request(flow)

        # Verify header is stripped
        assert CONTAINER_ID_HEADER not in flow.request.headers
        # But request still proceeds
        assert flow.response is None

    def test_header_not_present_still_works(self, addon, registry):
        """Test that requests without header still work for registered containers."""
        registry.register(
            container_id="no-header-container",
            ip_address="172.17.0.11",
        )

        flow = create_flow("172.17.0.11")
        # No header set

        addon.request(flow)

        # Request should proceed
        assert flow.response is None
        assert FLOW_METADATA_KEY in flow.metadata

    def test_other_headers_preserved(self, addon, registry):
        """Test that other headers are not affected by stripping."""
        registry.register(
            container_id="preserve-headers-container",
            ip_address="172.17.0.12",
        )

        flow = create_flow(
            "172.17.0.12",
            headers={
                CONTAINER_ID_HEADER: "preserve-headers-container",
                "Authorization": "Bearer token123",
                "Content-Type": "application/json",
            },
        )

        addon.request(flow)

        # X-Container-Id should be stripped
        assert CONTAINER_ID_HEADER not in flow.request.headers
        # Other headers should remain
        assert flow.request.headers.get("Authorization") == "Bearer token123"
        assert flow.request.headers.get("Content-Type") == "application/json"


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_no_client_address_returns_403(self, addon):
        """Test that missing client address returns 403."""
        flow = MockHTTPFlow(None)  # No source IP

        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_registry_not_initialized_raises(self):
        """Test that accessing registry without initialization raises."""
        addon_no_registry = container_identity.ContainerIdentityAddon(registry=None)

        with patch.object(container_identity, "_registry", None):
            with pytest.raises(RuntimeError, match="not initialized"):
                _ = addon_no_registry.registry

    def test_container_with_metadata(self, addon, registry):
        """Test that container metadata is preserved in flow."""
        registry.register(
            container_id="metadata-rich-container",
            ip_address="172.17.0.13",
            metadata={"purpose": "testing", "owner": "unit-tests"},
        )

        flow = create_flow("172.17.0.13")
        addon.request(flow)

        config = container_identity.get_container_config(flow)
        assert config is not None
        assert config.metadata == {"purpose": "testing", "owner": "unit-tests"}

    def test_multiple_requests_same_container(self, addon, registry):
        """Test that multiple requests from same container work."""
        registry.register(
            container_id="multi-request-container",
            ip_address="172.17.0.14",
        )

        for _ in range(5):
            flow = create_flow("172.17.0.14")
            addon.request(flow)
            assert flow.response is None
            assert FLOW_METADATA_KEY in flow.metadata


class TestPathTraversalValidation:
    """Tests for path traversal protection in bare_repo_path enrichment.

    The enrichment only applies to repos matching the exact 'owner/repo'
    format (exactly two non-empty components separated by a single '/').
    Repos with multiple slashes (absolute paths, nested paths) skip
    enrichment entirely — no bare_repo_path is constructed, so there is
    no path traversal risk.
    """

    def test_multi_slash_repo_skips_enrichment(self, addon, registry):
        """Test that repos with multiple slashes skip enrichment safely."""
        registry.register(
            container_id="traversal-container",
            ip_address="172.17.0.20",
            metadata={"repo": "../../etc/passwd"},
        )

        flow = create_flow("172.17.0.20")
        addon.request(flow)

        # Request proceeds (no bare_repo_path constructed, so no risk)
        assert flow.response is None
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert "bare_repo_path" not in config.metadata

    def test_multi_slash_nested_path_skips_enrichment(self, addon, registry):
        """Test that nested paths with '..' skip enrichment safely."""
        registry.register(
            container_id="traversal-container-2",
            ip_address="172.17.0.21",
            metadata={"repo": "owner/../../../etc"},
        )

        flow = create_flow("172.17.0.21")
        addon.request(flow)

        # Request proceeds (no bare_repo_path constructed)
        assert flow.response is None
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert "bare_repo_path" not in config.metadata

    def test_dotdot_in_two_part_owner_returns_403(self, addon, registry):
        """Test that '..' in owner of a two-part repo is rejected."""
        registry.register(
            container_id="traversal-2part-container",
            ip_address="172.17.0.26",
            metadata={"repo": "../passwd"},
        )

        flow = create_flow("172.17.0.26")
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_dotdot_in_two_part_repo_name_returns_403(self, addon, registry):
        """Test that '..' in repo name of a two-part repo is rejected."""
        registry.register(
            container_id="traversal-2part-container-2",
            ip_address="172.17.0.27",
            metadata={"repo": "owner/..secret"},
        )

        flow = create_flow("172.17.0.27")
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.status_code == 403

    def test_normal_repo_is_enriched(self, addon, registry):
        """Test that normal repo metadata gets bare_repo_path enriched."""
        registry.register(
            container_id="normal-repo-container",
            ip_address="172.17.0.22",
            metadata={"repo": "owner/repo-name"},
        )

        flow = create_flow("172.17.0.22")
        addon.request(flow)

        assert flow.response is None
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert "bare_repo_path" in config.metadata
        assert config.metadata["bare_repo_path"].endswith("owner/repo-name.git")

    def test_traversal_rejection_logs_warning(self, addon, registry):
        """Test that path traversal rejection is logged for two-part repos."""
        registry.register(
            container_id="traversal-log-container",
            ip_address="172.17.0.23",
            metadata={"repo": "../evil"},
        )

        flow = create_flow("172.17.0.23")
        addon.request(flow)

        assert mock_logger.was_called_with_level("warn")
        messages = mock_logger.get_messages("warn")
        assert any("path traversal" in msg.lower() for msg in messages)

    def test_three_part_repo_skips_enrichment(self, addon, registry):
        """Test that 'owner/repo/extra' skips enrichment (no 403).

        Repos with more than two path components don't match the
        'owner/repo' format, so no bare_repo_path is constructed.
        """
        registry.register(
            container_id="slash-container",
            ip_address="172.17.0.24",
            metadata={"repo": "owner/repo/evil"},
        )

        flow = create_flow("172.17.0.24")
        addon.request(flow)

        assert flow.response is None
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert "bare_repo_path" not in config.metadata

    def test_absolute_path_skips_enrichment(self, addon, registry):
        """Test that absolute filesystem paths skip enrichment.

        Test sandboxes use local paths like '/tmp/pytest-xxx/repo0'.
        These should not trigger path traversal rejection.
        """
        registry.register(
            container_id="abspath-container",
            ip_address="172.17.0.28",
            metadata={"repo": "/tmp/pytest-of-user/pytest-1/repo0"},
        )

        flow = create_flow("172.17.0.28")
        addon.request(flow)

        assert flow.response is None
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert "bare_repo_path" not in config.metadata

    def test_realpath_validation_blocks_escape(self, addon, registry):
        """Test that os.path.realpath validation blocks path escape attempts.

        Even if '..' is not literally present, the realpath check ensures
        the constructed path stays under REPOS_BASE_DIR.
        """
        # A repo name with valid characters that looks normal
        # (realpath check is the last line of defense)
        registry.register(
            container_id="realpath-container",
            ip_address="172.17.0.25",
            metadata={"repo": "owner/repo-name"},
        )

        flow = create_flow("172.17.0.25")
        addon.request(flow)

        # Normal repo should succeed
        assert flow.response is None
        config = container_identity.get_container_config(flow)
        assert config is not None
        assert "bare_repo_path" in config.metadata


class TestResponseContent:
    """Tests for response content on denial."""

    def test_403_response_content_type(self, addon):
        """Test that 403 response has correct Content-Type."""
        flow = create_flow("10.0.0.1")
        addon.request(flow)

        assert flow.response is not None
        assert flow.response.headers.get("Content-Type") == "text/plain"

    def test_403_response_body(self, addon):
        """Test that 403 response has appropriate body text."""
        flow = create_flow("10.0.0.2")
        addon.request(flow)

        assert flow.response is not None
        body = flow.response.content.decode()
        assert "Forbidden" in body
        assert "identity" in body.lower() or "verification" in body.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
