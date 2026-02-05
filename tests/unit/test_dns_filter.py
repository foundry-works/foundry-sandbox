"""Unit tests for DNS filtering mitmproxy addon.

Tests the DNSFilterAddon class which filters DNS queries based on
container identity and domain allowlist policy.

Note: These tests use mock objects for mitmproxy types since mitmproxy_rs
cannot be loaded in sandboxed environments. The mocking approach ensures
we test the actual business logic without requiring the full mitmproxy runtime.
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# Add unified-proxy to path for registry import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))


# Mock mitmproxy DNS components before importing dns_filter
class MockDNSQuestion:
    """Mock DNS question in a DNS request."""

    def __init__(self, name, query_type=1):
        """Initialize DNS question.

        Args:
            name: Domain name being queried (str or bytes).
            query_type: Query type (1=A, 28=AAAA, 5=CNAME).
        """
        self.name = name
        self.type = query_type


class MockDNSRequest:
    """Mock DNS request."""

    def __init__(self, question):
        self.question = question

    def fail(self, response_code):
        """Create a failed DNS response.

        Args:
            response_code: DNS response code (e.g., NXDOMAIN).

        Returns:
            MockDNSResponse with the failure code.
        """
        return MockDNSResponse(response_code)


class MockDNSResponse:
    """Mock DNS response."""

    def __init__(self, response_code):
        self.response_code = response_code


class MockDNSClientConn:
    """Mock DNS client connection."""

    def __init__(self, peername):
        self.peername = peername


class MockDNSFlow:
    """Mock mitmproxy DNSFlow class."""

    def __init__(self, domain, source_ip, query_type=1):
        """Create a DNS flow.

        Args:
            domain: Domain being queried (str).
            source_ip: Source IP address (or None).
            query_type: DNS query type (default: 1 for A record).
        """
        self.request = MockDNSRequest(MockDNSQuestion(domain, query_type))
        if source_ip is None:
            self.client_conn = MockDNSClientConn(None)
        else:
            self.client_conn = MockDNSClientConn((source_ip, 12345))
        self.response = None


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


# Mock DNS module components
mock_dns = MagicMock()
mock_dns.DNSFlow = MockDNSFlow
mock_dns.response_codes = MagicMock()
mock_dns.response_codes.NXDOMAIN = 3  # Standard DNS NXDOMAIN code

# Create ctx mock
mock_ctx = MockCtx()

# Create mock mitmproxy
mock_mitmproxy = MagicMock()
mock_mitmproxy.dns = mock_dns
mock_mitmproxy.ctx = mock_ctx

# Install mocks into sys.modules BEFORE importing dns_filter
sys.modules["mitmproxy"] = mock_mitmproxy
sys.modules["mitmproxy.dns"] = mock_dns
sys.modules["mitmproxy.ctx"] = mock_ctx

# Now add addons path and import dns_filter
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))

# Import the module - it will use our mocked mitmproxy
import dns_filter

# Ensure the module uses our mock ctx
dns_filter.ctx = mock_ctx
dns_filter.dns = mock_dns

# Import registry directly (no mitmproxy dependency)
from registry import ContainerRegistry


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
    """Create a DNSFilterAddon with a test registry."""
    addon_instance = dns_filter.DNSFilterAddon(registry=registry)
    return addon_instance


@pytest.fixture
def addon_custom_allowlist(registry):
    """Create a DNSFilterAddon with a custom allowlist."""
    custom_allowlist = ["allowed.com", "*.allowed.com", "exact-match.org"]
    addon_instance = dns_filter.DNSFilterAddon(
        registry=registry,
        allowlist=custom_allowlist,
    )
    return addon_instance


@pytest.fixture(autouse=True)
def reset_mock_ctx():
    """Reset mock ctx before each test."""
    mock_ctx.log.reset()
    yield


def create_dns_flow(domain, source_ip, query_type=1):
    """Create a test DNS flow.

    Args:
        domain: Domain being queried.
        source_ip: Source IP address (or None for missing address).
        query_type: DNS query type (default: 1 for A record).

    Returns:
        Configured MockDNSFlow for testing.
    """
    return MockDNSFlow(domain, source_ip, query_type)


class TestAllowlistMatching:
    """Tests for _is_allowed() method with various domain patterns."""

    def test_exact_domain_match(self, addon):
        """Test exact domain matching."""
        assert addon._is_allowed("github.com") is True
        assert addon._is_allowed("pypi.org") is True
        assert addon._is_allowed("npmjs.org") is True

    def test_wildcard_subdomain_match(self, addon):
        """Test wildcard pattern matches subdomains."""
        # *.github.com should match api.github.com
        assert addon._is_allowed("api.github.com") is True
        assert addon._is_allowed("raw.github.com") is True
        assert addon._is_allowed("files.pypi.org") is True
        assert addon._is_allowed("registry.npmjs.org") is True

    def test_wildcard_base_domain_match(self, addon):
        """Test wildcard pattern matches base domain."""
        # *.github.com should also match github.com
        assert addon._is_allowed("github.com") is True

    def test_domain_not_in_allowlist(self, addon):
        """Test domain not in allowlist returns False."""
        assert addon._is_allowed("evil.com") is False
        assert addon._is_allowed("malicious.net") is False
        assert addon._is_allowed("random-site.org") is False

    def test_trailing_dot_handling(self, addon):
        """Test trailing dot is stripped before matching."""
        # Domains with trailing dots should be normalized
        assert addon._is_allowed("github.com.") is True
        assert addon._is_allowed("pypi.org.") is True

    def test_partial_match_not_allowed(self, addon):
        """Test partial matches don't pass."""
        # Should not match subdomains of non-wildcard entries
        assert addon._is_allowed("sub.files.pythonhosted.org") is False

    def test_case_insensitivity(self, addon):
        """Test that domain matching is case-insensitive (per RFC 4343)."""
        # DNS names are case-insensitive per RFC 4343
        assert addon._is_allowed("GitHub.com") is True
        assert addon._is_allowed("GITHUB.COM") is True
        assert addon._is_allowed("PyPi.Org") is True

    def test_subdomain_of_wildcard(self, addon):
        """Test nested subdomain matches wildcard pattern."""
        # api.cdn.github.com should match *.github.com
        assert addon._is_allowed("api.cdn.github.com") is True

    def test_custom_allowlist(self, addon_custom_allowlist):
        """Test addon with custom allowlist."""
        assert addon_custom_allowlist._is_allowed("allowed.com") is True
        assert addon_custom_allowlist._is_allowed("sub.allowed.com") is True
        assert addon_custom_allowlist._is_allowed("exact-match.org") is True
        assert addon_custom_allowlist._is_allowed("github.com") is False


class TestAllowedDomainResolves:
    """Tests for dns_request allowing queries to allowlisted domains."""

    def test_registered_container_allowed_domain_proceeds(self, addon, registry):
        """Test registered container querying allowlisted domain is allowed."""
        registry.register(
            container_id="test-container",
            ip_address="172.17.0.2",
        )

        flow = create_dns_flow("github.com", "172.17.0.2")
        addon.dns_request(flow)

        # No response set means query is allowed to proceed
        assert flow.response is None

    def test_wildcard_domain_allowed(self, addon, registry):
        """Test wildcard matched domain is allowed."""
        registry.register(
            container_id="test-container",
            ip_address="172.17.0.3",
        )

        flow = create_dns_flow("api.github.com", "172.17.0.3")
        addon.dns_request(flow)

        assert flow.response is None

    def test_allowed_query_logged_as_allowed(self, addon, registry):
        """Test allowed queries are logged with 'allowed' status."""
        registry.register(
            container_id="logging-test",
            ip_address="172.17.0.4",
        )

        flow = create_dns_flow("pypi.org", "172.17.0.4")
        addon.dns_request(flow)

        # Check debug log contains 'allowed'
        assert mock_ctx.log.was_called_with_level("debug")
        messages = mock_ctx.log.get_messages("debug")
        assert any("allowed" in msg.lower() for msg in messages)

    def test_multiple_allowed_queries(self, addon, registry):
        """Test multiple allowed queries from same container."""
        registry.register(
            container_id="multi-query",
            ip_address="172.17.0.5",
        )

        domains = ["github.com", "pypi.org", "npmjs.org"]
        for domain in domains:
            flow = create_dns_flow(domain, "172.17.0.5")
            addon.dns_request(flow)
            assert flow.response is None


class TestBlockedDomainNXDOMAIN:
    """Tests for dns_request blocking non-allowed domains with NXDOMAIN."""

    def test_registered_container_blocked_domain_nxdomain(self, addon, registry):
        """Test registered container querying non-allowed domain gets NXDOMAIN."""
        registry.register(
            container_id="blocked-test",
            ip_address="172.17.0.10",
        )

        flow = create_dns_flow("evil.com", "172.17.0.10")
        addon.dns_request(flow)

        # Response should be set with NXDOMAIN
        assert flow.response is not None
        assert flow.response.response_code == 3  # NXDOMAIN

    def test_blocked_query_logged(self, addon, registry):
        """Test blocked queries are logged."""
        registry.register(
            container_id="logging-blocked",
            ip_address="172.17.0.11",
        )

        flow = create_dns_flow("blocked-site.com", "172.17.0.11")
        addon.dns_request(flow)

        # Should log at info level with 'blocked'
        assert mock_ctx.log.was_called_with_level("info")
        messages = mock_ctx.log.get_messages("info")
        assert any("blocked" in msg.lower() for msg in messages)

    def test_blocked_query_reason_not_in_allowlist(self, addon, registry):
        """Test blocked query includes reason in log."""
        registry.register(
            container_id="reason-test",
            ip_address="172.17.0.12",
        )

        flow = create_dns_flow("unauthorized.org", "172.17.0.12")
        addon.dns_request(flow)

        messages = mock_ctx.log.get_messages("info")
        assert any("not_in_allowlist" in msg for msg in messages)

    def test_subdomain_not_matching_wildcard_blocked(self, addon, registry):
        """Test subdomain that doesn't match wildcard is blocked."""
        registry.register(
            container_id="wildcard-test",
            ip_address="172.17.0.13",
        )

        # This shouldn't match *.github.com because it's not a subdomain
        flow = create_dns_flow("github.com.evil.com", "172.17.0.13")
        addon.dns_request(flow)

        assert flow.response is not None
        assert flow.response.response_code == 3


class TestContainerIdentification:
    """Tests for container lookup by IP and handling unknown containers."""

    def test_known_ip_identified(self, addon, registry):
        """Test known IP is identified and proceeds to allowlist check."""
        registry.register(
            container_id="identified-container",
            ip_address="172.17.0.20",
        )

        flow = create_dns_flow("github.com", "172.17.0.20")
        addon.dns_request(flow)

        # Should be allowed (both identified and in allowlist)
        assert flow.response is None

    def test_unknown_ip_returns_nxdomain(self, addon, registry):
        """Test unknown IP returns NXDOMAIN immediately."""
        # Don't register this IP
        flow = create_dns_flow("github.com", "192.168.1.100")
        addon.dns_request(flow)

        # Should be blocked even though domain is in allowlist
        assert flow.response is not None
        assert flow.response.response_code == 3

    def test_unknown_ip_logs_warning(self, addon, registry):
        """Test unknown IP is logged with warning."""
        flow = create_dns_flow("github.com", "10.0.0.99")
        addon.dns_request(flow)

        assert mock_ctx.log.was_called_with_level("warn")
        messages = mock_ctx.log.get_messages("warn")
        assert any("unknown IP" in msg for msg in messages)

    def test_unknown_ip_reason_unknown_container(self, addon, registry):
        """Test unknown IP gets 'unknown_container' reason."""
        flow = create_dns_flow("github.com", "172.16.0.50")
        addon.dns_request(flow)

        messages = mock_ctx.log.get_messages("info")
        assert any("unknown_container" in msg for msg in messages)

    def test_no_client_address_returns_nxdomain(self, addon):
        """Test missing client address returns NXDOMAIN."""
        flow = create_dns_flow("github.com", None)
        addon.dns_request(flow)

        assert flow.response is not None
        assert flow.response.response_code == 3

    def test_no_client_address_logs_warning(self, addon):
        """Test missing client address logs warning."""
        flow = create_dns_flow("github.com", None)
        addon.dns_request(flow)

        assert mock_ctx.log.was_called_with_level("warn")
        messages = mock_ctx.log.get_messages("warn")
        assert any("no client address" in msg for msg in messages)

    def test_no_client_address_reason(self, addon):
        """Test missing client address gets 'no_client_address' reason."""
        flow = create_dns_flow("github.com", None)
        addon.dns_request(flow)

        messages = mock_ctx.log.get_messages("info")
        assert any("no_client_address" in msg for msg in messages)


class TestQueryTypeHandling:
    """Tests for _get_query_type_name() method."""

    def test_query_type_a_record(self, addon):
        """Test type 1 returns 'A'."""
        assert addon._get_query_type_name(1) == "A"

    def test_query_type_aaaa_record(self, addon):
        """Test type 28 returns 'AAAA'."""
        assert addon._get_query_type_name(28) == "AAAA"

    def test_query_type_cname(self, addon):
        """Test type 5 returns 'CNAME'."""
        assert addon._get_query_type_name(5) == "CNAME"

    def test_query_type_ns(self, addon):
        """Test type 2 returns 'NS'."""
        assert addon._get_query_type_name(2) == "NS"

    def test_query_type_mx(self, addon):
        """Test type 15 returns 'MX'."""
        assert addon._get_query_type_name(15) == "MX"

    def test_query_type_txt(self, addon):
        """Test type 16 returns 'TXT'."""
        assert addon._get_query_type_name(16) == "TXT"

    def test_query_type_ptr(self, addon):
        """Test type 12 returns 'PTR'."""
        assert addon._get_query_type_name(12) == "PTR"

    def test_query_type_unknown(self, addon):
        """Test unknown type returns numeric string."""
        assert addon._get_query_type_name(999) == "999"

    def test_different_query_types_processed(self, addon, registry):
        """Test different query types are processed correctly."""
        registry.register(
            container_id="query-type-test",
            ip_address="172.17.0.30",
        )

        # Test A, AAAA, CNAME queries
        for query_type in [1, 28, 5]:
            flow = create_dns_flow("github.com", "172.17.0.30", query_type)
            addon.dns_request(flow)
            assert flow.response is None


class TestBytesVsStringHandling:
    """Tests for handling domain names as bytes vs strings."""

    def test_bytes_domain_name(self, addon, registry):
        """Test domain name provided as bytes is handled correctly."""
        registry.register(
            container_id="bytes-test",
            ip_address="172.17.0.40",
        )

        # Create flow with bytes domain name
        flow = MockDNSFlow(b"github.com", "172.17.0.40")
        addon.dns_request(flow)

        assert flow.response is None

    def test_string_domain_name(self, addon, registry):
        """Test domain name provided as string is handled correctly."""
        registry.register(
            container_id="string-test",
            ip_address="172.17.0.41",
        )

        # Create flow with string domain name
        flow = MockDNSFlow("github.com", "172.17.0.41")
        addon.dns_request(flow)

        assert flow.response is None


class TestDefaultAllowlist:
    """Tests for the default allowlist configuration."""

    def test_default_allowlist_github(self, addon):
        """Test default allowlist includes GitHub domains."""
        assert addon._is_allowed("github.com") is True
        assert addon._is_allowed("api.github.com") is True
        assert addon._is_allowed("raw.githubusercontent.com") is True
        assert addon._is_allowed("objects.githubusercontent.com") is True

    def test_default_allowlist_pypi(self, addon):
        """Test default allowlist includes PyPI domains."""
        assert addon._is_allowed("pypi.org") is True
        assert addon._is_allowed("files.pythonhosted.org") is True

    def test_default_allowlist_npm(self, addon):
        """Test default allowlist includes npm domains."""
        assert addon._is_allowed("npmjs.org") is True
        assert addon._is_allowed("registry.npmjs.org") is True


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_empty_domain(self, addon, registry):
        """Test empty domain name is handled."""
        registry.register(
            container_id="empty-domain-test",
            ip_address="172.17.0.50",
        )

        flow = create_dns_flow("", "172.17.0.50")
        addon.dns_request(flow)

        # Empty domain not in allowlist, should be blocked
        assert flow.response is not None
        assert flow.response.response_code == 3

    def test_no_question_in_request(self, addon, registry):
        """Test DNS request without question is handled."""
        registry.register(
            container_id="no-question-test",
            ip_address="172.17.0.51",
        )

        flow = MockDNSFlow("github.com", "172.17.0.51")
        flow.request.question = None
        addon.dns_request(flow)

        # Should log warning and return early (no response set)
        assert mock_ctx.log.was_called_with_level("warn")

    def test_registry_not_initialized_raises(self):
        """Test that accessing registry without initialization raises."""
        addon_no_registry = dns_filter.DNSFilterAddon(registry=None)

        with patch.object(dns_filter, "_registry", None):
            with pytest.raises(RuntimeError, match="not initialized"):
                _ = addon_no_registry.registry

    def test_very_long_domain_name(self, addon, registry):
        """Test very long domain name is handled."""
        registry.register(
            container_id="long-domain-test",
            ip_address="172.17.0.52",
        )

        # Create a very long subdomain
        long_domain = "a" * 100 + ".github.com"
        flow = create_dns_flow(long_domain, "172.17.0.52")
        addon.dns_request(flow)

        # Should match *.github.com wildcard
        assert flow.response is None

    def test_ipv6_source_address(self, addon, registry):
        """Test IPv6 source address is handled."""
        registry.register(
            container_id="ipv6-test",
            ip_address="2001:db8::1",
        )

        flow = MockDNSFlow("github.com", "2001:db8::1")
        addon.dns_request(flow)

        assert flow.response is None


class TestLogging:
    """Tests for structured logging behavior."""

    def test_allowed_query_logs_container_id(self, addon, registry):
        """Test allowed query logs include container ID context."""
        registry.register(
            container_id="log-context-test",
            ip_address="172.17.0.60",
        )

        flow = create_dns_flow("github.com", "172.17.0.60")
        addon.dns_request(flow)

        # Verify logging was called (context set/cleared)
        messages = mock_ctx.log.get_messages()
        assert len(messages) > 0

    def test_blocked_query_logs_reason(self, addon, registry):
        """Test blocked query logs include reason."""
        registry.register(
            container_id="reason-log-test",
            ip_address="172.17.0.61",
        )

        flow = create_dns_flow("blocked.com", "172.17.0.61")
        addon.dns_request(flow)

        info_messages = mock_ctx.log.get_messages("info")
        assert any("not_in_allowlist" in msg for msg in info_messages)

    def test_query_type_logged(self, addon, registry):
        """Test query type is included in logs."""
        registry.register(
            container_id="query-type-log-test",
            ip_address="172.17.0.62",
        )

        flow = create_dns_flow("github.com", "172.17.0.62", query_type=28)
        addon.dns_request(flow)

        # AAAA query should be logged
        messages = mock_ctx.log.get_messages()
        assert any("AAAA" in msg for msg in messages)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
