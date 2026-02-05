"""Integration test linking container registration to DNS filtering.

Verifies that a container registered via the internal API can resolve
allowlisted domains, while blocked domains or unknown containers are denied.
"""

import os
import sys
import tempfile
from unittest.mock import MagicMock

import pytest

# Add unified-proxy to path for core modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from internal_api import create_app, rate_limiter
from registry import ContainerRegistry


# -----------------------------------------------------------------------------
# Minimal mitmproxy DNS mocks (mirrors unit tests)
# -----------------------------------------------------------------------------
class MockDNSQuestion:
    def __init__(self, name, query_type=1):
        self.name = name
        self.type = query_type


class MockDNSRequest:
    def __init__(self, question):
        self.question = question

    def fail(self, response_code):
        return MockDNSResponse(response_code)


class MockDNSResponse:
    def __init__(self, response_code):
        self.response_code = response_code


class MockDNSClientConn:
    def __init__(self, peername):
        self.peername = peername


class MockDNSFlow:
    def __init__(self, domain, source_ip, query_type=1):
        self.request = MockDNSRequest(MockDNSQuestion(domain, query_type))
        if source_ip is None:
            self.client_conn = MockDNSClientConn(None)
        else:
            self.client_conn = MockDNSClientConn((source_ip, 12345))
        self.response = None


class MockCtxLog:
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


class MockCtx:
    def __init__(self):
        self.log = MockCtxLog()


mock_dns = MagicMock()
mock_dns.DNSFlow = MockDNSFlow
mock_dns.response_codes = MagicMock()
mock_dns.response_codes.NXDOMAIN = 3

mock_ctx = MockCtx()

mock_mitmproxy = MagicMock()
mock_mitmproxy.dns = mock_dns
mock_mitmproxy.ctx = mock_ctx

# Inject mocks before importing dns_filter
sys.modules["mitmproxy"] = mock_mitmproxy
sys.modules["mitmproxy.dns"] = mock_dns
sys.modules["mitmproxy.ctx"] = mock_ctx

# Add addons path and import dns_filter using mocks
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))
import dns_filter  # noqa: E402

dns_filter.ctx = mock_ctx
dns_filter.dns = mock_dns


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    rate_limiter._buckets.clear()
    yield
    rate_limiter._buckets.clear()


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield os.path.join(tmpdir, "test_registry.db")


@pytest.fixture
def registry(temp_db):
    return ContainerRegistry(db_path=temp_db)


@pytest.fixture
def api_client(registry):
    app = create_app(registry)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_registration_allows_allowlisted_dns(api_client, registry):
    # Register container via internal API
    response = api_client.post(
        "/internal/containers",
        json={"container_id": "dns-container", "ip_address": "172.18.0.5"},
    )
    assert response.status_code == 201

    addon = dns_filter.DNSFilterAddon(registry=registry, allowlist=["allowed.com"])

    # Allowlisted domain should pass (no NXDOMAIN response)
    flow_allowed = MockDNSFlow("allowed.com", "172.18.0.5")
    addon.dns_request(flow_allowed)
    assert flow_allowed.response is None

    # Non-allowlisted domain should be blocked
    flow_blocked = MockDNSFlow("blocked.com", "172.18.0.5")
    addon.dns_request(flow_blocked)
    assert flow_blocked.response is not None
    assert flow_blocked.response.response_code == mock_dns.response_codes.NXDOMAIN


def test_unregistered_container_dns_blocked(registry):
    addon = dns_filter.DNSFilterAddon(registry=registry, allowlist=["allowed.com"])
    flow = MockDNSFlow("allowed.com", "172.18.0.99")
    addon.dns_request(flow)
    assert flow.response is not None
    assert flow.response.response_code == mock_dns.response_codes.NXDOMAIN
