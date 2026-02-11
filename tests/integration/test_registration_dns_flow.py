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

from tests.mocks import MockCtx, MockDNSFlow

# Set up mitmproxy.dns in sys.modules before importing dns_filter
_mock_dns = MagicMock()
_mock_dns.DNSFlow = MockDNSFlow
_mock_dns.response_codes = MagicMock()
_mock_dns.response_codes.NXDOMAIN = 3

sys.modules["mitmproxy.dns"] = _mock_dns

# Add addons path and import dns_filter (uses conftest mitmproxy mocks)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy/addons"))
import dns_filter  # noqa: E402


@pytest.fixture(autouse=True)
def _dns_filter_mocks():
    """Inject integration-test mocks into dns_filter for each test, then restore."""
    mock_ctx = MockCtx()
    orig_ctx = dns_filter.ctx
    orig_dns = dns_filter.dns
    dns_filter.ctx = mock_ctx
    dns_filter.dns = _mock_dns
    yield mock_ctx
    dns_filter.ctx = orig_ctx
    dns_filter.dns = orig_dns


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
    assert flow_blocked.response.response_code == _mock_dns.response_codes.NXDOMAIN


def test_unregistered_container_dns_blocked(registry):
    addon = dns_filter.DNSFilterAddon(registry=registry, allowlist=["allowed.com"])
    flow = MockDNSFlow("allowed.com", "172.18.0.99")
    addon.dns_request(flow)
    assert flow.response is not None
    assert flow.response.response_code == _mock_dns.response_codes.NXDOMAIN
