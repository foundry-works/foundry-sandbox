"""
Pytest configuration for integration tests.

Sets up mitmproxy mocking before test imports to allow testing addons
that depend on mitmproxy without having mitmproxy installed.
"""

import os
import sys

import pytest

# Add unified-proxy to path
unified_proxy_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "unified-proxy",
)
if unified_proxy_dir not in sys.path:
    sys.path.insert(0, unified_proxy_dir)


from tests.mocks import install_mitmproxy_mocks

_MOCK_KWARGS = {"include_dns": True}

install_mitmproxy_mocks(**_MOCK_KWARGS)


@pytest.fixture(autouse=True)
def ensure_mitmproxy_mocks():
    """Reapply mitmproxy mocks before each test to avoid cross-test leakage."""
    install_mitmproxy_mocks(**_MOCK_KWARGS)
    yield
