"""
Pytest configuration for unit tests.

Sets up mitmproxy mocking before test imports to allow testing addons
that depend on mitmproxy without having mitmproxy installed.

Set MITMPROXY_NO_MOCK=1 to skip mock installation (used by the proxy
drift check workflow to test against real mitmproxy).
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

_SKIP_MOCKS = os.environ.get("MITMPROXY_NO_MOCK") == "1"

if not _SKIP_MOCKS:
    from tests.mocks import install_mitmproxy_mocks

    _MOCK_KWARGS = {"include_dns": False}

    install_mitmproxy_mocks(**_MOCK_KWARGS)

    @pytest.fixture(autouse=True)
    def ensure_mitmproxy_mocks():
        """Reapply mitmproxy mocks before each test to avoid cross-test leakage."""
        install_mitmproxy_mocks(**_MOCK_KWARGS)
        yield
