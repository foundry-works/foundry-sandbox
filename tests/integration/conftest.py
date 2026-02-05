"""
Pytest configuration for integration tests.

Sets up mitmproxy mocking before test imports to allow testing addons
that depend on mitmproxy without having mitmproxy installed.
"""

import os
import sys
from unittest import mock

# Add unified-proxy to path
unified_proxy_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "unified-proxy"
)
if unified_proxy_dir not in sys.path:
    sys.path.insert(0, unified_proxy_dir)


class MockHTTPResponse:
    """Mock mitmproxy HTTP Response that tracks status_code correctly."""

    @staticmethod
    def make(status_code: int, body: bytes, headers: dict):
        resp = mock.MagicMock()
        resp.status_code = status_code
        resp.content = body
        resp.headers = headers
        return resp


# Set up mitmproxy mocks if not already done
if "mitmproxy" not in sys.modules:
    mock_http_module = mock.MagicMock()
    mock_http_module.Response = MockHTTPResponse

    mock_ctx = mock.MagicMock()
    mock_ctx.log = mock.MagicMock()

    # Create a mock mitmproxy module with proper attribute access
    mock_mitmproxy = mock.MagicMock()
    mock_mitmproxy.http = mock_http_module
    mock_mitmproxy.ctx = mock_ctx

    sys.modules["mitmproxy"] = mock_mitmproxy
    sys.modules["mitmproxy.http"] = mock_http_module
    sys.modules["mitmproxy.ctx"] = mock_ctx
    sys.modules["mitmproxy.flow"] = mock.MagicMock()
    sys.modules["mitmproxy.dns"] = mock.MagicMock()
