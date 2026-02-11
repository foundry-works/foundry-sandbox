"""Shared mitmproxy mock classes for the test suite.

Provides canonical, case-insensitive MockHeaders and common mock types
used across unit, integration, and security tests.  Individual test
modules still define their own MockRequest / MockHTTPFlow when those
require module-specific constructor signatures.

Also provides DNS mock classes (MockDNSQuestion, MockDNSRequest, etc.)
and install_mitmproxy_mocks() for sys.modules injection used by conftest
files.
"""

from __future__ import annotations

import sys
from unittest import mock


class MockHeaders(dict):
    """Case-insensitive header dict matching real mitmproxy behavior."""

    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default

    def __contains__(self, key):
        return any(k.lower() == key.lower() for k in self.keys())

    def __delitem__(self, key):
        for k in list(self.keys()):
            if k.lower() == key.lower():
                super().__delitem__(k)
                return
        raise KeyError(key)

    def __setitem__(self, key, value):
        # Remove existing key with same name (case-insensitive) first
        for k in list(self.keys()):
            if k.lower() == key.lower():
                super().__delitem__(k)
        super().__setitem__(key, value)


class MockHTTPResponse:
    """Mock mitmproxy HTTP Response that tracks status_code correctly."""

    @staticmethod
    def make(status_code: int, body: bytes, headers: dict):
        resp = mock.MagicMock()
        resp.status_code = status_code
        resp.content = body
        resp.headers = headers
        return resp


class MockResponse:
    """Mock mitmproxy Response with make() classmethod."""

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


class MockCtxLog:
    """Mock mitmproxy ctx.log with call tracking and query helpers."""

    def __init__(self):
        self.calls = []

    def info(self, msg, **kwargs):
        self.calls.append(("info", msg))

    def warn(self, msg, **kwargs):
        self.calls.append(("warn", msg))

    def warning(self, msg, **kwargs):
        self.calls.append(("warn", msg))

    def debug(self, msg, **kwargs):
        self.calls.append(("debug", msg))

    def error(self, msg, **kwargs):
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


# ---------------------------------------------------------------------------
# DNS mock classes
# ---------------------------------------------------------------------------


class MockDNSQuestion:
    """Mock DNS question in a DNS request.

    Args:
        name: Domain name being queried (str or bytes).
        query_type: Query type (1=A, 28=AAAA, 5=CNAME).
    """

    def __init__(self, name, query_type=1):
        self.name = name
        self.type = query_type


class MockDNSRequest:
    """Mock DNS request."""

    def __init__(self, question):
        self.question = question

    def fail(self, response_code):
        """Create a failed DNS response."""
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
    """Mock mitmproxy DNSFlow class.

    Args:
        domain: Domain being queried (str).
        source_ip: Source IP address (or None).
        query_type: DNS query type (default: 1 for A record).
    """

    def __init__(self, domain, source_ip, query_type=1):
        self.request = MockDNSRequest(MockDNSQuestion(domain, query_type))
        if source_ip is None:
            self.client_conn = MockDNSClientConn(None)
        else:
            self.client_conn = MockDNSClientConn((source_ip, 12345))
        self.response = None


# ---------------------------------------------------------------------------
# Mitmproxy sys.modules injection
# ---------------------------------------------------------------------------


def install_mitmproxy_mocks(*, include_dns: bool = False) -> None:
    """Install stable mitmproxy mocks into sys.modules.

    Used by conftest.py files to allow importing mitmproxy-dependent addons
    without having mitmproxy installed.

    LIMITATION: These mocks replicate mitmproxy's API surface based on a
    point-in-time snapshot.  If the real mitmproxy API changes (e.g.
    ``Response.make()`` parameter renames, new required arguments on
    ``HTTPFlow``), tests will continue to pass against these mocks while
    production breaks.  To mitigate this:

    - Prefer installing real mitmproxy in the test environment when feasible.
    - When that isn't practical, periodically run the proxy addon tests with
      real mitmproxy installed (e.g. in a dedicated CI job) to catch drift.
    - Keep mock method signatures as close to the real API as possible and
      avoid adding convenience methods that don't exist on the real classes.

    Args:
        include_dns: If True, also install mitmproxy.dns mock module.
    """
    mock_http_module = mock.MagicMock()
    mock_http_module.Response = MockHTTPResponse

    mock_ctx = mock.MagicMock()
    mock_ctx.log = mock.MagicMock()

    mock_mitmproxy = mock.MagicMock()
    mock_mitmproxy.http = mock_http_module
    mock_mitmproxy.ctx = mock_ctx

    sys.modules["mitmproxy"] = mock_mitmproxy
    sys.modules["mitmproxy.http"] = mock_http_module
    sys.modules["mitmproxy.ctx"] = mock_ctx
    sys.modules["mitmproxy.flow"] = mock.MagicMock()

    if include_dns:
        sys.modules["mitmproxy.dns"] = mock.MagicMock()
