"""
Pytest configuration for unified-proxy tests.

Sets up the Python path and module mocking before imports.

Set MITMPROXY_NO_MOCK=1 to skip mock installation (used by the proxy
drift check workflow to test against real mitmproxy).
"""

import os
import sys

# Add the unified-proxy directory to the path so addons module is found
unified_proxy_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if unified_proxy_dir not in sys.path:
    sys.path.insert(0, unified_proxy_dir)

# Add root tests dir to path so we can import the shared mocks module
root_tests_dir = os.path.normpath(os.path.join(unified_proxy_dir, os.pardir, "tests"))
if root_tests_dir not in sys.path:
    sys.path.insert(0, root_tests_dir)

_SKIP_MOCKS = os.environ.get("MITMPROXY_NO_MOCK") == "1"

if not _SKIP_MOCKS and "mitmproxy" not in sys.modules:
    # Block problematic imports before any test modules load
    # This prevents mitmproxy import chain issues
    from mocks import install_mitmproxy_mocks  # noqa: E402

    install_mitmproxy_mocks()
