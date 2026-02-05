"""
Pytest configuration for unified-proxy tests.

Sets up the Python path and module mocking before imports.
"""

import os
import sys
from unittest import mock

# Add the unified-proxy directory to the path so addons module is found
unified_proxy_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if unified_proxy_dir not in sys.path:
    sys.path.insert(0, unified_proxy_dir)

# Block problematic imports before any test modules load
# This prevents mitmproxy import chain issues

# Only set up mocks if not already done
if "mitmproxy" not in sys.modules:
    sys.modules["mitmproxy"] = mock.MagicMock()
    sys.modules["mitmproxy.http"] = mock.MagicMock()
    sys.modules["mitmproxy.ctx"] = mock.MagicMock()
    sys.modules["mitmproxy.flow"] = mock.MagicMock()
