"""Shared JSON error helper for API gateways.

Extracted into its own module to break the circular import between
gateway_base (which imports gateway_middleware) and gateway_middleware
(which needs the same error contract).
"""

import json

from aiohttp import web


def gateway_error(status: int, message: str) -> web.Response:
    """Return a JSON error response matching the gateway error contract."""
    body = json.dumps({"error": {"type": "gateway_error", "message": message}})
    return web.Response(
        status=status,
        body=body.encode(),
        content_type="application/json",
    )
