"""Shared limits for host-side HTTP proxying."""

from __future__ import annotations

import os


CHUNK_SIZE = 64 * 1024
UPSTREAM_TIMEOUT_SECONDS = 30.0
UPSTREAM_MAX_RESPONSE_BYTES = 50 * 1024 * 1024


class UpstreamResponseTooLarge(Exception):
    """Raised when an upstream response exceeds the configured cap."""


def read_capped_response(response, max_bytes: int | None = None) -> bytes:
    """Read an http.client response while enforcing a hard byte cap."""
    limit = max_bytes if max_bytes is not None else UPSTREAM_MAX_RESPONSE_BYTES
    chunks: list[bytes] = []
    total = 0

    while True:
        chunk = response.read(CHUNK_SIZE)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise UpstreamResponseTooLarge(
                f"Upstream response exceeds {limit} bytes"
            )
        chunks.append(chunk)


def _read_env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _read_env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


UPSTREAM_TIMEOUT_SECONDS = _read_env_float(
    "FOUNDRY_GIT_SAFETY_UPSTREAM_TIMEOUT_SECONDS",
    UPSTREAM_TIMEOUT_SECONDS,
)
UPSTREAM_MAX_RESPONSE_BYTES = _read_env_int(
    "FOUNDRY_GIT_SAFETY_UPSTREAM_MAX_RESPONSE_BYTES",
    UPSTREAM_MAX_RESPONSE_BYTES,
)
