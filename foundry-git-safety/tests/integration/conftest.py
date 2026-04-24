"""Integration test fixtures for foundry-git-safety server and config loading."""

import json
import os
import time
import uuid

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
)
from foundry_git_safety.decision_log import configure_decision_log
from foundry_git_safety.server import create_git_api


# ---------------------------------------------------------------------------
# Session-scoped Flask app
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def git_api_app(tmp_path_factory):
    """Session-scoped Flask app created via create_git_api() with real stores.

    Uses tmp_path_factory so the temp dirs live for the whole session.
    """
    secrets_dir = tmp_path_factory.mktemp("secrets")
    data_dir = tmp_path_factory.mktemp("data")
    logs_dir = tmp_path_factory.mktemp("logs")

    # Write a test HMAC secret for the known sandbox id
    test_sandbox_id = "test-sandbox-1"
    (secrets_dir / test_sandbox_id).write_bytes(b"test-integration-secret-key\n")

    secret_store = SecretStore(secrets_path=str(secrets_dir))
    nonce_store = NonceStore()
    rate_limiter = RateLimiter(
        burst=300,
        sustained=120,
        global_ceiling=1000,
        ip_window=60,
        ip_max=100,
    )

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
        data_dir=str(data_dir),
    )

    # Configure the decision-log singleton for the session so the
    # session-scoped app never writes to the real ~/.foundry.
    configure_decision_log(log_dir=str(logs_dir))

    # Stash references so tests can inspect internal state if needed
    app._test_secrets_dir = secrets_dir
    app._test_data_dir = data_dir
    app._test_sandbox_id = test_sandbox_id

    return app


@pytest.fixture
def git_api_client(git_api_app):
    """Flask test client for the git API app."""
    return git_api_app.test_client()


@pytest.fixture(autouse=True)
def _reset_stores(git_api_app):
    """Reset rate limiter state between tests to prevent cross-test pollution."""
    yield
    # Reset per-IP throttle and per-sandbox buckets so rate-limit tests
    # don't poison subsequent tests in the same session.
    limiter = git_api_app.rate_limiter
    limiter._ip_counters.clear()
    limiter._sandbox_buckets.clear()
    limiter._global_timestamps.clear()


# ---------------------------------------------------------------------------
# Auth headers factory
# ---------------------------------------------------------------------------


@pytest.fixture
def auth_headers(git_api_app):
    """Factory fixture that returns a callable.

    Usage::

        headers = auth_headers(sandbox_id, body_bytes)

    The callable computes the HMAC signature and returns a dict of headers
    (X-Sandbox-Id, X-Request-Timestamp, X-Request-Nonce, X-Request-Signature).
    """

    def _make_headers(
        sandbox_id: str | None = None,
        body: bytes = b"{}",
        sandbox_id_override: str | None = None,
        timestamp_override: str | None = None,
    ) -> dict[str, str]:
        sid = sandbox_id or git_api_app._test_sandbox_id
        timestamp = timestamp_override or str(time.time())
        nonce = uuid.uuid4().hex

        secret = git_api_app.secret_store.get_secret(sid)
        if secret is None:
            # If no secret on file, use a dummy — the test is intentionally
            # checking auth failure.
            secret = b"no-secret"

        signature = compute_signature(
            method="POST",
            path="/git/exec",
            body=body,
            timestamp=timestamp,
            nonce=nonce,
            secret=secret,
        )

        return {
            "X-Sandbox-Id": sid,
            "X-Request-Timestamp": timestamp,
            "X-Request-Nonce": nonce,
            "X-Request-Signature": signature,
        }

    return _make_headers


# ---------------------------------------------------------------------------
# Sandbox metadata file helper
# ---------------------------------------------------------------------------


@pytest.fixture
def sandbox_metadata_file(git_api_app):
    """Write a metadata JSON file for a sandbox under the data dir.

    Returns a callable ``(sandbox_id, metadata_dict) -> path``.
    """

    def _write(sandbox_id: str, metadata: dict) -> str:
        sandboxes_dir = os.path.join(str(git_api_app._test_data_dir), "sandboxes")
        os.makedirs(sandboxes_dir, exist_ok=True)
        path = os.path.join(sandboxes_dir, f"{sandbox_id}.json")
        with open(path, "w") as f:
            json.dump(metadata, f)
        return path

    return _write
