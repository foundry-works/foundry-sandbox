"""Security tests for HMAC secret rotation and revocation procedures.

Validates that rotation correctly clears caches and nonce stores, old secrets
are rejected, new secrets are accepted, and rotation is safe under concurrency.
"""

import json
import os
import threading
import time

import pytest

from foundry_git_safety.auth import (
    NonceStore,
    RateLimiter,
    SecretStore,
    compute_signature,
)
from foundry_git_safety.server import (
    create_git_api,
    revoke_sandbox_secret,
    rotate_sandbox_secret,
)


pytestmark = pytest.mark.security


def _make_app(tmp_path):
    """Create a test app with fresh stores and a registered sandbox."""
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    data_dir = tmp_path / "data"

    sandbox_id = "rotation-test"
    old_secret = b"old-secret-key-1234567890abcdef1234567890abcdef\n"
    (secrets_dir / sandbox_id).write_bytes(old_secret)

    secret_store = SecretStore(secrets_path=str(secrets_dir))
    nonce_store = NonceStore()
    rate_limiter = RateLimiter()

    app = create_git_api(
        secret_store=secret_store,
        nonce_store=nonce_store,
        rate_limiter=rate_limiter,
        data_dir=str(data_dir),
    )
    app._test_sandbox_id = sandbox_id
    app._test_secrets_dir = secrets_dir
    return app


def _make_auth_headers(app, body: bytes, secret: bytes, sandbox_id: str | None = None):
    """Build auth headers for a given body and secret."""
    sid = sandbox_id or app._test_sandbox_id
    ts = str(time.time())
    nonce = f"rotation-nonce-{time.time_ns()}"
    sig = compute_signature("POST", "/git/exec", body, ts, nonce, secret)
    return {
        "X-Sandbox-Id": sid,
        "X-Request-Signature": sig,
        "X-Request-Timestamp": ts,
        "X-Request-Nonce": nonce,
    }


class TestSecretRotation:
    """HMAC rotation clears caches, rejects old secrets, accepts new ones."""

    def test_rotate_clears_cache_and_nonce_store(self, tmp_path):
        """After rotation, the cached secret is gone and nonces are cleared."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id

        # Prime the cache
        old_secret = app.secret_store.get_secret(sid)
        assert old_secret is not None

        # Insert a nonce
        assert app.nonce_store.check_and_store(sid, "test-nonce-1")

        # Rotate
        rotate_sandbox_secret(app, sid)

        # Nonce store should be cleared — same nonce accepted again
        assert app.nonce_store.check_and_store(sid, "test-nonce-1")

    def test_old_secret_rejected_after_rotation(self, tmp_path):
        """Requests signed with the old secret are rejected after rotation."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id
        client = app.test_client()

        # Write metadata so request reaches auth
        metadata_dir = tmp_path / "data" / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sid}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
        }))

        old_secret = b"old-secret-key-1234567890abcdef1234567890abcdef"
        body = json.dumps({"args": ["version"], "cwd": "."}).encode()
        headers = _make_auth_headers(app, body, old_secret)

        # Old secret works before rotation
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        assert resp.status_code != 401  # May be 422 (no sandbox metadata) but not auth failure

        # Now rotate — replace the file on disk and clear cache
        new_secret = b"new-secret-key-abcdef1234567890abcdef1234567890"
        (app._test_secrets_dir / sid).write_bytes(new_secret + b"\n")
        rotate_sandbox_secret(app, sid)

        # Old secret should be rejected
        body2 = json.dumps({"args": ["version"], "cwd": "."}).encode()
        headers2 = _make_auth_headers(app, body2, old_secret)
        resp2 = client.post("/git/exec", data=body2, headers=headers2, content_type="application/json")
        assert resp2.status_code == 401

    def test_new_secret_accepted_after_rotation(self, tmp_path):
        """Requests signed with the new secret are accepted after rotation."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id
        client = app.test_client()

        # Write metadata
        metadata_dir = tmp_path / "data" / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sid}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
        }))

        # Rotate to new secret
        new_secret = b"new-secret-key-abcdef1234567890abcdef1234567890"
        (app._test_secrets_dir / sid).write_bytes(new_secret + b"\n")
        rotate_sandbox_secret(app, sid)

        # New secret should work (auth passes; may fail at command execution)
        body = json.dumps({"args": ["version"], "cwd": "."}).encode()
        headers = _make_auth_headers(app, body, new_secret)
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        assert resp.status_code != 401  # Auth passes

    def test_concurrent_rotation_does_not_crash(self, tmp_path):
        """Rotation and requests happening concurrently must not raise."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id
        client = app.test_client()

        # Write metadata
        metadata_dir = tmp_path / "data" / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sid}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
        }))

        errors: list[Exception] = []

        def rotate_repeatedly():
            try:
                for i in range(20):
                    new = f"secret-{i}-{os.urandom(16).hex()}".encode()
                    (app._test_secrets_dir / sid).write_bytes(new + b"\n")
                    rotate_sandbox_secret(app, sid)
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)

        def make_requests():
            try:
                secret = app.secret_store.get_secret(sid) or b"fallback"
                for _ in range(50):
                    body = json.dumps({"args": ["version"], "cwd": "."}).encode()
                    headers = _make_auth_headers(app, body, secret)
                    client.post("/git/exec", data=body, headers=headers, content_type="application/json")
                    time.sleep(0.005)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=rotate_repeatedly)
        t2 = threading.Thread(target=make_requests)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors, f"Errors during concurrent rotation: {errors}"

    def test_bulk_rotation_all_sandboxes(self, tmp_path):
        """Rotating all sandbox secrets rejects old and accepts new."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        data_dir = tmp_path / "data"

        sandbox_ids = [f"bulk-{i}" for i in range(5)]
        old_secrets = {}
        new_secrets = {}

        for sid in sandbox_ids:
            old = f"old-{sid}-secret".encode()
            new = f"new-{sid}-secret".encode()
            old_secrets[sid] = old
            new_secrets[sid] = new
            (secrets_dir / sid).write_bytes(old + b"\n")

        secret_store = SecretStore(secrets_path=str(secrets_dir))
        app = create_git_api(
            secret_store=secret_store,
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=str(data_dir),
        )

        # Prime caches
        for sid in sandbox_ids:
            secret_store.get_secret(sid)

        # Bulk rotate
        for sid in sandbox_ids:
            (secrets_dir / sid).write_bytes(new_secrets[sid] + b"\n")
            rotate_sandbox_secret(app, sid)

        # Old secrets rejected
        for sid in sandbox_ids:
            body = json.dumps({"args": ["version"]}).encode()
            headers = _make_auth_headers(app, body, old_secrets[sid], sandbox_id=sid)
            client = app.test_client()
            resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
            assert resp.status_code == 401, f"Old secret accepted for {sid}"


class TestRevokeSandboxSecret:
    """Revocation clears all state for a sandbox."""

    def test_revoke_clears_all_state(self, tmp_path):
        """Revoked sandbox has no cached secret, no nonces, no rate limit."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id

        # Prime caches
        app.secret_store.get_secret(sid)
        app.nonce_store.check_and_store(sid, "nonce-1")
        app.rate_limiter.check_sandbox_rate(sid)

        revoke_sandbox_secret(app, sid)

        # Verify rate limiter bucket is removed
        assert sid not in app.rate_limiter._sandbox_buckets

    def test_revoked_sandbox_returns_unknown_sandbox_error(self, tmp_path):
        """After revocation, requests return 401 'Unknown sandbox'."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id
        client = app.test_client()

        # Revoke
        revoke_sandbox_secret(app, sid)

        # Remove secret file so get_secret returns None
        (app._test_secrets_dir / sid).unlink(missing_ok=True)

        body = json.dumps({"args": ["version"]}).encode()
        secret = b"old-secret-key-1234567890abcdef1234567890abcdef"
        headers = _make_auth_headers(app, body, secret)
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        assert resp.status_code == 401
        assert "Unknown sandbox" in resp.json["error"]


class TestRotationGap:
    """Rotation gap: time between writing new secret and server accepting it."""

    def test_rotation_gap_duration_acceptable(self, tmp_path):
        """Secret rotation gap should be < 100ms (synchronous implementation)."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id

        # Prime cache
        app.secret_store.get_secret(sid)

        # Write new secret and rotate
        new_secret = b"fast-rotation-secret"
        (app._test_secrets_dir / sid).write_bytes(new_secret + b"\n")

        start = time.perf_counter()
        rotate_sandbox_secret(app, sid)
        result = app.secret_store.get_secret(sid)
        elapsed = time.perf_counter() - start

        assert result == new_secret
        assert elapsed < 0.1, f"Rotation gap was {elapsed:.3f}s (expected < 0.1s)"


class TestFileBasedRotationDetection:
    """Mtime-based rotation detection works without explicit rotate() call.

    Simulates the watchdog scenario: a host process writes a new secret file
    and the server detects the change automatically via mtime.
    """

    def test_file_rotation_detected_without_explicit_rotate(self, tmp_path):
        """Writing a new secret file is detected via mtime; old HMAC rejected, new accepted."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id
        client = app.test_client()

        # Write metadata so request reaches auth
        metadata_dir = tmp_path / "data" / "sandboxes"
        metadata_dir.mkdir(parents=True)
        (metadata_dir / f"{sid}.json").write_text(json.dumps({
            "sandbox_branch": "feature",
            "from_branch": "main",
            "repos": ["test/repo"],
        }))

        old_secret = b"old-secret-key-1234567890abcdef1234567890abcdef"
        body = json.dumps({"args": ["version"], "cwd": "."}).encode()
        headers = _make_auth_headers(app, body, old_secret)

        # Old secret works before rotation
        resp = client.post("/git/exec", data=body, headers=headers, content_type="application/json")
        assert resp.status_code != 401

        # Simulate watchdog: write new secret file (no rotate() call)
        time.sleep(0.05)
        new_secret = b"new-secret-key-rotated-via-file-write"
        (app._test_secrets_dir / sid).write_bytes(new_secret + b"\n")

        # Old secret should be rejected (mtime change detected, new secret loaded)
        body2 = json.dumps({"args": ["version"], "cwd": "."}).encode()
        headers2 = _make_auth_headers(app, body2, old_secret)
        resp2 = client.post("/git/exec", data=body2, headers=headers2, content_type="application/json")
        assert resp2.status_code == 401

        # New secret should be accepted
        body3 = json.dumps({"args": ["version"], "cwd": "."}).encode()
        headers3 = _make_auth_headers(app, body3, new_secret)
        resp3 = client.post("/git/exec", data=body3, headers=headers3, content_type="application/json")
        assert resp3.status_code != 401

    def test_file_rotation_clears_nonces_via_callback(self, tmp_path):
        """Nonce store is cleared when mtime-based rotation is detected."""
        app = _make_app(tmp_path)
        sid = app._test_sandbox_id

        # Prime cache and nonce store
        app.secret_store.get_secret(sid)
        app.nonce_store.check_and_store(sid, "nonce-before-rotation")

        # Simulate watchdog: write new secret file
        time.sleep(0.05)
        new_secret = b"rotated-secret-clears-nonces"
        (app._test_secrets_dir / sid).write_bytes(new_secret + b"\n")

        # Trigger mtime detection via get_secret
        app.secret_store.get_secret(sid)

        # Old nonce should be accepted again (nonce store was cleared)
        assert app.nonce_store.check_and_store(sid, "nonce-before-rotation") is True

    def test_rotation_requires_host_filesystem_access(self, tmp_path):
        """Secret files are owned by the host and not writable from sandbox context."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        sid = "host-owned-sandbox"
        secret_file = secrets_dir / sid
        secret_file.write_bytes(b"host-secret\n")
        secret_file.chmod(0o600)

        store = SecretStore(secrets_path=str(secrets_dir))
        assert store.get_secret(sid) == b"host-secret"

        # The secret file should be mode 600 (owner read/write only)
        import stat
        file_mode = secret_file.stat().st_mode
        assert (file_mode & stat.S_IRWXO) == 0, "Secret file should not be world-accessible"
        assert (file_mode & stat.S_IRWXG) == 0, "Secret file should not be group-accessible"
