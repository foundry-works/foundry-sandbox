"""Integration tests for observability endpoints (/health, /ready, /metrics)."""

import json
import os
from pathlib import Path

import pytest

from foundry_git_safety.auth import NonceStore, RateLimiter, SecretStore
from foundry_git_safety.metrics import registry
from foundry_git_safety.schemas.foundry_yaml import FoundryConfig, GitSafetyConfig, ObservabilityConfig
from foundry_git_safety.server import create_git_api


@pytest.fixture
def app(tmp_path):
    data_dir = str(tmp_path / "data")
    secrets_dir = str(tmp_path / "secrets")
    os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
    os.makedirs(secrets_dir, exist_ok=True)

    return create_git_api(
        secret_store=SecretStore(secrets_path=secrets_dir),
        nonce_store=NonceStore(),
        rate_limiter=RateLimiter(),
        data_dir=data_dir,
    )


@pytest.fixture
def client(app):
    return app.test_client()


class TestHealthEndpoint:
    def test_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["config_valid"] is True
        assert data["config_error"] is None
        assert "uptime_seconds" in data

    def test_includes_uptime(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert data["uptime_seconds"] >= 0


class TestReadyEndpoint:
    def test_returns_ready_when_healthy(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ready"] is True
        assert "checks" in data
        assert data["checks"]["workspace"]["ok"] is True
        assert data["checks"]["config"]["ok"] is True
        assert data["checks"]["secret_store"]["ok"] is True

    def test_returns_503_when_workspace_missing(self, tmp_path):
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(secrets_dir, exist_ok=True)

        app = create_git_api(
            data_dir="/nonexistent/path",
            secret_store=SecretStore(secrets_path=secrets_dir),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
        )
        client = app.test_client()
        resp = client.get("/ready")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["ready"] is False
        assert data["checks"]["workspace"]["ok"] is False

    def test_returns_503_when_secrets_dir_missing(self, tmp_path):
        data_dir = str(tmp_path / "data")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)

        app = create_git_api(
            data_dir=data_dir,
            secret_store=SecretStore(secrets_path="/nonexistent/secrets"),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
        )
        client = app.test_client()
        resp = client.get("/ready")
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["ready"] is False
        assert data["checks"]["secret_store"]["ok"] is False
        assert "nonexistent/secrets" in data["checks"]["secret_store"]["detail"]


class TestMetricsEndpoint:
    def test_returns_prometheus_format(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.content_type
        text = resp.data.decode()
        assert "# HELP git_safety_operations_total" in text
        assert "# TYPE git_safety_operations_total counter" in text
        assert "process_uptime_seconds" in text

    def test_metrics_increment_after_request(self, tmp_path):
        data_dir = str(tmp_path / "data")
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
        os.makedirs(secrets_dir, exist_ok=True)

        registry.reset()

        store = SecretStore(secrets_path=secrets_dir)
        sandbox_id = "test-sbx-1"
        secret = "a" * 64
        Path(secrets_dir, sandbox_id).write_text(secret)
        metadata = {"sandbox_branch": "feature", "from_branch": "main", "repos": []}
        Path(data_dir, "sandboxes", f"{sandbox_id}.json").write_text(json.dumps(metadata))

        app = create_git_api(
            secret_store=store,
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=data_dir,
        )
        c = app.test_client()

        # Send a request with missing headers -> should record "error" outcome
        c.post("/git/exec", data="{}", content_type="application/json")

        resp = c.get("/metrics")
        text = resp.data.decode()
        assert "git_safety_operations_total" in text


class TestEndpointRouting:
    def test_404_for_unknown_path(self, client):
        resp = client.get("/unknown")
        assert resp.status_code == 404

    def test_health_get_only(self, client):
        resp = client.post("/health")
        assert resp.status_code == 405

    def test_metrics_get_only(self, client):
        resp = client.post("/metrics")
        assert resp.status_code == 405


class TestConfigDrivenDecisionLog:
    def test_config_threads_decision_log_dir(self, tmp_path, monkeypatch):
        from foundry_git_safety import decision_log

        monkeypatch.setattr(decision_log, "_writer", None)

        log_dir = str(tmp_path / "configured-logs")
        data_dir = str(tmp_path / "data")
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
        os.makedirs(secrets_dir, exist_ok=True)

        cfg = FoundryConfig(
            git_safety=GitSafetyConfig(
                observability=ObservabilityConfig(decision_log_dir=log_dir),
            ),
        )
        create_git_api(
            secret_store=SecretStore(secrets_path=secrets_dir),
            data_dir=data_dir,
            config=cfg,
        )

        # Write a decision via the module-level function
        decision_log.write_decision(
            sandbox="sbx-test", rule="test_rule", verb="push", outcome="deny",
        )
        log_path = Path(log_dir) / "decisions.jsonl"
        assert log_path.exists()
        entry = json.loads(log_path.read_text().strip())
        assert entry["sandbox"] == "sbx-test"

        # Clean up singleton
        decision_log._writer.close()
        monkeypatch.setattr(decision_log, "_writer", None)


class TestDecisionLogHealthChecks:
    def test_health_includes_logging_status(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert "logging" in data
        assert data["logging"]["ok"] is True
        assert "writable" in data["logging"]["detail"].lower() or "decision" in data["logging"]["detail"].lower()

    def test_ready_includes_decision_log_check(self, client):
        resp = client.get("/ready")
        data = resp.get_json()
        assert "decision_log" in data["checks"]
        assert data["checks"]["decision_log"]["ok"] is True

    def test_ready_returns_200_with_degraded_log(self, tmp_path, monkeypatch):
        """Decision-log degradation should not trigger 503."""
        from foundry_git_safety import decision_log

        monkeypatch.setattr(decision_log, "_writer", None)
        monkeypatch.setenv("GIT_SAFETY_DECISION_LOG_DIR", "/proc/nonexistent/path")

        data_dir = str(tmp_path / "data")
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
        os.makedirs(secrets_dir, exist_ok=True)

        app = create_git_api(
            secret_store=SecretStore(secrets_path=secrets_dir),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=data_dir,
        )
        client = app.test_client()

        resp = client.get("/ready")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ready"] is True
        assert data["checks"]["decision_log"]["ok"] is False

        monkeypatch.setattr(decision_log, "_writer", None)

    def test_health_shows_degraded_with_bad_log_dir(self, tmp_path, monkeypatch):
        from foundry_git_safety import decision_log

        monkeypatch.setattr(decision_log, "_writer", None)
        monkeypatch.setenv("GIT_SAFETY_DECISION_LOG_DIR", "/proc/nonexistent/path")

        data_dir = str(tmp_path / "data")
        secrets_dir = str(tmp_path / "secrets")
        os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)
        os.makedirs(secrets_dir, exist_ok=True)

        app = create_git_api(
            secret_store=SecretStore(secrets_path=secrets_dir),
            nonce_store=NonceStore(),
            rate_limiter=RateLimiter(),
            data_dir=data_dir,
        )
        client = app.test_client()

        resp = client.get("/health")
        data = resp.get_json()
        assert data["logging"]["ok"] is False
        assert data["status"] == "degraded"

        monkeypatch.setattr(decision_log, "_writer", None)
