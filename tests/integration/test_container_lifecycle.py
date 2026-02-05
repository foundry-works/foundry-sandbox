"""Integration tests for container lifecycle in the unified-proxy.

Tests container lifecycle including:
- Container registration via internal API
- Container unregistration
- Proxy restart preserves registrations (SQLite persistence)
- Sandbox reconnects after proxy restart (TTL-based recovery)
"""

import os
import sys
import tempfile
import time

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from registry import ContainerRegistry
from internal_api import create_app, rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter between tests to avoid 429 errors."""
    rate_limiter._buckets.clear()
    yield
    rate_limiter._buckets.clear()


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_registry.db")
        yield db_path


@pytest.fixture
def registry(temp_db):
    """Create a fresh registry for each test."""
    return ContainerRegistry(db_path=temp_db)


@pytest.fixture
def api_client(registry):
    """Create Flask test client for internal API."""
    app = create_app(registry)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestContainerRegistration:
    """Test container registration via internal API."""

    def test_register_new_container(self, api_client):
        """Test registering a new container returns 201."""
        response = api_client.post(
            "/internal/containers",
            json={
                "container_id": "test-container-001",
                "ip_address": "172.17.0.100",
            },
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "registered"
        assert data["container"]["container_id"] == "test-container-001"

    def test_register_returns_registration_details(self, api_client):
        """Test registration response includes full container details."""
        response = api_client.post(
            "/internal/containers",
            json={
                "container_id": "details-container",
                "ip_address": "172.17.0.101",
                "ttl_seconds": 7200,
            },
        )
        assert response.status_code == 201
        data = response.get_json()
        container = data["container"]
        assert container["container_id"] == "details-container"
        assert container["ip_address"] == "172.17.0.101"
        assert container["ttl_seconds"] == 7200
        assert "registered_at" in container
        assert "last_seen" in container

    def test_register_with_metadata(self, api_client):
        """Test registration preserves optional metadata."""
        metadata = {"env": "test", "sandbox_name": "my-sandbox"}
        response = api_client.post(
            "/internal/containers",
            json={
                "container_id": "metadata-container",
                "ip_address": "172.17.0.102",
                "metadata": metadata,
            },
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["container"]["metadata"] == metadata

    def test_register_duplicate_ip_conflict(self, api_client):
        """Test registering different container with same IP returns 409."""
        # Register first container
        api_client.post(
            "/internal/containers",
            json={
                "container_id": "first-container",
                "ip_address": "172.17.0.103",
            },
        )

        # Try to register different container with same IP
        response = api_client.post(
            "/internal/containers",
            json={
                "container_id": "second-container",
                "ip_address": "172.17.0.103",
            },
        )
        assert response.status_code == 409
        data = response.get_json()
        assert data["error"] == "Conflict"

    def test_register_missing_container_id(self, api_client):
        """Test registration without container_id returns 400."""
        response = api_client.post(
            "/internal/containers",
            json={"ip_address": "172.17.0.104"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "container_id is required" in data["message"]

    def test_register_missing_ip_address(self, api_client):
        """Test registration without ip_address returns 400."""
        response = api_client.post(
            "/internal/containers",
            json={"container_id": "no-ip-container"},
        )
        assert response.status_code == 400
        data = response.get_json()
        assert "ip_address is required" in data["message"]


class TestContainerUnregistration:
    """Test container unregistration via internal API."""

    def test_unregister_existing_container(self, api_client):
        """Test unregistering existing container returns 200."""
        # Register first
        api_client.post(
            "/internal/containers",
            json={
                "container_id": "to-unregister",
                "ip_address": "172.17.0.110",
            },
        )

        # Unregister
        response = api_client.delete("/internal/containers/to-unregister")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "unregistered"

    def test_unregister_invalidates_cache(self, api_client, registry):
        """Test unregistration invalidates cache (subsequent lookups fail)."""
        # Register
        api_client.post(
            "/internal/containers",
            json={
                "container_id": "cache-test",
                "ip_address": "172.17.0.111",
            },
        )
        assert registry.get_by_ip("172.17.0.111") is not None

        # Unregister
        api_client.delete("/internal/containers/cache-test")

        # Verify cache is invalidated
        assert registry.get_by_ip("172.17.0.111") is None
        assert registry.get_by_container_id("cache-test") is None

    def test_unregister_nonexistent_returns_404(self, api_client):
        """Test unregistering non-existent container returns 404."""
        response = api_client.delete("/internal/containers/nonexistent-id")
        assert response.status_code == 404
        data = response.get_json()
        assert data["error"] == "Not found"


class TestProxyRestartPreservesRegistrations:
    """Test that registrations survive proxy restart (SQLite persistence)."""

    def test_registration_survives_restart(self, temp_db):
        """Test registration persists after creating new registry instance."""
        # Create first registry and register container
        registry1 = ContainerRegistry(db_path=temp_db)
        registry1.register(
            container_id="persistent-container",
            ip_address="172.17.0.120",
            ttl_seconds=86400,
            metadata={"name": "test-sandbox"},
        )
        registry1.close()

        # Simulate proxy restart by creating new registry instance
        registry2 = ContainerRegistry(db_path=temp_db)

        # Verify registration persisted
        config = registry2.get_by_container_id("persistent-container")
        assert config is not None
        assert config.ip_address == "172.17.0.120"
        assert config.metadata == {"name": "test-sandbox"}
        registry2.close()

    def test_multiple_registrations_survive_restart(self, temp_db):
        """Test multiple registrations persist after restart."""
        # Create first registry and register multiple containers
        registry1 = ContainerRegistry(db_path=temp_db)
        for i in range(5):
            registry1.register(
                container_id=f"container-{i}",
                ip_address=f"172.17.0.{130 + i}",
            )
        registry1.close()

        # Simulate restart
        registry2 = ContainerRegistry(db_path=temp_db)

        # Verify all registrations persisted
        assert registry2.count() == 5
        for i in range(5):
            config = registry2.get_by_ip(f"172.17.0.{130 + i}")
            assert config is not None
            assert config.container_id == f"container-{i}"
        registry2.close()

    def test_expired_registration_after_restart(self, temp_db):
        """Test expired registrations are rejected after restart."""
        # Register with very short TTL
        registry1 = ContainerRegistry(db_path=temp_db)
        registry1.register(
            container_id="short-lived",
            ip_address="172.17.0.140",
            ttl_seconds=1,  # 1 second TTL
        )
        registry1.close()

        # Wait for TTL to expire
        time.sleep(1.5)

        # Simulate restart
        registry2 = ContainerRegistry(db_path=temp_db)

        # Verify expired registration is not returned
        config = registry2.get_by_ip("172.17.0.140")
        assert config is None
        registry2.close()


class TestSandboxReconnectsAfterRestart:
    """Test sandbox reconnection scenarios after proxy restart."""

    def test_container_request_succeeds_after_proxy_restart(self, temp_db):
        """Test container can continue making requests after proxy restart."""
        # Initial registration
        registry1 = ContainerRegistry(db_path=temp_db)
        registry1.register(
            container_id="reconnect-test",
            ip_address="172.17.0.150",
            ttl_seconds=86400,
        )
        registry1.close()

        # Simulate proxy restart
        registry2 = ContainerRegistry(db_path=temp_db)

        # Container's request should succeed (lookup by IP works)
        config = registry2.get_by_ip("172.17.0.150")
        assert config is not None
        assert config.container_id == "reconnect-test"
        assert not config.is_expired
        registry2.close()

    def test_container_must_reregister_after_ttl_expires(self, temp_db):
        """Test container must re-register after TTL expiration."""
        # Initial registration with short TTL
        registry1 = ContainerRegistry(db_path=temp_db)
        registry1.register(
            container_id="expired-container",
            ip_address="172.17.0.151",
            ttl_seconds=1,
        )
        registry1.close()

        # Wait for TTL to expire
        time.sleep(1.5)

        # Simulate restart - container tries to make request
        registry2 = ContainerRegistry(db_path=temp_db)

        # Lookup should fail (expired)
        config = registry2.get_by_ip("172.17.0.151")
        assert config is None

        # Container re-registers
        new_config = registry2.register(
            container_id="expired-container",
            ip_address="172.17.0.151",
            ttl_seconds=86400,
        )
        assert new_config is not None

        # Now lookup succeeds
        config = registry2.get_by_ip("172.17.0.151")
        assert config is not None
        assert config.container_id == "expired-container"
        registry2.close()

    def test_renew_updates_last_seen(self, registry):
        """Test renewing registration extends TTL window."""
        registry.register(
            container_id="renewal-test",
            ip_address="172.17.0.152",
            ttl_seconds=86400,
        )

        original = registry.get_by_container_id("renewal-test")
        original_last_seen = original.last_seen

        # Wait a bit then renew
        time.sleep(0.1)
        renewed = registry.renew("renewal-test")

        assert renewed is not None
        assert renewed.last_seen > original_last_seen
        assert renewed.container_id == "renewal-test"

    def test_container_ip_change_after_restart(self, temp_db):
        """Test container can re-register with new IP after network change."""
        # Initial registration
        registry1 = ContainerRegistry(db_path=temp_db)
        registry1.register(
            container_id="moving-container",
            ip_address="172.17.0.160",
        )
        registry1.close()

        # Simulate restart with container at new IP
        registry2 = ContainerRegistry(db_path=temp_db)

        # Container re-registers with new IP
        registry2.register(
            container_id="moving-container",
            ip_address="172.17.0.161",  # New IP
        )

        # Old IP no longer works
        assert registry2.get_by_ip("172.17.0.160") is None

        # New IP works
        config = registry2.get_by_ip("172.17.0.161")
        assert config is not None
        assert config.container_id == "moving-container"
        registry2.close()


class TestInternalAPIEndpoints:
    """Test additional internal API endpoints."""

    def test_health_check(self, api_client):
        """Test health check endpoint returns healthy status."""
        response = api_client.get("/internal/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "healthy"
        assert "containers_registered" in data

    def test_get_container_details(self, api_client):
        """Test getting container details by ID."""
        # Register first
        api_client.post(
            "/internal/containers",
            json={
                "container_id": "get-details",
                "ip_address": "172.17.0.170",
            },
        )

        # Get details
        response = api_client.get("/internal/containers/get-details")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "found"
        assert data["container"]["container_id"] == "get-details"

    def test_get_nonexistent_container(self, api_client):
        """Test getting non-existent container returns 404."""
        response = api_client.get("/internal/containers/nonexistent")
        assert response.status_code == 404

    def test_list_containers(self, api_client):
        """Test listing all registered containers."""
        # Register multiple containers
        for i in range(3):
            api_client.post(
                "/internal/containers",
                json={
                    "container_id": f"list-test-{i}",
                    "ip_address": f"172.17.0.{180 + i}",
                },
            )

        # List all
        response = api_client.get("/internal/containers")
        assert response.status_code == 200
        data = response.get_json()
        assert data["count"] == 3
        assert len(data["containers"]) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
