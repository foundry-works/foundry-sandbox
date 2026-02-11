"""Unit tests for container registry with stress tests.

Tests the ContainerRegistry class including basic CRUD operations,
cache consistency, concurrent reads, and stress testing.
"""

import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

import registry as _registry_module
from registry import ContainerRegistry


@pytest.fixture
def time_control():
    """Controllable time mock for registry tests.

    Replaces time.time() in the registry module so tests can advance
    time instantly instead of sleeping.
    """
    _now = [1000.0]
    _original = _registry_module.time.time

    def _fake_time():
        return _now[0]

    def _advance(seconds):
        _now[0] += seconds

    _registry_module.time.time = _fake_time
    try:
        yield _advance
    finally:
        _registry_module.time.time = _original


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


class TestBasicCRUD:
    """Tests for basic CRUD operations."""

    def test_register_new_container(self, registry):
        """Test registering a new container."""
        config = registry.register(
            container_id="test-container",
            ip_address="172.17.0.2",
        )
        assert config.container_id == "test-container"
        assert config.ip_address == "172.17.0.2"
        assert config.ttl_seconds == 86400  # default

    def test_register_with_custom_ttl(self, registry):
        """Test registering with custom TTL."""
        config = registry.register(
            container_id="short-lived",
            ip_address="172.17.0.3",
            ttl_seconds=3600,
        )
        assert config.ttl_seconds == 3600

    def test_register_with_metadata(self, registry):
        """Test registering with metadata."""
        config = registry.register(
            container_id="metadata-container",
            ip_address="172.17.0.4",
            metadata={"env": "test", "version": "1.0"},
        )
        assert config.metadata == {"env": "test", "version": "1.0"}

    def test_get_by_ip(self, registry):
        """Test looking up container by IP."""
        registry.register(container_id="lookup-test", ip_address="172.17.0.5")
        config = registry.get_by_ip("172.17.0.5")
        assert config is not None
        assert config.container_id == "lookup-test"

    def test_get_by_ip_not_found(self, registry):
        """Test lookup for non-existent IP returns None."""
        config = registry.get_by_ip("192.168.1.1")
        assert config is None

    def test_get_by_container_id(self, registry):
        """Test looking up container by ID."""
        registry.register(container_id="id-lookup", ip_address="172.17.0.6")
        config = registry.get_by_container_id("id-lookup")
        assert config is not None
        assert config.ip_address == "172.17.0.6"

    def test_get_by_container_id_not_found(self, registry):
        """Test lookup for non-existent ID returns None."""
        config = registry.get_by_container_id("nonexistent")
        assert config is None

    def test_unregister(self, registry):
        """Test unregistering a container."""
        registry.register(container_id="to-remove", ip_address="172.17.0.7")
        assert registry.unregister("to-remove") is True
        assert registry.get_by_container_id("to-remove") is None

    def test_unregister_not_found(self, registry):
        """Test unregistering non-existent container returns False."""
        assert registry.unregister("nonexistent") is False

    def test_renew(self, registry, time_control):
        """Test renewing registration updates last_seen."""
        registry.register(container_id="renewable", ip_address="172.17.0.8")
        original = registry.get_by_container_id("renewable")
        time_control(0.1)
        renewed = registry.renew("renewable")
        assert renewed is not None
        assert renewed.last_seen > original.last_seen

    def test_renew_not_found(self, registry):
        """Test renewing non-existent container returns None."""
        assert registry.renew("nonexistent") is None

    def test_list_all(self, registry):
        """Test listing all containers."""
        registry.register(container_id="list-1", ip_address="172.17.0.10")
        registry.register(container_id="list-2", ip_address="172.17.0.11")
        all_containers = registry.list_all()
        assert len(all_containers) == 2
        ids = {c.container_id for c in all_containers}
        assert ids == {"list-1", "list-2"}

    def test_count(self, registry):
        """Test container count."""
        assert registry.count() == 0
        registry.register(container_id="count-1", ip_address="172.17.0.12")
        assert registry.count() == 1
        registry.register(container_id="count-2", ip_address="172.17.0.13")
        assert registry.count() == 2

    def test_update_existing_registration(self, registry):
        """Test updating an existing registration."""
        registry.register(container_id="updatable", ip_address="172.17.0.14")
        updated = registry.register(
            container_id="updatable",
            ip_address="172.17.0.15",
            ttl_seconds=7200,
        )
        assert updated.ip_address == "172.17.0.15"
        assert updated.ttl_seconds == 7200
        assert registry.count() == 1

    def test_ip_conflict_raises(self, registry):
        """Test that IP conflict with different container raises."""
        registry.register(container_id="first", ip_address="172.17.0.16")
        with pytest.raises(ValueError, match="already registered"):
            registry.register(container_id="second", ip_address="172.17.0.16")


class TestCacheConsistency:
    """Tests for cache consistency with database."""

    def test_cache_reflects_registration(self, registry):
        """Test cache is updated on registration."""
        registry.register(container_id="cached", ip_address="172.17.0.20")
        # Immediate lookup should hit cache
        config = registry.get_by_ip("172.17.0.20")
        assert config is not None

    def test_cache_reflects_unregistration(self, registry):
        """Test cache is cleared on unregistration."""
        registry.register(container_id="to-clear", ip_address="172.17.0.21")
        registry.unregister("to-clear")
        assert registry.get_by_ip("172.17.0.21") is None

    def test_cache_reflects_ip_change(self, registry):
        """Test cache handles container IP change."""
        registry.register(container_id="moving", ip_address="172.17.0.22")
        registry.register(container_id="moving", ip_address="172.17.0.23")
        assert registry.get_by_ip("172.17.0.22") is None
        assert registry.get_by_ip("172.17.0.23") is not None

    def test_expired_entry_removed_from_cache(self, registry, time_control):
        """Test expired entries are removed on access."""
        registry.register(
            container_id="expiring",
            ip_address="172.17.0.24",
            ttl_seconds=1,
        )
        time_control(1.5)
        assert registry.get_by_ip("172.17.0.24") is None

    def test_cleanup_expired(self, registry, time_control):
        """Test cleanup_expired removes all expired entries."""
        registry.register(container_id="old1", ip_address="172.17.0.25", ttl_seconds=1)
        registry.register(container_id="old2", ip_address="172.17.0.26", ttl_seconds=1)
        registry.register(container_id="fresh", ip_address="172.17.0.27", ttl_seconds=3600)
        time_control(1.5)
        removed = registry.cleanup_expired()
        assert removed == 2
        assert registry.count() == 1
        assert registry.get_by_container_id("fresh") is not None

    def test_persistence_across_instances(self, temp_db):
        """Test data persists across registry instances."""
        reg1 = ContainerRegistry(db_path=temp_db)
        reg1.register(container_id="persistent", ip_address="172.17.0.28")
        reg1.close()

        reg2 = ContainerRegistry(db_path=temp_db)
        config = reg2.get_by_container_id("persistent")
        assert config is not None
        assert config.ip_address == "172.17.0.28"
        reg2.close()


class TestConcurrentReads:
    """Tests for concurrent read operations."""

    def test_concurrent_reads_same_key(self, registry):
        """Test multiple threads reading the same key."""
        registry.register(container_id="shared", ip_address="172.17.0.30")
        results = []
        errors = []

        def reader():
            try:
                for _ in range(100):
                    config = registry.get_by_ip("172.17.0.30")
                    if config:
                        results.append(config.container_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 1000
        assert all(r == "shared" for r in results)

    def test_concurrent_reads_different_keys(self, registry):
        """Test multiple threads reading different keys."""
        for i in range(10):
            registry.register(container_id=f"container-{i}", ip_address=f"172.17.0.{40+i}")

        results = {i: [] for i in range(10)}
        errors = []

        def reader(idx):
            try:
                for _ in range(50):
                    config = registry.get_by_ip(f"172.17.0.{40+idx}")
                    if config:
                        results[idx].append(config.container_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        for i in range(10):
            assert len(results[i]) == 50
            assert all(r == f"container-{i}" for r in results[i])


class TestStressTest:
    """Stress tests: 100 concurrent lookups + 10 writes/sec."""

    def test_stress_concurrent_lookups_with_writes(self, registry):
        """Stress test: 100 concurrent lookups with 10 writes/sec for 3 seconds."""
        # Pre-populate registry
        for i in range(50):
            registry.register(container_id=f"stress-{i}", ip_address=f"172.17.1.{i}")

        read_count = [0]
        write_count = [0]
        errors = []
        stop_event = threading.Event()

        def reader():
            while not stop_event.is_set():
                try:
                    idx = read_count[0] % 50
                    config = registry.get_by_ip(f"172.17.1.{idx}")
                    if config:
                        read_count[0] += 1
                except Exception as e:
                    errors.append(("read", e))

        def writer():
            while not stop_event.is_set():
                try:
                    idx = 50 + (write_count[0] % 50)
                    registry.register(
                        container_id=f"stress-write-{idx}",
                        ip_address=f"172.17.2.{idx % 256}",
                    )
                    write_count[0] += 1
                    time.sleep(0.1)  # 10 writes/sec
                except Exception as e:
                    errors.append(("write", e))

        # Start 100 reader threads
        reader_threads = [threading.Thread(target=reader) for _ in range(100)]
        # Start writer threads (aim for ~10 writes/sec total)
        writer_threads = [threading.Thread(target=writer) for _ in range(2)]

        for t in reader_threads + writer_threads:
            t.start()

        # Run for 3 seconds
        time.sleep(3)
        stop_event.set()

        for t in reader_threads + writer_threads:
            t.join(timeout=2)

        # Verify results
        assert not errors, f"Errors occurred: {errors}"
        assert read_count[0] > 100, f"Expected many reads, got {read_count[0]}"
        assert write_count[0] >= 20, f"Expected ~30 writes, got {write_count[0]}"

    def test_high_throughput_reads(self, registry):
        """Test high throughput read operations using thread pool."""
        # Pre-populate
        for i in range(100):
            registry.register(container_id=f"throughput-{i}", ip_address=f"172.17.3.{i}")

        successful_reads = [0]
        lock = threading.Lock()

        def read_task(idx):
            config = registry.get_by_ip(f"172.17.3.{idx % 100}")
            if config:
                with lock:
                    successful_reads[0] += 1
            return config is not None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(read_task, i) for i in range(1000)]
            results = [f.result() for f in as_completed(futures)]

        assert all(results)
        assert successful_reads[0] == 1000


class TestContainerConfig:
    """Tests for ContainerConfig dataclass."""

    def test_is_expired_false(self, registry):
        """Test is_expired returns False for fresh registration."""
        config = registry.register(
            container_id="fresh",
            ip_address="172.17.0.50",
            ttl_seconds=3600,
        )
        assert not config.is_expired

    def test_is_expired_true(self, registry):
        """Test is_expired returns True after TTL."""
        config = registry.register(
            container_id="old",
            ip_address="172.17.0.51",
            ttl_seconds=1,
        )
        time.sleep(1.5)
        assert config.is_expired

    def test_to_dict(self, registry):
        """Test to_dict serialization."""
        config = registry.register(
            container_id="serialize-me",
            ip_address="172.17.0.52",
            metadata={"key": "value"},
        )
        d = config.to_dict()
        assert d["container_id"] == "serialize-me"
        assert d["ip_address"] == "172.17.0.52"
        assert d["metadata"] == {"key": "value"}
        assert "registered_at" in d
        assert "last_seen" in d
        assert "ttl_seconds" in d


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
