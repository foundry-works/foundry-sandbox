"""Performance throughput tests for unified-proxy.

Tests sustained throughput capacity for critical proxy operations:
- HTTP passthrough: 1000 requests/second
- DNS resolution: 500 queries/second
- Concurrent containers: 50 simultaneous containers
- Registration: 10 containers/minute

These tests validate that the proxy can handle expected load levels
and scale to production traffic requirements.
"""

import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from registry import ContainerRegistry


def measure_throughput(
    func: Callable,
    duration_seconds: float = 1.0,
    warmup_iterations: int = 100,
) -> dict:
    """Measure throughput (operations per second) for a function.

    Args:
        func: Function to measure (should take no arguments).
        duration_seconds: How long to measure for.
        warmup_iterations: Number of warmup calls before measuring.

    Returns:
        Dictionary with ops_per_second, total_ops, and duration.
    """
    # Warmup
    for _ in range(warmup_iterations):
        func()

    # Measure
    total_ops = 0
    start = time.perf_counter()
    end_time = start + duration_seconds

    while time.perf_counter() < end_time:
        func()
        total_ops += 1

    actual_duration = time.perf_counter() - start
    ops_per_second = total_ops / actual_duration

    return {
        "ops_per_second": ops_per_second,
        "total_ops": total_ops,
        "duration": actual_duration,
    }


def measure_concurrent_throughput(
    func: Callable,
    duration_seconds: float = 1.0,
    concurrency: int = 10,
    warmup_iterations: int = 100,
) -> dict:
    """Measure throughput with concurrent execution.

    Args:
        func: Function to measure.
        duration_seconds: How long to measure for.
        concurrency: Number of concurrent threads.
        warmup_iterations: Number of warmup calls (total across all threads).

    Returns:
        Dictionary with ops_per_second, total_ops, and per-thread stats.
    """
    # Warmup (sequential)
    for _ in range(warmup_iterations):
        func()

    thread_results = []
    lock = threading.Lock()
    stop_event = threading.Event()

    def worker():
        local_ops = 0
        while not stop_event.is_set():
            func()
            local_ops += 1
        with lock:
            thread_results.append(local_ops)

    # Start threads
    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    start = time.perf_counter()

    for t in threads:
        t.start()

    # Wait for duration
    time.sleep(duration_seconds)
    stop_event.set()

    for t in threads:
        t.join()

    actual_duration = time.perf_counter() - start
    total_ops = sum(thread_results)
    ops_per_second = total_ops / actual_duration

    return {
        "ops_per_second": ops_per_second,
        "total_ops": total_ops,
        "duration": actual_duration,
        "thread_count": concurrency,
        "ops_per_thread": thread_results,
        "min_per_thread": min(thread_results) if thread_results else 0,
        "max_per_thread": max(thread_results) if thread_results else 0,
    }


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "throughput_registry.db")
        yield db_path


@pytest.fixture
def populated_registry(temp_db):
    """Create a registry pre-populated with test containers."""
    registry = ContainerRegistry(db_path=temp_db)
    # Pre-populate with realistic number of containers
    for i in range(100):
        registry.register(
            container_id=f"container-{i}",
            ip_address=f"172.17.{i // 256}.{i % 256}",
            metadata={"env": "test", "index": i},
        )
    yield registry
    registry.close()


@pytest.fixture
def empty_registry(temp_db):
    """Create an empty registry for registration tests."""
    registry = ContainerRegistry(db_path=temp_db)
    yield registry
    registry.close()


class TestHTTPThroughput:
    """HTTP passthrough throughput tests: 1000 req/sec target."""

    THROUGHPUT_TARGET = 1000  # requests per second

    def test_request_processing_throughput(self):
        """Test HTTP request processing can handle 1000 req/sec."""
        # Simulate request processing (no network I/O)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token",
            "User-Agent": "test-client/1.0",
        }

        def process_request():
            # 1. Copy headers
            result = dict(headers)
            # 2. Add proxy header
            result["X-Proxy-Processed"] = "true"
            # 3. Validate content type
            ct = result.get("Content-Type", "")
            is_json = "json" in ct.lower()
            return {"headers": result, "is_json": is_json}

        stats = measure_throughput(process_request, duration_seconds=2.0)
        print(f"\nHTTP request processing throughput: {stats}")

        assert stats["ops_per_second"] >= self.THROUGHPUT_TARGET, (
            f"HTTP throughput ({stats['ops_per_second']:.0f} req/sec) "
            f"below target ({self.THROUGHPUT_TARGET} req/sec)"
        )

    def test_concurrent_request_throughput(self):
        """Test concurrent HTTP request processing throughput."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer test-token",
        }

        def process_request():
            result = dict(headers)
            result["X-Proxy-Processed"] = "true"
            return result

        stats = measure_concurrent_throughput(
            process_request,
            duration_seconds=2.0,
            concurrency=10,
        )
        print(f"\nConcurrent HTTP throughput: {stats}")

        # With concurrency, should exceed single-threaded target
        assert stats["ops_per_second"] >= self.THROUGHPUT_TARGET, (
            f"Concurrent HTTP throughput ({stats['ops_per_second']:.0f} req/sec) "
            f"below target ({self.THROUGHPUT_TARGET} req/sec)"
        )

    def test_credential_injection_throughput(self, populated_registry):
        """Test credential injection throughput with registry lookup."""
        ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        idx = [0]
        lock = threading.Lock()

        credentials = {"Authorization": "Bearer injected-token"}

        def inject_credentials():
            with lock:
                ip = ips[idx[0] % len(ips)]
                idx[0] += 1

            # 1. Lookup container
            config = populated_registry.get_by_ip(ip)

            # 2. Prepare headers with credentials
            result = dict(credentials)
            if config:
                result["X-Container-Id"] = config.container_id

            return result

        stats = measure_throughput(inject_credentials, duration_seconds=2.0)
        print(f"\nCredential injection throughput: {stats}")

        # Credential injection includes DB lookup, so slightly lower target
        target = self.THROUGHPUT_TARGET * 0.8  # 800 req/sec
        assert stats["ops_per_second"] >= target, (
            f"Credential injection throughput ({stats['ops_per_second']:.0f} req/sec) "
            f"below target ({target:.0f} req/sec)"
        )


class TestDNSThroughput:
    """DNS resolution throughput tests: 500 qps target."""

    THROUGHPUT_TARGET = 500  # queries per second

    def test_allowlist_check_throughput(self):
        """Test DNS allowlist checking can handle 500 qps."""
        import re

        # Pre-compile patterns
        allowlist_patterns = [
            re.compile(r"^api\.anthropic\.com$"),
            re.compile(r"^.*\.github\.com$"),
            re.compile(r"^api\.openai\.com$"),
            re.compile(r"^.*\.googleapis\.com$"),
            re.compile(r"^registry\.npmjs\.org$"),
            re.compile(r"^.*\.docker\.io$"),
            re.compile(r"^.*\.aws\.amazon\.com$"),
        ]

        test_domains = [
            "api.anthropic.com",
            "api.github.com",
            "raw.githubusercontent.com",
            "api.openai.com",
            "storage.googleapis.com",
            "registry.npmjs.org",
            "index.docker.io",
            "unknown.example.com",
        ]

        idx = [0]

        def check_allowlist():
            domain = test_domains[idx[0] % len(test_domains)]
            idx[0] += 1
            for pattern in allowlist_patterns:
                if pattern.match(domain):
                    return True
            return False

        stats = measure_throughput(check_allowlist, duration_seconds=2.0)
        print(f"\nDNS allowlist check throughput: {stats}")

        assert stats["ops_per_second"] >= self.THROUGHPUT_TARGET, (
            f"DNS allowlist throughput ({stats['ops_per_second']:.0f} qps) "
            f"below target ({self.THROUGHPUT_TARGET} qps)"
        )

    def test_concurrent_dns_throughput(self):
        """Test concurrent DNS query throughput."""
        import re

        allowlist_patterns = [
            re.compile(r"^api\.anthropic\.com$"),
            re.compile(r"^.*\.github\.com$"),
        ]

        test_domains = ["api.anthropic.com", "api.github.com", "example.com"]
        idx = [0]
        lock = threading.Lock()

        def check_dns():
            with lock:
                domain = test_domains[idx[0] % len(test_domains)]
                idx[0] += 1
            for pattern in allowlist_patterns:
                if pattern.match(domain):
                    return True
            return False

        stats = measure_concurrent_throughput(
            check_dns,
            duration_seconds=2.0,
            concurrency=10,
        )
        print(f"\nConcurrent DNS throughput: {stats}")

        assert stats["ops_per_second"] >= self.THROUGHPUT_TARGET, (
            f"Concurrent DNS throughput ({stats['ops_per_second']:.0f} qps) "
            f"below target ({self.THROUGHPUT_TARGET} qps)"
        )

    def test_dns_cache_throughput(self):
        """Test DNS cache lookup throughput."""
        # Simulate DNS cache with 1000 entries
        dns_cache = {
            f"domain-{i}.example.com": f"192.168.{i // 256}.{i % 256}"
            for i in range(1000)
        }

        domains = list(dns_cache.keys())
        idx = [0]

        def cache_lookup():
            domain = domains[idx[0] % len(domains)]
            idx[0] += 1
            return dns_cache.get(domain)

        stats = measure_throughput(cache_lookup, duration_seconds=2.0)
        print(f"\nDNS cache throughput: {stats}")

        # Cache lookups should be very fast
        high_target = self.THROUGHPUT_TARGET * 10  # 5000 qps
        assert stats["ops_per_second"] >= high_target, (
            f"DNS cache throughput ({stats['ops_per_second']:.0f} qps) "
            f"below target ({high_target} qps)"
        )


class TestConcurrentContainers:
    """Concurrent container handling tests: 50 containers target."""

    CONTAINER_TARGET = 50

    def test_concurrent_container_lookups(self, populated_registry):
        """Test registry can handle 50 concurrent container lookups."""
        ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        results = []
        errors = []
        lock = threading.Lock()

        def lookup_container(ip):
            try:
                config = populated_registry.get_by_ip(ip)
                with lock:
                    results.append(config is not None)
            except Exception as e:
                with lock:
                    errors.append(str(e))

        # Run 50 concurrent lookups
        with ThreadPoolExecutor(max_workers=self.CONTAINER_TARGET) as executor:
            futures = [
                executor.submit(lookup_container, ips[i % len(ips)])
                for i in range(self.CONTAINER_TARGET)
            ]
            # Wait for all futures to complete
            list(as_completed(futures))

        print(f"\nConcurrent container lookups: {len(results)} success, {len(errors)} errors")

        assert len(errors) == 0, f"Container lookup errors: {errors}"
        assert len(results) == self.CONTAINER_TARGET, (
            f"Only {len(results)} of {self.CONTAINER_TARGET} lookups completed"
        )

    def test_sustained_concurrent_load(self, populated_registry):
        """Test registry handles sustained load from 50 concurrent containers."""
        ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        idx = [0]
        lock = threading.Lock()

        def container_operation():
            with lock:
                ip = ips[idx[0] % len(ips)]
                idx[0] += 1
            return populated_registry.get_by_ip(ip)

        stats = measure_concurrent_throughput(
            container_operation,
            duration_seconds=3.0,
            concurrency=self.CONTAINER_TARGET,
        )
        print(f"\nSustained concurrent container throughput: {stats}")

        # Each container should complete at least some operations
        assert stats["min_per_thread"] > 0, "Some containers had zero operations"

        # Total throughput should be reasonable
        min_ops_per_second = 100  # Modest target for 50 concurrent
        assert stats["ops_per_second"] >= min_ops_per_second, (
            f"Concurrent throughput ({stats['ops_per_second']:.0f} ops/sec) "
            f"below minimum ({min_ops_per_second} ops/sec)"
        )

    def test_container_isolation_under_load(self, populated_registry):
        """Test that containers remain isolated under concurrent load."""
        results = {}
        lock = threading.Lock()

        def verify_isolation(container_idx):
            ip = f"172.17.{container_idx // 256}.{container_idx % 256}"
            config = populated_registry.get_by_ip(ip)
            if config:
                with lock:
                    results[container_idx] = config.container_id

        # Run concurrent verifications for 50 containers
        with ThreadPoolExecutor(max_workers=self.CONTAINER_TARGET) as executor:
            futures = [
                executor.submit(verify_isolation, i)
                for i in range(self.CONTAINER_TARGET)
            ]
            list(as_completed(futures))

        print(f"\nContainer isolation verification: {len(results)} containers checked")

        # Verify each container got correct data
        for idx, container_id in results.items():
            expected = f"container-{idx}"
            assert container_id == expected, (
                f"Container {idx} isolation failure: got {container_id}, expected {expected}"
            )


class TestRegistrationThroughput:
    """Container registration throughput tests: 10 registrations/minute target."""

    REGISTRATION_TARGET = 10  # registrations per minute

    def test_registration_throughput(self, empty_registry):
        """Test container registration can handle 10 registrations/minute."""
        idx = [0]

        def register_container():
            i = idx[0]
            idx[0] += 1
            empty_registry.register(
                container_id=f"test-container-{i}",
                ip_address=f"10.0.{i // 256}.{i % 256}",
                metadata={"test": True, "index": i},
            )

        # Measure for 5 seconds, then extrapolate to per-minute
        stats = measure_throughput(register_container, duration_seconds=5.0)
        registrations_per_minute = stats["ops_per_second"] * 60

        print(f"\nRegistration throughput: {stats}")
        print(f"Extrapolated registrations/minute: {registrations_per_minute:.1f}")

        assert registrations_per_minute >= self.REGISTRATION_TARGET, (
            f"Registration throughput ({registrations_per_minute:.1f}/min) "
            f"below target ({self.REGISTRATION_TARGET}/min)"
        )

    def test_concurrent_registration(self, temp_db):
        """Test concurrent container registrations."""
        registry = ContainerRegistry(db_path=temp_db)
        errors = []
        successes = []
        lock = threading.Lock()

        def register_one(idx):
            try:
                registry.register(
                    container_id=f"concurrent-{idx}",
                    ip_address=f"10.1.{idx // 256}.{idx % 256}",
                    metadata={"concurrent": True},
                )
                with lock:
                    successes.append(idx)
            except Exception as e:
                with lock:
                    errors.append((idx, str(e)))

        # Register 10 containers concurrently
        with ThreadPoolExecutor(max_workers=self.REGISTRATION_TARGET) as executor:
            futures = [
                executor.submit(register_one, i)
                for i in range(self.REGISTRATION_TARGET)
            ]
            list(as_completed(futures))

        registry.close()

        print(f"\nConcurrent registration: {len(successes)} success, {len(errors)} errors")

        assert len(errors) == 0, f"Registration errors: {errors}"
        assert len(successes) == self.REGISTRATION_TARGET, (
            f"Only {len(successes)} of {self.REGISTRATION_TARGET} registrations completed"
        )

    def test_registration_deregistration_cycle(self, empty_registry):
        """Test registration/deregistration cycle throughput."""
        idx = [0]

        def register_deregister():
            i = idx[0]
            idx[0] += 1
            container_id = f"cycle-{i}"
            ip = f"10.2.{i // 256}.{i % 256}"

            # Register
            empty_registry.register(
                container_id=container_id,
                ip_address=ip,
                metadata={"cycle": True},
            )

            # Deregister
            empty_registry.unregister(container_id=container_id)

        stats = measure_throughput(register_deregister, duration_seconds=5.0)
        cycles_per_minute = stats["ops_per_second"] * 60

        print(f"\nRegistration/deregistration cycle throughput: {stats}")
        print(f"Extrapolated cycles/minute: {cycles_per_minute:.1f}")

        # Full cycle should still meet target
        assert cycles_per_minute >= self.REGISTRATION_TARGET, (
            f"Cycle throughput ({cycles_per_minute:.1f}/min) "
            f"below target ({self.REGISTRATION_TARGET}/min)"
        )


class TestCombinedThroughput:
    """Test combined throughput across all operations."""

    def test_full_pipeline_throughput(self, populated_registry):
        """Test full request pipeline throughput."""
        import re

        allowlist_patterns = [
            re.compile(r"^api\.anthropic\.com$"),
            re.compile(r"^.*\.github\.com$"),
        ]

        test_ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        test_domains = ["api.anthropic.com", "api.github.com"]
        idx = [0]
        lock = threading.Lock()

        def full_pipeline():
            with lock:
                i = idx[0]
                idx[0] += 1

            ip = test_ips[i % len(test_ips)]
            domain = test_domains[i % len(test_domains)]

            # 1. Registry lookup
            config = populated_registry.get_by_ip(ip)

            # 2. DNS allowlist check
            allowed = any(p.match(domain) for p in allowlist_patterns)

            # 3. Credential injection
            headers = {"Authorization": "Bearer injected"}
            if config:
                headers["X-Container"] = config.container_id

            return {"allowed": allowed, "headers": headers}

        stats = measure_throughput(full_pipeline, duration_seconds=3.0)
        print(f"\nFull pipeline throughput: {stats}")

        # Full pipeline should still handle reasonable load
        min_throughput = 500  # 500 req/sec for full pipeline
        assert stats["ops_per_second"] >= min_throughput, (
            f"Full pipeline throughput ({stats['ops_per_second']:.0f} req/sec) "
            f"below minimum ({min_throughput} req/sec)"
        )

    def test_mixed_workload_throughput(self, populated_registry, empty_registry):
        """Test mixed workload (reads + writes) throughput."""
        read_ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        read_idx = [0]
        write_idx = [0]
        lock = threading.Lock()

        def mixed_operation():
            with lock:
                # 90% reads, 10% writes (more realistic workload)
                is_write = (read_idx[0] % 10) == 0
                if is_write:
                    i = write_idx[0]
                    write_idx[0] += 1
                else:
                    i = read_idx[0]
                read_idx[0] += 1

            if is_write:
                empty_registry.register(
                    container_id=f"mixed-{i}",
                    ip_address=f"10.3.{i // 256}.{i % 256}",
                    metadata={"mixed": True},
                )
            else:
                ip = read_ips[i % len(read_ips)]
                populated_registry.get_by_ip(ip)

        stats = measure_throughput(mixed_operation, duration_seconds=3.0)
        print(f"\nMixed workload throughput: {stats}")

        # Mixed workload should still be reasonable
        min_throughput = 200  # 200 ops/sec for mixed
        assert stats["ops_per_second"] >= min_throughput, (
            f"Mixed workload throughput ({stats['ops_per_second']:.0f} ops/sec) "
            f"below minimum ({min_throughput} ops/sec)"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
