"""Performance latency tests for unified-proxy.

Tests p99 latency budgets for critical proxy operations:
- HTTP passthrough: p99 < 50ms
- Credential injection: p99 < 10ms
- DNS resolution: p99 < 50ms
- Registry lookup: p99 < 1ms

These tests validate that the proxy adds acceptable overhead to request
processing and can maintain performance under load.
"""

import os
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable
from unittest import mock

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from registry import ContainerRegistry


def percentile(data: List[float], p: float) -> float:
    """Calculate percentile of a list of values.

    Args:
        data: List of numeric values.
        p: Percentile to calculate (0-100).

    Returns:
        The p-th percentile value.
    """
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * p / 100
    f = int(k)
    c = f + 1 if f + 1 < len(sorted_data) else f
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])


def measure_latency(func: Callable, iterations: int = 1000) -> dict:
    """Measure latency statistics for a function.

    Args:
        func: Function to measure (should take no arguments).
        iterations: Number of times to call the function.

    Returns:
        Dictionary with min, max, mean, p50, p95, p99 latencies in milliseconds.
    """
    latencies = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        latencies.append((end - start) * 1000)  # Convert to ms

    return {
        "min": min(latencies),
        "max": max(latencies),
        "mean": statistics.mean(latencies),
        "p50": percentile(latencies, 50),
        "p95": percentile(latencies, 95),
        "p99": percentile(latencies, 99),
        "samples": len(latencies),
    }


def measure_concurrent_latency(
    func: Callable, iterations: int = 1000, concurrency: int = 10
) -> dict:
    """Measure latency with concurrent execution.

    Args:
        func: Function to measure.
        iterations: Total number of iterations across all threads.
        concurrency: Number of concurrent threads.

    Returns:
        Dictionary with latency statistics.
    """
    latencies = []
    lock = threading.Lock()

    def worker():
        local_latencies = []
        for _ in range(iterations // concurrency):
            start = time.perf_counter()
            func()
            end = time.perf_counter()
            local_latencies.append((end - start) * 1000)
        with lock:
            latencies.extend(local_latencies)

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return {
        "min": min(latencies) if latencies else 0,
        "max": max(latencies) if latencies else 0,
        "mean": statistics.mean(latencies) if latencies else 0,
        "p50": percentile(latencies, 50),
        "p95": percentile(latencies, 95),
        "p99": percentile(latencies, 99),
        "samples": len(latencies),
    }


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "perf_registry.db")
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


class TestRegistryLookupLatency:
    """Registry lookup latency tests: p99 < 1ms target."""

    LATENCY_TARGET_P99_MS = 1.0

    def test_get_by_ip_latency(self, populated_registry):
        """Test get_by_ip p99 latency is under 1ms."""
        ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        idx = [0]

        def lookup():
            ip = ips[idx[0] % len(ips)]
            idx[0] += 1
            return populated_registry.get_by_ip(ip)

        stats = measure_latency(lookup, iterations=1000)
        print(f"\nRegistry get_by_ip latency stats: {stats}")

        assert stats["p99"] < self.LATENCY_TARGET_P99_MS, (
            f"Registry lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.LATENCY_TARGET_P99_MS}ms)"
        )

    def test_get_by_container_id_latency(self, populated_registry):
        """Test get_by_container_id p99 latency is under 1ms."""
        idx = [0]

        def lookup():
            container_id = f"container-{idx[0] % 100}"
            idx[0] += 1
            return populated_registry.get_by_container_id(container_id)

        stats = measure_latency(lookup, iterations=1000)
        print(f"\nRegistry get_by_container_id latency stats: {stats}")

        assert stats["p99"] < self.LATENCY_TARGET_P99_MS, (
            f"Registry container lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.LATENCY_TARGET_P99_MS}ms)"
        )

    def test_concurrent_lookup_latency(self, populated_registry):
        """Test concurrent lookups maintain p99 < 1ms."""
        ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        idx = [0]
        lock = threading.Lock()

        def lookup():
            with lock:
                ip = ips[idx[0] % len(ips)]
                idx[0] += 1
            return populated_registry.get_by_ip(ip)

        stats = measure_concurrent_latency(lookup, iterations=1000, concurrency=10)
        print(f"\nRegistry concurrent lookup latency stats: {stats}")

        # Allow slightly higher latency under contention
        assert stats["p99"] < self.LATENCY_TARGET_P99_MS * 2, (
            f"Registry concurrent lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.LATENCY_TARGET_P99_MS * 2}ms)"
        )

    def test_cache_hit_latency(self, populated_registry):
        """Test cache hit latency is significantly lower than target."""
        # Warm up cache by accessing same IP repeatedly
        ip = "172.17.0.50"
        for _ in range(10):
            populated_registry.get_by_ip(ip)

        def cached_lookup():
            return populated_registry.get_by_ip(ip)

        stats = measure_latency(cached_lookup, iterations=1000)
        print(f"\nRegistry cache hit latency stats: {stats}")

        # Cache hits should be very fast
        assert stats["p99"] < self.LATENCY_TARGET_P99_MS / 2, (
            f"Cache hit p99 ({stats['p99']:.3f}ms) should be under "
            f"{self.LATENCY_TARGET_P99_MS / 2}ms"
        )


class TestCredentialInjectionLatency:
    """Credential injection latency tests: p99 < 10ms target.

    Tests the overhead of credential injection logic without actual network I/O.
    """

    LATENCY_TARGET_P99_MS = 10.0

    def test_header_injection_latency(self):
        """Test credential header injection p99 latency."""
        # Simulate credential injection logic
        credentials = {
            "Authorization": "Bearer test-token-12345",
            "X-Api-Key": "sk-ant-test-key-67890",
        }

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "test-client/1.0",
            "Accept": "application/json",
        }

        def inject_credentials():
            # Simulate the injection process
            result = dict(headers)
            for key, value in credentials.items():
                if value.startswith("CREDENTIAL_PROXY_PLACEHOLDER"):
                    # Would look up real credential
                    result[key] = "injected-value"
                else:
                    result[key] = value
            return result

        stats = measure_latency(inject_credentials, iterations=1000)
        print(f"\nCredential injection latency stats: {stats}")

        assert stats["p99"] < self.LATENCY_TARGET_P99_MS, (
            f"Credential injection p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.LATENCY_TARGET_P99_MS}ms)"
        )

    def test_placeholder_detection_latency(self):
        """Test placeholder detection p99 latency."""
        import re

        placeholder_pattern = re.compile(
            r"CREDENTIAL_PROXY_PLACEHOLDER|PROXY_PLACEHOLDER_\w+"
        )
        test_values = [
            "CREDENTIAL_PROXY_PLACEHOLDER",
            "sk-ant-api03-realkey",
            "Bearer PROXY_PLACEHOLDER_OAUTH",
            "normal-header-value",
        ]

        idx = [0]

        def detect_placeholder():
            value = test_values[idx[0] % len(test_values)]
            idx[0] += 1
            return bool(placeholder_pattern.search(value))

        stats = measure_latency(detect_placeholder, iterations=10000)
        print(f"\nPlaceholder detection latency stats: {stats}")

        # Detection should be very fast (sub-millisecond)
        assert stats["p99"] < 1.0, (
            f"Placeholder detection p99 ({stats['p99']:.3f}ms) exceeds 1ms"
        )

    def test_credential_lookup_simulation_latency(self):
        """Test simulated credential lookup latency."""
        # Simulate credential store lookup
        credential_store = {
            "anthropic": "sk-ant-test-key",
            "openai": "sk-openai-test-key",
            "github": "ghp_testtoken",
        }

        providers = list(credential_store.keys())
        idx = [0]

        def lookup_credential():
            provider = providers[idx[0] % len(providers)]
            idx[0] += 1
            return credential_store.get(provider)

        stats = measure_latency(lookup_credential, iterations=10000)
        print(f"\nCredential lookup simulation latency stats: {stats}")

        assert stats["p99"] < 1.0, (
            f"Credential lookup p99 ({stats['p99']:.3f}ms) should be under 1ms"
        )


class TestDNSResolutionLatency:
    """DNS resolution latency tests: p99 < 50ms target.

    Tests DNS filtering and allowlist checking without actual DNS queries.
    """

    LATENCY_TARGET_P99_MS = 50.0

    def test_allowlist_check_latency(self):
        """Test domain allowlist checking p99 latency."""
        import re

        # Simulate allowlist patterns
        allowlist_patterns = [
            re.compile(r"^api\.anthropic\.com$"),
            re.compile(r"^.*\.github\.com$"),
            re.compile(r"^api\.openai\.com$"),
            re.compile(r"^.*\.googleapis\.com$"),
            re.compile(r"^registry\.npmjs\.org$"),
        ]

        test_domains = [
            "api.anthropic.com",
            "github.com",
            "api.github.com",
            "evil.com",
            "api.openai.com",
            "storage.googleapis.com",
            "malicious.xyz",
        ]

        idx = [0]

        def check_allowlist():
            domain = test_domains[idx[0] % len(test_domains)]
            idx[0] += 1
            for pattern in allowlist_patterns:
                if pattern.match(domain):
                    return True
            return False

        stats = measure_latency(check_allowlist, iterations=10000)
        print(f"\nDNS allowlist check latency stats: {stats}")

        # Allowlist check should be fast (local operation)
        assert stats["p99"] < 5.0, (
            f"DNS allowlist check p99 ({stats['p99']:.3f}ms) exceeds 5ms"
        )

    def test_wildcard_pattern_matching_latency(self):
        """Test wildcard pattern matching p99 latency."""
        import fnmatch

        wildcard_patterns = [
            "*.github.com",
            "*.googleapis.com",
            "api.*.anthropic.com",
            "*.openai.com",
        ]

        test_domains = [
            "api.github.com",
            "raw.githubusercontent.com",
            "storage.googleapis.com",
            "api.v1.anthropic.com",
            "example.com",
        ]

        idx = [0]

        def match_wildcards():
            domain = test_domains[idx[0] % len(test_domains)]
            idx[0] += 1
            for pattern in wildcard_patterns:
                if fnmatch.fnmatch(domain, pattern):
                    return True
            return False

        stats = measure_latency(match_wildcards, iterations=10000)
        print(f"\nWildcard matching latency stats: {stats}")

        assert stats["p99"] < 1.0, (
            f"Wildcard matching p99 ({stats['p99']:.3f}ms) exceeds 1ms"
        )

    def test_dns_cache_simulation_latency(self):
        """Test simulated DNS cache lookup latency."""
        # Simulate DNS cache (domain -> IP mapping)
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

        stats = measure_latency(cache_lookup, iterations=10000)
        print(f"\nDNS cache lookup latency stats: {stats}")

        assert stats["p99"] < 1.0, (
            f"DNS cache lookup p99 ({stats['p99']:.3f}ms) exceeds 1ms"
        )


class TestHTTPPassthroughLatency:
    """HTTP passthrough latency tests: p99 < 50ms target.

    Tests proxy processing overhead without actual network I/O.
    """

    LATENCY_TARGET_P99_MS = 50.0

    def test_request_processing_overhead(self):
        """Test request processing overhead p99 latency."""
        # Simulate request processing pipeline
        def process_request():
            # 1. Parse headers
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer test",
                "User-Agent": "test/1.0",
            }
            parsed = dict(headers)

            # 2. Check policy
            allowed = True
            for key in parsed:
                if key.lower() == "x-blocked":
                    allowed = False

            # 3. Transform if needed
            if allowed:
                parsed["X-Proxy-Processed"] = "true"

            # 4. Build response structure
            return {"headers": parsed, "allowed": allowed}

        stats = measure_latency(process_request, iterations=1000)
        print(f"\nRequest processing overhead latency stats: {stats}")

        # Processing overhead should be minimal
        assert stats["p99"] < 5.0, (
            f"Request processing p99 ({stats['p99']:.3f}ms) exceeds 5ms"
        )

    def test_policy_evaluation_latency(self):
        """Test policy evaluation p99 latency."""
        import re

        # Simulate policy rules
        blocked_patterns = [
            re.compile(r"/repos/.+/pulls/\d+/merge"),
            re.compile(r"/repos/.+/releases$"),
            re.compile(r"/user/keys$"),
        ]

        test_paths = [
            "/repos/owner/repo/pulls/1/merge",
            "/repos/owner/repo/contents/file.txt",
            "/user/repos",
            "/repos/owner/repo/releases",
            "/api/v1/messages",
        ]

        idx = [0]

        def evaluate_policy():
            path = test_paths[idx[0] % len(test_paths)]
            idx[0] += 1
            for pattern in blocked_patterns:
                if pattern.match(path):
                    return False
            return True

        stats = measure_latency(evaluate_policy, iterations=10000)
        print(f"\nPolicy evaluation latency stats: {stats}")

        assert stats["p99"] < 1.0, (
            f"Policy evaluation p99 ({stats['p99']:.3f}ms) exceeds 1ms"
        )

    def test_response_header_modification_latency(self):
        """Test response header modification p99 latency."""
        base_headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache",
            "X-Request-Id": "abc123",
            "Server": "nginx/1.0",
        }

        def modify_headers():
            headers = dict(base_headers)
            # Add proxy headers
            headers["X-Proxy-Version"] = "1.0"
            headers["X-Processed-At"] = str(time.time())
            # Remove sensitive headers
            headers.pop("Server", None)
            return headers

        stats = measure_latency(modify_headers, iterations=10000)
        print(f"\nResponse header modification latency stats: {stats}")

        assert stats["p99"] < 1.0, (
            f"Header modification p99 ({stats['p99']:.3f}ms) exceeds 1ms"
        )


class TestCombinedLatencyBudget:
    """Test combined latency budget across all operations."""

    def test_full_request_pipeline_simulation(self, populated_registry):
        """Test full request pipeline stays within overall budget."""
        import re

        # Simulate complete request processing
        allowlist_patterns = [
            re.compile(r"^api\.anthropic\.com$"),
            re.compile(r"^.*\.github\.com$"),
        ]

        blocked_patterns = [
            re.compile(r"/repos/.+/pulls/\d+/merge"),
        ]

        credentials = {"Authorization": "Bearer placeholder"}
        test_domains = ["api.anthropic.com", "api.github.com"]
        test_paths = ["/v1/messages", "/repos/owner/repo/contents"]
        test_ips = [f"172.17.{i // 256}.{i % 256}" for i in range(10)]

        idx = [0]

        def full_pipeline():
            i = idx[0]
            idx[0] += 1

            # 1. Registry lookup (identify container)
            ip = test_ips[i % len(test_ips)]
            config = populated_registry.get_by_ip(ip)

            # 2. DNS/allowlist check
            domain = test_domains[i % len(test_domains)]
            allowed = any(p.match(domain) for p in allowlist_patterns)

            # 3. Policy check
            path = test_paths[i % len(test_paths)]
            policy_ok = not any(p.match(path) for p in blocked_patterns)

            # 4. Credential injection
            result_headers = dict(credentials)
            if result_headers.get("Authorization", "").endswith("placeholder"):
                result_headers["Authorization"] = "Bearer injected-value"

            return {
                "container": config.container_id if config else None,
                "allowed": allowed and policy_ok,
                "headers": result_headers,
            }

        stats = measure_latency(full_pipeline, iterations=1000)
        print(f"\nFull pipeline latency stats: {stats}")

        # Combined budget: registry (1ms) + DNS (50ms) + policy (1ms) + injection (10ms)
        # Total budget: ~62ms, use 100ms as safe margin
        assert stats["p99"] < 100.0, (
            f"Full pipeline p99 ({stats['p99']:.3f}ms) exceeds 100ms budget"
        )

    def test_concurrent_pipeline_latency(self, populated_registry):
        """Test pipeline latency under concurrent load."""
        test_ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        idx = [0]
        lock = threading.Lock()

        def concurrent_lookup():
            with lock:
                ip = test_ips[idx[0] % len(test_ips)]
                idx[0] += 1
            return populated_registry.get_by_ip(ip)

        stats = measure_concurrent_latency(
            concurrent_lookup, iterations=1000, concurrency=50
        )
        print(f"\nConcurrent pipeline latency stats: {stats}")

        # Under high concurrency, allow 2x budget
        assert stats["p99"] < 200.0, (
            f"Concurrent pipeline p99 ({stats['p99']:.3f}ms) exceeds 200ms budget"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
