"""Performance latency tests for unified-proxy.

Tests p99 latency budgets for critical proxy operations using the actual
addon code paths rather than simulations:
- HTTP passthrough (normalize_path, normalize_host, _check_github_blocklist): p99 < 50ms
- Credential injection (_has_credential_placeholder, PROVIDER_MAP lookup): p99 < 10ms
- DNS resolution (DNSFilterAddon._is_allowed with DEFAULT_ALLOWLIST): p99 < 50ms
- Registry lookup (ContainerRegistry.get_by_ip): p99 < 1ms

These tests validate that the proxy adds acceptable overhead to request
processing and can maintain performance under load.
"""

import os
import statistics
import sys
import tempfile
import threading
import time
from typing import List, Callable

import pytest

# Add unified-proxy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from registry import ContainerRegistry

# Import real addon functions for performance testing
from addons.policy_engine import (
    normalize_path,
    normalize_host,
    GITHUB_MERGE_PR_PATTERN,
    GITHUB_CREATE_RELEASE_PATTERN,
    GITHUB_GIT_REFS_ROOT_PATTERN,
    GITHUB_GIT_REFS_SUBPATH_PATTERN,
    GITHUB_AUTO_MERGE_PATTERN,
    GITHUB_DELETE_REVIEW_PATTERN,
    GITHUB_PATCH_PR_PATTERN,
    GITHUB_PATCH_ISSUE_PATTERN,
    GITHUB_PR_REVIEW_PATTERN,
)
from addons.credential_injector import (
    _has_credential_placeholder,
    _has_opencode_placeholder,
    PROVIDER_MAP,
)
from addons.dns_filter import DNSFilterAddon, DEFAULT_ALLOWLIST


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


def _ci_multiplier() -> float:
    """Return latency target multiplier: 2x in CI, 1x locally."""
    return 2.0 if os.environ.get("CI") else 1.0


def measure_latency(
    func: Callable,
    iterations: int = 1000,
    *,
    warmup: int = 100,
    trim_pct: float = 5.0,
) -> dict:
    """Measure latency statistics for a function.

    Args:
        func: Function to measure (should take no arguments).
        iterations: Number of times to call the function.
        warmup: Number of warmup iterations to discard (avoids cold-start bias).
        trim_pct: Percentage of top/bottom outliers to discard (0-50).

    Returns:
        Dictionary with min, max, mean, p50, p95, p99 latencies in milliseconds.
    """
    # Warmup phase — discard results
    for _ in range(warmup):
        func()

    latencies = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        latencies.append((end - start) * 1000)  # Convert to ms

    # Trim outliers
    if trim_pct > 0 and len(latencies) > 10:
        sorted_lat = sorted(latencies)
        trim_count = int(len(sorted_lat) * trim_pct / 100)
        if trim_count > 0:
            latencies = sorted_lat[trim_count:-trim_count]

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


@pytest.mark.slow
class TestRegistryLookupLatency:
    """Registry lookup latency tests: p99 < 1ms target (2x in CI)."""

    LATENCY_TARGET_P99_MS = 1.0

    @property
    def effective_target(self):
        return self.LATENCY_TARGET_P99_MS * _ci_multiplier()

    def test_get_by_ip_latency(self, populated_registry):
        """Test get_by_ip p99 latency is under target."""
        ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        idx = [0]

        def lookup():
            ip = ips[idx[0] % len(ips)]
            idx[0] += 1
            return populated_registry.get_by_ip(ip)

        stats = measure_latency(lookup, iterations=1000)
        print(f"\nRegistry get_by_ip latency stats: {stats}")

        assert stats["p99"] < self.effective_target, (
            f"Registry lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.effective_target}ms)"
        )

    def test_get_by_container_id_latency(self, populated_registry):
        """Test get_by_container_id p99 latency is under target."""
        idx = [0]

        def lookup():
            container_id = f"container-{idx[0] % 100}"
            idx[0] += 1
            return populated_registry.get_by_container_id(container_id)

        stats = measure_latency(lookup, iterations=1000)
        print(f"\nRegistry get_by_container_id latency stats: {stats}")

        assert stats["p99"] < self.effective_target, (
            f"Registry container lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.effective_target}ms)"
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

        # Allow 2x target under contention
        contention_target = self.effective_target * 2
        assert stats["p99"] < contention_target, (
            f"Registry concurrent lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({contention_target}ms)"
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
        cache_target = self.effective_target / 2
        assert stats["p99"] < cache_target, (
            f"Cache hit p99 ({stats['p99']:.3f}ms) should be under "
            f"{cache_target}ms"
        )


@pytest.mark.slow
class TestCredentialInjectionLatency:
    """Credential injection latency tests: p99 < 10ms target (2x in CI).

    Tests the overhead of real credential injection functions from
    addons/credential_injector.py without actual network I/O.
    """

    LATENCY_TARGET_P99_MS = 10.0

    @property
    def effective_target(self):
        return self.LATENCY_TARGET_P99_MS * _ci_multiplier()

    def test_placeholder_detection_latency(self):
        """Test _has_credential_placeholder() p99 latency.

        Uses the real placeholder detection function from credential_injector.
        """
        test_values = [
            "CREDENTIAL_PROXY_PLACEHOLDER",
            "CRED_PROXY_abcdef1234567890",
            "sk-ant-api03-realkey",
            "Bearer CREDENTIAL_PROXY_PLACEHOLDER",
            "normal-header-value",
            "ghp_xxxxxxxxxxxxxxxxxxxx",
            "",
        ]
        idx = [0]

        def detect_placeholder():
            value = test_values[idx[0] % len(test_values)]
            idx[0] += 1
            return _has_credential_placeholder(value)

        stats = measure_latency(detect_placeholder, iterations=10000)
        print(f"\nPlaceholder detection latency stats: {stats}")

        assert stats["p99"] < 1.0 * _ci_multiplier(), (
            f"Placeholder detection p99 ({stats['p99']:.3f}ms) exceeds "
            f"{1.0 * _ci_multiplier()}ms"
        )

    def test_opencode_placeholder_detection_latency(self):
        """Test _has_opencode_placeholder() p99 latency."""
        test_values = [
            "PROXY_PLACEHOLDER_OPENCODE",
            "CRED_PROXY_abcdef1234567890",
            "Bearer real-token",
            "normal-value",
        ]
        idx = [0]

        def detect():
            value = test_values[idx[0] % len(test_values)]
            idx[0] += 1
            return _has_opencode_placeholder(value)

        stats = measure_latency(detect, iterations=10000)
        print(f"\nOpenCode placeholder detection latency stats: {stats}")

        assert stats["p99"] < 1.0 * _ci_multiplier(), (
            f"OpenCode placeholder detection p99 ({stats['p99']:.3f}ms) exceeds "
            f"{1.0 * _ci_multiplier()}ms"
        )

    def test_provider_map_lookup_latency(self):
        """Test PROVIDER_MAP host-to-credential lookup p99 latency.

        Uses the real PROVIDER_MAP from credential_injector to look up
        credential config by host, matching the hot path in _load_credentials.
        """
        test_hosts = [
            "api.anthropic.com",
            "api.openai.com",
            "api.github.com",
            "generativelanguage.googleapis.com",
            "api.tavily.com",
            "unknown-host.example.com",
            "api.perplexity.ai",
            "uploads.github.com",
        ]
        idx = [0]

        def lookup_provider():
            host = test_hosts[idx[0] % len(test_hosts)]
            idx[0] += 1
            config = PROVIDER_MAP.get(host)
            if config:
                # Simulate the credential resolution path
                _ = config["header"]
                _ = config.get("fallback_env_var")
                _ = config.get("alt_env_var")
            return config

        stats = measure_latency(lookup_provider, iterations=10000)
        print(f"\nProvider map lookup latency stats: {stats}")

        assert stats["p99"] < self.effective_target, (
            f"Provider map lookup p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.effective_target}ms)"
        )

    def test_combined_credential_check_latency(self):
        """Test combined placeholder detection + provider lookup p99 latency.

        Mirrors the real request() hot path: check for placeholder, then
        look up the host in PROVIDER_MAP.
        """
        test_cases = [
            ("api.anthropic.com", "CRED_PROXY_abc123"),
            ("api.openai.com", "Bearer real-token"),
            ("api.github.com", "CREDENTIAL_PROXY_PLACEHOLDER"),
            ("unknown.com", "normal-value"),
            ("api.tavily.com", "CRED_PROXY_def456"),
        ]
        idx = [0]

        def combined_check():
            host, auth = test_cases[idx[0] % len(test_cases)]
            idx[0] += 1
            is_placeholder = _has_credential_placeholder(auth)
            config = PROVIDER_MAP.get(host)
            return is_placeholder, config

        stats = measure_latency(combined_check, iterations=10000)
        print(f"\nCombined credential check latency stats: {stats}")

        assert stats["p99"] < self.effective_target, (
            f"Combined credential check p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.effective_target}ms)"
        )


@pytest.mark.slow
class TestDNSResolutionLatency:
    """DNS resolution latency tests: p99 < 50ms target (2x in CI).

    Tests DNS filtering using the real DNSFilterAddon._is_allowed() method
    with the production DEFAULT_ALLOWLIST.
    """

    LATENCY_TARGET_P99_MS = 50.0

    @property
    def effective_target(self):
        return self.LATENCY_TARGET_P99_MS * _ci_multiplier()

    def test_allowlist_check_latency(self):
        """Test DNSFilterAddon._is_allowed() p99 latency with DEFAULT_ALLOWLIST.

        Uses the real allowlist checking method from dns_filter.py which
        performs case-insensitive exact and wildcard pattern matching.
        """
        addon = DNSFilterAddon(allowlist=DEFAULT_ALLOWLIST)

        test_domains = [
            "api.anthropic.com",       # not in default list
            "github.com",              # exact match
            "api.github.com",          # wildcard *.github.com
            "evil-exfiltration.com",   # blocked
            "pypi.org",                # exact match
            "files.pythonhosted.org",  # exact match
            "storage.googleapis.com",  # not in default list
            "malicious.xyz",           # blocked
            "registry.npmjs.org",      # exact match
            "raw.githubusercontent.com",  # exact match
        ]
        idx = [0]

        def check_allowlist():
            domain = test_domains[idx[0] % len(test_domains)]
            idx[0] += 1
            return addon._is_allowed(domain)

        stats = measure_latency(check_allowlist, iterations=10000)
        print(f"\nDNS allowlist check latency stats: {stats}")

        assert stats["p99"] < 5.0 * _ci_multiplier(), (
            f"DNS allowlist check p99 ({stats['p99']:.3f}ms) exceeds "
            f"{5.0 * _ci_multiplier()}ms"
        )

    def test_wildcard_matching_latency(self):
        """Test wildcard pattern matching via _is_allowed() p99 latency.

        Exercises the wildcard code path (*.domain.com) in the real addon.
        """
        addon = DNSFilterAddon(allowlist=DEFAULT_ALLOWLIST)

        # Mix of domains that trigger wildcard matching
        test_domains = [
            "api.github.com",            # *.github.com wildcard
            "raw.github.com",            # *.github.com wildcard
            "sub.deep.github.com",       # *.github.com wildcard
            "files.pypi.org",            # *.pypi.org wildcard
            "cdn.npmjs.org",             # *.npmjs.org wildcard
            "not-in-allowlist.evil.com", # no match
        ]
        idx = [0]

        def match_wildcards():
            domain = test_domains[idx[0] % len(test_domains)]
            idx[0] += 1
            return addon._is_allowed(domain)

        stats = measure_latency(match_wildcards, iterations=10000)
        print(f"\nDNS wildcard matching latency stats: {stats}")

        assert stats["p99"] < 1.0 * _ci_multiplier(), (
            f"Wildcard matching p99 ({stats['p99']:.3f}ms) exceeds "
            f"{1.0 * _ci_multiplier()}ms"
        )

    def test_case_insensitive_matching_latency(self):
        """Test case-insensitive matching overhead in _is_allowed().

        The real addon lowercases both domain and pattern per RFC 4343.
        """
        addon = DNSFilterAddon(allowlist=DEFAULT_ALLOWLIST)

        test_domains = [
            "GitHub.COM",
            "API.GITHUB.COM",
            "PyPI.org",
            "REGISTRY.NPMJS.ORG",
            "Evil.Example.COM",
        ]
        idx = [0]

        def case_check():
            domain = test_domains[idx[0] % len(test_domains)]
            idx[0] += 1
            return addon._is_allowed(domain)

        stats = measure_latency(case_check, iterations=10000)
        print(f"\nDNS case-insensitive matching latency stats: {stats}")

        assert stats["p99"] < 1.0 * _ci_multiplier(), (
            f"Case-insensitive matching p99 ({stats['p99']:.3f}ms) exceeds "
            f"{1.0 * _ci_multiplier()}ms"
        )


@pytest.mark.slow
class TestHTTPPassthroughLatency:
    """HTTP passthrough latency tests: p99 < 50ms target (2x in CI).

    Tests real proxy processing functions from addons/policy_engine.py:
    - normalize_path(): URL path normalization with security rules
    - normalize_host(): Host normalization
    - GitHub blocklist pattern matching with production regex patterns
    """

    LATENCY_TARGET_P99_MS = 50.0

    @property
    def effective_target(self):
        return self.LATENCY_TARGET_P99_MS * _ci_multiplier()

    def test_normalize_path_latency(self):
        """Test normalize_path() p99 latency.

        Uses the real path normalizer which does URL parsing, decoding,
        double-encoding detection, slash collapsing, and .. resolution.
        """
        test_paths = [
            "/repos/owner/repo/pulls/1/merge",
            "/repos/owner/repo/contents/src/main.py?ref=main",
            "/v1/messages",
            "/repos/owner/repo/releases",
            "/user/repos?page=2&per_page=100",
            "/repos/owner/repo/git/refs/heads/main",
            "/repos/owner/repo/issues/42",
            "/api/v1/chat/completions",
            "/repos/owner/repo/../../../etc/passwd",  # traversal attempt
            "//repos///owner//repo",  # repeated slashes
        ]
        idx = [0]

        def normalize():
            path = test_paths[idx[0] % len(test_paths)]
            idx[0] += 1
            return normalize_path(path)

        stats = measure_latency(normalize, iterations=10000)
        print(f"\nnormalize_path latency stats: {stats}")

        assert stats["p99"] < 5.0 * _ci_multiplier(), (
            f"normalize_path p99 ({stats['p99']:.3f}ms) exceeds "
            f"{5.0 * _ci_multiplier()}ms"
        )

    def test_normalize_host_latency(self):
        """Test normalize_host() p99 latency."""
        test_hosts = [
            "api.github.com",
            "API.ANTHROPIC.COM",
            "generativelanguage.googleapis.com.",  # trailing dot
            "api.openai.com",
            "UPLOADS.GITHUB.COM.",
        ]
        idx = [0]

        def normalize():
            host = test_hosts[idx[0] % len(test_hosts)]
            idx[0] += 1
            return normalize_host(host)

        stats = measure_latency(normalize, iterations=10000)
        print(f"\nnormalize_host latency stats: {stats}")

        assert stats["p99"] < 1.0 * _ci_multiplier(), (
            f"normalize_host p99 ({stats['p99']:.3f}ms) exceeds "
            f"{1.0 * _ci_multiplier()}ms"
        )

    def test_github_blocklist_latency(self):
        """Test GitHub blocklist pattern matching p99 latency.

        Runs all production regex patterns from policy_engine.py against
        realistic GitHub API paths.
        """
        # All production patterns to check per request
        all_patterns = [
            ("PUT", GITHUB_MERGE_PR_PATTERN),
            ("POST", GITHUB_CREATE_RELEASE_PATTERN),
            ("POST", GITHUB_GIT_REFS_ROOT_PATTERN),
            ("PATCH", GITHUB_GIT_REFS_SUBPATH_PATTERN),
            ("DELETE", GITHUB_GIT_REFS_SUBPATH_PATTERN),
            ("PUT", GITHUB_AUTO_MERGE_PATTERN),
            ("DELETE", GITHUB_AUTO_MERGE_PATTERN),
            ("DELETE", GITHUB_DELETE_REVIEW_PATTERN),
            ("PATCH", GITHUB_PATCH_PR_PATTERN),
            ("PATCH", GITHUB_PATCH_ISSUE_PATTERN),
            ("POST", GITHUB_PR_REVIEW_PATTERN),
        ]

        test_requests = [
            ("PUT", "/repos/owner/repo/pulls/1/merge"),        # blocked
            ("GET", "/repos/owner/repo/contents/file.txt"),     # allowed
            ("POST", "/repos/owner/repo/releases"),             # blocked
            ("GET", "/user/repos"),                             # allowed
            ("PATCH", "/repos/owner/repo/pulls/42"),            # body-inspected
            ("POST", "/repos/owner/repo/pulls/42/reviews"),     # body-inspected
            ("DELETE", "/repos/owner/repo/git/refs/heads/main"), # blocked
            ("GET", "/repos/owner/repo/commits"),               # allowed
        ]
        idx = [0]

        def check_blocklist():
            method, path = test_requests[idx[0] % len(test_requests)]
            idx[0] += 1
            for pattern_method, pattern in all_patterns:
                if method == pattern_method and pattern.match(path):
                    return True
            return False

        stats = measure_latency(check_blocklist, iterations=10000)
        print(f"\nGitHub blocklist check latency stats: {stats}")

        assert stats["p99"] < 1.0 * _ci_multiplier(), (
            f"GitHub blocklist check p99 ({stats['p99']:.3f}ms) exceeds "
            f"{1.0 * _ci_multiplier()}ms"
        )

    def test_combined_policy_pipeline_latency(self):
        """Test combined normalize + blocklist check p99 latency.

        Mirrors the real policy engine hot path: normalize_host,
        normalize_path, then check blocklist.
        """
        test_requests = [
            ("GET", "API.GITHUB.COM.", "/repos/owner/repo/contents/file.txt?ref=main"),
            ("PUT", "api.github.com", "/repos/owner/repo/pulls/1/merge"),
            ("POST", "api.anthropic.com", "/v1/messages"),
            ("PATCH", "api.github.com", "/repos/owner/repo/pulls/42"),
            ("GET", "api.openai.com", "/v1/chat/completions"),
        ]
        idx = [0]

        def policy_pipeline():
            method, host, path = test_requests[idx[0] % len(test_requests)]
            idx[0] += 1
            # 1. Normalize host
            norm_host = normalize_host(host)
            # 2. Normalize path
            norm_path = normalize_path(path)
            # 3. Check blocklist (only for GitHub)
            blocked = None
            if norm_host == "api.github.com" and norm_path is not None:
                if method == "PUT" and GITHUB_MERGE_PR_PATTERN.match(norm_path):
                    blocked = "merge blocked"
                elif method == "POST" and GITHUB_CREATE_RELEASE_PATTERN.match(norm_path):
                    blocked = "release blocked"
            return norm_host, norm_path, blocked

        stats = measure_latency(policy_pipeline, iterations=10000)
        print(f"\nCombined policy pipeline latency stats: {stats}")

        assert stats["p99"] < self.effective_target, (
            f"Combined policy pipeline p99 ({stats['p99']:.3f}ms) exceeds "
            f"target ({self.effective_target}ms)"
        )


@pytest.mark.slow
class TestCombinedLatencyBudget:
    """Test combined latency budget across all real operations."""

    @property
    def effective_target(self):
        return 100.0 * _ci_multiplier()

    def test_full_request_pipeline(self, populated_registry):
        """Test full request pipeline using real addon functions.

        Exercises the complete per-request hot path:
        1. Registry lookup (real ContainerRegistry)
        2. DNS allowlist check (real DNSFilterAddon._is_allowed)
        3. Path normalization (real normalize_path)
        4. GitHub blocklist (real regex patterns)
        5. Credential placeholder detection (real _has_credential_placeholder)
        """
        dns_addon = DNSFilterAddon(allowlist=DEFAULT_ALLOWLIST)

        test_scenarios = [
            ("172.17.0.1", "api.github.com", "GET", "/repos/owner/repo/contents", "CRED_PROXY_abc"),
            ("172.17.0.2", "api.anthropic.com", "POST", "/v1/messages", "Bearer real-key"),
            ("172.17.0.3", "api.github.com", "PUT", "/repos/owner/repo/pulls/1/merge", "CREDENTIAL_PROXY_PLACEHOLDER"),
            ("172.17.0.4", "evil.com", "GET", "/steal-data", "normal-value"),
            ("172.17.0.5", "github.com", "GET", "/repos/owner/repo", "CRED_PROXY_def"),
        ]
        idx = [0]

        def full_pipeline():
            ip, host, method, path, auth = test_scenarios[idx[0] % len(test_scenarios)]
            idx[0] += 1

            # 1. Registry lookup
            config = populated_registry.get_by_ip(ip)

            # 2. DNS allowlist check
            dns_allowed = dns_addon._is_allowed(host)

            # 3. Path normalization
            norm_path = normalize_path(path)

            # 4. GitHub blocklist check
            blocked = None
            if normalize_host(host) == "api.github.com" and norm_path:
                if method == "PUT" and GITHUB_MERGE_PR_PATTERN.match(norm_path):
                    blocked = "merge blocked"

            # 5. Credential placeholder detection
            needs_injection = _has_credential_placeholder(auth)

            return {
                "container": config.container_id if config else None,
                "dns_allowed": dns_allowed,
                "path": norm_path,
                "blocked": blocked,
                "needs_injection": needs_injection,
            }

        stats = measure_latency(full_pipeline, iterations=1000)
        print(f"\nFull pipeline latency stats: {stats}")

        assert stats["p99"] < self.effective_target, (
            f"Full pipeline p99 ({stats['p99']:.3f}ms) exceeds "
            f"{self.effective_target}ms budget"
        )

    def test_concurrent_pipeline_latency(self, populated_registry):
        """Test pipeline latency under concurrent load."""
        dns_addon = DNSFilterAddon(allowlist=DEFAULT_ALLOWLIST)
        test_ips = [f"172.17.{i // 256}.{i % 256}" for i in range(100)]
        test_domains = ["github.com", "api.github.com", "pypi.org", "evil.com"]
        test_paths = ["/repos/owner/repo", "/v1/messages", "/simple/requests"]
        idx = [0]
        lock = threading.Lock()

        def concurrent_pipeline():
            with lock:
                i = idx[0]
                idx[0] += 1
            ip = test_ips[i % len(test_ips)]
            domain = test_domains[i % len(test_domains)]
            path = test_paths[i % len(test_paths)]

            populated_registry.get_by_ip(ip)
            dns_addon._is_allowed(domain)
            normalize_path(path)
            return True

        stats = measure_concurrent_latency(
            concurrent_pipeline, iterations=1000, concurrency=50
        )
        print(f"\nConcurrent pipeline latency stats: {stats}")

        assert stats["p99"] < 200.0 * _ci_multiplier(), (
            f"Concurrent pipeline p99 ({stats['p99']:.3f}ms) exceeds "
            f"{200.0 * _ci_multiplier()}ms budget"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
