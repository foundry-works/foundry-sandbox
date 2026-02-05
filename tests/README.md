# Test Suite

This document describes the test structure, categories, and targets for the Foundry Sandbox test suite.

## Quick Start

```bash
# Run all tests
pytest tests/

# Run specific category
pytest tests/unit/
pytest tests/integration/
pytest tests/security/
pytest tests/performance/

# Run shell tests
./tests/run.sh

# Run security red-team tests (inside sandbox)
./tests/redteam-sandbox.sh
```

## Test Structure

```
tests/
├── unit/                    # Unit tests (fast, isolated)
│   ├── test_registry.py     # Container registry CRUD, cache, concurrency
│   ├── test_container_identity.py  # IP-based container identification
│   ├── test_circuit_breaker.py     # Circuit breaker state machine
│   ├── test_rate_limiter.py        # Token bucket rate limiting
│   ├── test_policy_engine.py       # Policy evaluation and enforcement
│   ├── test_dns_filter.py          # DNS allowlist filtering
│   ├── test_git_proxy.py           # Git protocol parsing
│   └── test_pktline.py             # Git pkt-line encoding/decoding
│
├── integration/             # Integration tests (component interactions)
│   ├── test_git_operations.py      # Git clone/push through proxy
│   ├── test_api_proxy.py           # API credential injection
│   └── test_container_lifecycle.py # Container registration/renewal
│
├── security/                # Security tests (adversarial scenarios)
│   └── test_git_policy.py   # Git policy bypass attempts
│
├── performance/             # Performance tests (latency, throughput)
│   ├── test_latency.py      # p99 latency budgets
│   └── test_throughput.py   # Operations per second
│
├── run.sh                   # Shell test runner
├── redteam-sandbox.sh       # Security red-team tests (run in sandbox)
├── test-pip-requirements.sh # Python dependency validation
├── test-pip-install-integration.sh  # pip install test
└── test_validate.sh         # Configuration validation
```

## Unit Tests

Unit tests validate individual components in isolation using mocks. They run fast and don't require network or Docker.

### Test Files

| File | Component | Coverage |
|------|-----------|----------|
| `test_registry.py` | `ContainerRegistry` | CRUD operations, cache consistency, TTL expiration, concurrent access, stress tests |
| `test_container_identity.py` | `ContainerIdentityAddon` | IP-based lookup, flow annotation, cache behavior |
| `test_circuit_breaker.py` | `CircuitBreakerAddon` | State transitions (closed→open→half-open), failure counting, timeout recovery |
| `test_rate_limiter.py` | `RateLimiterAddon` | Token bucket algorithm, per-container limits, refill behavior |
| `test_policy_engine.py` | `PolicyEngineAddon` | Policy evaluation, allowlist/blocklist, default actions |
| `test_dns_filter.py` | `DNSFilterAddon` | Domain matching, wildcard patterns, NXDOMAIN responses |
| `test_git_proxy.py` | `GitProxyAddon` | URL parsing, ref extraction, operation detection |
| `test_pktline.py` | `pktline` module | Packet encoding/decoding, flush packets, side-band |

### Running Unit Tests

```bash
# All unit tests
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ --cov=unified-proxy --cov-report=term-missing

# Specific test file
pytest tests/unit/test_registry.py -v

# Specific test class
pytest tests/unit/test_registry.py::TestBasicCRUD -v
```

## Integration Tests

Integration tests validate component interactions through the proxy stack. They use mocked HTTP responses to simulate real protocols.

### Test Files

| File | Scenario | Coverage |
|------|----------|----------|
| `test_git_operations.py` | Git through proxy | Clone, push, credential injection, branch policies, bot mode restrictions |
| `test_api_proxy.py` | API requests | Anthropic/OpenAI/Gemini credential injection, header manipulation |
| `test_container_lifecycle.py` | Container management | Registration, renewal, expiration, re-registration |

### Running Integration Tests

```bash
# All integration tests
pytest tests/integration/ -v

# With verbose output
pytest tests/integration/ -v --capture=no
```

## Security Tests

Security tests validate defense against adversarial scenarios. Each test class represents a category of attack.

### Test File: `test_git_policy.py`

| Attack Category | Tests |
|-----------------|-------|
| Unauthorized repo access | Requests to non-allowlisted repos blocked |
| Branch deletion bypass | Force push, symbolic refs, path traversal all blocked |
| Auth mode bypass | Bot containers restricted to sandbox/* branches |
| Push size evasion | Large pushes rejected regardless of chunking |

### Security Properties

- **Unauthorized repository access is always blocked**
- **Branch/tag deletion cannot be circumvented**
- **Auth mode restrictions cannot be bypassed**
- **Push size limits cannot be evaded**

### Running Security Tests

```bash
# All security tests
pytest tests/security/ -v

# With full assertion output
pytest tests/security/ -v --tb=long
```

## Performance Tests

Performance tests validate latency and throughput targets under load.

### Latency Targets (`test_latency.py`)

| Operation | p99 Target | Measurement |
|-----------|------------|-------------|
| HTTP passthrough | < 50ms | End-to-end proxy overhead |
| Credential injection | < 10ms | Header manipulation time |
| DNS resolution | < 50ms | Allowlist lookup + upstream query |
| Registry lookup | < 1ms | In-memory cache + SQLite |

### Throughput Targets (`test_throughput.py`)

| Operation | Target | Description |
|-----------|--------|-------------|
| HTTP passthrough | 1000 req/s | Sustained request rate |
| DNS resolution | 500 queries/s | DNS query handling |
| Concurrent containers | 50 | Simultaneous active containers |
| Registration | 10 containers/min | New container onboarding |

### Running Performance Tests

```bash
# All performance tests
pytest tests/performance/ -v

# Skip slow tests (CI mode)
pytest tests/performance/ -v -m "not slow"

# With detailed timing
pytest tests/performance/ -v --durations=10
```

## Shell Tests

Shell tests validate sandbox behavior and CLI functionality.

### Test Files

| File | Purpose |
|------|---------|
| `run.sh` | Main test runner (help, list, status, config, info commands) |
| `redteam-sandbox.sh` | Security red-team tests (run inside sandbox) |
| `test-pip-requirements.sh` | Python dependency installation |
| `test-pip-install-integration.sh` | pip install integration test |
| `test_validate.sh` | Configuration file validation |

### Red-Team Tests (`redteam-sandbox.sh`)

**Run inside the sandbox container.** Validates credential isolation:

1. **Environment credential leakage** - No real API keys in environment
2. **Proxy bypass attempts** - Direct connections blocked
3. **DNS exfiltration** - External DNS queries blocked
4. **Filesystem credential hunting** - No credentials in mounted volumes
5. **Network isolation** - Only allowlisted destinations reachable

```bash
# Inside sandbox container
./tests/redteam-sandbox.sh
```

## Test Configuration

### pytest.ini

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    security: security-focused tests
    performance: performance benchmarks
```

### Required Dependencies

```
pytest>=7.0
pytest-cov>=4.0
pytest-timeout>=2.0
```

## Writing New Tests

### Unit Test Template

```python
"""Unit tests for <component>."""

import pytest

@pytest.fixture
def component():
    """Create component instance for testing."""
    return MyComponent()

class TestFeature:
    """Tests for specific feature."""

    def test_happy_path(self, component):
        """Test normal operation."""
        result = component.do_thing()
        assert result == expected

    def test_edge_case(self, component):
        """Test edge case handling."""
        with pytest.raises(ValueError):
            component.do_thing(invalid_input)
```

### Security Test Template

```python
"""Security tests for <attack category>."""

import pytest

class TestAttackCategory:
    """Tests for specific attack vector."""

    def test_attack_variant_blocked(self):
        """Verify attack variant is blocked."""
        # Attempt attack
        result = attempt_attack()
        # Verify blocked
        assert result.blocked
        assert "denied" in result.message
```

## CI Integration

Tests run automatically on:
- Pull request creation
- Push to main branch
- Nightly performance regression

### Recommended CI Configuration

```yaml
test:
  script:
    - pytest tests/unit/ tests/integration/ tests/security/ -v --junitxml=report.xml
    - pytest tests/performance/ -v -m "not slow"
  artifacts:
    reports:
      junit: report.xml
```

## See Also

- [Architecture](../docs/architecture.md) - System components
- [Security](../docs/security/index.md) - Security model
- [Operations](../docs/operations.md) - Operational procedures
