# Observability Guide

This guide covers metrics, logging, and alerting for the unified proxy.

## Prometheus Metrics

The unified proxy exposes Prometheus metrics at `/internal/metrics`.

### HTTP Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxy_requests_total` | Counter | container_id, upstream_host, method, status | Total HTTP requests processed |
| `proxy_request_duration_seconds` | Histogram | container_id, upstream_host | Request latency in seconds |

**Latency Buckets**: 10ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s

### DNS Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxy_dns_queries_total` | Counter | container_id, query_type, result | Total DNS queries processed |
| `proxy_dns_duration_seconds` | Histogram | container_id, query_type | DNS query latency in seconds |

**DNS Latency Buckets**: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms

### Rate Limiter Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxy_rate_limit_remaining` | Gauge | container_id, upstream_host | Remaining rate limit tokens |

### Circuit Breaker Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxy_circuit_breaker_state` | Gauge | container_id, upstream_host | Circuit state (0=closed, 1=half-open, 2=open) |

**State Values**:
- `0` = CLOSED (healthy, passing traffic)
- `1` = HALF_OPEN (testing recovery)
- `2` = OPEN (failing fast, blocking traffic)

## Structured Logging

The unified proxy uses JSON-formatted logs for machine parsing.

### Log Format

```json
{
  "timestamp": "2026-02-05T13:45:00.123456Z",
  "level": "INFO",
  "message": "Processing request",
  "logger": "addons.credential_injector",
  "request_id": "req-abc123",
  "container_id": "sandbox-xyz",
  "upstream_host": "api.anthropic.com",
  "method": "POST",
  "path": "/v1/messages"
}
```

### Log Fields

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp with microseconds |
| `level` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `message` | Human-readable log message |
| `logger` | Logger name (usually module path) |
| `request_id` | Unique request identifier for tracing |
| `container_id` | Source container identifier |
| Additional fields | Context-specific data |

### Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `LOG_LEVEL` | INFO | Minimum log level |
| `LOG_FORMAT` | json | Output format (json or text) |
| `LOG_INCLUDE_TIMESTAMP` | true | Include timestamps |
| `LOG_INCLUDE_LOCATION` | true | Include file/line info |

### Correlation IDs

Each request is assigned a `request_id` for end-to-end tracing:

```python
from logging_config import set_context, clear_context

# At request start
set_context(request_id="req-123", container_id="sandbox-abc")

# All subsequent logs include these IDs
logger.info("Processing request")  # Includes request_id, container_id

# At request end
clear_context()
```

## Recommended Alerts

> These alerts are relevant for team or multi-tenant deployments where Prometheus is configured. For single-user setups, the [troubleshooting procedures](operations.md#troubleshooting) are typically sufficient.

| Alert | Expression | Severity | Trigger |
|-------|-----------|----------|---------|
| Circuit breaker open | `proxy_circuit_breaker_state == 2` | Critical | Upstream failing for 1m |
| High error rate | `5xx rate / total rate > 0.1` | Critical | >10% errors for 5m |
| Rate limit low | `proxy_rate_limit_remaining < 10` | Warning | Few tokens remaining for 2m |
| High latency | `p95 request duration > 5s` | Warning | Sustained for 5m |
| Slow DNS | `p95 DNS duration > 100ms` | Warning | Sustained for 5m |

For debugging procedures (request tracing, circuit breaker investigation, rate limiting, DNS resolution, container identity), see [Operations: Troubleshooting](operations.md#troubleshooting).

## Metrics Endpoint

Access metrics at the internal API endpoint:

```bash
# From inside Docker network
curl http://unified-proxy:8080/internal/metrics

# Sample output
# HELP proxy_requests_total Total HTTP requests processed by the proxy
# TYPE proxy_requests_total counter
proxy_requests_total{container_id="sandbox-abc",upstream_host="api.anthropic.com",method="POST",status="200"} 42
```

## Git Operation Audit Logs

The git API server (`git_operations.py`) emits structured audit log entries for all git operations. These logs use the `git_audit` logger and include detailed context for security investigation.

### Audit Log Fields

| Field | Description |
|-------|-------------|
| `event` | Event type (e.g., `git_operation`) |
| `action` | Git subcommand executed (e.g., `push`, `fetch`, `checkout`) |
| `decision` | Outcome: `allowed`, `denied`, or `error` |
| `sandbox_id` | Sandbox identity from HMAC authentication |
| `container_id` | Source container identifier |
| `reason` | Explanation for denied operations (e.g., branch isolation violation) |
| `matched_rule` | Which policy rule matched (e.g., `protected_branch`, `branch_isolation`) |
| `command_args` | Git command arguments (sanitized) |
| `exit_code` | Process exit code for executed commands |
| `policy_version` | Policy schema version for audit compatibility |
| `request_id` | Unique request identifier for tracing |

### Example Queries

```bash
# Find all denied git operations
docker logs unified-proxy 2>&1 | grep '"decision": "denied"'

# Find branch isolation violations
docker logs unified-proxy 2>&1 | grep 'branch_isolation'

# Find operations by a specific sandbox
docker logs unified-proxy 2>&1 | grep '"sandbox_id": "abc123"'

# Find protected branch enforcement events
docker logs unified-proxy 2>&1 | grep 'protected_branch'
```

## See Also

- [Architecture](architecture.md) — System components
- [ADR-005](adr/005-failure-modes.md) — Failure modes and resilience
- [Operations](operations.md) — Operational procedures
