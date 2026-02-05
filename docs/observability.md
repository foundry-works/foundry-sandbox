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

### Critical Alerts

```yaml
# Circuit breaker opened (upstream failing)
- alert: ProxyCircuitBreakerOpen
  expr: proxy_circuit_breaker_state == 2
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "Circuit breaker open for {{ $labels.upstream_host }}"
    description: "Container {{ $labels.container_id }} circuit to {{ $labels.upstream_host }} is open"

# High error rate
- alert: ProxyHighErrorRate
  expr: |
    sum(rate(proxy_requests_total{status=~"5.."}[5m]))
    / sum(rate(proxy_requests_total[5m])) > 0.1
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High proxy error rate"
    description: "Error rate exceeds 10% for 5 minutes"
```

### Warning Alerts

```yaml
# Rate limit approaching
- alert: ProxyRateLimitLow
  expr: proxy_rate_limit_remaining < 10
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "Rate limit running low"
    description: "Container {{ $labels.container_id }} has few rate limit tokens remaining"

# High latency
- alert: ProxyHighLatency
  expr: |
    histogram_quantile(0.95,
      rate(proxy_request_duration_seconds_bucket[5m])
    ) > 5
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High proxy latency"
    description: "P95 latency exceeds 5 seconds"

# DNS resolution slow
- alert: ProxyDNSSlowResolution
  expr: |
    histogram_quantile(0.95,
      rate(proxy_dns_duration_seconds_bucket[5m])
    ) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Slow DNS resolution"
    description: "P95 DNS latency exceeds 100ms"
```

## Debugging Workflows

### Request Tracing

1. **Find request ID** from client logs or error message
2. **Search proxy logs** by request_id:
   ```bash
   docker logs unified-proxy 2>&1 | grep "req-abc123"
   ```
3. **Follow the flow** through addons:
   - container_identity (identification)
   - credential_injector (credential injection)
   - rate_limiter (throttling decision)
   - circuit_breaker (upstream health)

### Circuit Breaker Investigation

1. **Check circuit state**:
   ```bash
   curl -s http://unified-proxy:9090/internal/metrics | grep circuit_breaker
   ```
2. **Review failure logs**:
   ```bash
   docker logs unified-proxy 2>&1 | grep -i "circuit\|failure" | tail -50
   ```
3. **Check upstream health**:
   ```bash
   curl -v https://api.anthropic.com/health
   ```

### Rate Limit Investigation

1. **Check remaining tokens**:
   ```bash
   curl -s http://unified-proxy:9090/internal/metrics | grep rate_limit
   ```
2. **Review rate limit logs**:
   ```bash
   docker logs unified-proxy 2>&1 | grep "rate limit" | tail -20
   ```
3. **Identify high-volume container**:
   ```promql
   topk(5, sum by (container_id) (rate(proxy_requests_total[5m])))
   ```

### DNS Resolution Issues

1. **Check DNS metrics**:
   ```bash
   curl -s http://unified-proxy:9090/internal/metrics | grep dns
   ```
2. **Review blocked queries**:
   ```bash
   docker logs unified-proxy 2>&1 | grep "dns.*blocked\|NXDOMAIN"
   ```
3. **Verify allowlist** includes the domain

### Container Identity Issues

1. **Check registration**:
   ```bash
   curl -s --unix-socket /var/run/unified-proxy/internal.sock \
     http://localhost/internal/containers
   ```
2. **Review identity logs**:
   ```bash
   docker logs unified-proxy 2>&1 | grep "identity\|unknown.*ip"
   ```
3. **Verify container IP** matches registration

## Metrics Endpoint

Access metrics at the internal API endpoint:

```bash
# From inside Docker network
curl http://unified-proxy:9090/internal/metrics

# Sample output
# HELP proxy_requests_total Total HTTP requests processed by the proxy
# TYPE proxy_requests_total counter
proxy_requests_total{container_id="sandbox-abc",upstream_host="api.anthropic.com",method="POST",status="200"} 42
```

## See Also

- [Architecture](architecture.md) - System components
- [ADR-005](adr/005-failure-modes.md) - Failure modes and resilience
- [Operations](operations.md) - Operational procedures
