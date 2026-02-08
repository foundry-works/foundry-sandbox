# ADR-001: Unified Proxy Architecture

## Status

Accepted

Date: 2026-02-04

## Context

The foundry-sandbox project requires a proxy component for credential isolation and request interception. The proxy must handle:

1. **Git operations** — Smart HTTP protocol proxying to github.com, with credential injection, branch isolation, and history protection (force-push blocking)
2. **API credential injection** — HTTPS MITM to inject API keys (Anthropic, OpenAI, Google, Tavily, Semantic Scholar, Perplexity, Zhipu, GitHub) into outbound requests
3. **Domain allowlist enforcement** — Egress filtering for all request types
4. **DNS filtering** — Allowlist-based DNS resolution to block non-permitted domains
5. **OAuth token refresh interception** — Transparent credential refresh for AI tool CLIs
6. **Container identity** — Per-container session management for multi-sandbox deployments

### Constraints

1. **Single port**: Docker networking is simplest with a single proxy endpoint
2. **Unified allowlist**: Domain allowlist logic should exist in one place
3. **Security surface**: Fewer services means fewer points of compromise for credential handling
4. **Operational simplicity**: One container to monitor, one health check, one startup sequence
5. **Credential co-location**: Git credentials and API keys are managed by the same trust boundary

## Decision

Implement a single **unified-proxy** service that handles all proxy responsibilities:

### Single Service Architecture

- All proxy functionality lives in `/workspace/unified-proxy/`
- mitmproxy-based service listening on port 8080 (HTTP/HTTPS) and optionally port 53 (DNS)
- Internal API via Unix socket (`/var/run/proxy/internal.sock`) for health checks, metrics, and container registration
- Single Docker container in the compose setup

### Components

- **Container Registry** (`registry.py`) — SQLite-backed identity storage with TTL and WAL mode
- **Internal API** (`internal_api.py`) — Flask REST API for container registration and health checks
- **Addon Chain** — 7 mitmproxy addons handling:
  - Container identity (`container_identity.py`)
  - Credential injection (`credential_injector.py`)
  - Git proxy (`git_proxy.py`)
  - Rate limiting (`rate_limiter.py`)
  - Circuit breaker (`circuit_breaker.py`)
  - Policy engine (`policy_engine.py`)
  - Metrics (`metrics.py`)
- **DNS Filter** (`dns_filter.py`) — Integrated mitmproxy DNS filtering addon

### Unified Request Handling

- ALL traffic (Git and API) routes through the same service
- Handles both Git Smart HTTP protocol and general HTTP/HTTPS requests
- Maintains per-container access control for all operations
- Single domain allowlist loading and validation (`config/allowlist.yaml`)

### Integrated Credential Management

- Single credential cache for all providers
- Unified placeholder detection and real credential injection
- Supports Bearer, x-api-key, and request body credential formats
- Handles OAuth token refresh interception

### Consolidated Configuration

- Single set of environment variables
- Single Docker volume mount for allowlist config
- Single health check endpoint via Unix socket

## Consequences

### Positive

- **Reduced Operational Complexity**: Single service reduces startup time, health checks, dependency management, and troubleshooting
- **Unified Security Model**: Single point of credential handling reduces attack surface and simplifies security reviews
- **Easier Maintenance**: Domain allowlist, credential injection, and egress filtering have single implementations
- **Simplified Networking**: Single port (8080) with simple Docker networking
- **Better Resource Utilization**: One container image, one process, reduced memory footprint
- **Consistent Error Handling**: Unified error responses and audit logging across all request types
- **Simplified Testing**: Single service to test, shared test utilities for both Git and API requests

### Negative

- **Single Point of Failure**: If the unified proxy goes down, all sandbox operations fail (mitigated by fail-closed design — see [ADR-005](005-failure-modes.md))
- **Larger Single Service**: Combined responsibilities increase per-service complexity
- **Sequential Startup**: Cannot parallelize proxy initialization across multiple services

### Neutral

- **mitmproxy Foundation**: Built on mitmproxy framework for mature, well-tested TLS handling and flow interception
- **Addon Architecture**: mitmproxy addon chain provides clean separation of concerns within the single service
- **Image Size**: Single medium-sized image rather than multiple smaller ones

## Alternatives Considered

### Alternative 1: Separate Gateway and API Proxy Services

- **Approach**: Run two separate proxy containers — one for Git operations, one for API credential injection
- **Rejection Reason**: Duplicates domain allowlist logic, requires complex Docker networking for two competing port 8080 services, doubles operational burden (two health checks, two startup sequences, two codebases to maintain), and increases credential handling attack surface

### Alternative 2: Envoy/HAProxy as Intermediary

- **Approach**: Use a mature proxy framework as intermediary between services and external APIs
- **Rejection Reason**: Adds another layer of complexity; doesn't consolidate credential handling; increases operational burden further

### Alternative 3: API Gateway Framework (Kong, Tyk)

- **Approach**: Use a specialized API gateway platform
- **Rejection Reason**: External dependency adds operational complexity; overkill for single-tenant sandbox use case; increases attack surface; reduces control over credential handling

## References

- `unified-proxy/entrypoint.sh` — Proxy startup with internal API, addon validation, and mitmproxy
- `unified-proxy/registry.py` — SQLite-backed container registry
- `unified-proxy/addons/` — mitmproxy addon chain
- `docker-compose.credential-isolation.yml` — Single-service composition
- [Security Architecture](../security/security-architecture.md) — Security pillars overview
- [Credential Isolation](../security/credential-isolation.md) — Credential isolation threat model
- [Architecture](../architecture.md) — System architecture documentation
