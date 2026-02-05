# ADR-001: Unified Proxy Consolidation

## Status

Accepted

Date: 2026-02-04
Implemented: 2026-02-05

### Implementation Notes

The unified-proxy has been fully implemented, consolidating the gateway and api-proxy into a single mitmproxy-based service with the following components:

- **Container Registry** (`registry.py`) - SQLite-backed identity storage with TTL
- **Internal API** (`internal_api.py`) - Flask REST API for container registration
- **Addon Chain** - 7 addons handling identity, credentials, git, rate limiting, circuit breaker, policy, and metrics
- **DNS Filter** - Integrated dnsmasq-based DNS filtering

The gateway/ directory and lib/gateway.sh have been deleted. All functionality migrated to unified-proxy/.

## Context

The foundry-sandbox project currently maintains TWO separate proxy components for credential isolation and request interception:

1. **Gateway Service** (`/workspace/gateway/`) - A Python/Flask-based service on port 8080
   - Handles Git operations (Smart HTTP)
   - Manages session tokens for container isolation
   - Validates repository access and enforces history protection (force-push blocking)
   - Proxies requests to github.com
   - Maintains domain allowlist for egress filtering
   - Listens on TCP port 8080 (exposed to host for session management)

2. **API Proxy Service** (`/workspace/api-proxy/`) - A mitmproxy-based addon on port 8080
   - Injects API credentials into HTTP/HTTPS requests
   - Supports multiple providers (Anthropic, OpenAI, Google, Tavily, Semantic Scholar, Perplexity, Zhipu, GitHub)
   - Handles OAuth token refresh interception
   - Manages credential placeholders for sandboxed environments
   - Performs HTTPS inspection via mitmproxy with certificate injection
   - Also maintains the same domain allowlist for egress filtering

### Current Problems

1. **Port Conflict**: Both services attempt to listen on port 8080, requiring complex Docker networking and volume sharing
2. **Duplicate Functionality**:
   - Domain allowlist logic duplicated in both gateway and api-proxy
   - Both services perform egress filtering independently
   - Credential placeholder handling exists only in api-proxy, but could be unified
3. **Operational Complexity**:
   - Two separate containers in the Docker Compose setup
   - Separate health checks and startup procedures
   - Shared configuration file (`firewall-allowlist.generated`) mounted to both containers
   - Separate dependency declarations in `docker-compose.credential-isolation.yml`
4. **Maintenance Burden**:
   - Bug fixes in domain matching logic must be applied in two places
   - Credential injection logic is isolated to mitmproxy addon
   - Git proxy logic in Flask is separate from HTTP/HTTPS credential injection
5. **Request Routing Complexity**:
   - Git requests route through gateway → github.com
   - API requests route through api-proxy with TLS interception
   - Sandboxes must be configured with both HTTP_PROXY and session tokens
6. **Security Surface Area**:
   - Two separate services with different codebases and maintenance patterns
   - Multiple points for credential handling increases risk if either service is compromised
   - Mitmproxy with custom addon has significant complexity (certificate handling, flow interception)

## Decision

Consolidate both proxy services into a single **unified-proxy** component that:

1. **Single Service Architecture**:
   - Combine gateway and api-proxy into `/workspace/unified-proxy/`
   - Single Python/Flask-based service (replacing both gateway.py and mitmproxy addon)
   - Listen on a single port (8080)
   - Single health check and startup procedure

2. **Unified Request Handling**:
   - Route ALL traffic (Git and API) through the same service
   - Handle both Git Smart HTTP protocol and general HTTP/HTTPS requests
   - Maintain session-based access control for all operations

3. **Integrated Credential Management**:
   - Single credential cache for all providers
   - Unified placeholder detection and real credential injection
   - Support both Bearer and x-api-key header formats
   - Handle OAuth token refresh interception

4. **Unified Domain Allowlist**:
   - Single domain allowlist loading and validation
   - Centralized egress filtering for all request types
   - Remove duplication of hostname matching logic

5. **Consolidated Configuration**:
   - Single environment variable set
   - Single Docker volume mount for firewall config
   - Single health check endpoint

## Consequences

### Positive

- **Reduced Operational Complexity**: Single service instead of two reduces startup time, health checks, dependency management, and troubleshooting
- **Unified Security Model**: Single point of credential handling reduces attack surface and simplifies security reviews
- **Easier Maintenance**: Domain allowlist changes, credential injection logic, and egress filtering have single implementations
- **Simplified Networking**: Single port (8080) instead of two competing services, reduces Docker networking complexity
- **Better Resource Utilization**: One container image, one process, reduced memory footprint
- **Consistent Error Handling**: Unified error responses and audit logging across all request types
- **Simplified Testing**: Single service to test, shared test utilities for both Git and API requests
- **Easier Future Enhancement**: Adding new providers, protocols, or security features requires only one codebase update

### Negative

- **Migration Complexity**: Requires rewriting the mitmproxy addon into Flask middleware for HTTPS interception
- **HTTPS Interception Learning Curve**: Requires implementing custom certificate generation and TLS handling (mitmproxy handled this automatically)
- **Larger Single Service**: Single service becomes more complex with combined responsibilities
- **Shorter Startup Window**: Can no longer run services in parallel during container startup
- **Rewritten Test Suite**: Existing tests for both services must be consolidated and rewritten
- **Potential Performance Impact**: Depending on HTTPS implementation, may need optimization for TLS handshake overhead
- **Technical Debt During Transition**: Old code must be carefully decommissioned to avoid service disruption

### Neutral

- **Protocol Support Changes**: Shift from mitmproxy framework (mature, widely-tested) to custom Flask-based TLS handling (more control, potentially less battle-tested)
- **Development Time**: Consolidation requires initial development effort but pays long-term dividends in maintenance
- **Deployment Image Size**: Slight reduction in total image size (two smaller images → one medium image)

## Alternatives Considered

### Alternative 1: Improve Current Two-Service Model
- **Approach**: Keep gateway and api-proxy separate but reduce duplication
- **How**: Extract shared domain allowlist into library; improve communication between services
- **Rejection Reason**: Still maintains complexity of two services, two ports, two containers; doesn't address fundamental operational burden

### Alternative 2: Replace Mitmproxy with Envoy/HAProxy
- **Approach**: Use mature proxy framework as intermediary between gateway and external APIs
- **How**: Chain gateway → envoy → api destinations
- **Rejection Reason**: Adds another layer of complexity; doesn't consolidate credential handling; increases operational burden further

### Alternative 3: API Gateway Framework (Kong, Tyk)
- **Approach**: Use specialized API gateway platform
- **How**: Deploy Kong/Tyk as central proxy for credential injection and routing
- **Rejection Reason**: External dependency adds operational complexity; overkill for this use case; increases attack surface; reduces control over credential handling

### Alternative 4: Partial Consolidation (Dual Protocols)
- **Approach**: Keep gateway as main service, add HTTP/HTTPS credential injection to it
- **How**: Extend gateway.py to handle both Git protocol and general HTTP/HTTPS credential injection
- **Rejection Reason**: This IS the recommended approach; it's a subset of full consolidation and still valid as an incremental step

## References

- `/workspace/gateway/gateway.py` - (deleted; migrated to `unified-proxy/`)
- `/workspace/api-proxy/inject-credentials.py` - (deleted; migrated to `unified-proxy/addons/credential_injector.py`)
- `/workspace/docker-compose.credential-isolation.yml` - Unified single-service composition
- `/workspace/docs/security/credential-isolation.md` - Credential isolation security model
- `/workspace/docs/architecture.md` - System architecture documentation
- NIST SP 800-12 Rev. 1 - Principles of defense in depth (consolidation reduces complexity for same security)
