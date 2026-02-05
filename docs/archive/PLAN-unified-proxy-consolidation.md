# Consolidated Proxy Architecture Plan

## Overview

Consolidate the gateway and api-proxy into a single mitmproxy-based service that handles all external traffic (git operations + API calls + DNS). Replace session tokens with container identity.

**Document Structure:**
- This plan covers architecture, key decisions, and implementation details
- Decision records in `docs/adr/`
- Decision records in `docs/adr/`
- Test matrices in `tests/README.md`

## Current Architecture (2 Services)

```
┌─────────────────────────────────────────────────────────┐
│  SANDBOX CONTAINER                                       │
│  - No real credentials                                   │
│  - Session token for git                                 │
│  - Placeholder tokens for APIs                           │
└─────────────────────────────────────────────────────────┘
         │                              │
         │ git (session token)          │ HTTPS (placeholder)
         ▼                              ▼
┌─────────────────────┐      ┌─────────────────────────────┐
│  GATEWAY (Flask)    │      │  API-PROXY (mitmproxy)      │
│  - Session mgmt     │      │  - Credential injection     │
│  - Git proxy        │      │  - OAuth token mgmt         │
│  - DNS (dnsmasq)    │      │  - GitHub API filter        │
│  - Policy checks    │      │  - Egress filtering         │
└─────────────────────┘      └─────────────────────────────┘
         │                              │
         ▼                              ▼
    github.com              api.anthropic.com, etc.
```

**Problems:**
- Two services doing similar things (proxying, policy, credential handling)
- Session token indirection adds complexity
- PLAN.md Phase 2 would add GitHub API proxy to gateway → more overlap

## Proposed Architecture (Single Unified Service)

```
┌─────────────────────────────────────────────────────────┐
│  SANDBOX CONTAINER                                       │
│  - No real credentials                                   │
│  - Identified by container IP + container_id             │
│  - HTTP_PROXY / HTTPS_PROXY → unified-proxy:8080        │
│  - DNS → unified-proxy:53                                │
│  - Git uses same proxy (GIT_PROXY_COMMAND or env)        │
└─────────────────────────────────────────────────────────┘
         │
         │ ALL traffic (git + APIs + DNS)
         ▼
┌─────────────────────────────────────────────────────────┐
│  UNIFIED-PROXY (mitmproxy 11+)                          │
│                                                          │
│  Modes: --mode regular@8080 --mode dns@53               │
│                                                          │
│  Addons:                                                 │
│  ├─ container_identity.py    # ID by IP + container_id  │
│  ├─ policy_engine.py         # Centralized policy       │
│  ├─ dns_filter.py            # DNS query filtering      │
│  ├─ git_proxy.py             # Git protocol handling    │
│  ├─ credential_injector.py   # API credential injection │
│  ├─ metrics.py               # Prometheus metrics       │
│  └─ oauth_managers/          # Token refresh handlers   │
│                                                          │
│  Config: allowlist.yaml (single source of truth)        │
└─────────────────────────────────────────────────────────┘
         │
         ▼
   github.com, api.anthropic.com, api.openai.com, etc.
```

## Key Changes

### 1. Container Identity Replaces Sessions

**Before:** Host creates session → gets token → passes to container → container uses token
**After:** Host registers container identity → proxy identifies by client IP

```python
# container_identity.py (new mitmproxy addon)

class ContainerIdentity:
    """Identify containers by source IP. Optional X-Container-Id header for extra validation."""

    def __init__(self, registry):
        self.registry = registry

    def request(self, flow):
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None

        if not client_ip:
            flow.response = Response.make(403, b'{"error": "Cannot determine client IP"}')
            return

        # Primary identification: lookup by source IP
        config = self.registry.get_by_ip(client_ip)

        if not config:
            flow.response = Response.make(403, b'{"error": "Unknown source IP"}')
            return

        # Optional validation: if X-Container-Id header present, verify it matches
        # This catches misconfigurations but is NOT required for access
        header_id = flow.request.headers.get("X-Container-Id")
        if header_id and header_id != config.container_id:
            flow.response = Response.make(403, b'{"error": "Container ID mismatch"}')
            return

        if datetime.now(timezone.utc) > config.expires_at:
            self.registry.unregister(config.container_id)
            flow.response = Response.make(403, b'{"error": "Container registration expired"}')
            return

        # Strip X-Container-Id header before forwarding (don't leak to upstream)
        if "X-Container-Id" in flow.request.headers:
            del flow.request.headers["X-Container-Id"]

        # Attach container config to flow for other addons
        flow.metadata["container"] = config
```

**How identity is set:** The host registers container metadata at creation time:
- Container ID is the Docker container ID (64-char hex, cryptographically random)
- Container IP is assigned by Docker and registered with the proxy
- Network isolation ensures only the registered IP can make requests

**Container ID security:**
- Docker container IDs are generated using cryptographic randomness (not predictable)
- Even if an attacker guesses an ID, IP binding prevents spoofing
- IDs are not secrets - they're identifiers verified against source IP

**Identity model (IP-based with optional header validation):**
- **Primary:** Source IP → container lookup (sufficient for access)
- **Optional:** `X-Container-Id` header validated if present (catches misconfigurations)
- **No header required:** Most HTTP clients work without modification
- Network-level isolation ensures sandboxes can only reach the proxy, not each other

**Future hardening (if needed):** HMAC-signed headers and/or mTLS can be added later for stronger guarantees in multi-tenant deployments.

**Registration endpoint** (simple HTTP API on proxy, host-only via Unix socket):
```
POST /internal/containers
{
  "container_ip": "172.18.0.5",
  "container_id": "abc123def456789...",  # Full 64-char Docker container ID
  "repos": ["owner/repo1", "owner/repo2"],
  "auth_mode": "bot",
  "expires_at": "2026-12-31T00:00:00Z"
}

DELETE /internal/containers/{container_id}
```

**Rate limiting:** Registration API is rate-limited to 10 req/sec to prevent abuse from compromised host processes. Implemented via simple token bucket in `internal_api.py`.

**Persistence:** Container registry is stored in sqlite (`/var/lib/unified-proxy/registry.db`). This survives proxy restarts without requiring the host to re-register active sandboxes.

**Registration Lifecycle:**

```
┌──────────┐     ┌─────────────┐     ┌──────────────┐     ┌─────────┐
│sandbox.sh│     │unified-proxy│     │  registry.db │     │ sandbox │
└────┬─────┘     └──────┬──────┘     └──────┬───────┘     └────┬────┘
     │                  │                   │                  │
     │ 1. POST /internal/containers         │                  │
     │    (via Unix socket)                 │                  │
     │─────────────────>│                   │                  │
     │                  │ 2. INSERT         │                  │
     │                  │──────────────────>│                  │
     │                  │       OK          │                  │
     │                  │<──────────────────│                  │
     │   201 Created    │                   │                  │
     │<─────────────────│                   │                  │
     │                  │                   │                  │
     │ 3. docker run (container gets IP from Docker network)   │
     │────────────────────────────────────────────────────────>│
     │                  │                   │                  │
     │                  │ 4. HTTPS request  │                  │
     │                  │    (source IP = container IP)        │
     │                  │<─────────────────────────────────────│
     │                  │ 5. SELECT by IP   │                  │
     │                  │──────────────────>│                  │
     │                  │   container cfg   │                  │
     │                  │<──────────────────│                  │
     │                  │ 6. Inject creds, forward to upstream │
     │                  │─────────────────────────────────────>│
     │                  │                   │                  │
     │ 7. docker stop   │                   │                  │
     │────────────────────────────────────────────────────────>│
     │                  │                   │                  │
     │ 8. DELETE /internal/containers/{id}  │                  │
     │─────────────────>│                   │                  │
     │                  │ 9. DELETE         │                  │
     │                  │──────────────────>│                  │
     │   200 OK         │                   │                  │
     │<─────────────────│                   │                  │
```

**Key points:**
- Registration MUST happen before container starts (step 1 before step 3)
- Container IP is assigned by Docker and passed to registration API
- Unregistration should happen after container stops (cleanup)
- If sandbox.sh crashes, expired registrations are auto-pruned on proxy startup

**Registration auth:** Network isolation only—the registration API binds to the host-only interface and is not reachable from sandbox containers.

#### Registration API Network Isolation

The registration API must be completely inaccessible from sandbox containers. This is achieved through **Unix domain socket** (preferred) or network isolation.

**Option A: Unix Domain Socket (Recommended)**

The simplest and most portable approach - no IP address or iptables configuration needed:

```yaml
# docker-compose.credential-isolation.yml
services:
  unified-proxy:
    volumes:
      - proxy-socket:/var/run/proxy

  # Host process accesses via: curl --unix-socket /var/run/proxy/api.sock http://localhost/internal/containers
```

```python
# internal_api.py
import socket

# Bind to Unix socket, not TCP
sock_path = "/var/run/proxy/api.sock"
app.run(host=f"unix://{sock_path}")
```

**Benefits:**
- No IP address assumptions (docker0 varies by installation)
- No iptables rules needed
- Works with rootless Docker
- Filesystem permissions control access

**Option B: Network Isolation (Alternative)**

If TCP is required, use a dedicated internal network:

```yaml
services:
  unified-proxy:
    networks:
      - credential-isolation  # Sandbox-facing
      - internal-api          # Host-only, no sandbox access

  sandbox:
    networks:
      - credential-isolation  # Only this network

networks:
  credential-isolation:
    driver: bridge
  internal-api:
    driver: bridge
    internal: true  # No external routing
```

The proxy binds the registration API to the `internal-api` network interface. Sandboxes on `credential-isolation` have no route to it.

**Verification test (must fail from sandbox):**
```bash
# From inside sandbox container - should fail:
curl -sf --connect-timeout 2 http://unified-proxy:8081/internal/containers && echo "FAIL" || echo "OK: Blocked"
```

### Proxy Wrapper Implementation

The sandbox uses **IP-based identity**. The `X-Container-Id` header provides optional validation to catch misconfigurations but is not required for access.

#### Identity Model

1. **Primary:** Source IP → container lookup (sufficient for access, works for all traffic including DNS)
2. **Optional:** `X-Container-Id` header validated if present (catches misconfigurations, e.g., wrong proxy routing)
3. **No header = allowed:** Header is not required; most HTTP clients work without modification

#### Container Environment Setup

```bash
#!/bin/bash
# /etc/profile.d/sandbox-proxy.sh
# Sourced on container start

export PROXY_HOST="${UNIFIED_PROXY_HOST:-unified-proxy}"
export PROXY_PORT="${UNIFIED_PROXY_PORT:-8080}"

# Standard proxy environment variables
export http_proxy="http://${PROXY_HOST}:${PROXY_PORT}"
export https_proxy="http://${PROXY_HOST}:${PROXY_PORT}"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$https_proxy"
export no_proxy="localhost,127.0.0.1"
export NO_PROXY="$no_proxy"
```

#### Git Configuration

Git is configured at container creation (not via aliases):

```bash
# Set during container initialization
git config --global http.proxy "http://unified-proxy:8080"
# NOTE: Do NOT use http.extraHeader - it leaks to upstream servers
```

The proxy identifies git requests by source IP, same as other traffic.

#### Why Not Header Injection?

| Approach | Problem |
|----------|---------|
| Bash aliases | Don't work in scripts, subshells, non-interactive shells |
| http.extraHeader | **Leaks container ID to GitHub's servers** |
| LD_PRELOAD | Complex, breaks some apps, security concerns |
| Wrapper scripts | Fragile, easy to bypass |

**Solution:** Rely on IP-based identity. The header is optional defense-in-depth, not required.

#### Network-Level Enforcement

All egress is blocked except to the proxy. Tools that ignore proxy env vars are blocked at network layer:

```bash
# Sandbox iptables rules (applied at container creation)
iptables -A OUTPUT -d ${PROXY_IP} -p tcp --dport 8080 -j ACCEPT  # HTTP proxy
iptables -A OUTPUT -d ${PROXY_IP} -p udp --dport 53 -j ACCEPT    # DNS
iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT                       # Localhost
iptables -A OUTPUT -j DROP                                        # Block all else
```

This handles: statically linked binaries, non-proxy-aware tools, direct IP connections, SSH git URLs.

### 2. Git Handled by mitmproxy

Git over HTTPS works through HTTP proxy. mitmproxy intercepts:

```python
# git_proxy.py (new mitmproxy addon)

ZERO_SHA = "0" * 40

class GitProxy:
    """Handle git operations with policy enforcement."""

    def request(self, flow):
        if not self._is_git_request(flow):
            return

        container = flow.metadata.get("container")
        if not container:
            return  # ContainerIdentity addon will reject

        # Check repo authorization
        owner, repo = self._extract_repo(flow.request.path)
        if f"{owner}/{repo}" not in container.repos:
            flow.response = Response.make(403, b"Repo not authorized")
            return

        # For git-receive-pack (push), check policy
        if "git-receive-pack" in flow.request.path:
            self._check_push_policy(flow, container)

    def _check_push_policy(self, flow, container):
        """Parse pkt-line, detect deletion and enforce branch restrictions."""
        body = flow.request.content
        updates = parse_pktline(body)

        for old_sha, new_sha, refname, _ in updates:
            # Block branch/tag deletion
            if new_sha == ZERO_SHA:
                flow.response = Response.make(403,
                    f"Branch deletion blocked: {refname}".encode())
                return

            # Bot mode: restrict to sandbox/* branches
            if container.auth_mode == "bot":
                if not refname.startswith("refs/heads/sandbox/"):
                    flow.response = Response.make(403,
                        f"Bot mode: can only push to sandbox/* branches".encode())
                    return

        # Note: Force-push detection delegated to GitHub branch protection
```

### 3. Unified Policy Engine

```python
# policy_engine.py (new mitmproxy addon)

class PolicyEngine:
    """Centralized policy for all operations."""

    def __init__(self):
        self.config = load_config()  # From YAML or env
        self._compile_patterns()

    def request(self, flow):
        container = flow.metadata.get("container")
        host = flow.request.host
        method = flow.request.method
        path = flow.request.path

        # Check blocked API patterns
        result = self.check_api_endpoint(host, path, method)
        if not result.allowed:
            flow.response = Response.make(403, result.reason.encode())
            return

    def check_api_endpoint(self, host, path, method):
        """Check if API endpoint is allowed."""
        if host == "api.github.com":
            # Block PR merge
            if method == "PUT" and re.match(r'/repos/[^/]+/[^/]+/pulls/\d+/merge', path):
                return PolicyResult(False, "PR merge blocked - use GitHub UI")
            # Block release creation
            if method == "POST" and re.match(r'/repos/[^/]+/[^/]+/releases$', path):
                return PolicyResult(False, "Release creation blocked")

        return PolicyResult(True)
```

### 4. Credential Injection (Existing, Minor Changes)

Current `inject-credentials.py` stays mostly the same. Changes:
- GitHub token injection now applies to git operations too (unified)
- Can check `flow.metadata["container"]` for per-container rules

### 5. DNS Integration into Unified Proxy

**Decision:** Integrate DNS using mitmproxy's native DNS mode.

mitmproxy 11+ (Oct 2024) has production-ready DNS support:
- Native mode: `--mode dns@53`
- Based on Hickory DNS (Rust library) - production-grade
- Supports all query types (A, AAAA, HTTPS, TXT, etc.)
- `dns_name_servers` option for upstream configuration
- `dns_use_hosts_file` option available

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│  UNIFIED-PROXY CONTAINER                                         │
│                                                                  │
│  mitmproxy (single process)                                     │
│  ├─ HTTP/HTTPS proxy mode (port 8080)                           │
│  └─ DNS server mode (port 53)                                   │
│                                                                  │
│  Addons:                                                        │
│  ├─ container_identity.py                                       │
│  ├─ policy_engine.py      ← Shared allowlist for DNS + HTTP     │
│  ├─ dns_filter.py         ← DNS query filtering                 │
│  ├─ credential_injector.py                                      │
│  └─ git_proxy.py                                                │
│                                                                  │
│  /etc/unified-proxy/allowlist.yaml  ← Single source of truth    │
└─────────────────────────────────────────────────────────────────┘
```

**DNS Filter Addon:**

DNS queries don't have HTTP headers, so container identity uses **source IP only**. This is secure because:
- Each container has a unique IP on the Docker network
- Sandboxes cannot spoof source IPs within Docker's network namespace
- The registry maps container IPs to their configuration

```python
# dns_filter.py
from mitmproxy import dns, ctx

class DNSFilter:
    def __init__(self, registry):
        self.registry = registry
        self.policy = None  # Injected by policy_engine

    def dns_request(self, flow: dns.DNSFlow) -> None:
        # Identify container by source IP (no headers in DNS)
        client_ip = flow.client_conn.peername[0]
        container = self.registry.get_by_ip(client_ip)

        if not container:
            ctx.log.warn(f"DNS blocked: unknown source IP {client_ip}")
            flow.response = flow.request.fail(dns.response_codes.REFUSED)
            return

        query = flow.request.questions[0]
        hostname = query.name.rstrip('.')

        if not self.policy.is_domain_allowed(hostname):
            ctx.log.warn(f"DNS blocked: {hostname} from {container.container_id}")
            flow.response = flow.request.fail(dns.response_codes.NXDOMAIN)
            return

        # Attach container to flow metadata for logging
        flow.metadata["container"] = container
        # Allow query to proceed to upstream DNS
```

**Note:** DNS policy is currently global (same allowlist for all containers). Per-container DNS policy could be added by checking `container.allowed_domains` if needed.

**Unified Allowlist (single source of truth):**
```yaml
# /etc/unified-proxy/allowlist.yaml
version: 1

domains:
  # GitHub
  - github.com
  - api.github.com
  - uploads.github.com
  - raw.githubusercontent.com
  - objects.githubusercontent.com
  - codeload.github.com

  # AI Providers (wildcards)
  - "*.openai.com"
  - "*.chatgpt.com"
  - api.anthropic.com
  - generativelanguage.googleapis.com

  # Research APIs
  - api.tavily.com
  - api.perplexity.ai
  - api.semanticscholar.org

  # Package repos
  - pypi.org
  - files.pythonhosted.org
```

**Entrypoint (dual-mode):**
```bash
exec mitmdump \
    --mode regular@8080 \
    --mode dns@53 \
    --set dns_name_servers=127.0.0.11 \
    -s /opt/proxy/addons/container_identity.py \
    -s /opt/proxy/addons/rate_limiter.py \
    -s /opt/proxy/addons/circuit_breaker.py \
    -s /opt/proxy/addons/policy_engine.py \
    -s /opt/proxy/addons/dns_filter.py \
    -s /opt/proxy/addons/credential_injector.py \
    -s /opt/proxy/addons/git_proxy.py
```

**Addon load order matters:**
1. `container_identity` - Must run first to populate `flow.metadata["container"]`
2. `rate_limiter` - Early rejection saves processing; uses container identity
3. `circuit_breaker` - Check upstream availability before processing
4. `policy_engine` - Policy checks before credential injection
5. `dns_filter` - DNS-specific filtering
6. `credential_injector` - Add credentials after policy approval
7. `git_proxy` - Git-specific handling (runs last)

**Benefits:**
1. **Single allowlist** - no sync issues between dnsmasq.conf and HTTP allowlist
2. **Unified logging** - DNS queries in same structured log format
3. **Single process** - simpler container, fewer failure modes
4. **Consistent policy** - same code path for DNS and HTTP filtering

## File Structure

```
unified-proxy/                # Renamed from api-proxy/
├── addons/
│   ├── __init__.py
│   ├── container_identity.py  # NEW: Container identification
│   ├── policy_engine.py       # NEW: Centralized policy (DNS + HTTP)
│   ├── dns_filter.py          # NEW: DNS query filtering
│   ├── git_proxy.py           # NEW: Git protocol handling
│   ├── credential_injector.py # REFACTORED: from inject-credentials.py
│   ├── github_filter.py       # EXISTS: merged into policy_engine
│   ├── circuit_breaker.py     # NEW: Per-upstream circuit breakers
│   ├── rate_limiter.py        # NEW: Per-container rate limiting
│   ├── metrics.py             # NEW: Prometheus metrics
│   └── oauth_managers/
│       ├── __init__.py
│       ├── codex.py           # EXISTS: from codex-token-manager.py
│       ├── gemini.py          # EXISTS: from gemini-token-manager.py
│       └── opencode.py        # EXISTS: from opencode-token-manager.py
├── registry.py                # NEW: sqlite persistence for container registry
├── pktline.py                 # NEW: Git pkt-line parser (from gateway)
├── config.py                  # NEW: Unified config loader
├── internal_api.py            # NEW: /internal/* endpoints for registration
├── entrypoint.sh              # UPDATED: dual-mode (HTTP + DNS)
├── Dockerfile                 # UPDATED
└── requirements.txt           # UPDATED

config/
├── allowlist.yaml             # NEW: Unified allowlist (DNS + HTTP)
├── policy.yaml.example        # NEW: Example policy config
└── policy.yaml                # GITIGNORED: Actual policy config

lib/
├── proxy.sh                  # NEW: replaces gateway.sh
└── gateway.sh                # DELETE after migration

tests/
├── unit/
│   ├── test_container_identity.py
│   ├── test_policy_engine.py
│   ├── test_git_proxy.py
│   ├── test_rate_limiter.py   # NEW
│   └── test_pktline.py
├── integration/
│   ├── test_git_operations.py
│   ├── test_api_proxy.py
│   └── test_container_lifecycle.py
├── security/
│   ├── test_policy_bypass.py
│   ├── test_container_isolation.py
│   └── redteam-sandbox.sh    # EXISTS: updated
├── docker-compose.test.yml    # NEW: Test infrastructure
└── README.md                  # NEW: Test documentation

docs/
├── architecture.md           # UPDATED
└── adr/
    ├── 000-template.md       # NEW
    ├── 001-consolidation.md  # NEW
    ├── 002-container-identity.md  # NEW
    └── 003-policy-engine.md  # NEW
```

### Test Infrastructure (docker-compose.test.yml)

```yaml
# tests/docker-compose.test.yml
version: "3.8"

services:
  unified-proxy:
    build:
      context: ../unified-proxy
      dockerfile: Dockerfile
    ports:
      - "18080:8080"   # HTTP proxy (test port)
      - "1053:53/udp"  # DNS (test port)
    volumes:
      - proxy-socket:/var/run/proxy
      - ../config:/etc/unified-proxy:ro
      - proxy-data:/var/lib/unified-proxy
    environment:
      - LOG_LEVEL=debug
    networks:
      - test-network
    healthcheck:
      test: ["CMD", "python3", "-c", "import socket; s=socket.socket(); s.connect(('localhost', 8080)); s.close()"]
      interval: 5s
      timeout: 3s
      retries: 3

  test-sandbox:
    image: ubuntu:22.04
    command: sleep infinity
    environment:
      - http_proxy=http://unified-proxy:8080
      - https_proxy=http://unified-proxy:8080
      - HTTP_PROXY=http://unified-proxy:8080
      - HTTPS_PROXY=http://unified-proxy:8080
    networks:
      - test-network
    depends_on:
      unified-proxy:
        condition: service_healthy

volumes:
  proxy-socket:
  proxy-data:

networks:
  test-network:
    driver: bridge
```

**Usage:**
```bash
# Start test infrastructure
cd tests && docker-compose -f docker-compose.test.yml up -d

# Register test container (from host, via Unix socket)
curl --unix-socket /var/run/proxy/api.sock \
  -X POST http://localhost/internal/containers \
  -H "Content-Type: application/json" \
  -d '{"container_ip": "172.20.0.3", "container_id": "test123", "repos": ["test/repo"]}'

# Run tests
pytest tests/integration/

# Cleanup
docker-compose -f docker-compose.test.yml down -v
```

## Critical Files to Modify/Create

| File | Action | Priority |
|------|--------|----------|
| `unified-proxy/addons/container_identity.py` | Create | Phase 1 |
| `unified-proxy/registry.py` | Create | Phase 1 |
| `unified-proxy/internal_api.py` | Create | Phase 1 |
| `tests/docker-compose.test.yml` | Create | Phase 1 |
| `unified-proxy/addons/policy_engine.py` | Create | Phase 2 |
| `unified-proxy/addons/dns_filter.py` | Create | Phase 2 |
| `unified-proxy/addons/circuit_breaker.py` | Create | Phase 2 |
| `unified-proxy/addons/rate_limiter.py` | Create | Phase 2 |
| `config/allowlist.yaml` | Create | Phase 2 |
| `config/policy.yaml.example` | Create | Phase 2 |
| `unified-proxy/addons/metrics.py` | Create | Phase 2 |
| `unified-proxy/addons/git_proxy.py` | Create | Phase 3 |
| `unified-proxy/pktline.py` | Port from gateway | Phase 3 |
| `lib/proxy.sh` | Create | Phase 5 |
| `docker-compose.credential-isolation.yml` | Modify | Phase 5 |
| `gateway/` | Delete entire directory | Phase 6 |

## Implementation Phases

### Phase Dependencies

```
Phase 0: Infrastructure Setup
    │
    ▼
Phase 1: Container Identity ◄──────────────────────┐
    │                                               │
    ▼                                               │
Phase 2: Policy Engine                              │
    │                                               │
    ├───────────────┐                               │
    ▼               ▼                               │
Phase 3:        Phase 4:                            │
Git Proxy       Credential Injection ───────────────┘
    │               │                 (uses flow.metadata["container"])
    └───────┬───────┘
            ▼
      Phase 5: Infrastructure Changes
            │
            ▼
      Phase 6: Cleanup & Documentation
```

**Critical dependencies:**
- Phase 1 (Container Identity) must complete before Phase 3 and Phase 4 (both use `flow.metadata["container"]`)
- Phase 2 (Policy Engine) should complete before Phase 3 (git policy relies on policy engine patterns)
- Phases 3 and 4 can run in parallel after their dependencies are met
- Phase 5 requires all proxy functionality complete (Phases 1-4)
- Phase 6 is cleanup only after Phase 5 validation

### Pre-Implementation: Research Validation

Before detailed implementation, the following was validated:

**Git proxy research (completed):**
- `http.proxy` git config: Works with mitmproxy, recommended approach
- `GIT_PROXY_COMMAND`: Requires netcat, more complex
- `ALL_PROXY`: Less reliable across git versions

**mitmproxy DNS mode (validated):**
- Tested with mitmproxy 11.x
- `--mode dns@53` works for query interception
- Hickory DNS backend is stable

**Conclusion:** Proceed with `http.proxy` for git + mitmproxy DNS mode.

### Phase 0: Infrastructure Setup
**Goal:** Set up test infrastructure and ADRs

1. Create test structure (`tests/unit/`, `tests/integration/`, `tests/security/`)
2. Write ADR-001 (Consolidation decision)
3. Write ADR-002 (Container identity)
4. Set up Docker Compose for testing

**Deliverables:**
- Test infrastructure
- ADR documents

### Phase 1: Container Identity
**Goal:** Replace session tokens with container IP + container_id identity, persisted in sqlite

**Files:**
- `api-proxy/addons/container_identity.py` (new)
- `api-proxy/registry.py` (new - sqlite persistence layer)
- `api-proxy/tests/test_container_identity.py` (new)
- `lib/proxy.sh` (new, replaces gateway.sh session functions)

**Implementation:**
```python
# registry.py - sqlite persistence with in-memory cache
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict

@dataclass
class ContainerConfig:
    container_id: str
    container_ip: str
    repos: List[str]
    auth_mode: str  # 'user' or 'bot'
    expires_at: datetime
    created_at: datetime

class ContainerRegistry:
    """
    SQLite-backed registry with in-memory cache for fast lookups.
    Cache is refreshed on writes and periodically (every 60s).
    """

    def __init__(self, db_path: str = "/var/lib/unified-proxy/registry.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._cache_by_id: Dict[str, ContainerConfig] = {}
        self._cache_by_ip: Dict[str, ContainerConfig] = {}
        self._init_db()
        self._refresh_cache()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS containers (
                    container_id TEXT PRIMARY KEY,
                    container_ip TEXT NOT NULL UNIQUE,
                    repos TEXT NOT NULL,
                    auth_mode TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON containers(container_ip)")

    def _refresh_cache(self):
        """Reload cache from SQLite."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT * FROM containers").fetchall()
            self._cache_by_id.clear()
            self._cache_by_ip.clear()
            for row in rows:
                config = self._row_to_config(row)
                self._cache_by_id[config.container_id] = config
                self._cache_by_ip[config.container_ip] = config

    def get(self, container_id: str) -> Optional[ContainerConfig]:
        """Lookup by container ID (cache)."""
        with self._lock:
            return self._cache_by_id.get(container_id)

    def get_by_ip(self, ip: str) -> Optional[ContainerConfig]:
        """Lookup by source IP (cache) - primary identification method."""
        with self._lock:
            return self._cache_by_ip.get(ip)

    def register(self, config: ContainerConfig) -> None:
        """Insert or replace, then refresh cache."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO containers VALUES (?, ?, ?, ?, ?, ?)",
                    self._config_to_row(config)
                )
            self._refresh_cache()

    def unregister(self, container_id: str) -> None:
        """Delete and refresh cache."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM containers WHERE container_id = ?", (container_id,))
            self._refresh_cache()
```

**Concurrency notes:**
- In-memory cache avoids SQLite contention on every request
- Cache refresh is atomic (under lock)
- SQLite is only accessed on registration/unregistration (infrequent)
- WAL mode allows concurrent readers during cache refresh

```python
# container_identity.py
class ContainerIdentity:
    def __init__(self, registry: ContainerRegistry):
        self.registry = registry

    def request(self, flow: HTTPFlow):
        client_ip = flow.client_conn.peername[0]

        # Primary: lookup by source IP
        config = self.registry.get_by_ip(client_ip)
        if not config:
            flow.response = Response.make(403, b'{"error": "Unknown source IP"}')
            return

        # Defense-in-depth: verify header if present
        header_id = flow.request.headers.get("X-Container-Id")
        if header_id and header_id != config.container_id:
            flow.response = Response.make(403, b'{"error": "Container ID mismatch"}')
            return

        if datetime.now(timezone.utc) > config.expires_at:
            self.registry.unregister(config.container_id)
            flow.response = Response.make(403, b'{"error": "Container registration expired"}')
            return

        # Strip internal header before forwarding to upstream
        if "X-Container-Id" in flow.request.headers:
            del flow.request.headers["X-Container-Id"]

        flow.metadata["container"] = config
```

**Registration API** (internal endpoint, Unix socket only):
```python
# internal_api.py
from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
from registry import ContainerRegistry, ContainerConfig

app = Flask(__name__)
registry = ContainerRegistry()

# Rate limiting for registration API (10 req/sec)
from functools import wraps
import time
_last_requests = []

def rate_limit(max_per_second=10):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            now = time.monotonic()
            _last_requests[:] = [t for t in _last_requests if now - t < 1.0]
            if len(_last_requests) >= max_per_second:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            _last_requests.append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/internal/containers', methods=['POST'])
@rate_limit(10)
def register_container():
    data = request.get_json()

    # Validate required fields
    required = ['container_ip', 'container_id', 'repos']
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({'error': f'Missing required fields: {missing}'}), 400

    # Parse expiration (default: 24 hours)
    expires_at_str = data.get('expires_at')
    if expires_at_str:
        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
    else:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    config = ContainerConfig(
        container_id=data['container_id'],
        container_ip=data['container_ip'],
        repos=data['repos'],
        auth_mode=data.get('auth_mode', 'user'),
        expires_at=expires_at,
        created_at=datetime.now(timezone.utc),
    )

    registry.register(config)
    return jsonify({'status': 'registered', 'container_id': config.container_id}), 201

@app.route('/internal/containers/<container_id>', methods=['DELETE'])
@rate_limit(10)
def unregister_container(container_id):
    existing = registry.get(container_id)
    if not existing:
        return jsonify({'error': 'Container not found'}), 404

    registry.unregister(container_id)
    return jsonify({'status': 'unregistered', 'container_id': container_id}), 200

@app.route('/internal/health', methods=['GET'])
def health():
    checks = {
        'registry_accessible': True,  # Would fail if sqlite corrupted
    }
    try:
        # Verify registry is accessible
        registry._refresh_cache()
    except Exception as e:
        checks['registry_accessible'] = False
        checks['registry_error'] = str(e)

    status = 'healthy' if all(v for k, v in checks.items() if not k.endswith('_error')) else 'degraded'
    return jsonify({'status': status, 'checks': checks}), 200 if status == 'healthy' else 503
```

**Verification:**
- Unknown source IP → 403
- Mismatched header (if present) → 403
- Expired registration → 403
- Valid registration → request proceeds
- Header stripped before forwarding to upstream
- Proxy restart → registrations persist (sqlite)

### Phase 2: Policy Engine
**Goal:** Centralized policy checks (adapted from PLAN.md)

**Files:**
- `api-proxy/addons/policy_engine.py` (new)
- `api-proxy/tests/test_policy_engine.py` (new)
- `config/policy.yaml` (new)

**Implementation:** (same PolicyResult, check methods from PLAN.md, adapted to mitmproxy)
```python
# policy_engine.py
from config import load_config

@dataclass
class PolicyResult:
    allowed: bool
    reason: Optional[str] = None

class PolicyEngine:
    def __init__(self):
        self.config = load_config().get('policy', {})
        self._blocked_patterns = self._compile_patterns()

    def request(self, flow: HTTPFlow):
        result = self.check_api_endpoint(
            flow.request.host,
            flow.request.path,
            flow.request.method
        )
        if not result.allowed:
            flow.response = Response.make(403, json.dumps({
                'error': result.reason
            }).encode())
```

**Verification:**
- `PUT /repos/x/y/pulls/1/merge` → 403
- `POST /repos/x/y/releases` → 403
- `GET /repos/x/y/pulls` → allowed

### Phase 3: Git Proxy
**Goal:** Handle git operations in mitmproxy

**Files:**
- `api-proxy/addons/git_proxy.py` (new)
- `api-proxy/pktline.py` (ported from gateway/gateway.py)
- `api-proxy/tests/test_git_proxy.py` (new)
- `api-proxy/tests/test_pktline.py` (new)

**Implementation:**
- Port `parse_pktline()` and `check_ref_updates()` from gateway.py
- Add mitmproxy addon for git request handling
- Implement repo authorization check
- Implement branch deletion blocking
- Implement auth mode branch restrictions

**Force-push handling:**
Force-push prevention is delegated to GitHub branch protection rules. The proxy does not attempt to verify fast-forward pushes because:
- It would require GitHub API calls on every push (latency, rate limits, availability)
- GitHub already provides robust branch protection
- Repos that need force-push protection should enable it in GitHub settings

The proxy blocks **branch deletion** (detectable from pkt-line: `new_sha` is all zeros) but allows all other pushes to proceed.

- **Large git pushes:**
  - Set mitmproxy `stream_large_bodies` for git endpoints
  - Enforce size limits (see table below)
  - If exceeded → 413 with guidance to split pushes

  **Push size limits (canonical):**

  | Threshold | Bytes | Action |
  |-----------|-------|--------|
  | Warning | 50MB | Log warning, allow push |
  | Hard limit | 100MB | Reject with 413 |
  | Per-repo override | Up to 500MB | Custom limit via registration |

  **Per-repo override:** Allow larger pushes for specific repositories:
  ```yaml
  # Per-container registration
  {
    "container_id": "abc123",
    "repos": [
      {"name": "owner/small-repo"},
      {"name": "owner/monorepo", "max_receive_pack_bytes": 524288000}  # 500MB override
    ]
  }
  ```

  3. **Large initial imports:**
     - Sandboxes are not suitable for importing large existing repositories
     - Guidance: Clone repository on host, then mount or copy into sandbox
     - Alternative: Use GitHub's import feature or host-side git operations
     ```bash
     # On host (not in sandbox):
     git clone --mirror https://github.com/owner/large-repo.git
     # Then start sandbox with repo already present
     ```

  4. **Chunked push guidance:**
     - For legitimate large changes, push in smaller batches:
     ```bash
     # Instead of one large push:
     git push origin feature-branch  # May exceed limit

     # Push commits in chunks:
     git push origin HEAD~100:refs/heads/feature-branch
     git push origin HEAD~50:refs/heads/feature-branch
     git push origin HEAD:refs/heads/feature-branch
     ```

  5. **Improved error message (413 response):**
     ```json
     {
       "error": "Push size exceeds limit",
       "details": {
         "push_size_bytes": 250000000,
         "push_size_human": "238.4 MB",
         "limit_bytes": 209715200,
         "limit_human": "200 MB"
       },
       "guidance": {
         "message": "Your push exceeds the size limit. Alternatives:",
         "options": [
           "Split into smaller commits and push incrementally",
           "Use Git LFS for large binary files",
           "Request per-repository limit increase"
         ],
         "example": [
           "git push origin HEAD~50:refs/heads/branch",
           "git push origin HEAD:refs/heads/branch"
         ]
       }
     }
     ```

**Verification:**
- Clone authorized repo → works
- Clone unauthorized repo → 403
- Delete branch → 403
- Bot mode push to `main` → 403
- Bot mode push to `sandbox/feature` → works
- Force push → allowed (delegated to GitHub branch protection)

### Phase 4: Credential Injection Refactor
**Goal:** Integrate existing credential injection with new architecture

**Files:**
- `api-proxy/addons/credential_injector.py` (refactored from inject-credentials.py)
- `api-proxy/addons/oauth_managers/` (moved from root)

**Changes:**
- Move inject-credentials.py logic into addon class
- Integrate with container identity for per-container rules (optional)
- Ensure GitHub token injection works for both git and API

**Verification:**
- API calls get credentials injected
- Git operations get GitHub token
- OAuth refresh flows work

### Phase 5: Infrastructure Changes
**Goal:** Update Docker setup, remove gateway service entirely (DNS now handled by unified-proxy)

**Files:**
- `docker-compose.credential-isolation.yml` (modified)
- `lib/proxy.sh` (finalized)

**Changes:**
- Rename `api-proxy/` → `unified-proxy/`
- Remove gateway service entirely (mitmproxy handles DNS via `--mode dns@53`)
- Update sandbox DNS to point to unified-proxy:53
- Update sandbox entrypoint to use new registration
- Update docker-compose environment variables

**Verification:**
- `docker-compose up` starts unified-proxy only (no separate gateway/dns service)
- DNS resolution works via unified-proxy:53
- Git and API traffic flows through unified-proxy:8080

### Phase 6: Cleanup & Documentation
**Goal:** Remove old code, update docs

**Files:**
- `gateway/` (delete entire directory - DNS now in unified-proxy)
- `lib/gateway.sh` (delete, replaced by proxy.sh)
- `docs/architecture.md` (update)
- `docs/adr/001-consolidation.md` (finalize)
- `docs/adr/002-container-identity.md` (write)
- `docs/adr/003-policy-engine.md` (write)
- `docs/adr/004-dns-integration.md` (write)
- `PLAN.md` (archive or delete)
- `COMPARISON.md` (archive or delete)

**Verification:**
- All tests pass
- Security tests pass
- Documentation reflects new architecture

## Migration Strategy

Transitioning from the current dual-service architecture (gateway + api-proxy) to the unified proxy.

### Approach: Parallel Testing, Then Cutover

For a dev sandbox tool, a simple parallel test approach is sufficient:

1. **Test Phase:** Run unified-proxy alongside existing stack, manually test key operations
2. **Validation:** Run automated test suite against unified-proxy
3. **Cutover:** Switch all new sandboxes to unified-proxy
4. **Cleanup:** Remove old gateway/api-proxy after 1 week with no issues

### Parallel Testing

Run both stacks, compare behavior offline (no complex traffic splitting):

```bash
# Start unified-proxy on alternate ports for testing
docker-compose -f docker-compose.test.yml up unified-proxy

# Run test suite against both
./tests/integration/run-all.sh --target old
./tests/integration/run-all.sh --target unified

# Compare results
diff test-results-old.json test-results-unified.json
```

### Rollback Procedure

If issues are found after cutover:

```bash
# 1. Stop unified-proxy
docker-compose stop unified-proxy

# 2. Start old stack
docker-compose up -d gateway api-proxy

# 3. Update sandbox config to use old proxy
./sandbox.sh config set proxy_backend old

# 4. Restart affected sandboxes
./sandbox.sh restart --all

# 5. Verify
./tests/integration/smoke-test.sh
```

### Cutover Checklist

- [ ] All integration tests pass against unified-proxy
- [ ] Security tests pass (redteam-sandbox.sh)
- [ ] Performance baseline established
- [ ] Rollback procedure documented and tested
- [ ] Old stack kept available for 1 week post-cutover

## Testing Strategy

### Unit Tests (pytest)
```python
# test_git_proxy.py
import pytest
from mitmproxy.test import tflow
from addons.git_proxy import GitProxy
from registry import ContainerConfig

def test_push_to_unauthorized_repo():
    addon = GitProxy()
    flow = tflow.tclientconn()
    flow.request.path = "/owner/unauthorized-repo.git/git-receive-pack"
    flow.metadata["container"] = ContainerConfig(
        container_id="test",
        container_ip="172.18.0.5",
        repos=["owner/other-repo"],
        auth_mode="user",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        created_at=datetime.now(timezone.utc),
    )

    addon.request(flow)

    assert flow.response.status_code == 403
    assert b"not authorized" in flow.response.content

def test_branch_deletion_blocked():
    # ... test pkt-line parsing and deletion detection
```

### Integration Tests
```bash
# Start unified-proxy in test mode
docker-compose -f docker-compose.test.yml up -d

# Register test container (via Unix socket mounted from proxy-socket volume)
curl --unix-socket ./proxy-socket/api.sock \
  -X POST http://localhost/internal/containers \
  -H "Content-Type: application/json" \
  -d '{"container_ip": "172.20.0.3", "container_id": "test123", "repos": ["test/repo"]}'

# Test git clone (should work)
docker exec test-sandbox git clone http://github.com/test/repo

# Test git push to unauthorized repo (should fail)
docker exec test-sandbox git push http://github.com/other/repo  # 403

# Test PR merge API (should fail)
docker exec test-sandbox curl -X PUT http://api.github.com/repos/test/repo/pulls/1/merge  # 403
```

### Security Tests
- Verify container can't access other container's repos
- Verify force push detection works
- Verify PR merge blocking works
- Verify unknown container IPs or missing container_id are rejected

### Performance Tests

See `tests/performance/README.md` for detailed benchmarks. Key targets:

| Operation | p99 Target |
|-----------|------------|
| HTTP passthrough | <50ms |
| Git clone (small) | <2s |
| Credential injection | <10ms |

### Compatibility Tests

See `tests/compatibility/README.md` for test matrices covering:
- Git versions: 2.30, 2.34, 2.39, 2.43
- HTTP clients: curl, wget, Python requests, Node fetch, Go net/http

## Configuration

### Per-Container Config (at registration)
```json
{
  "container_ip": "172.18.0.5",
  "container_id": "abc123def456",
  "repos": ["owner/repo1", "owner/repo2"],
  "auth_mode": "bot",
  "expires_at": "2026-12-31T00:00:00Z"
}
```

### Global Policy Config (YAML)
```yaml
# config/policy.yaml
policy:
  blocked_api_patterns:
    PUT:
      - "^/repos/[^/]+/[^/]+/pulls/\\d+/merge$"
    POST:
      - "^/repos/[^/]+/[^/]+/releases$"
    DELETE:
      - "^/repos/[^/]+/[^/]+$"

  allow_branch_deletion: false

git:
  push_limits:
    warning_bytes: 52428800       # 50MB - log warning
    hard_limit_bytes: 104857600   # 100MB - reject with 413

# Note: Force-push prevention delegated to GitHub branch protection
# Per-repo overrides can increase hard_limit_bytes up to 500MB

# Circuit breaker configuration
circuit_breakers:
  defaults:
    failure_threshold: 5          # Failures before opening circuit
    recovery_timeout: 30          # Seconds before attempting recovery
    success_threshold: 2          # Successes needed to close circuit

  upstreams:
    github.com: {}                # Uses defaults
    api.github.com: {}            # Uses defaults
    api.anthropic.com:
      failure_threshold: 3        # AI APIs: fewer failures before circuit opens
      recovery_timeout: 60        # Longer recovery for AI APIs
    api.openai.com:
      failure_threshold: 3
      recovery_timeout: 60
    api.tavily.com:
      failure_threshold: 3
      recovery_timeout: 60

# Rate limiting per container
rate_limits:
  enabled: true
  defaults:
    requests_per_second: 100      # Per-container limit
    burst_size: 200               # Allow short bursts
  per_upstream:
    api.github.com:
      requests_per_second: 50     # GitHub has its own rate limits
    api.anthropic.com:
      requests_per_second: 20     # AI APIs: be conservative
    api.openai.com:
      requests_per_second: 20
```

## What Gets Simpler

1. **No session token dance** - Container identity is implicit
2. **Single proxy for everything** - No routing decisions
3. **Unified policy** - One place for all security rules
4. **Easier debugging** - One service's logs to check
5. **Consistent credential handling** - Same pattern for git and APIs

## What Gets More Complex

1. **mitmproxy addon testing** - Different paradigm than Flask
2. **Git protocol in mitmproxy** - New code, needs careful implementation
3. **Container registration** - New endpoint to manage
4. **Rate limiting state** - Per-container token buckets need memory management
5. **Circuit breaker tuning** - Need to balance between sensitivity and false positives

## Failure Modes and Recovery

### Single Point of Failure Analysis

The unified-proxy handles all egress traffic. If it fails:
- **Immediate impact:** All sandboxes lose external connectivity (git, API calls, DNS)
- **Blast radius:** Every active sandbox affected simultaneously
- **Data at risk:** None (stateless proxying, sqlite persists registrations)

### Health Check Configuration

**Docker health check:**
```yaml
unified-proxy:
  healthcheck:
    test: ["CMD", "python3", "-c",
           "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 8080)); s.close()"]
    interval: 5s
    timeout: 3s
    retries: 3
    start_period: 15s
  restart: unless-stopped
```

**Internal health endpoint (`/internal/health`):**
```python
@app.route('/internal/health', methods=['GET'])
def health():
    checks = {
        'proxy_listening': check_proxy_port(8080),
        'dns_listening': check_proxy_port(53),
        'registry_accessible': check_registry(),
        'addons_loaded': check_addons_loaded(),
    }
    status = 'healthy' if all(checks.values()) else 'degraded'
    return {'status': status, 'checks': checks}, 200 if status == 'healthy' else 503
```

### Recovery Behavior

| Scenario | Docker Action | Recovery Time |
|----------|---------------|---------------|
| Proxy crash (OOM, panic) | Auto-restart | 5-15 seconds |
| Health check failure (3x) | Container restart | 15-30 seconds |
| Host reboot | Auto-start on boot | 30-60 seconds |

**SQLite persistence ensures seamless recovery:**
- Container registrations survive proxy restarts
- No re-registration needed for active sandboxes
- On startup: prune expired registrations, log recovery stats

### Graceful Degradation

**Decision: Fail-closed (recommended)**
- If registry unavailable, reject all requests with 503
- Security boundaries must not degrade
- Sandboxes see immediate failure, can retry

### Circuit Breaker (Default)

Per-upstream circuit breakers protect against cascading failures. **Enabled by default.** Configuration loaded from `policy.yaml`.

```python
# circuit_breaker.py
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from config import load_config

@dataclass
class CircuitConfig:
    failure_threshold: int = 5      # Failures before opening
    recovery_timeout: int = 30      # Seconds before half-open
    success_threshold: int = 2      # Successes to close from half-open

class CircuitBreaker:
    def __init__(self, config: CircuitConfig):
        self.config = config
        self.failures = 0
        self.successes = 0
        self.state = "closed"  # closed, open, half-open
        self.opened_at = None
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        with self._lock:
            if self.state == "closed":
                return True
            if self.state == "open":
                if datetime.now() > self.opened_at + timedelta(seconds=self.config.recovery_timeout):
                    self.state = "half-open"
                    return True
                return False
            return True  # half-open: allow probe requests

    def record_success(self):
        with self._lock:
            if self.state == "half-open":
                self.successes += 1
                if self.successes >= self.config.success_threshold:
                    self.state = "closed"
                    self.failures = 0
                    self.successes = 0

    def record_failure(self):
        with self._lock:
            self.failures += 1
            if self.failures >= self.config.failure_threshold:
                self.state = "open"
                self.opened_at = datetime.now()

def load_circuit_breakers() -> dict[str, CircuitBreaker]:
    """Load circuit breaker config from policy.yaml."""
    config = load_config().get('circuit_breakers', {})
    defaults = config.get('defaults', {
        'failure_threshold': 5,
        'recovery_timeout': 30,
        'success_threshold': 2,
    })

    circuits = {}
    for host, overrides in config.get('upstreams', {}).items():
        cfg = CircuitConfig(
            failure_threshold=overrides.get('failure_threshold', defaults['failure_threshold']),
            recovery_timeout=overrides.get('recovery_timeout', defaults['recovery_timeout']),
            success_threshold=overrides.get('success_threshold', defaults['success_threshold']),
        )
        circuits[host] = CircuitBreaker(cfg)
    return circuits

UPSTREAM_CIRCUITS = load_circuit_breakers()
```

**Usage in request flow:**
```python
def request(self, flow: HTTPFlow):
    circuit = UPSTREAM_CIRCUITS.get(flow.request.host)
    if circuit and not circuit.allow_request():
        flow.response = Response.make(503, json.dumps({
            'error': 'Service temporarily unavailable',
            'reason': 'circuit_breaker_open',
            'upstream': flow.request.host,
            'retry_after': 30,
        }).encode())

def response(self, flow: HTTPFlow):
    circuit = UPSTREAM_CIRCUITS.get(flow.request.host)
    if circuit:
        if flow.response.status_code >= 500:
            circuit.record_failure()
        else:
            circuit.record_success()
```

### Rate Limiting (Per-Container)

Prevents a compromised or misconfigured sandbox from overwhelming the proxy or upstream services.

```python
# rate_limiter.py
import time
import threading
from dataclasses import dataclass
from config import load_config

@dataclass
class RateLimitConfig:
    requests_per_second: float
    burst_size: int

class TokenBucket:
    """Token bucket rate limiter."""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.tokens = config.burst_size
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Refill tokens
            self.tokens = min(
                self.config.burst_size,
                self.tokens + elapsed * self.config.requests_per_second
            )

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False

class RateLimiter:
    """Per-container, per-upstream rate limiting."""

    def __init__(self):
        config = load_config().get('rate_limits', {})
        self.enabled = config.get('enabled', True)
        self.defaults = RateLimitConfig(
            requests_per_second=config.get('defaults', {}).get('requests_per_second', 100),
            burst_size=config.get('defaults', {}).get('burst_size', 200),
        )
        self.per_upstream = {
            host: RateLimitConfig(**cfg)
            for host, cfg in config.get('per_upstream', {}).items()
        }
        # Map: (container_id, upstream) -> TokenBucket
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, container_id: str, upstream: str) -> TokenBucket:
        key = (container_id, upstream)
        with self._lock:
            if key not in self._buckets:
                config = self.per_upstream.get(upstream, self.defaults)
                self._buckets[key] = TokenBucket(config)
            return self._buckets[key]

    def request(self, flow: HTTPFlow):
        if not self.enabled:
            return

        container = flow.metadata.get("container")
        if not container:
            return  # ContainerIdentity will reject

        bucket = self._get_bucket(container.container_id, flow.request.host)
        if not bucket.allow():
            flow.response = Response.make(429, json.dumps({
                'error': 'Rate limit exceeded',
                'container_id': container.container_id,
                'upstream': flow.request.host,
                'retry_after': 1,
            }).encode())
            flow.response.headers['Retry-After'] = '1'
```

**Rate limit cleanup:** Buckets for unregistered containers are pruned periodically (every 5 minutes) to prevent memory growth.

## Observability

### Key Metrics

| Category | Key Metrics |
|----------|-------------|
| Requests | `proxy_requests_total`, `proxy_request_duration_seconds` |
| Git | `proxy_git_operations_total`, `proxy_git_push_blocked_total` |
| DNS | `proxy_dns_queries_total` |
| Rate Limiting | `proxy_rate_limit_rejected_total`, `proxy_rate_limit_bucket_tokens` |
| Circuit Breaker | `proxy_circuit_breaker_state`, `proxy_circuit_breaker_failures_total` |
| Health | `proxy_registered_containers` |

### Alerting

| Alert | Condition |
|-------|-----------|
| High error rate | 5xx > 1% for 5 min |
| Git failures | > 0.5% for 10 min |
| Rate limit rejections | > 10/min for any container (potential abuse) |
| Circuit breaker open | Any upstream circuit open > 2 min |

### Endpoints

- `GET /internal/metrics` - Prometheus format
- `GET /internal/health` - Health check

All internal endpoints protected by Unix socket isolation.

See `docs/observability.md` for full metrics catalog and log format.

## Certificate Management

### Overview

mitmproxy generates a CA certificate on first start. Sandboxes must trust this CA to allow HTTPS interception.

**Distribution:** Shared Docker volume (`mitm-certs`) mounted read-only in sandboxes.

**Environment variables for sandbox:**
```yaml
environment:
  - NODE_EXTRA_CA_CERTS=/certs/mitmproxy-ca.pem
  - REQUESTS_CA_BUNDLE=/certs/mitmproxy-ca.pem
  - SSL_CERT_FILE=/certs/mitmproxy-ca.pem
```

**Rotation:** Every 90 days. Procedure: drain sandboxes → stop proxy → delete CA → restart.

**Certificate pinning:** Apps that pin certificates will fail. Options: passthrough mode for specific hosts, or document as unsupported.

See `docs/certificates.md` for detailed procedures.


## Elements from Previous Plan

**Kept:** Policy engine design, YAML config structure, test organization, auth modes, fail-closed design.

**Discarded:** Session tokens, Flask gateway, token hashing.

**ADRs to write:** See `docs/adr/` for templates. Required: ADR-001 (Consolidation), ADR-002 (Identity), ADR-003 (Policy), ADR-004 (DNS).

## Resolved Design Decisions

| Question | Decision |
|----------|----------|
| DNS integration | Integrate via mitmproxy's native DNS mode (`--mode dns@53`) |
| Registration persistence | SQLite with in-memory cache |
| Force-push detection | Delegate to GitHub branch protection (proxy only blocks deletion) |
| Large git pushes | Stream with 50MB warning, 100MB hard limit (configurable per-repo) |
| Git over SSH | Block at network level, enforce HTTPS |
| Container identity | IP-based (sufficient for access); optional header validation for misconfiguration detection |
| Circuit breaker | Default enabled, configurable via policy.yaml |
| Rate limiting | Per-container, per-upstream; configurable via policy.yaml |
| Registration API isolation | Unix domain socket (preferred) or internal Docker network |

## Verification

After implementation:
```bash
# 1. Sandbox can clone authorized repo
git clone https://github.com/owner/authorized-repo  # ✓

# 2. Sandbox cannot clone unauthorized repo
git clone https://github.com/owner/other-repo  # 403 ✓

# 3. Sandbox cannot delete branches
git push origin --delete feature-branch  # 403 ✓

# 4. Sandbox cannot merge PR via API
gh pr merge 123  # 403 ✓

# 5. Sandbox can call allowed APIs
curl https://api.anthropic.com/v1/messages  # ✓ (with injected creds)

# 6. Unknown source IPs are rejected
# (from container not registered)
curl https://api.github.com/user  # 403 ✓

# 7. Proxy restart preserves registrations
docker restart unified-proxy
curl https://api.github.com/user  # ✓ (still works, sqlite persisted)

# 8. DNS filtering works (allowlisted domain)
dig @unified-proxy api.github.com  # ✓ returns IP

# 9. DNS filtering blocks non-allowlisted domain
dig @unified-proxy evil.example.com  # NXDOMAIN ✓

# 10. Metrics endpoint works (via Unix socket)
curl --unix-socket /var/run/proxy/api.sock http://localhost/internal/metrics  # ✓

# 11. Health check works
curl --unix-socket /var/run/proxy/api.sock http://localhost/internal/health  # ✓

# 12. X-Container-Id header not leaked to upstream
# (verify via mitmproxy logs or upstream server logs)

# 13. Circuit breaker activates on upstream failure
# (simulate github.com outage, verify fast 503 responses)

# 14. Rate limiting works
# (burst 200+ requests, verify 429 responses after limit)
for i in {1..250}; do curl -s -o /dev/null -w "%{http_code}\n" https://api.github.com/user; done | grep 429  # ✓

# 15. Request without X-Container-Id header succeeds (header is optional)
curl -x http://unified-proxy:8080 https://api.github.com/user  # ✓ (no header needed)

# 16. Mismatched X-Container-Id header is rejected
curl -x http://unified-proxy:8080 -H "X-Container-Id: wrong-id" https://api.github.com/user  # 403 ✓
```

## Security Addendum: Identity & Control Plane

**Goal:** Ensure container identity cannot be spoofed by another container and internal APIs are not exposed to sandboxes.

**Design:**
1. **Primary identity:** Source IP lookup (sufficient for access, works for all traffic including DNS)
2. **Optional validation:** `X-Container-Id` header verified if present, stripped before forwarding
3. **Registration API isolation:** Unix domain socket (preferred) or internal Docker network
4. **Container IDs:** Docker's cryptographically random 64-char hex IDs (used for optional validation only)

**Threats Mitigated:**
- Cross-container spoofing: Each container has unique IP on Docker network, cannot be spoofed
- Unregistered access: Unknown source IPs rejected with 403
- Registration API access: Unix socket not reachable from sandbox containers
- Header leakage: `X-Container-Id` stripped before forwarding to upstream servers
- Misconfiguration detection: If header present but mismatched, request rejected

**What the header does NOT provide:**
- The header is not required for access (IP is sufficient)
- The header is not a secret (container IDs are not confidential)
- Missing header does not trigger warnings or errors

**Future hardening (if needed):**
For multi-tenant deployments with stronger security requirements, HMAC-signed headers and/or mTLS can be added.

### Container-Internal Configuration

The IP-based identity scheme has no secrets within the container. Container ID is used for optional validation only, not as a secret.

**Security relies on:**
1. **Network isolation:** Sandboxes can only reach the proxy, not each other or the host
2. **IP binding:** Proxy identifies containers by their unique Docker network IP
3. **Registration API isolation:** Unix socket not accessible from sandbox containers

**Threat model:**

| Threat | Protection | Notes |
|--------|-----------|-------|
| Container A spoofs Container B | Impossible | Each container has unique IP on Docker network |
| Sandbox accesses registration API | Unix socket isolation | Not reachable from sandbox |
| Header spoofing | No impact | IP is the identity; header is optional validation |
| Root compromise in sandbox | Limited impact | Can only access own authorized repos |
| ID guessing | Not a threat | IP is the identity, not the ID |

**Future hardening (if needed):**

For deployments requiring stronger guarantees, HMAC signatures or mTLS can be added. These would require secret protection mechanisms (tmpfs, Docker secrets, etc.) within containers.

### Future Hardening Options

For multi-tenant deployments requiring stronger guarantees:
- **HMAC signatures:** Per-container secret, replay protection
- **mTLS:** Per-container client certificates

These can be added as optional modes without changing core architecture.

## ADR Summaries

| ADR | Decision | Key Consequence |
|-----|----------|-----------------|
| ADR-001: Consolidation | Single mitmproxy service for all egress | Simpler architecture, single point of failure |
| ADR-002: Identity | Source IP as sole identity (header optional) | Works for DNS, no secrets needed, most clients work unmodified |
| ADR-003: Policy | Centralized policy in mitmproxy addon | Single audit point, fail-closed |
| ADR-004: DNS | mitmproxy native DNS mode | Single allowlist for DNS + HTTP |

Full ADR documents in `docs/adr/`.

## Identity Test Checklist

**Unit Tests**
- Unknown source IP → 403
- Missing `X-Container-Id` header → allowed (header is optional)
- Mismatched `X-Container-Id` header (when present) → 403
- Expired registration → 403, auto-unregistered
- Valid registration (IP match, no header) → request proceeds
- Valid registration (IP match, header match) → request proceeds
- `X-Container-Id` header stripped before forwarding
- `flow.client_conn.peername` is None → 403 with clear error

**Integration Tests**
- Container A cannot access Container B's repos (different IPs)
- Registration API not reachable from sandbox network
- Proxy restart preserves registrations (sqlite)
- DNS requests identified by source IP (no header possible)
- HTTP request without header succeeds if IP registered

**Security Tests**
- Attempt to hit `/internal/containers` from sandbox → blocked (Unix socket / network isolation)
- Request from unregistered IP → 403
- Header not leaked to upstream servers
- Mismatched header from valid IP → 403 (catches misconfiguration)

## Operational Notes

1. **Registration lifecycle**
   - Register container with proxy before starting sandbox
   - Unregister when sandbox is stopped/destroyed
   - Set appropriate `expires_at` to auto-expire stale registrations

2. **Proxy restarts**
   - Registrations persist in sqlite—no re-registration needed
   - On startup, prune expired registrations

3. **Failure modes**
   - Unknown source IP → 403 with "Unknown source IP"
   - Header present but mismatched → 403 with "Container ID mismatch"
   - Expired registration → 403 with "Container registration expired" (and auto-unregister)
   - Cannot determine client IP → 403 with "Cannot determine client IP"
   - Missing header → allowed (header is optional)

4. **SQLite recovery procedures**

   **Backup (recommended: daily cron):**
   ```bash
   # Safe backup using sqlite3 .backup (handles WAL correctly)
   sqlite3 /var/lib/unified-proxy/registry.db ".backup /var/lib/unified-proxy/registry.db.bak"
   ```

   **Corruption detection:**
   ```bash
   sqlite3 /var/lib/unified-proxy/registry.db "PRAGMA integrity_check;"
   # Expected output: "ok"
   ```

   **Recovery from corruption:**
   ```bash
   # Option A: Restore from backup
   cp /var/lib/unified-proxy/registry.db.bak /var/lib/unified-proxy/registry.db
   docker restart unified-proxy

   # Option B: Rebuild from scratch (all sandboxes must re-register)
   rm /var/lib/unified-proxy/registry.db
   docker restart unified-proxy
   # Then restart all active sandboxes to trigger re-registration
   ```

   **Recovery from unavailable registry during request:**
   - Proxy returns 503 "Registry unavailable" (fail-closed)
   - Health check marks service degraded
   - Docker may restart container based on health check

   **WAL file handling:**
   - WAL files (`registry.db-wal`, `registry.db-shm`) are normal
   - Do NOT delete them while proxy is running
   - They are automatically checkpointed on clean shutdown
