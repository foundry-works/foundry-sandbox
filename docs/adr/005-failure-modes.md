# ADR-005: Failure Modes and Readiness Design

## Status

Accepted

Date: 2026-02-04

## Context

The unified proxy is a critical security component that enforces credential isolation and network restrictions. If the proxy fails silently or becomes partially available, the sandbox could:

1. Bypass security controls and access external systems directly
2. Expose real credentials to untrusted code
3. Be blocked from legitimate operations due to missing proxy dependencies

Without careful failure mode design, the system creates a false sense of security—the sandbox appears isolated but can partially bypass controls if the proxy degrades.

### Current System

The credential isolation architecture uses one proxy container:

- **Unified Proxy**: Holds all credentials (GitHub token, API keys for Anthropic, OpenAI, Google, etc.), enforces DNS filtering, performs HTTPS MITM to inject credentials, and proxies git operations through an authenticated API

The unified proxy must be healthy and reachable for the sandbox to operate securely. The sandbox depends on:
- Unified proxy for DNS resolution and domain filtering
- Unified proxy for outbound HTTP/HTTPS requests with credential injection
- Unified proxy for git operations via the git API
- Correct certificate trust setup for HTTPS interception
- SQLite-backed container registry for session management

## Decision

We implement **fail-closed behavior** with strict readiness requirements and ordered initialization:

### 1. Fail-Closed Behavior

**Principle:** If any security component fails, deny all access rather than gracefully degrade.

**Implementation:**

- **Proxy failure** → DNS cannot be routed through proxy, credentials cannot be injected
  - DNS firewall rules (iptables) block all DNS to external resolvers
  - HTTP_PROXY and HTTPS_PROXY environment variables point to unified-proxy:8080
  - If unified-proxy is unreachable, all HTTP/HTTPS and DNS requests fail
  - Sandbox cannot resolve external domains → cannot connect anywhere
  - Legitimate operations fail (curl, git clone) → user sees clear error
  - No silent fallback to direct network access
  - No fallback to using placeholder credentials
  - No fallback to direct API access

- **Certificate trust failure** → HTTPS interception breaks
  - mitmproxy CA mounted to container as read-only
  - If missing or corrupt, git clone fails (GnuTLS validates CA bundle)
  - API requests to mitmproxy-intercepted endpoints fail (certificate validation error)
  - Application fails explicitly → user sees "certificate verify failed"

**Rationale:** Explicit failure is preferable to silent compromise. Users and operators should see that security is broken, not assume it's working.

### 2. Readiness Probe Checks

**Definition:** Conditions that must be met before accepting traffic (starting the user shell).

**Implemented checks (in order):**

1. **Unified Proxy Readiness** (`unified-proxy`)
   - Docker healthcheck: `curl -sf --unix-socket /var/run/proxy/internal.sock http://localhost/internal/health`
   - Timeout: 5 seconds per attempt
   - Retries: 5 attempts before marking unhealthy
   - Start period: 10 seconds (grace time for initialization)
   - What it validates: Internal API is running, mitmproxy is listening, addons loaded
   - What it does NOT validate: All credentials loaded correctly

2. **Sandbox Dependency on Proxy** (`dev` service)
   - Docker compose `depends_on` with `condition: service_healthy`
   - Blocks container startup until unified-proxy is healthy
   - If proxy fails healthcheck, sandbox container fails to start
   - Error message clearly shows which dependency failed

3. **Runtime Readiness Checks** (in entrypoint)
   - After proxy is marked healthy, entrypoint validates additional conditions:
     - DNS configuration (in `entrypoint-root.sh`)
     - mitmproxy CA certificate mounted and readable
     - Unified-proxy IP resolved and added to /etc/hosts

**Design Rationale:**

The healthcheck validates *availability*, not *correctness*. Full validation happens during entrypoint initialization, after Docker marks the service healthy. This two-stage approach:
- Prevents premature startup if port is not listening
- Allows full configuration validation before shell prompt
- Gives operators visibility into each stage of failure

### 3. Startup Sequence

**Order is critical for fail-closed behavior:**

#### Stage 0: Docker Service Startup (Orchestrator Level)

1. **docker-compose up** is called
2. Docker starts the unified-proxy service

#### Stage 1: Proxy Initialization

**Unified Proxy** (`unified-proxy`):
```
1. Load Python environment
2. Start internal API via Unix socket (/var/run/proxy/internal.sock)
3. Validate addons (credential injector, DNS filter, policy engine, etc.)
4. Load mitmproxy certificates (stored in named volume: mitm-certs)
5. Load domain allowlist from config/allowlist.yaml
6. Initialize SQLite container registry (/var/lib/unified-proxy/registry.db)
7. Start mitmproxy with HTTP mode (port 8080) and optional DNS mode (port 53)
8. Write readiness marker (/var/run/proxy/ready)
9. Docker healthcheck succeeds when internal API returns healthy
```

#### Stage 2: Sandbox Initialization (After Proxy Healthy)

Once the proxy passes healthcheck, sandbox (`dev`) container starts:

1. **entrypoint-root.sh** (runs as root):
   ```
   1. Resolve unified-proxy IP via getent hosts unified-proxy
   2. Add to /etc/hosts for reliable resolution:
      - "${PROXY_IP} unified-proxy"
   3. Configure DNS firewall (iptables rules):
      - ACCEPT DNS to unified-proxy IP only
      - DROP DNS to all other destinations
      - Prevents: dig @8.8.8.8, direct external DNS resolution
   4. Install mitmproxy CA certificate:
      - Copy /certs/mitmproxy-ca.pem to system CA store
      - Run update-ca-certificates
      - This allows git (GnuTLS) to verify MITM'd connections
   5. Drop privileges and exec entrypoint.sh as ubuntu user
   ```

   **Failure modes:**
   - Cannot resolve unified-proxy → **FAIL**: Warning logged, proxy IP remains unset. DNS iptables rules still block external DNS. Sandbox cannot reach anything.
   - mitmproxy CA missing → **FAIL**: git clone fails with "certificate verify failed"
   - iptables rules fail → **LOG WARNING**: DNS might leak. Operator should see warning in logs.

2. **entrypoint.sh** (runs as ubuntu user):
   ```
   1. Create home directories (tmpfs is empty on each restart)
   2. Fix permissions on mounted volumes
   3. Set npm, pip configuration
   4. Configure Claude onboarding
   5. Copy proxy stubs if enabled
   6. Apply gitconfig rewriting if enabled
   7. Return prompt or execute passed command
   ```

**Timing:**
- Healthcheck start_period: 10s grace time
- Healthcheck interval: 5s checks
- With 5 retries at 5s each: ~35s total time to mark unhealthy
- Typical healthy startup: 2-5 seconds
- Sandbox startup (once proxy healthy): 1-2 seconds

### 4. Graceful Shutdown

**Scenario:** User or orchestrator initiates `docker-compose down` or `docker stop <container>`.

**Shutdown sequence:**

1. **Sandbox container** (dev):
   - Docker sends SIGTERM to main process (shell or command)
   - Grace period: 10 seconds (Docker default)
   - After grace period: SIGKILL
   - On SIGTERM: Bash saves command history, closes files
   - No active connections to proxy survive (would still fail-closed if killed)

2. **Unified Proxy container** (unified-proxy):
   - Docker sends SIGTERM to mitmproxy process
   - Grace period: 10 seconds
   - mitmproxy stops accepting new connections
   - In-flight HTTP/HTTPS and git requests continue until completion or timeout
   - SQLite registry persists to disk (WAL mode ensures consistency)
   - After SIGKILL: container stops

3. **Named volumes** (mitm-certs, proxy-data):
   - Preserved for next startup (unless explicitly deleted)
   - Certificates remain valid
   - Container registry database preserved
   - Allowlist remains available

**Cleanup on container stop:**
- Tmpfs mounts cleared (/tmp, /var/tmp, /home/ubuntu, etc.)
- Ephemeral git worktree state removed
- No persistent data loss (by design—sandboxes are ephemeral)

**Connection draining:**
- No explicit drain mechanism implemented
- Git operations that are mid-clone might leave partial state
- This is acceptable: next sandbox will start fresh
- Reason: Sandboxes are typically short-lived (minutes to hours)

**Resource cleanup:**
- Volumes retained for next sandbox (certificates don't expire)
- Network released by Docker
- Memory reclaimed
- Port released (unified-proxy:8080, optionally :53)

### 5. Error Scenarios and Recovery

**Scenario A: Unified Proxy Crashes During Operation**

1. Proxy process dies
2. Docker healthcheck detects failure (internal API unreachable)
3. Sandbox's HTTP/HTTPS requests fail: "Connection refused to unified-proxy:8080"
4. DNS queries fail (port 53 unreachable, iptables blocks external DNS)
5. User sees explicit error, must restart docker-compose
6. Credentials never exposed (proxy held all credentials)

**Scenario B: Unified Proxy Becomes Unresponsive**

1. Proxy process hangs (Python deadlock, etc.)
2. Healthcheck fails: internal API endpoint times out
3. Docker marks unified-proxy unhealthy
4. Active sandbox continues running but cannot make new requests
5. User must restart docker-compose
6. Next startup: proxy healthcheck fails → sandbox fails to start

**Scenario C: DNS Firewall Rules Not Applied**

1. entrypoint-root.sh attempts iptables rules
2. Rules fail (e.g., iptables command not found, permission issue)
3. Script logs warning but continues (not fatal)
4. Sandbox starts but DNS is not blocked
5. **Problem:** Sandbox can make direct DNS queries
6. **Mitigation:** Proxy configured for allowlist, but direct DNS bypass possible
7. **Recommendation:** Operator should see "Failed to apply DNS firewall" in logs

**Scenario D: mitmproxy CA Certificate Not Mounted**

1. /certs/mitmproxy-ca.pem does not exist
2. entrypoint-root.sh skips installation (silent skip)
3. Sandbox starts and user runs `git clone`
4. git connects to proxy, receives MITM'd connection
5. Certificate validation fails: "unable to get local issuer certificate"
6. User sees explicit TLS error
7. Clear failure: not a silent bypass

## Consequences

### Positive

- **Security by Default:** Proxy failure results in lockdown, not graceful degradation
- **Operator Visibility:** Failed healthchecks and logs make problems obvious
- **Explicit Errors:** Users see "Connection refused" or "Certificate verify failed," not mysterious timeouts
- **Reliable Isolation:** No partial bypass scenarios where sandbox appears isolated but isn't
- **Clear Dependency Chain:** docker-compose ordering makes startup requirements explicit
- **Defense-in-Depth on DNS:** Combination of proxy DNS filtering + iptables firewall rules + /etc/hosts prevents multiple bypass paths
- **Persistent Sessions:** SQLite-backed container registry survives proxy restarts, avoiding re-authentication

### Negative

- **Startup Time:** Waiting for healthchecks adds 2-5 seconds to sandbox creation
- **Logging Noise:** If proxy frequently fails/recovers, logs accumulate quickly
- **No Graceful Degradation:** Cannot operate with reduced functionality (e.g., if DNS fails but HTTP still needed)
- **Manual Restart Required:** No automatic recovery if proxy becomes unhealthy mid-operation

### Neutral

- **Single Proxy Container:** One service to monitor (simpler than multi-service, but single point of failure)
- **Healthcheck Overhead:** ~0.5% CPU to perform health checks every 5-10 seconds (negligible)
- **TLS MITM:** Explicit design choice to intercept HTTPS; documented in credential-isolation.md threat model

## Alternatives Considered

### Alternative 1: Graceful Degradation

If proxy fails, allow direct API calls with placeholder credentials (fail-open).

**Rationale for rejection:**
- Placeholder credentials would fail at API endpoint anyway
- Creates false sense of security if proxy silently fails
- Operator might not notice isolation is broken
- Security boundary should be all-or-nothing, not degraded

### Alternative 2: Proxy Auto-Restart

If unified-proxy becomes unhealthy, automatically restart it.

**Rationale for rejection:**
- Docker's `restart: unless-stopped` already does this
- Automatic restart can mask underlying problems
- If proxy fails repeatedly, need operator intervention to investigate
- Scenario: proxy crashes, auto-restarts, sandbox unaware, makes request with old session → fails

### Alternative 3: Multiple Proxy Instances

Run 2-3 replicas of the proxy with load balancing.

**Rationale for rejection:**
- SQLite registry would need to be shared or replaced with distributed store
- Adds Docker networking complexity
- Sandboxes still cannot operate if all replicas fail
- Cost/complexity not justified for single-tenant use case

### Alternative 4: External Session Store

Store sessions in Redis/database external to the proxy.

**Rationale for rejection:**
- Adds persistent storage dependency
- Increases attack surface (compromise of session store = all sessions)
- SQLite with WAL mode provides sufficient durability within a single container
- Sandboxes are ephemeral—expected to be recreated
- Not worth the complexity and security cost

## References

- [docker-compose.credential-isolation.yml](/workspace/docker-compose.credential-isolation.yml) - Healthcheck configuration
- [Security Architecture](/workspace/docs/security/security-architecture.md) - Security pillars overview
- [Credential Isolation](/workspace/docs/security/credential-isolation.md) - Credential isolation threat model
- [entrypoint-root.sh](/workspace/entrypoint-root.sh) - DNS firewall and startup initialization
- [entrypoint.sh](/workspace/entrypoint.sh) - Sandbox user-level startup
- [unified-proxy/entrypoint.sh](/workspace/unified-proxy/entrypoint.sh) - Proxy startup with internal API, addon validation, and mitmproxy
- [unified-proxy/registry.py](/workspace/unified-proxy/registry.py) - SQLite-backed container registry
- Docker Compose Documentation: [depends_on with service_healthy condition](https://docs.docker.com/compose/compose-file/compose-file-v3/#depends_on)
