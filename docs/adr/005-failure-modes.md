# ADR-005: Failure Modes and Readiness Design

## Status

Accepted

Date: 2026-02-04

## Context

The unified proxy system (gateway + api-proxy) is a critical security component that enforces credential isolation and network restrictions. If the proxy fails silently or becomes partially available, the sandbox could:

1. Bypass security controls and access external systems directly
2. Expose real credentials to untrusted code
3. Be blocked from legitimate operations due to missing proxy dependencies

Without careful failure mode design, the system creates a false sense of security—the sandbox appears isolated but can partially bypass controls if the proxy degrades.

### Current System

The credential isolation architecture uses two proxy containers:

- **Gateway**: Holds GitHub credentials, enforces DNS routing, injects credentials for git operations
- **API Proxy**: Holds API keys (Anthropic, OpenAI, Google, etc.), performs HTTPS MITM to inject credentials

Both proxies must be healthy and reachable for the sandbox to operate securely. The sandbox depends on:
- Gateway for DNS resolution and git credential injection
- API Proxy for outbound HTTP/HTTPS requests
- Correct certificate trust setup for HTTPS interception

## Decision

We implement **fail-closed behavior** with strict readiness requirements and ordered initialization:

### 1. Fail-Closed Behavior

**Principle:** If any security component fails, deny all access rather than gracefully degrade.

**Implementation:**

- **Gateway failure** → DNS cannot be routed through gateway
  - DNS firewall rules (iptables) block all DNS to external resolvers
  - Sandbox cannot resolve external domains → cannot connect anywhere
  - Legitimate operations fail (curl, git clone) → user sees clear error
  - No silent fallback to direct network access

- **API Proxy failure** → credentials cannot be injected
  - HTTP_PROXY and HTTPS_PROXY environment variables point to api-proxy:8080
  - If api-proxy is unreachable, HTTP/HTTPS requests fail with connection refused
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

1. **API Proxy Readiness** (`api-proxy`)
   - Docker healthcheck: TCP connect to port 8080
   - Timeout: 5 seconds per attempt
   - Retries: 5 attempts before marking unhealthy
   - Start period: 10 seconds (grace time for initialization)
   - What it validates: Port is listening, basic connectivity works
   - What it does NOT validate: Credentials loaded, MITM setup complete

2. **Gateway Readiness** (`gateway`)
   - Docker healthcheck: HTTP GET to `/health` endpoint
   - Timeout: 5 seconds per attempt
   - Retries: 3 attempts before marking unhealthy
   - Start period: 10 seconds (grace time for initialization)
   - What it validates: Flask app is running, can handle requests
   - What it does NOT validate: Credentials loaded, domain allowlist loaded

3. **Sandbox Dependency on Proxies** (`dev` service)
   - Docker compose `depends_on` with `condition: service_healthy`
   - Blocks container startup until both proxies are healthy
   - If either proxy fails healthcheck, sandbox container fails to start
   - Error message clearly shows which dependency failed

4. **Runtime Readiness Checks** (in entrypoint)
   - After proxies are marked healthy, entrypoint validates additional conditions:
     - Gateway DNS configuration (in `entrypoint-root.sh`)
     - mitmproxy CA certificate mounted and readable
     - Domain allowlist loaded (gateway logs confirm)
     - Gateway IP resolved and added to /etc/hosts

**Design Rationale:**

The healthchecks validate *availability*, not *correctness*. Full validation happens during entrypoint initialization, after Docker marks services healthy. This two-stage approach:
- Prevents premature startup if port is not listening
- Allows full configuration validation before shell prompt
- Gives operators visibility into each stage of failure

### 3. Startup Sequence

**Order is critical for fail-closed behavior:**

#### Stage 0: Docker Service Startup (Orchestrator Level)

1. **docker-compose up** is called
2. Docker starts both proxy services (concurrently):
   - api-proxy (healthcheck: port 8080 TCP)
   - gateway (healthcheck: /health HTTP endpoint)

#### Stage 1: Proxy Initialization (Parallel)

**API Proxy** (`api-proxy:8080`):
```
1. Load Python environment
2. Parse configuration from environment variables
3. Load mitmproxy certificates (stored in named volume: mitm-certs)
4. Start mitmproxy server
5. Listen on 0.0.0.0:8080 (TCP port available)
6. Docker healthcheck succeeds when port 8080 accepts connections
```

**Gateway** (`gateway:8080`):
```
1. Load Python environment
2. Load domain allowlist from firewall-allowlist.generated
3. Initialize Flask application
4. Load session storage (in-memory dictionary)
5. Listen on 0.0.0.0:8080 (TCP port available)
6. Docker healthcheck: HTTP GET /health
7. Response: {"status": "healthy"}, 200 OK
8. If allowlist fails to load: log warning but continue
   (operations will fail at runtime, not silently succeed)
```

**Dependency:** API Proxy and Gateway are independent (can start concurrently). No ordering required between them.

#### Stage 2: Sandbox Initialization (After Proxies Healthy)

Once both proxies pass healthcheck, sandbox (`dev`) container starts:

1. **entrypoint-root.sh** (runs as root):
   ```
   1. Resolve internal service IPs:
      - Gateway IP via getent hosts gateway
      - API Proxy IP via getent hosts api-proxy
   2. Add to /etc/hosts for reliable resolution:
      - "${GATEWAY_IP} gateway"
      - "${API_PROXY_IP} api-proxy"
   3. Configure DNS firewall (iptables rules):
      - ACCEPT DNS to gateway IP only
      - DROP DNS to all other destinations
      - Prevents: dig @8.8.8.8, direct external DNS resolution
   4. Install mitmproxy CA certificate:
      - Copy /certs/mitmproxy-ca.pem to system CA store
      - Run update-ca-certificates
      - This allows git (GnuTLS) to verify MITM'd connections
   5. Drop privileges and exec entrypoint.sh as ubuntu user
   ```

   **Failure modes:**
   - Cannot resolve gateway → **FAIL**: Warning logged, but gateway IP remains unset. DNS iptables rules still block external DNS. Sandbox cannot reach anything.
   - mitmproxy CA missing → **FAIL**: git clone fails with "certificate verify failed"
   - iptables rules fail → **LOG WARNING**: DNS might leak. Operator should see warning in logs.

2. **entrypoint.sh** (runs as ubuntu user):
   ```
   1. Create home directories (tmpfs is empty on each restart)
   2. Fix permissions on mounted volumes
   3. Set npm, pip configuration
   4. Configure Claude onboarding
   5. Copy proxy stubs (gateway mode) if enabled
   6. Apply gateway gitconfig rewriting (gateway mode) if enabled
   7. Return prompt or execute passed command
   ```

**Timing:**
- Healthcheck start_period: 10s grace time
- Healthcheck interval: 5s checks
- With 5 retries at 5s each: ~35s total time to mark unhealthy
- Typical healthy startup: 2-5 seconds per proxy
- Sandbox startup (once proxies healthy): 1-2 seconds

### 4. Graceful Shutdown

**Scenario:** User or orchestrator initiates `docker-compose down` or `docker stop <container>`.

**Shutdown sequence:**

1. **Sandbox container** (dev):
   - Docker sends SIGTERM to main process (shell or command)
   - Grace period: 10 seconds (Docker default)
   - After grace period: SIGKILL
   - On SIGTERM: Bash saves command history, closes files
   - No active connections to gate/proxy (would still fail-closed if killed)

2. **Gateway container** (gateway):
   - Docker sends SIGTERM to Flask process
   - Grace period: 10 seconds
   - Flask stops accepting new connections (no new sessions)
   - In-flight git operations continue until completion or timeout
   - Session storage discarded (in-memory only, not persistent)
   - After SIGKILL: container stops

3. **API Proxy container** (api-proxy):
   - Docker sends SIGTERM to mitmproxy process
   - Grace period: 10 seconds
   - mitmproxy stops accepting new connections
   - In-flight HTTP/HTTPS requests continue until completion or timeout
   - After SIGKILL: container stops

4. **Named volumes** (mitm-certs, proxy-stubs):
   - Preserved for next startup (unless explicitly deleted)
   - Certificates remain valid
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
- Port released (api-proxy:8080, gateway:8080)

### 5. Error Scenarios and Recovery

**Scenario A: API Proxy Crashes During Operation**

1. Proxy process dies
2. Docker healthcheck detects no port listening (fails after 5 retries)
3. Sandbox's HTTP/HTTPS requests fail: "Connection refused to api-proxy:8080"
4. User sees explicit error, must restart docker-compose
5. Credentials never exposed (proxy held all credentials)

**Scenario B: Gateway Becomes Unresponsive**

1. Gateway process hangs (Python deadlock, etc.)
2. Healthcheck fails: /health endpoint times out
3. Docker marks gateway unhealthy
4. Active sandbox continues running but cannot make new git requests
5. Existing git credentials in filesystem still valid (short-lived tokens)
6. User must restart docker-compose
7. Next startup: gateway healthcheck fails → sandbox fails to start

**Scenario C: DNS Firewall Rules Not Applied**

1. entrypoint-root.sh attempts iptables rules
2. Rules fail (e.g., iptables command not found, permission issue)
3. Script logs warning but continues (not fatal)
4. Sandbox starts but DNS is not blocked
5. **Problem:** Sandbox can make direct DNS queries
6. **Mitigation:** gateway configured for allowlist, but direct DNS bypass possible
7. **Recommendation:** Operator should see "Failed to apply DNS firewall" in logs

**Scenario D: mitmproxy CA Certificate Not Mounted**

1. /certs/mitmproxy-ca.pem does not exist
2. entrypoint-root.sh skips installation (silent skip)
3. Sandbox starts and user runs `git clone`
4. git connects to gateway, receives MITM'd connection
5. Certificate validation fails: "unable to get local issuer certificate"
6. User sees explicit TLS error
7. Clear failure: not a silent bypass

## Consequences

### Positive

- **Security by Default:** Proxy failures result in lockdown, not graceful degradation
- **Operator Visibility:** Failed healthchecks and logs make problems obvious
- **Explicit Errors:** Users see "Connection refused" or "Certificate verify failed," not mysterious timeouts
- **Reliable Isolation:** No partial bypass scenarios where sandbox appears isolated but isn't
- **Clear Dependency Chain:** docker-compose ordering makes startup requirements explicit
- **Defense-in-Depth on DNS:** Combination of gateway routing + iptables firewall rules + /etc/hosts prevents multiple bypass paths

### Negative

- **Operational Overhead:** Operators must monitor two proxy services plus healthchecks
- **Startup Time:** Waiting for healthchecks adds 2-5 seconds to sandbox creation
- **Logging Noise:** If proxies frequently fail/recover, logs accumulate quickly
- **No Graceful Degradation:** Cannot operate with reduced functionality (e.g., if API proxy down but git still needed)
- **Cached Credentials Risk:** Session tokens are in-memory; gateway restart loses sessions and requires re-auth
- **Manual Restart Required:** No automatic recovery if proxy becomes unhealthy mid-operation

### Neutral

- **Two Proxy Containers:** Requires Docker Compose to manage two services (not a security difference, just complexity)
- **Healthcheck Overhead:** ~0.5% CPU to perform /health checks every 5-10 seconds (negligible)
- **TLS MITM:** Explicit design choice to intercept HTTPS; documented in credential-isolation.md threat model

## Alternatives Considered

### Alternative 1: Graceful Degradation

If API proxy fails, allow direct API calls with placeholder credentials (fail-open).

**Rationale for rejection:**
- Placeholder credentials would fail at API endpoint anyway
- Creates false sense of security if proxy silently fails
- Operator might not notice isolation is broken
- Security boundary should be all-or-nothing, not degraded

### Alternative 2: Proxy Auto-Restart

If gateway/api-proxy becomes unhealthy, automatically restart them.

**Rationale for rejection:**
- Docker's `restart: unless-stopped` already does this
- Automatic restart can mask underlying problems
- If proxies fail repeatedly, need operator intervention to investigate
- Sessions would be lost (in-memory store) anyway
- Scenario: proxy crashes, auto-restarts, sandbox unaware, makes git request with old token → fails

### Alternative 3: Multiple Proxy Instances

Run 2-3 replicas of each proxy with load balancing.

**Rationale for rejection:**
- Session affinity becomes complex (tokens only valid on creating instance)
- Adds Docker networking complexity
- Sandboxes still cannot operate if all replicas fail
- Cost/complexity not justified for single-tenant use case

### Alternative 4: Persistent Session Store

Store sessions in Redis/database so they survive proxy restarts.

**Rationale for rejection:**
- Adds persistent storage dependency
- Increases attack surface (compromise of session store = all sessions)
- Sessions are short-lived (24h inactivity, 7d absolute TTL)
- Sandboxes are ephemeral—expected to be recreated
- Not worth the complexity and security cost

## References

- [docker-compose.credential-isolation.yml](/workspace/docker-compose.credential-isolation.yml) - Healthcheck configuration
- [Security Architecture](/workspace/docs/security/security-architecture.md) - Security pillars overview
- [Credential Isolation](/workspace/docs/security/credential-isolation.md) - Gateway threat model and network isolation
- [entrypoint-root.sh](/workspace/entrypoint-root.sh) - DNS firewall and startup initialization
- [entrypoint.sh](/workspace/entrypoint.sh) - Sandbox user-level startup
- [gateway.py](/workspace/gateway/gateway.py) - Health endpoint and domain allowlist loading
- Docker Compose Documentation: [depends_on with service_healthy condition](https://docs.docker.com/compose/compose-file/compose-file-v3/#depends_on)
