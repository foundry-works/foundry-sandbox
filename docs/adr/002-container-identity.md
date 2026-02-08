# ADR-002: Container Identity Design

## Status

Accepted

Date: 2026-02-04

### Implementation Notes

Container identity implemented in `unified-proxy/addons/container_identity.py`:

- **IP-based identity** - Primary identification via source IP from socket inspection
- **Optional header validation** - X-Container-Id header for additional verification
- **SQLite registry** - Persistent storage with write-through cache (`registry.py`)
- **TTL-based expiration** - Default 24-hour TTL with auto-cleanup
- **Internal API** - RESTful registration via Unix socket (`internal_api.py`)

## Context

The unified proxy needs to reliably identify which sandbox container is making requests. This is crucial for:

- **Per-container policy enforcement** - Different sandboxes may have different access policies, network allowlists, and credential profiles
- **Credential isolation** - Each sandbox must authenticate with its own session token, and real credentials must be injected per-container
- **Audit logging** - Requests must be traceable to specific sandboxes for security monitoring and compliance
- **Resource quotas** - Rate limiting and resource allocation should be per-container
- **Sandbox lifecycle management** - Container start/stop/restart events must be tracked to maintain accurate identity registrations

The identity mechanism must:
1. Uniquely identify containers across their lifecycle
2. Handle container restarts (same identity after restart vs. fresh identity)
3. Support optional verification for additional security
4. Work within Docker's networking model
5. Clean up stale registrations when containers are removed

## Decision

We implement a **two-layer container identity model**:

### Layer 1: IP-Based Identity (Primary)

Containers are identified by their unique IP address on the Docker network created for the sandbox. This is the primary identity mechanism:

- Each sandbox container receives a unique IP from the docker-compose service's network
- The IP address is stable within the container's lifetime
- The IP is registered in the SQLite-backed identity registry when the container connects to the proxy
- The IP can be discovered from the proxy's perspective via socket inspection or explicit registration

**Advantages:**
- Network-native: No additional protocol overhead
- Automatic: Docker assigns IPs; no manual coordination needed
- Persistent within container lifetime: Survives most network transients
- Kernel-enforced: Cannot be spoofed without network-level privileges

**Limitations:**
- IP changes on container restart (fresh container gets new IP)
- Requires proxy to inspect source IPs on each request

### Layer 2: Optional Header Validation (Secondary)

For additional security and explicit verification, containers may include an `X-Sandbox-ID` header in requests:

```
X-Sandbox-ID: sandbox-name:container-start-time:session-token
```

Structure:
- `sandbox-name`: Human-readable sandbox identifier (e.g., "repo-feature-branch")
- `container-start-time`: Container start timestamp (ISO 8601), prevents replay across restarts
- `session-token`: Cryptographically secure token (32+ bytes, base64-encoded), unique per container instance

**Validation rules:**
1. Extract source IP from request
2. Look up IP in identity registry
3. If `X-Sandbox-ID` header present:
   - Parse the header
   - Verify session token matches registered token for this IP
   - Verify sandbox name matches registered name
   - Verify container-start-time matches or is within acceptable skew
4. Reject request if header validation fails (security policy configurable)

**Advantages:**
- Defense in depth: Prevents spoofing if network is compromised
- Explicit: Clear audit trail of intended sandbox identity
- Helps detect container restarts: `container-start-time` differs from previous requests
- Resistant to IP reuse attacks: Session token prevents old IPs from being reused

### Registration Lifecycle

#### 1. Container Registration (Startup)

When a container starts and makes its first request to the proxy:

```
Container starts
    ↓
entrypoint.sh generates session token
    ↓
Container makes initial request with X-Sandbox-ID header
    ↓
Proxy validates header and registers:
  {
    "ip": "172.20.0.5",
    "sandbox_name": "repo-feature-branch",
    "start_time": "2026-02-04T10:30:45.123Z",
    "session_token": "base64_encoded_token",
    "registered_at": "2026-02-04T10:30:46.000Z",
    "last_seen": "2026-02-04T10:30:46.000Z"
  }
    ↓
Subsequent requests use IP-based lookup (header optional)
```

#### 2. TTL and Renewal

Registrations have a configurable TTL (default: 24 hours):

- **TTL clock starts:** When container is registered
- **TTL reset:** On each request from that IP, update `last_seen` timestamp
- **TTL expiration:** If `now - last_seen > TTL`, mark registration as stale
- **Cleanup:** Stale registrations are removed on next garbage collection run

TTL rationale:
- Long enough for normal container lifecycle (run, attach, detach, reattach)
- Short enough to detect orphaned containers (crashed, not properly stopped)
- Prevents IP reuse attacks: Ensure enough grace period to detect old IP being reused

#### 3. Container Restart

When a container restarts (e.g., `docker compose restart` or `cast start`):

```
Container stops
    ↓
Old IP released back to Docker network pool
Old registration marked for expiration (TTL stops being renewed)
    ↓
Container restarts
    ↓
New IP assigned (likely different from old IP)
    ↓
Container makes request with NEW session token (generated at startup)
    ↓
Proxy sees new IP + new token
    ↓
Creates new registration
Previous registration eventually garbage collected
```

This design allows:
- Clear distinction between "same container after restart" (new IP, new token) vs. "network hiccup" (same IP, same token)
- Audit trail: Old and new registrations visible in logs before cleanup
- Policy decisions: Proxy can decide whether restart resets quota, permissions, etc.

#### 4. Container Removal (Graceful)

When container is removed via `cast destroy` or explicit `docker compose down`:

Option A (Proactive cleanup):
```
cast destroy sandbox-name
    ↓
Script sends shutdown signal to proxy:
  DELETE /proxy/containers/{sandbox-name}
    ↓
Proxy:
  - Finds all registrations matching sandbox_name
  - Marks as "removed"
  - Closes any active sessions
  - Immediately deletes registrations
    ↓
Container stops
```

Option B (Passive expiration):
```
Container stops
    ↓
No more requests arrive from that IP
    ↓
Registration reaches TTL expiration
    ↓
Garbage collection deletes registration
```

Recommendation: Implement both. Proactive is fast, passive provides safety net.

#### 5. Garbage Collection

Automatic cleanup process runs periodically (default: every 5 minutes):

```
For each registration:
  if registration.state == "removed":
    delete immediately
  elif now - registration.last_seen > TTL:
    delete (and log as expired)
  else:
    keep

Log orphaned containers and removals for audit trail
```

### Restart Detection

Using the `container-start-time` field, the proxy can detect when a container restarts:

```
Request 1: X-Sandbox-ID: sandbox-name:2026-02-04T10:30:45.123Z:token123
  → Proxy registers: start_time = 2026-02-04T10:30:45.123Z

Request 2 (5 min later): X-Sandbox-ID: sandbox-name:2026-02-04T10:35:12.456Z:token456
  → start_time CHANGED
  → Proxy detects restart
  → Actions: reset quota, close old sessions, create new registration
```

This explicit signal is more reliable than inferring from IP changes alone.

## Consequences

### Positive

- **Simplicity:** IP addresses are assigned by Docker; no manual registration protocol needed
- **Decoupling:** Proxy doesn't need to know sandbox names; identity works even if names change
- **Defense in depth:** Header-based verification provides additional security layer
- **Auditability:** Session tokens and start times provide clear audit trail
- **Graceful restart handling:** Containers can restart and obtain new identity without manual intervention
- **Passive safety:** TTL ensures registrations eventually clean up even if proxy crashes or containers die unexpectedly
- **Clear signals:** Container restart is explicitly detectable via `container-start-time` change
- **Persistence:** SQLite-backed registry survives proxy restarts without losing container registrations

### Negative

- **IP dependencies:** Proxy must reliably inspect request source IPs (fails if load balancer strips this information)
- **Network requirements:** Requires containers to be on a dedicated Docker network or accessible by IP
- **Token generation:** Requires entrypoint.sh to generate cryptographically secure tokens (adds dependency on `/dev/urandom` or similar)
- **Registration overhead:** Each new container adds registry entry and requires first request before identity is known
- **Clock skew:** Verifying `container-start-time` requires proxy and containers to have synchronized clocks (or accept skew tolerance)
- **TTL tuning:** TTL value is configuration-dependent; too short causes false expiration, too long delays cleanup
- **Restart ambiguity:** Without header validation, cannot distinguish between "container restarted" vs. "network reassigned IP"

### Neutral

- **Session tokens:** Generated fresh each startup; doesn't impact existing authentication mechanisms
- **Dual-layer approach:** Complexity is only incurred if both IP + header validation are used; simple deployments can use IP alone
- **Logging:** Registration events (create, renew, expire, remove) add to logs but provide valuable audit trail

## Alternatives Considered

### A1: Container Name-Based Identity

**Proposal:** Use Docker container name as the identity (e.g., `foundry-sandbox-repo-feature-branch-1`).

**Rejected because:**
- Container names are user-configurable and may collide
- Less suitable for API-based identification (container name not visible to proxy without Docker API access)
- Requires proxy to maintain mapping from container name to IP
- Container names don't change on restart, masking restart events

### A2: Docker Container ID (SHA256)

**Proposal:** Use Docker's immutable container ID as identity (regenerated on restart).

**Rejected because:**
- Requires proxy to communicate with Docker daemon (increases attack surface)
- Docker IDs not accessible from inside containers without socket access
- Less human-readable for debugging
- Doesn't work if proxy and containers run on different hosts

### A3: DNS Name-Based Identity

**Proposal:** Use service DNS names (e.g., `sandbox-name.docker.local`).

**Rejected because:**
- Requires custom DNS configuration (adds deployment complexity)
- DNS names may not be unique across runs
- DNS resolution adds latency
- Less reliable than IPs on internal Docker networks

### A4: Header-Only Identity (No IP Layer)

**Proposal:** Skip IP-based identification; use only `X-Sandbox-ID` header.

**Rejected because:**
- Header can be spoofed if attacker controls client (malicious AI code in container)
- No automatic discovery: proxy must wait for header before identity is known
- Doesn't leverage Docker's built-in network isolation
- Fails if request path doesn't support custom headers (e.g., some proxies strip headers)

### A5: Capability-Based Identity

**Proposal:** Containers prove identity via cryptographic challenge/response (like TLS client certificates).

**Rejected because:**
- High complexity for implementation and deployment
- Overkill for internal Docker network (traffic already isolated)
- Significant performance overhead
- Difficult to debug
- Better to use IP + header as lightweight approximation

## References

- [Security Architecture](../security/security-architecture.md) - Credential isolation and network controls
- [Network Isolation](../security/network-isolation.md) - Docker network setup and firewall rules
- [Architecture](../architecture.md) - System overview and component interactions
- `unified-proxy/addons/container_identity.py` — Identity addon implementation
- `unified-proxy/registry.py` — SQLite-backed container registry
- `unified-proxy/internal_api.py` — Registration REST API
- Docker Networking: https://docs.docker.com/engine/network/
- Docker Compose Networking: https://docs.docker.com/compose/networking/
