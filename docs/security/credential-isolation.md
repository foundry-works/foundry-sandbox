# Credential Isolation: Threat Model

This document defines the security scope, trust boundaries, threats, and explicit design decisions for credential isolation.

## Scope

### What This Document Covers

This threat model covers the **credential isolation system** - a proxy that:
- Isolates real credentials (GitHub tokens, API keys) from AI sandbox containers
- Injects credentials into outbound requests through a unified proxy
- Provides container-registration-based authentication for sandbox containers

### What This Document Does NOT Cover

- General AI sandbox safety (see [sandbox-threats.md](sandbox-threats.md))
- Host-level security (OS hardening, Docker daemon security)
- Upstream service security (GitHub, Anthropic, OpenAI)

---

## Trust Boundaries

### Trusted Components

| Component | Trust Level | Rationale |
|-----------|-------------|-----------|
| Docker Host | Full | Controls all containers, has root access |
| Orchestrator | High | Creates/destroys sandboxes, registers containers via Unix socket |
| Unified Proxy Container | High | Holds all real credentials (GitHub tokens, API keys), injects into requests, filters DNS |

### Untrusted Components

| Component | Trust Level | Threats |
|-----------|-------------|---------|
| Sandbox Contents | None | AI-generated code, user code, dependencies |
| Sandbox Network Traffic | None | May attempt credential theft, data exfiltration |
| Sandbox Environment | None | May inspect memory, environment, filesystem |

### Trust Boundary Diagram

```
+------------------------------------------------------------------+
|                         TRUSTED ZONE                             |
|  +------------------+  +------------------+  +------------------+ |
|  |  Docker Host     |  |   Orchestrator   |  |  Unified Proxy   | |
|  |  - root access   |  |  - container     |  |  - GITHUB_TOKEN  | |
|  |  - all volumes   |  |    registration  |  |  - API keys      | |
|  +------------------+  |  - Unix socket   |  |  - HTTPS MITM    | |
|                        +------------------+  |  - DNS filter     | |
|                                              +------------------+ |
+------------------------------------------------------------------+
                              |
          TRUST BOUNDARY (Docker network + iptables)
                              |
+------------------------------------------------------------------+
|                        UNTRUSTED ZONE                            |
|  +------------------+  +------------------+  +------------------+ |
|  |    Sandbox 1     |  |    Sandbox 2     |  |    Sandbox N     | |
|  |  - AI code       |  |  - AI code       |  |  - AI code       | |
|  |  - registered IP |  |  - registered IP |  |  - registered IP | |
|  |  - placeholder   |  |  - placeholder   |  |  - placeholder   | |
|  |    API keys      |  |    API keys      |  |    API keys      | |
|  +------------------+  +------------------+  +------------------+ |
+------------------------------------------------------------------+
```

---

## Primary Threats

### Priority 1: Credential Theft / Unauthorized Token Access

**Threat:** Malicious or compromised code in a sandbox obtains the real GitHub token or API keys.

**Attack Vectors:**
- Reading credentials from environment variables
- Intercepting network traffic to capture injected credentials
- Memory scraping of proxy processes
- Exploiting proxy vulnerabilities to dump credentials

**Mitigations:**
- Credentials never enter sandbox environment (placeholder values only)
- Container registration binds sandboxes to their IP address
- Network isolation prevents direct credential interception
- Proxy runs in a separate container with minimal attack surface

### Priority 2: Unauthorized Repository Access

**Threat:** A sandbox accesses repositories beyond its authorized scope.

**Attack Vectors:**
- Forging requests to access other repos via the proxy
- Bypassing repository allowlist validation
- Exploiting container registration to impersonate another sandbox

**Mitigations:**
- Container registration with IP binding
- Proxy validates all repository access against policy
- Registration requires orchestrator access (Unix socket only)

### Priority 3: Lateral Movement Between Sandboxes

**Threat:** One compromised sandbox attacks or accesses another sandbox.

**Attack Vectors:**
- Direct container-to-container communication
- Shared network resource exploitation
- IP spoofing to impersonate another container

**Mitigations:**
- Each sandbox project has its own isolated Docker network
- Container registration bound to originating IP
- CAP_NET_RAW dropped prevents IP spoofing and ARP poisoning

### Priority 4: Unified Proxy Compromise

**Threat:** Attacker gains control of the unified proxy.

**Attack Vectors:**
- Exploiting application vulnerabilities (injection, deserialization)
- Container escape from sandbox to proxy
- Privilege escalation within proxy container

**Mitigations:**
- Proxy runs as non-root user (mitmproxy user, via gosu privilege drop)
- Minimal container image with reduced attack surface
- Input validation on all external inputs
- Network segmentation limits blast radius (proxy-egress is separate from credential-isolation)

---

## Critical Configuration Requirements

### DNS Filtering Must Be Enabled for True Isolation

**DNS filtering is enabled by default** (`PROXY_ENABLE_DNS=true`).

Without DNS filtering, sandboxes can bypass the proxy by:
1. Using hardcoded IP addresses instead of domain names
2. Using alternative DNS resolvers to resolve github.com directly
3. Making network requests to IP addresses that bypass credential injection

**Configuration:**

In `docker-compose.credential-isolation.yml`, the sandbox's DNS is configured by `entrypoint-root.sh` to point to the unified-proxy's DNS filter:

```yaml
# unified-proxy runs DNS on port 53
environment:
  - PROXY_ENABLE_DNS=true

# entrypoint-root.sh resolves unified-proxy IP dynamically and writes /etc/resolv.conf
# iptables rules restrict DNS to unified-proxy only
```

**Verification:**

```bash
# From sandbox: verify DNS routing
dig github.com  # Should return proxy-filtered response

# From sandbox: verify direct DNS is blocked
dig @8.8.8.8 github.com  # Should fail (blocked by iptables)
```

**Impact if not configured:** IP-based network requests bypass credential injection and repository scoping. The proxy becomes security theater rather than actual isolation.

---

## Explicit Non-Requirements

The following capabilities were evaluated and **explicitly excluded** from the implementation. This section documents the rationale and accepted risks.

### Rate Limiting on Git Operations - ACCEPTED RISK

**Decision:** Rate limiting on git operations and container registration limits are not implemented.

**Threat Model Rationale:**

1. **Trust Boundary**: The proxy operates within a trusted orchestration environment. Container registration is only accessible from the orchestrator (Unix socket), not from sandboxed containers. The orchestrator is a trusted component.

2. **Resource Exhaustion is Not Primary Threat**: The primary threats are credential theft and unauthorized repository access. DoS via resource exhaustion:
   - Affects availability, not confidentiality/integrity
   - Can be mitigated at infrastructure layer (container resource limits, orchestrator-level controls)
   - Is self-limiting (attacker exhausts their own sandbox resources)

3. **Operational Complexity**: Rate limiting adds state management, clock dependencies, and configuration complexity that increases attack surface for the primary threats.

4. **GitHub's Own Rate Limits**: Upstream GitHub API already enforces rate limits per token. The proxy doesn't amplify requests beyond what a direct connection would allow.

5. **Single-Tenant Model**: Each sandbox is isolated. A sandbox exhausting resources only affects itself, not other users.

**Accepted Risks:**
- A compromised orchestrator could register many containers (mitigated by: orchestrator is trusted)
- A single sandbox could make many git requests (mitigated by: GitHub rate limits, container resource limits)
- Registry could grow large (mitigated by: TTL-based expiration and cleanup in SQLite registry)

### Custom Seccomp/AppArmor Profiles - NOT IMPLEMENTED

**Decision:** Custom seccomp and AppArmor profiles are not specified in Dockerfiles.

**Threat Model Rationale:**

1. **Docker Defaults Are Sufficient**: Docker's default seccomp profile already blocks ~44 dangerous syscalls including `ptrace`, `mount`, `reboot`, `kexec_load`, `init_module`. Custom profiles provide marginal additional benefit.

2. **Container Escape is a Docker/Kernel Issue**: If a container escape vulnerability exists in Docker or the Linux kernel, custom profiles may not prevent exploitation. This is an infrastructure-level concern, not application-level.

3. **Host-Level Configuration**: AppArmor profiles must be installed on the Docker host, not just in container images. This is operational/infrastructure configuration outside this codebase's scope.

4. **Not the Primary Threat**: The primary threats are credential theft and unauthorized repository access. These are mitigated by the proxy's authentication, network isolation, and allowlists - not syscall filtering.

5. **Complexity vs. Benefit**: Custom profiles require ongoing maintenance as application needs change. The security benefit is marginal given existing controls.

**Accepted Risks:**
- A kernel/Docker vulnerability could allow container escape (mitigated by: infrastructure patching, not in scope of this implementation)
- Exotic syscall-based attacks possible (mitigated by: Docker default seccomp, read-only filesystem, network isolation)

### CAP_NET_RAW Dropped from Sandboxes - IMPLEMENTED

**Decision:** Sandbox containers have CAP_NET_RAW capability dropped via `cap_drop: NET_RAW`.

**Threat Model Rationale:**

1. **Supply Chain Attack Protection**: Malicious npm packages, Python libraries, or other dependencies may contain code that attempts to exploit network-level attacks. By dropping CAP_NET_RAW, we prevent:
   - IP spoofing (crafting packets with forged source addresses)
   - ARP poisoning (redirecting traffic via fake ARP replies)
   - Raw packet sniffing on the Docker bridge network

2. **Defense-in-Depth for Network Isolation**: CAP_NET_RAW is required to craft raw packets that could bypass network controls at Layer 2. Dropping this capability closes this gap.

3. **Container Registration Protection**: Without CAP_NET_RAW, an attacker cannot:
   - Spoof the source IP to bypass container IP binding
   - Sniff unencrypted traffic on the bridge network
   - Perform ARP spoofing to redirect proxy traffic

4. **Minimal Operational Impact**: The only tools affected are:
   - `ping` / `traceroute` (ICMP requires raw sockets)
   - Low-level network debugging tools
   These are rarely needed in AI coding sandboxes.

**Attack Vectors Blocked:**

| Attack | Mechanism | Protection |
|--------|-----------|------------|
| IP Spoofing | CAP_NET_RAW + raw packets | Blocked - cannot create raw sockets |
| ARP Poisoning | Craft ARP replies | Blocked - cannot create raw sockets |
| Packet Sniffing | Raw sockets on bridge | Blocked - cannot create raw sockets |
| Registration Hijacking | Spoof container IP | Blocked - IP spoofing prevented |

### Mutual TLS (mTLS) for Internal Traffic - NOT IMPLEMENTED

**Decision:** Proxy-to-sandbox communication uses plaintext HTTP over Docker internal network, not mTLS.

**Threat Model Rationale:**

1. **Network Already Isolated**: The internal network prevents direct container-to-container traffic. iptables rules restrict egress. Only the unified proxy is reachable from sandboxes on the internal network.

2. **If Attacker Has Network Access, They Already Won**: To intercept Docker bridge traffic, an attacker must have already compromised a container. At that point, they can read environment variables directly - mTLS wouldn't prevent this.

3. **Significant Operational Complexity**: mTLS requires:
   - Certificate generation per sandbox
   - Certificate distribution at container creation
   - Certificate rotation and revocation
   - Debugging TLS issues in ephemeral containers

4. **Existing Mitigations Are Sufficient**:
   - Container registration with IP binding
   - TTL-based expiration (24h default, stored in SQLite)
   - Network isolation via Docker bridge + iptables
   - Read-only filesystem prevents persistent attacker presence

5. **Attack Scenario Analysis**: The realistic attack path is: compromise sandbox -> read placeholder values -> attempt exfiltration (blocked by network). mTLS doesn't change this threat model.

**Accepted Risks:**
- Network-level MITM on Docker bridge (mitigated by: network isolation, attacker would need container escape first)
- Registration data interception in transit (mitigated by: IP binding, TTLs, network isolation)

---

## Defense Layers

This section documents what IS implemented to address the primary threats.

### Layer 1: Network Isolation

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Internal network | `internal: true` on Docker network | Direct external access |
| CAP_NET_RAW dropped | `cap_drop: NET_RAW` on both sandbox and proxy | L2 attacks, IP spoofing, ARP poisoning |
| DNS isolation | DNS routed through unified-proxy DNS filter (enabled by default) | DNS exfiltration |
| iptables rules | `safety/network-firewall.sh` | Defense-in-depth for network controls |

### Layer 2: Container Registration

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Container registry | SQLite-backed registry (`registry.py`) with TTL | Container identity management |
| IP binding | Registrations bound to container IP | Registration reuse from other IPs |
| TTL expiration | Registrations expire after 24h (configurable) | Stale registration abuse |
| Internal API | Unix socket only (`/var/run/proxy/internal.sock`) | Unauthorized registration |

### Layer 3: Credential Proxying

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Git credential injection | Unified proxy injects GITHUB_TOKEN for git operations | Token exposure in sandbox |
| API credential injection | Unified proxy injects API keys for HTTP/HTTPS requests | API key exposure in sandbox |
| Placeholder values | Sandbox sees `CREDENTIAL_PROXY_PLACEHOLDER` | Environment variable scraping |
| Policy engine | Addon chain enforces per-request policy | Unauthorized API access |

### Layer 4: Request Validation

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Domain allowlisting | DNS-level + policy engine domain restrictions | Data exfiltration |
| Git operation filtering | `git_proxy.py` addon blocks dangerous operations | Force push, history rewriting |
| Rate limiting | `rate_limiter.py` addon | Resource exhaustion |
| Circuit breaker | `circuit_breaker.py` addon | Cascading failures |

### Layer 5: Audit and Monitoring

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Request logging | All proxy requests logged via `metrics.py` addon | Incident investigation |
| Sensitive data filtering | Tokens filtered from logs | Log-based credential exposure |
| Container lifecycle logging | Registration create/destroy logged | Registration abuse detection |

---

## Attack Scenarios and Responses

### Scenario 1: Malicious npm Package in Sandbox (Supply Chain Attack)

**Attack:** User installs npm package that attempts to read environment variables and exfiltrate credentials.

**Response:**
1. Package reads `ANTHROPIC_API_KEY` -> gets `CREDENTIAL_PROXY_PLACEHOLDER`
2. Package attempts direct HTTPS to api.anthropic.com -> blocked by network isolation
3. Package attempts DNS exfiltration -> blocked by DNS filter
4. Package attempts raw packet crafting to bypass network controls -> blocked by CAP_NET_RAW dropped
5. Attack fails, credentials remain secure

### Scenario 2: AI-Generated Code Probes for Tokens

**Attack:** AI generates code that searches filesystem and memory for tokens.

**Response:**
1. Filesystem search finds only placeholder environment variables
2. No real credentials exist anywhere in the sandbox
3. Exfiltration attempts get placeholder values, not real secrets
4. Attack fails - credentials never entered the sandbox

### Scenario 3: Compromised Container Attempts Lateral Movement

**Attack:** Attacker gains shell in Sandbox A, attempts to attack Sandbox B.

**Response:**
1. Direct network connection to Sandbox B -> blocked by separate isolated networks per project
2. ARP spoofing to intercept Sandbox B traffic -> blocked by CAP_NET_RAW dropped (cannot create raw sockets)
3. IP spoofing to impersonate Sandbox B -> blocked by CAP_NET_RAW dropped
4. DNS rebinding to redirect Sandbox B -> blocked by unified-proxy DNS filter
5. Attack fails, Sandbox B remains isolated

### Scenario 4: Container Registration Theft and Reuse

**Attack:** Attacker obtains container registration details, attempts to use from different location.

**Response:**
1. Attacker uses registration from different IP -> rejected by IP binding
2. Attacker waits for registration to expire -> registration expires via TTL
3. Attacker attempts to create new registration -> requires orchestrator access (Unix socket only)
4. Attack fails, IP binding prevents registration reuse

---

## Security Testing Checklist

### Network Isolation Verification

```bash
# From sandbox: verify cannot reach external directly
curl -v https://github.com 2>&1 | grep -E "(Connection refused|timed out)"

# From sandbox: verify DNS only resolves via unified-proxy
dig @8.8.8.8 github.com  # Should fail
dig github.com  # Should work (uses unified-proxy DNS)
```

### Credential Isolation Verification

```bash
# From sandbox: verify real credentials not exposed
echo $GITHUB_TOKEN  # Should be empty
echo $ANTHROPIC_API_KEY  # Should be CREDENTIAL_PROXY_PLACEHOLDER

# From sandbox: verify credential injection works
git clone https://github.com/allowed/repo.git  # Should work
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/v1/messages  # Should work via proxy
```

### Container Registration Verification

```bash
# From host: verify registration requires Unix socket
# Registration is done via orchestrator (lib/proxy.sh) through Unix socket or docker exec
# Direct HTTP access to internal API is not exposed outside the proxy container

# Verify container is registered:
docker exec <proxy-container> curl -s --unix-socket /var/run/proxy/internal.sock http://localhost/internal/containers
```

### CAP_NET_RAW Verification (Supply Chain Protection)

```bash
# From sandbox: verify CAP_NET_RAW is dropped
cat /proc/self/status | grep CapEff
# Decode capabilities (requires capsh on host):
# capsh --decode=<hex_value>
# Should NOT include cap_net_raw (bit 13)

# From sandbox: verify raw socket creation fails
python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)"
# Should raise: PermissionError: [Errno 1] Operation not permitted

# From sandbox: verify ping fails (requires CAP_NET_RAW)
ping -c 1 unified-proxy
# Should fail with "Operation not permitted" or similar
```

---

## Known Limitations

### Basic Auth Does Not Validate Container Registration

**Behavior:** When using Basic auth (git credential helper flow), the proxy identifies the container by its source IP address from the container registry, not by a shared secret.

**Security Implications:**
- An attacker who can spoof the container's IP could impersonate it
- CAP_NET_RAW is dropped to prevent IP spoofing
- Docker network isolation prevents cross-network IP spoofing

**Mitigating Factors:**
- IP binding via container registry provides strong protection within isolated Docker networks
- Container registrations are managed by the orchestrator (trusted component)
- Network isolation prevents external access to the isolation network
- TTL-based expiration limits exposure window

---

## Related Documentation

- [Network Isolation](network-isolation.md) - Detailed network architecture
- [Security Architecture](security-architecture.md) - Security pillars and defense layers
- [Sandbox Threats](sandbox-threats.md) - AI-as-threat-actor model for sandbox safety

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-31 | 1.0 | Initial threat model for credential isolation gateway |
| 2026-02-05 | 2.0 | Updated for unified-proxy consolidation: merged gateway + API proxy into single service, replaced session tokens with container registry (SQLite-backed), updated DNS filtering to use integrated mitmproxy DNS mode |
