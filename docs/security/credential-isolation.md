# Credential Isolation

This document covers the credential isolation system: its **network architecture**, **trust boundaries**, **threats**, **defense layers**, and **explicit design decisions**.

## Overview

```
+------------------+     +------------------------------+     +------------------+
|    Sandbox       |     |       Unified Proxy          |     |  External APIs   |
|    (dev)         |     |                              |     |  (GitHub, Anthro- |
|                  |---->|  API Gateways (9848-9852)    |---->|   pic, OpenAI,   |
|  [placeholders]  |     |  Squid SNI filter (:8080)    |     |   Gemini, etc.)  |
|                  |     |  mitmproxy (:8081, optional)  |     |                  |
|                  |     |  DNS filter (:53)            |     |                  |
|                  |     |  [ALL CREDS]                 |     |                  |
+------------------+     +------------------------------+     +------------------+
```

The credential isolation system prevents sandbox containers from directly accessing credentials (GitHub tokens, API keys) while still allowing them to perform authenticated operations through a controlled proxy.

## Scope

### What This Document Covers

This threat model covers the **credential isolation system** - a proxy that:
- Isolates real credentials (GitHub tokens, API keys) from AI sandbox containers
- Injects credentials into outbound requests through a unified proxy
- Provides container-registration-based authentication for sandbox containers

### What This Document Does NOT Cover

- General AI sandbox safety (see [Security Model](security-model.md))
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
- Registry could grow large (mitigated by: explicit unregistration on destroy, optional TTL-based cleanup)

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

**Rationale:** Dropping CAP_NET_RAW prevents IP spoofing, ARP poisoning, and raw packet sniffing — attacks that could bypass network isolation and container registration IP binding. This protects against supply chain attacks (malicious packages attempting L2 network exploits) with minimal operational impact (only `ping`/`traceroute` are affected). See [Security Model: Network Isolation](security-model.md#network-isolation) for the full defense layer breakdown.

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
   - Explicit unregistration on sandbox destroy (optional TTL if configured)
   - Network isolation via Docker bridge + iptables
   - Read-only filesystem prevents persistent attacker presence

5. **Attack Scenario Analysis**: The realistic attack path is: compromise sandbox -> read placeholder values -> attempt exfiltration (blocked by network). mTLS doesn't change this threat model.

**Accepted Risks:**
- Network-level MITM on Docker bridge (mitigated by: network isolation, attacker would need container escape first)
- Registration data interception in transit (mitigated by: IP binding, network isolation)

---

## Defense Layers

The credential isolation system relies on five defense layers:

1. **Network isolation** — Internal Docker network, CAP_NET_RAW dropped, DNS filtering, iptables rules
2. **Container registration** — SQLite-backed registry with IP binding, explicit unregistration, Unix socket-only API
3. **Credential proxying** — Placeholder values in sandbox, real credentials injected by proxy at request time
4. **Request validation** — Domain allowlisting, git operation filtering, branch isolation, protected branches, rate limiting
5. **Audit and monitoring** — Request logging, sensitive data filtering, container lifecycle logging

Each layer is described in detail in [Security Model](security-model.md) under the corresponding pillar.

---

## Network Security Layers

Network isolation is enforced through five layers: internal Docker networking, proxy routing, DNS isolation, iptables rules, and CAP_NET_RAW dropped. See [Security Model: Network Isolation](security-model.md#network-isolation) for the full breakdown.

### Proxy Routing

Outbound traffic is routed through the unified proxy via three mechanisms:

- **API Gateways** — Major providers (Anthropic :9848, GitHub :9850, Gemini :9851, ChatGPT/Codex :9852) route through dedicated gateways that inject credentials and forward to upstream over HTTPS. See [Architecture: API Gateways](../architecture.md#api-gateways) for ports and details.
- **Squid Forward Proxy** — All other HTTPS traffic routes through Squid on port 8080 (SNI-based domain filtering). MITM-required domains are forwarded to mitmproxy via `cache_peer`.
- **Git API Server** — Git operations go through the git API server (port 8083) with HMAC authentication. HTTPS push/fetch credentials are injected via `FOUNDRY_PROXY_GIT_TOKEN`.

```yaml
environment:
  - HTTP_PROXY=http://unified-proxy:8080
  - HTTPS_PROXY=http://unified-proxy:8080
  - NO_PROXY=localhost,127.0.0.1,unified-proxy,chatgpt.com
```

---

## Credential Exposure Matrix

| Credential | Unified Proxy | Sandbox |
|------------|---------------|---------|
| GITHUB_TOKEN / GH_TOKEN | Yes | No (empty) |
| ANTHROPIC_API_KEY | Yes | Placeholder |
| OPENAI_API_KEY | Yes | Placeholder |
| GOOGLE_API_KEY | Yes | Placeholder |
| Other API Keys | Yes | Placeholder |
| FOUNDRY_PROXY_GIT_TOKEN | Yes (subprocess env only) | No (never exposed) |

The unified proxy holds all real credentials. Sandboxes never see real values.

---

## Service Dependencies

```
unified-proxy ───────> dev (sandbox)
```

The unified proxy must be healthy before the sandbox starts:

```yaml
depends_on:
  unified-proxy:
    condition: service_healthy
```

The healthcheck verifies the internal API is responsive via Unix socket:

```yaml
healthcheck:
  test: ["CMD", "curl", "-sf", "--unix-socket", "/var/run/proxy/internal.sock", "http://localhost/internal/health"]
  interval: 5s
  timeout: 5s
  retries: 5
  start_period: 10s
```

---

## Attack Scenarios and Responses

| Scenario | Attack | Outcome |
|----------|--------|---------|
| **Supply chain** (malicious npm package) | Package reads env vars, attempts direct HTTPS, DNS exfiltration, raw packet crafting | Gets placeholder values only; all exfiltration paths blocked by network isolation, DNS filter, and CAP_NET_RAW dropped |
| **AI token probing** | AI-generated code searches filesystem and memory for tokens | Finds only placeholder values — real credentials never enter the sandbox |
| **Lateral movement** | Compromised Sandbox A attempts to reach Sandbox B via direct connection, ARP/IP spoofing, or DNS rebinding | Blocked by separate isolated networks, CAP_NET_RAW dropped, and DNS filter |
| **Registration theft** | Attacker obtains registration details, attempts reuse from different location | Rejected by IP binding; registrations removed on destroy; new registration requires orchestrator (Unix socket) |

See [Security Model](security-model.md) for the full defense layer breakdown behind each outcome.

---

## Verification and Testing

### Network Isolation

```bash
# Check network config
docker network inspect credential-isolation

# From sandbox: verify direct external access blocked
curl -v https://github.com 2>&1 | grep -E "(Connection refused|timed out)"

# From sandbox: verify proxy-routed access works
git clone https://github.com/owner/repo.git  # Should work

# From sandbox: verify DNS filtering
dig @8.8.8.8 github.com  # Should fail (blocked by iptables)
dig github.com  # Should work (uses unified-proxy DNS)
```

### Credential Isolation

```bash
# From sandbox: verify real credentials not exposed
echo $GITHUB_TOKEN  # Should be empty
echo $ANTHROPIC_API_KEY  # Should be CREDENTIAL_PROXY_PLACEHOLDER

# From sandbox: verify credential injection works
git clone https://github.com/allowed/repo.git  # Should work
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/v1/messages  # Should work via proxy
```

### Container Registration

```bash
# From host: verify registration requires Unix socket
# Registration is done via orchestrator (lib/proxy.sh) through Unix socket or docker exec
# Direct HTTP access to internal API is not exposed outside the proxy container

# Verify container is registered:
docker exec <proxy-container> curl -s --unix-socket /var/run/proxy/internal.sock http://localhost/internal/containers
```

### CAP_NET_RAW (Supply Chain Protection)

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
- Explicit unregistration on sandbox destroy limits exposure window

---

## Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.credential-isolation.yml` | Service definitions and network config |
| `safety/network-firewall.sh` | iptables rules for defense-in-depth |
| `config/allowlist.yaml` | Domain allowlist (single source of truth) |
| `unified-proxy/` | Unified proxy for all egress traffic |

## See Also

- [Security Model](security-model.md) — Security pillars, threat model, and hardening details
- [ADR-009: API Gateways](../adr/009-api-gateways.md) — Gateway architecture decision

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-31 | 1.0 | Initial threat model for credential isolation gateway |
| 2026-02-05 | 2.0 | Updated for unified-proxy consolidation: merged gateway + API proxy into single service, replaced session tokens with container registry (SQLite-backed), updated DNS filtering to use integrated mitmproxy DNS mode |
| 2026-02-08 | 2.1 | Added v0.10-v0.11 features: branch isolation enforcement, protected branch policies, GitHub API endpoint filtering, FOUNDRY_PROXY_GIT_TOKEN injection |
| 2026-02-22 | 2.2 | Merged network-isolation.md content: network topology, security layers, credential exposure matrix, bypass proof, service dependencies |
| 2026-02-22 | 2.3 | Deduplicated defense layers, network security layers, attack scenarios, and CAP_NET_RAW section — replaced with cross-references to security-model.md |
