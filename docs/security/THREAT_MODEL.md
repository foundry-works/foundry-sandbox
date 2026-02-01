# Credential Isolation Gateway: Threat Model

This document defines the security scope, trust boundaries, threats, and explicit design decisions for the credential isolation gateway.

## Scope

### What This Document Covers

This threat model covers the **credential isolation gateway** - a proxy system that:
- Isolates real credentials (GitHub tokens, API keys) from AI sandbox containers
- Injects credentials into outbound requests through controlled proxies
- Provides session-based authentication for sandbox containers

### What This Document Does NOT Cover

- General AI sandbox safety (see [threat-model.md](threat-model.md))
- Host-level security (OS hardening, Docker daemon security)
- Upstream service security (GitHub, Anthropic, OpenAI)

---

## Trust Boundaries

### Trusted Components

| Component | Trust Level | Rationale |
|-----------|-------------|-----------|
| Docker Host | Full | Controls all containers, has root access |
| Orchestrator | High | Creates/destroys sandboxes, manages sessions via localhost/Unix socket |
| Gateway Container | High | Holds real credentials, validates requests |
| API Proxy Container | High | Holds real API keys, intercepts HTTPS traffic |

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
|  |  Docker Host     |  |   Orchestrator   |  |    Gateway       | |
|  |  - root access   |  |  - session mgmt  |  |  - GITHUB_TOKEN  | |
|  |  - all volumes   |  |  - localhost     |  |  - credential    | |
|  +------------------+  +------------------+  |    injection     | |
|                                             +------------------+ |
|                                             +------------------+ |
|                                             |    API Proxy     | |
|                                             |  - API keys      | |
|                                             |  - HTTPS MITM    | |
|                                             +------------------+ |
+------------------------------------------------------------------+
                              |
          TRUST BOUNDARY (Docker network + iptables)
                              |
+------------------------------------------------------------------+
|                        UNTRUSTED ZONE                            |
|  +------------------+  +------------------+  +------------------+ |
|  |    Sandbox 1     |  |    Sandbox 2     |  |    Sandbox N     | |
|  |  - AI code       |  |  - AI code       |  |  - AI code       | |
|  |  - session token |  |  - session token |  |  - session token | |
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
- Session tokens are sandbox-specific, short-lived, IP-bound
- Network isolation prevents direct credential interception
- Proxies run in separate containers with minimal attack surface

### Priority 2: Unauthorized Repository Access

**Threat:** A sandbox accesses repositories beyond its authorized scope.

**Attack Vectors:**
- Forging requests to access other repos via the gateway
- Session hijacking to use another sandbox's permissions
- Bypassing repository allowlist validation

**Mitigations:**
- Session-based repository allowlisting (when configured)
- Session tokens bound to container IP
- Gateway validates all repository access against session scope

### Priority 3: Lateral Movement Between Sandboxes

**Threat:** One compromised sandbox attacks or accesses another sandbox.

**Attack Vectors:**
- Direct container-to-container communication
- Session token theft and reuse
- Shared network resource exploitation

**Mitigations:**
- ICC (Inter-Container Communication) disabled on isolation network
- Session tokens bound to originating IP
- Each sandbox has unique session credentials

### Priority 4: Gateway/Proxy Compromise

**Threat:** Attacker gains control of the gateway or API proxy.

**Attack Vectors:**
- Exploiting application vulnerabilities (injection, deserialization)
- Container escape from sandbox to gateway
- Privilege escalation within gateway container

**Mitigations:**
- Gateway runs as non-root user (when possible)
- Minimal container image with reduced attack surface
- Input validation on all external inputs
- Network segmentation limits blast radius

---

## Critical Configuration Requirements

### DNS Routing Must Be Enabled for True Isolation

**⚠️ IMPORTANT:** For complete credential isolation, DNS must be routed through the gateway.

Without DNS routing through the gateway (using dnsmasq), sandboxes can bypass the gateway by:
1. Using hardcoded IP addresses instead of domain names
2. Using alternative DNS resolvers to resolve github.com directly
3. Making network requests to IP addresses that bypass credential injection

**Required Configuration:**

In `docker-compose.credential-isolation.yml`, the sandbox must use the gateway as its DNS resolver:

```yaml
dev:
  dns:
    - gateway  # Route DNS through gateway's dnsmasq
```

The gateway's dnsmasq rewrites DNS responses for `github.com` to point to the gateway IP, ensuring all git traffic flows through the credential injection proxy.

**Verification:**

```bash
# From sandbox: verify DNS routing
dig github.com  # Should return gateway IP, not GitHub's actual IP

# From sandbox: verify direct IP access is blocked
curl -v https://140.82.112.4  # Should fail (GitHub IP blocked by network isolation)
```

**Impact if not configured:** IP-based network requests bypass credential injection and repository scoping. The gateway becomes security theater rather than actual isolation.

---

## Explicit Non-Requirements

The following capabilities were evaluated and **explicitly excluded** from the implementation. This section documents the rationale and accepted risks.

### Rate Limiting on Git Operations - ACCEPTED RISK

**Decision:** Rate limiting on git operations and session creation limits are not implemented.

**Threat Model Rationale:**

1. **Trust Boundary**: The gateway operates within a trusted orchestration environment. Session creation is only accessible from the orchestrator (localhost/Unix socket), not from sandboxed containers. The orchestrator is a trusted component.

2. **Resource Exhaustion is Not Primary Threat**: The primary threats are credential theft and unauthorized repository access. DoS via resource exhaustion:
   - Affects availability, not confidentiality/integrity
   - Can be mitigated at infrastructure layer (container resource limits, orchestrator-level controls)
   - Is self-limiting (attacker exhausts their own sandbox resources)

3. **Operational Complexity**: Rate limiting adds state management, clock dependencies, and configuration complexity that increases attack surface for the primary threats.

4. **GitHub's Own Rate Limits**: Upstream GitHub API already enforces rate limits per token. The gateway doesn't amplify requests beyond what a direct connection would allow.

5. **Single-Tenant Model**: Each sandbox is isolated. A sandbox exhausting sessions only affects itself, not other users.

**Accepted Risks:**
- A compromised orchestrator could create many sessions (mitigated by: orchestrator is trusted)
- A single sandbox could make many git requests (mitigated by: GitHub rate limits, container resource limits)
- Session table could grow large (mitigated by: session TTL and garbage collection already implemented)

### Custom Seccomp/AppArmor Profiles - NOT IMPLEMENTED

**Decision:** Custom seccomp and AppArmor profiles are not specified in Dockerfiles.

**Threat Model Rationale:**

1. **Docker Defaults Are Sufficient**: Docker's default seccomp profile already blocks ~44 dangerous syscalls including `ptrace`, `mount`, `reboot`, `kexec_load`, `init_module`. Custom profiles provide marginal additional benefit.

2. **Container Escape is a Docker/Kernel Issue**: If a container escape vulnerability exists in Docker or the Linux kernel, custom profiles may not prevent exploitation. This is an infrastructure-level concern, not application-level.

3. **Host-Level Configuration**: AppArmor profiles must be installed on the Docker host, not just in container images. This is operational/infrastructure configuration outside this codebase's scope.

4. **Not the Primary Threat**: The primary threats are credential theft and unauthorized repository access. These are mitigated by the gateway's authentication, network isolation, and allowlists - not syscall filtering.

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

2. **Defense-in-Depth for ICC=false**: While Docker's ICC=false blocks Layer 3/4 traffic between containers, it does NOT block Layer 2 (Ethernet) traffic. CAP_NET_RAW is required to craft raw packets that could bypass ICC at Layer 2. Dropping this capability closes this gap.

3. **Session Token Protection**: Without CAP_NET_RAW, an attacker cannot:
   - Spoof the source IP to bypass session IP binding
   - Sniff unencrypted session tokens on the bridge network
   - Perform ARP spoofing to redirect gateway traffic

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
| Session Hijacking | Spoof container IP | Blocked - IP spoofing prevented |

### Mutual TLS (mTLS) for Internal Traffic - NOT IMPLEMENTED

**Decision:** Gateway-to-sandbox communication uses plaintext HTTP over Docker internal network, not mTLS.

**Threat Model Rationale:**

1. **Network Already Isolated**: ICC=false blocks direct container-to-container traffic. iptables rules restrict egress. Only the gateway is reachable from sandboxes on the internal network.

2. **If Attacker Has Network Access, They Already Won**: To intercept Docker bridge traffic, an attacker must have already compromised a container. At that point, they can read credentials directly from `/run/secrets/gateway_token` - mTLS wouldn't prevent this.

3. **Significant Operational Complexity**: mTLS requires:
   - Certificate generation per sandbox
   - Certificate distribution at container creation
   - Certificate rotation and revocation
   - Debugging TLS issues in ephemeral containers

4. **Existing Mitigations Are Sufficient**:
   - Session tokens with IP binding
   - Short session TTLs (inactive sessions expire)
   - Network isolation via Docker bridge + iptables
   - Read-only filesystem prevents persistent attacker presence

5. **Attack Scenario Analysis**: The realistic attack path is: compromise sandbox -> read token from file/memory -> use token. mTLS doesn't prevent in-container credential theft, which is the primary concern.

**Accepted Risks:**
- Network-level MITM on Docker bridge (mitigated by: network isolation, attacker would need container escape first)
- Session token interception in transit (mitigated by: IP binding, short TTLs, network isolation)

---

## Defense Layers

This section documents what IS implemented to address the primary threats.

### Layer 1: Network Isolation

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Internal network | `internal: true` on Docker network | Direct external access |
| ICC disabled | `enable_icc: false` driver option | Container-to-container attacks (L3/L4) |
| CAP_NET_RAW dropped | `cap_drop: NET_RAW` | L2 attacks, IP spoofing, ARP poisoning |
| DNS isolation | DNS routed through gateway dnsmasq | DNS exfiltration |
| iptables rules | `safety/network-firewall.sh` | Defense-in-depth for network controls |

### Layer 2: Session-Based Authentication

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Session tokens | Random tokens generated per sandbox | Credential theft |
| Session secrets | Optional secondary authentication factor | Session hijacking |
| IP binding | Sessions bound to container IP | Session token reuse |
| TTL expiration | Sessions expire after inactivity | Stale session abuse |

### Layer 3: Credential Proxying

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Git credential injection | Gateway injects GITHUB_TOKEN | Token exposure in sandbox |
| API credential injection | API proxy injects API keys | API key exposure in sandbox |
| Placeholder values | Sandbox sees `CREDENTIAL_PROXY_PLACEHOLDER` | Environment variable scraping |

### Layer 4: Request Validation

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Repository allowlisting | Per-session repo restrictions | Unauthorized repo access |
| Path validation | Git path sanitization | Path traversal attacks |
| Domain allowlisting | DNS-level domain restrictions | Data exfiltration |

### Layer 5: Audit and Monitoring

| Control | Implementation | Threat Addressed |
|---------|----------------|------------------|
| Request logging | All gateway requests logged | Incident investigation |
| Sensitive data filtering | Tokens filtered from logs | Log-based credential exposure |
| Session lifecycle logging | Session create/destroy logged | Session abuse detection |

---

## Attack Scenarios and Responses

### Scenario 1: Malicious npm Package in Sandbox (Supply Chain Attack)

**Attack:** User installs npm package that attempts to read environment variables and exfiltrate credentials.

**Response:**
1. Package reads `ANTHROPIC_API_KEY` -> gets `CREDENTIAL_PROXY_PLACEHOLDER`
2. Package attempts direct HTTPS to api.anthropic.com -> blocked by network isolation
3. Package attempts DNS exfiltration -> blocked by DNS isolation
4. Package attempts raw packet crafting to bypass network controls -> blocked by CAP_NET_RAW dropped
5. Attack fails, credentials remain secure

### Scenario 2: AI-Generated Code Probes for Tokens

**Attack:** AI generates code that searches filesystem and memory for tokens.

**Response:**
1. Filesystem search finds `/run/secrets/gateway_token` -> contains session token, not real credentials
2. Session token is bound to this container's IP, useless elsewhere
3. Session token only works with gateway, which validates repository access
4. Attack succeeds at finding session token but cannot escalate to real credentials

### Scenario 3: Compromised Container Attempts Lateral Movement

**Attack:** Attacker gains shell in Sandbox A, attempts to attack Sandbox B.

**Response:**
1. Direct network connection to Sandbox B -> blocked by ICC=false
2. ARP spoofing to intercept Sandbox B traffic -> blocked by CAP_NET_RAW dropped (cannot create raw sockets)
3. IP spoofing to impersonate Sandbox B -> blocked by CAP_NET_RAW dropped
4. DNS rebinding to redirect Sandbox B -> blocked by gateway DNS control
5. Attack fails, Sandbox B remains isolated

### Scenario 4: Session Token Theft and Reuse

**Attack:** Attacker obtains session token from Sandbox A, attempts to use from different location.

**Response:**
1. Attacker uses token from different IP -> rejected by IP binding
2. Attacker waits for session to be reused -> session expires via TTL
3. Attacker attempts to create new session -> requires orchestrator access (localhost only)
4. Attack fails, session binding prevents token reuse

---

## Security Testing Checklist

### Network Isolation Verification

```bash
# From sandbox: verify cannot reach external directly
curl -v https://github.com 2>&1 | grep -E "(Connection refused|timed out)"

# From sandbox: verify cannot reach other containers
ping -c 1 <other-sandbox-ip>  # Should fail with ICC disabled

# From sandbox: verify DNS only resolves via gateway
dig @8.8.8.8 github.com  # Should fail
dig github.com  # Should work (uses gateway DNS)
```

### Credential Isolation Verification

```bash
# From sandbox: verify real credentials not exposed
echo $GITHUB_TOKEN  # Should be empty or session token
echo $ANTHROPIC_API_KEY  # Should be CREDENTIAL_PROXY_PLACEHOLDER

# From sandbox: verify credential injection works
git clone https://github.com/allowed/repo.git  # Should work
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/v1/messages  # Should work via proxy
```

### Session Security Verification

```bash
# From host: verify session creation requires localhost
curl http://gateway:8080/api/session -X POST  # Should fail from non-localhost

# From different container: verify session token IP binding
curl -H "Authorization: Bearer <sandbox-a-token>" http://gateway:8080/git/...  # Should fail from sandbox B
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
ping -c 1 gateway
# Should fail with "Operation not permitted" or similar
```

---

## Known Limitations

### Basic Auth Does Not Validate Session Secret

**Behavior:** When using Basic auth (git credential helper flow), only the session token is validated, not the session secret. The secret is not transmitted in Basic auth.

**Why This Exists:** Git credential helpers use Basic authentication (RFC 7617) which provides a single password field. Our credential helper stores the session token in the password field. The two-factor token:secret model was designed for Bearer auth API calls.

**Security Implications:**
- An attacker who obtains only the session token (without the secret) could use it from the same IP address
- The attacker must still pass IP binding validation (session bound to container IP)
- Docker ICC=false prevents other containers from accessing the sandbox's IP
- Tokens are stored with 0400 permissions in `/run/secrets/gateway_token`

**Mitigating Factors:**
- IP binding provides strong protection within isolated Docker networks
- Session tokens are cryptographically random (secrets.token_urlsafe(32))
- Network isolation prevents external access to sandbox network segment
- Short TTLs limit exposure window

**Alternative Considered:** Encode token:secret in Base64 as the password field. Rejected because:
- Adds complexity to credential helper
- May exceed git's maximum credential length on some platforms
- IP binding already provides sufficient security for threat model

### Session Store Is In-Memory Only

**Behavior:** Sessions are stored in a Python dictionary in the gateway process. If the gateway container restarts, all sessions are lost.

**Operational Impact:**
- Sandboxes must re-authenticate after gateway restart
- Re-authentication requires orchestrator intervention (session creation is localhost-only)
- No automatic session recovery mechanism

**Why Not Persistent Storage:**
- Sessions are short-lived (24h inactivity, 7d absolute)
- Adding persistent storage (Redis, filesystem) increases attack surface
- Gateway restarts should be rare in normal operation
- Sandboxes are typically short-lived and can be recreated

**Workarounds:**
- Orchestrator can detect failed git operations and recreate sessions
- For long-running sandboxes, schedule gateway restarts during maintenance windows
- Monitor gateway uptime as part of operational health checks

---

## Related Documentation

- [Network Isolation Model](network-isolation.md) - Detailed network architecture
- [Safety Layers](safety-layers.md) - General sandbox safety mechanisms
- [General Threat Model](threat-model.md) - AI-as-threat-actor model for sandbox safety

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-31 | 1.0 | Initial threat model for credential isolation gateway |
