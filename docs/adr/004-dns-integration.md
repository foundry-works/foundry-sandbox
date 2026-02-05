# ADR-004: DNS Integration

## Status

Accepted

Date: 2026-02-04

## Context

The Foundry Sandbox system needs to enforce network isolation through DNS filtering. Currently, the credential isolation gateway uses dnsmasq to control DNS resolution and restrict egress to allowlisted domains. The unified proxy architecture must decide how to integrate DNS control while maintaining flexibility for deployments that may not require DNS integration.

### Current State

The gateway implementation includes:
- **dnsmasq-based DNS filtering** (activated when `GATEWAY_ENABLE_DNS=true`)
- **Allowlist-driven configuration** (single source of truth in `gateway/allowlist.conf`)
- **Two-layer filtering**: DNS (dnsmasq) + firewall (iptables/ipset)
- **Domain allowlist** with support for:
  - Standard domains (resolved once at startup)
  - Wildcard domains (*.example.com pattern matching)
  - Rotating IP domains (re-resolved multiple times)
  - CIDR blocks for known IPs

### Constraints

1. **Root privileges required**: dnsmasq must bind to port 53 (requires root)
2. **Privilege dropping**: Security requires dnsmasq to drop to non-root after binding
3. **Container environment**: DNS configuration must work with Docker's internal DNS (127.0.0.11)
4. **Read-only filesystem**: /etc/resolv.conf is read-only; must be written before privilege drop
5. **Multi-network containers**: Internal services (gateway, api-proxy) live on credential-isolation network; dnsmasq may return wrong IPs without /etc/hosts override
6. **Network modes**: Sandbox can run in "limited", "unlimited", or "isolated" mode (affects DNS/firewall interaction)

## Decision

The unified proxy will implement **dual-mode DNS architecture**:

### Mode A: DNS-Enabled (with dnsmasq)

**When enabled** (`GATEWAY_ENABLE_DNS=true` and running as root):
- Gateway's entrypoint starts dnsmasq in foreground
- Entrypoint-root.sh (running first, as root) configures /etc/resolv.conf to point to gateway's dnsmasq
- Entrypoint-root.sh sets up DNS firewall rules (port 53 allowed only to gateway IP)
- Container resolves domains through allowlist-filtered DNS
- Two-layer filtering:
  1. DNS layer: dnsmasq returns NXDOMAIN for non-allowlisted domains
  2. Firewall layer: iptables blocks port 53 to non-gateway destinations

**Go Criteria (enable DNS integration):**
- Running as root with capability to start dnsmasq
- GATEWAY_ENABLE_DNS environment variable set to "true"
- /etc/dnsmasq.conf exists and is readable
- Network mode is "limited" (requires egress filtering)

### Mode B: DNS-Disabled (fallback)

**When disabled** (non-root execution or GATEWAY_ENABLE_DNS=false):
- No dnsmasq startup
- Container uses Docker's default DNS (127.0.0.11 or host-provided)
- Firewall rules still restrict egress (independent of DNS)
- Warning logged: "DNS routing disabled"
- Fallback to firewall-only isolation (less effective but still functional)

**No-Go Criteria (disable DNS integration):**
- Running as non-root user (dnsmasq cannot bind port 53)
- GATEWAY_ENABLE_DNS environment variable not set or false
- /etc/dnsmasq.conf missing
- Container lacks NET_ADMIN capability for firewall rules

### Allowlist Integration

The domain allowlist serves both DNS and firewall:

1. **Source of Truth**: `gateway/allowlist.conf` (human-edited)
   - Single file listing all allowed domains
   - Supports comments with CIDR blocks: `# 1.2.3.0/24`
   - Supports domain types: `github.com generic`, `api.openai.com rotating_ip`

2. **DNS Config Generation**: `gateway/build-configs.sh` generates `dnsmasq.conf`
   - Converts domain list to dnsmasq `server=/domain/127.0.0.11` directives
   - Sets `address=/#/` to block unlisted domains (returns NXDOMAIN)
   - Sets `no-resolv` to prevent /etc/resolv.conf fallback

3. **Firewall Config Generation**: `gateway/build-configs.sh` generates `firewall-allowlist.generated`
   - Exports domain arrays for `safety/network-firewall.sh`
   - Includes ALLOWLIST_DOMAINS, ROTATING_IP_DOMAINS, WILDCARD_DOMAINS, CIDR_BLOCKS
   - Used by firewall setup to pre-resolve IPs and create iptables rules

4. **Runtime Override**: Environment variables allow temporary allowlist expansion
   - `SANDBOX_ALLOWED_DOMAINS="domain1.com,domain2.com"` adds to firewall allowlist
   - Does NOT affect dnsmasq (would require configuration reload)

### Startup Sequence

```
Container Start
    │
    ├─── (credential isolation enabled)
    │
    ▼
entrypoint-root.sh (as root)
  ├─ Resolve internal service IPs (gateway, api-proxy) via Docker DNS
  ├─ Add to /etc/hosts (takes precedence over dnsmasq)
  │
  ├─ [DNS Enabled Branch]
  │  ├─ Configure /etc/resolv.conf: nameserver <gateway-ip>
  │  └─ Setup DNS firewall: allow UDP/TCP :53 to gateway, drop others
  │
  └─ Drop privileges via gosu
      │
      ▼
    entrypoint.sh (as ubuntu)
      ├─ Application setup (npm, Claude config, etc.)
      └─ Ready for commands
```

## Consequences

### Positive

- **Defense in depth**: Dual-layer filtering (DNS + firewall) prevents both direct DNS bypass and DNS spoofing
- **Flexible deployment**: Works in both restricted (DNS-enabled) and unrestricted (DNS-disabled) environments
- **Centralized allowlist**: Single source of truth (`allowlist.conf`) reduces maintenance burden and sync issues
- **Clear failure modes**: Graceful degradation if DNS cannot start (logs warning, continues with firewall-only mode)
- **Privilege separation**: dnsmasq runs as root (needed for port 53), but application runs as non-root
- **Scalable filtering**: ipset support for efficient iptables rules (handles thousands of IPs)
- **Multi-domain support**: Handles standard, wildcard, and rotating IP domains in single config

### Negative

- **Root requirement**: DNS filtering requires root privileges; non-root deployments lose DNS layer
- **Configuration complexity**: Three configuration files to maintain (allowlist.conf, dnsmasq.conf, firewall-allowlist.generated)
- **Network-dependent**: Relies on Docker's internal DNS (127.0.0.11); may not work with custom DNS setups
- **Startup order sensitivity**: entrypoint-root.sh must run before entrypoint.sh for DNS to work (tight coupling)
- **Manual regeneration**: After editing allowlist.conf, must run `gateway/build-configs.sh` to regenerate configs
- **Limited customization**: Runtime domain additions (SANDBOX_ALLOWED_DOMAINS) don't affect dnsmasq
- **IP churn**: Non-wildcard domains resolved once at startup; IP changes require restart

### Neutral

- **dnsmasq as dependency**: Adds another service to manage (but keeps existing architecture)
- **Logging overhead**: dnsmasq DNS query logging may impact performance in high-volume scenarios
- **IPv6 handling**: Firewall rules cover both IPv4 and IPv6, but dnsmasq focuses primarily on IPv4
- **Wildcard mode trade-offs**: Wildcard domains (*.api.example.com) open ports 80/443 to all destinations, relying on DNS+gateway validation

## Alternatives Considered

### 1. Proxy-Only Filtering (No DNS Control)
**Rejected**: Firewall-only isolation is insufficient. Attackers could:
- Use hardcoded IPs to bypass firewall rules
- Perform DNS rebinding attacks against gateway validation
- Exploit DNS timeouts or race conditions in gateway hostname resolution

### 2. dnsmasq Only (No Firewall)
**Rejected**: DNS-only filtering has critical gaps:
- No protection against direct IP-based requests (bypass DNS entirely)
- Single point of failure (if dnsmasq crashes, all egress fails)
- Cannot restrict to specific IPs within allowlisted domains (if domain uses shared hosting)

### 3. Strict Allowlist with Zero Customization
**Rejected**: Real-world deployments need flexibility:
- Temporary access to development/testing domains
- User-specific domain allowlists (research, monitoring tools)
- Runtime experimentation without rebuilding container

### 4. Full Network Namespace Isolation
**Rejected**: Adds complexity without corresponding security benefit:
- Requires additional network configuration per container
- Complicates gateway communication (separate network for credential exchange)
- Still needs allowlist enforcement (no free security)

### 5. DNS over HTTPS (DoH) Only
**Rejected**: DoH bypasses DNS filtering and prevents allowlist enforcement:
- DNS queries go directly to DoH provider, not through local DNS
- Requires blocking DoH endpoints (fragile, easy to circumvent)
- Incompatible with dnsmasq-based filtering

## References

- [Network Isolation Architecture](../security/network-isolation.md) - How DNS fits into broader network security
- [Domain Allowlist](../gateway/allowlist.conf) - Allowlisted domains and categories
- [Credential Isolation](../security/credential-isolation.md) - Gateway architecture and session management
- [Sandbox Threats](../security/sandbox-threats.md) - Threat model and what we protect against
- [Security Architecture](../security/security-architecture.md) - Defense in depth overview

### Implementation Files

- `gateway/entrypoint.sh` - Gateway startup with optional dnsmasq
- `gateway/build-configs.sh` - Configuration file generation from allowlist
- `entrypoint-root.sh` - Root entrypoint that configures DNS before privilege drop
- `safety/network-firewall.sh` - Firewall rule setup using allowlist
- `lib/gateway.sh` - Session management (calls gateway URL via TCP)
