# ADR-004: DNS Integration

## Status

Accepted

Date: 2026-02-04

## Context

The Foundry Sandbox system needs to enforce network isolation through DNS filtering. The unified proxy must control DNS resolution to restrict egress to allowlisted domains, while maintaining flexibility for deployments that may not require DNS integration.

### Current State

The unified-proxy implementation includes:
- **mitmproxy DNS addon filtering** (activated when `PROXY_ENABLE_DNS=true`, enabled by default)
- **Allowlist-driven configuration** (single source of truth in `config/allowlist.yaml`)
- **Two-layer filtering**: DNS (mitmproxy `dns_filter.py` addon) + firewall (iptables/ipset)
- **Domain allowlist** with support for:
  - Standard domains (resolved once at startup)
  - Wildcard domains (*.example.com pattern matching)
  - Rotating IP domains (re-resolved multiple times)
  - CIDR blocks for known IPs

### Constraints

1. **Root privileges required**: DNS must bind to port 53 (requires root)
2. **Privilege dropping**: Security requires dropping to non-root after binding
3. **Container environment**: DNS configuration must work with Docker's internal DNS (127.0.0.11)
4. **Read-only filesystem**: /etc/resolv.conf is read-only; must be written before privilege drop
5. **Single-service architecture**: The unified-proxy container handles both HTTP proxying and DNS filtering as mitmproxy addons
6. **Network modes**: Sandbox can run in "limited", "host-only", or "none" mode (affects DNS/firewall interaction)

## Decision

The unified proxy implements **dual-mode DNS architecture**:

### Mode A: DNS-Enabled (with mitmproxy DNS addon)

**When enabled** (`PROXY_ENABLE_DNS=true` and running as root):
- Unified-proxy starts mitmproxy with `--mode dns@53` and the `dns_filter.py` addon
- Entrypoint-root.sh (running first, as root) configures /etc/resolv.conf to point to unified-proxy's IP
- Entrypoint-root.sh sets up DNS firewall rules (port 53 allowed only to unified-proxy IP)
- Container resolves domains through allowlist-filtered DNS
- Two-layer filtering:
  1. DNS layer: `dns_filter.py` returns NXDOMAIN for non-allowlisted domains
  2. Firewall layer: iptables blocks port 53 to non-proxy destinations

**Go Criteria (enable DNS integration):**
- Running as root with capability to bind port 53
- `PROXY_ENABLE_DNS` environment variable set to "true" (default)
- `config/allowlist.yaml` exists and is readable
- Network mode is "limited" (requires egress filtering)

### Mode B: DNS-Disabled (fallback)

**When disabled** (non-root execution or `PROXY_ENABLE_DNS=false`):
- mitmproxy starts without `--mode dns@53`
- Container uses Docker's default DNS (127.0.0.11 or host-provided)
- Firewall rules still restrict egress (independent of DNS)
- Warning logged: "DNS routing disabled"
- Fallback to firewall-only isolation (less effective but still functional)

**No-Go Criteria (disable DNS integration):**
- Running as non-root user (cannot bind port 53)
- `PROXY_ENABLE_DNS` environment variable set to false
- `config/allowlist.yaml` missing
- Container lacks NET_ADMIN capability for firewall rules

### Allowlist Integration

The domain allowlist serves both DNS and firewall:

1. **Source of Truth**: `config/allowlist.yaml` (human-edited)
   - Single YAML file listing all allowed domains with category tags
   - Supports wildcard domains (*.example.com)
   - Supports CIDR blocks for known IPs

2. **DNS Filter**: `unified-proxy/addons/dns_filter.py` loads the allowlist at startup
   - Matches incoming DNS queries against the allowlist
   - Returns NXDOMAIN for non-allowlisted domains
   - Forwards allowlisted queries to Docker's internal DNS (127.0.0.11)

3. **Firewall Config**: `safety/network-firewall.sh` reads the allowlist
   - Resolves allowlisted domains to IPs and creates iptables rules
   - Includes ALLOWLIST_DOMAINS, WILDCARD_DOMAINS, CIDR_BLOCKS
   - Uses ipset for efficient iptables rules with large domain lists

4. **Runtime Override**: Environment variables allow temporary allowlist expansion
   - `SANDBOX_ALLOWED_DOMAINS="domain1.com,domain2.com"` adds to firewall allowlist
   - Does NOT affect DNS filter (would require proxy restart)

### Startup Sequence

```
Container Start
    │
    ├─── (credential isolation enabled)
    │
    ▼
entrypoint-root.sh (as root)
  ├─ Resolve unified-proxy IP via Docker DNS
  ├─ Add to /etc/hosts (takes precedence over DNS filtering)
  │
  ├─ [DNS Enabled Branch]
  │  ├─ Configure /etc/resolv.conf: nameserver <unified-proxy-ip>
  │  └─ Setup DNS firewall: allow UDP/TCP :53 to unified-proxy, drop others
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
- **Centralized allowlist**: Single source of truth (`config/allowlist.yaml`) reduces maintenance burden and sync issues
- **Clear failure modes**: Graceful degradation if DNS cannot start (logs warning, continues with firewall-only mode)
- **Integrated architecture**: DNS filtering runs as a mitmproxy addon within the same process, reducing operational complexity
- **Scalable filtering**: ipset support for efficient iptables rules (handles thousands of IPs)
- **Multi-domain support**: Handles standard, wildcard, and rotating IP domains in single config

### Negative

- **Root requirement**: DNS filtering requires root privileges; non-root deployments lose DNS layer
- **Network-dependent**: Relies on Docker's internal DNS (127.0.0.11); may not work with custom DNS setups
- **Startup order sensitivity**: entrypoint-root.sh must run before entrypoint.sh for DNS to work (tight coupling)
- **Limited customization**: Runtime domain additions (`SANDBOX_ALLOWED_DOMAINS`) don't affect DNS filter without restart
- **IP churn**: Non-wildcard domains resolved once at startup; IP changes require restart

### Neutral

- **mitmproxy DNS addon**: DNS filtering is built into the proxy process rather than being a separate service
- **Logging overhead**: DNS query logging may impact performance in high-volume scenarios
- **IPv6 handling**: Firewall rules cover both IPv4 and IPv6, but DNS filtering focuses primarily on IPv4
- **Wildcard mode trade-offs**: Wildcard domains (*.api.example.com) open ports 80/443 to all destinations, relying on DNS+proxy validation

## Alternatives Considered

### 1. Proxy-Only Filtering (No DNS Control)
**Rejected**: Firewall-only isolation is insufficient. Attackers could:
- Use hardcoded IPs to bypass firewall rules
- Perform DNS rebinding attacks against proxy validation
- Exploit DNS timeouts or race conditions in proxy hostname resolution

### 2. dnsmasq Only (No Firewall)
**Rejected**: DNS-only filtering has critical gaps:
- No protection against direct IP-based requests (bypass DNS entirely)
- Single point of failure (if DNS crashes, all egress fails)
- Cannot restrict to specific IPs within allowlisted domains (if domain uses shared hosting)

### 3. Strict Allowlist with Zero Customization
**Rejected**: Real-world deployments need flexibility:
- Temporary access to development/testing domains
- User-specific domain allowlists (research, monitoring tools)
- Runtime experimentation without rebuilding container

### 4. Full Network Namespace Isolation
**Rejected**: Adds complexity without corresponding security benefit:
- Requires additional network configuration per container
- Complicates proxy communication (separate network for credential exchange)
- Still needs allowlist enforcement (no free security)

### 5. DNS over HTTPS (DoH) Only
**Rejected**: DoH bypasses DNS filtering and prevents allowlist enforcement:
- DNS queries go directly to DoH provider, not through local DNS
- Requires blocking DoH endpoints (fragile, easy to circumvent)
- Incompatible with local DNS-based filtering

## References

- [Network Isolation Architecture](../security/network-isolation.md) - How DNS fits into broader network security
- Domain Allowlist - `config/allowlist.yaml`
- [Credential Isolation](../security/credential-isolation.md) - Proxy architecture and session management
- [Sandbox Threats](../security/sandbox-threats.md) - Threat model and what we protect against
- [Security Architecture](../security/security-architecture.md) - Defense in depth overview

### Implementation Files

- `unified-proxy/entrypoint.sh` - Proxy startup with integrated DNS filter
- `unified-proxy/addons/dns_filter.py` - DNS filtering addon for mitmproxy
- `entrypoint-root.sh` - Root entrypoint that configures DNS before privilege drop
- `safety/network-firewall.sh` - Firewall rule setup using allowlist
- `lib/proxy.sh` - Container registration (calls proxy via Unix socket)
