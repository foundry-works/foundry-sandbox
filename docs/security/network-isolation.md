# Network Isolation Model

This document explains the credential isolation network architecture, its security layers, and proof that no bypass path exists.

## Overview

The credential isolation system prevents sandbox containers from directly accessing credentials (GitHub tokens, API keys) while still allowing them to perform authenticated operations through a controlled proxy.

```
+------------------+     +------------------+     +------------------+
|    Sandbox       |     |  Unified Proxy   |     |  External APIs   |
|    (dev)         |---->|  (mitmproxy +    |---->|  (GitHub, Anthro-|
|                  |     |   DNS filter)    |     |   pic, OpenAI)   |
|  [placeholders]  |     |  [ALL CREDS]     |     |                  |
+------------------+     +------------------+     +------------------+
```

## Security Layers

### Layer 1: Internal Network (`internal: true`)

The `credential-isolation` network is configured with `internal: true`, which means:

- No default gateway to external networks
- Containers cannot route traffic outside the Docker network
- All external access must go through explicitly connected services

```yaml
networks:
  credential-isolation:
    driver: bridge
    internal: true
```

### Layer 2: Proxy Routing

All outbound traffic from the sandbox is routed through the unified proxy:

- `HTTP_PROXY` and `HTTPS_PROXY` point to `unified-proxy:8080`
- Sandbox uses placeholder API keys (`CREDENTIAL_PROXY_PLACEHOLDER`)
- Unified proxy intercepts requests and injects real credentials
- mitmproxy CA certificate trusted by sandbox for HTTPS interception
- Git operations in shadow mode go through the git API server (port 8083), not the HTTPS proxy. HTTPS git push/fetch credentials are injected via `GIT_CREDENTIAL_TOKEN` in the proxy's subprocess environment

```yaml
environment:
  - HTTP_PROXY=http://unified-proxy:8080
  - HTTPS_PROXY=http://unified-proxy:8080
  - NO_PROXY=localhost,127.0.0.1,unified-proxy
```

### Layer 3: DNS Isolation

DNS is routed through the unified proxy's DNS filter (enabled by default via `PROXY_ENABLE_DNS=true`):

```yaml
# Sandbox resolv.conf is configured by entrypoint-root.sh to point to unified-proxy
# iptables rules restrict DNS to unified-proxy only
```

This enables:
- Domain allowlisting at DNS level
- Blocking of unauthorized domains
- Preventing DNS-based data exfiltration

### Layer 4: iptables Rules (Defense-in-Depth)

Additional iptables rules in `safety/network-firewall.sh`:

**Container-level (OUTPUT chain):**
- Allow traffic to unified-proxy
- Allow DNS only to unified-proxy
- Allow traffic to allowlisted domains (resolved at startup)
- Wildcard mode: open ports 80/443 (security via DNS filtering)
- Drop all other outbound traffic

**Host-level (DOCKER-USER chain):**
- Block direct external egress from sandbox subnet
- Allow DNS only to unified-proxy
- Processed before Docker's own rules

### Layer 5: CAP_NET_RAW Dropped

Both sandbox and unified-proxy containers drop `CAP_NET_RAW`:

```yaml
cap_drop:
  - NET_RAW
```

This prevents IP spoofing, ARP poisoning, and raw packet sniffing on the Docker bridge network.

## Credential Exposure Matrix

| Credential | Unified Proxy | Sandbox |
|------------|---------------|---------|
| GITHUB_TOKEN / GH_TOKEN | Yes | No (empty) |
| ANTHROPIC_API_KEY | Yes | Placeholder |
| OPENAI_API_KEY | Yes | Placeholder |
| GOOGLE_API_KEY | Yes | Placeholder |
| Other API Keys | Yes | Placeholder |
| GIT_CREDENTIAL_TOKEN | Yes (subprocess env only) | No (never exposed) |

The unified proxy holds all real credentials. Sandboxes never see real values.

## Proof of No Bypass Path

### Direct External Access
- **Blocked by:** `internal: true` network
- **Backup:** DOCKER-USER chain drops external egress

### Container-to-Container Snooping
- **Blocked by:** Separate Docker networks per sandbox project
- **Backup:** iptables OUTPUT rules, CAP_NET_RAW dropped

### DNS Exfiltration
- **Blocked by:** DNS routed to unified-proxy only
- **Backup:** DOCKER-USER chain drops port 53 except to unified-proxy

### Credential Theft from Proxy
- **Blocked by:** Sandboxes only see placeholder values
- **Backup:** Real credentials never enter sandbox environment

### Direct GitHub/API Access
- **Blocked by:** Proxy environment variables enforced
- **Backup:** Network-level blocking of direct connections

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

## Configuration Files

| File | Purpose |
|------|---------|
| `docker-compose.credential-isolation.yml` | Service definitions and network config |
| `safety/network-firewall.sh` | iptables rules for defense-in-depth |
| `config/allowlist.yaml` | Domain allowlist (single source of truth) |
| `unified-proxy/` | Unified proxy for all egress traffic |

## Verification

To verify isolation is working:

1. **Check network config:**
   ```bash
   docker network inspect credential-isolation
   ```

2. **Test from sandbox:**
   ```bash
   # Should fail - direct external access blocked
   curl https://github.com

   # Should work - routed through proxy
   git clone https://github.com/owner/repo.git
   ```

3. **Verify credentials not exposed:**
   ```bash
   # In sandbox - should show placeholder
   echo $ANTHROPIC_API_KEY
   # Output: CREDENTIAL_PROXY_PLACEHOLDER
   ```

4. **Verify DNS filtering:**
   ```bash
   # Should fail - not on allowlist
   dig @8.8.8.8 example.com

   # Should work - goes through unified-proxy DNS
   dig github.com
   ```
