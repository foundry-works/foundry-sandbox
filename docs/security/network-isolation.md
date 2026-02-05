# Network Isolation Model

This document explains the credential isolation network architecture, its security layers, and proof that no bypass path exists.

## Overview

The credential isolation system prevents sandbox containers from directly accessing credentials (GitHub tokens, API keys) while still allowing them to perform authenticated operations through controlled proxies.

```
+------------------+     +------------------+     +------------------+
|    Sandbox       |     |    Gateway       |     |   GitHub.com     |
|    (dev)         |---->|    (git proxy)   |---->|   (upstream)     |
|                  |     |    [GH_TOKEN]    |     |                  |
+------------------+     +------------------+     +------------------+
        |
        |                +------------------+     +------------------+
        +--------------->|    API Proxy     |---->|   API Endpoints  |
                         |    (mitmproxy)   |     |   (Anthropic,    |
                         |    [API_KEYS]    |     |    OpenAI, etc)  |
                         +------------------+     +------------------+
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

### Layer 2: ICC Disabled (Inter-Container Communication)

ICC is disabled via Docker driver options:

```yaml
driver_opts:
  com.docker.network.bridge.enable_icc: "false"
```

This prevents:
- Sandbox containers from communicating with each other
- Port scanning or lateral movement between sandboxes
- Only explicitly allowed container-to-container traffic works

### Layer 3: Proxy Routing

All outbound traffic from sandbox is routed through proxies:

**Git Operations (Gateway):**
- Sandbox uses session token + secret for authentication
- Gateway validates session and injects real `GITHUB_TOKEN`
- Gateway proxies to github.com with real credentials
- Sandbox never sees the real token

**API Requests (API Proxy):**
- `HTTP_PROXY` and `HTTPS_PROXY` point to api-proxy
- Sandbox uses placeholder API keys (`CREDENTIAL_PROXY_PLACEHOLDER`)
- API proxy intercepts requests and injects real credentials
- mitmproxy CA certificate trusted by sandbox for HTTPS interception

```yaml
environment:
  - HTTP_PROXY=http://api-proxy:8080
  - HTTPS_PROXY=http://api-proxy:8080
  - NO_PROXY=localhost,127.0.0.1,api-proxy,gateway
```

### Layer 4: DNS Isolation

DNS is routed through the gateway's dnsmasq:

```yaml
dns:
  - gateway
```

This enables:
- Domain allowlisting at DNS level
- Blocking of unauthorized domains
- Preventing DNS-based data exfiltration

### Layer 5: iptables Rules (Defense-in-Depth)

Additional iptables rules in `safety/network-firewall.sh`:

**Container-level (OUTPUT chain):**
- Allow traffic to gateway and api-proxy
- Allow DNS only to configured resolvers
- Allow traffic to allowlisted domains (resolved at startup)
- Wildcard mode: open ports 80/443 (security via DNS filtering)
- Drop all other outbound traffic

**Host-level (DOCKER-USER chain):**
- Block direct external egress from sandbox subnet
- Allow DNS only to gateway
- Processed before Docker's own rules

## Credential Exposure Matrix

| Credential | Gateway | API Proxy | Sandbox |
|------------|---------|-----------|---------|
| GITHUB_TOKEN | Yes | Optional* | No |
| ANTHROPIC_API_KEY | No | Yes | Placeholder |
| OPENAI_API_KEY | No | Yes | Placeholder |
| Other API Keys | No | Yes | Placeholder |

*Optional: The API proxy only uses `GITHUB_TOKEN`/`GH_TOKEN` for GitHub API requests (e.g., PRs, releases). Git operations remain gateway-only.

## Proof of No Bypass Path

### Direct External Access
- **Blocked by:** `internal: true` network
- **Backup:** DOCKER-USER chain drops external egress

### Container-to-Container Snooping
- **Blocked by:** ICC disabled (`enable_icc: false`)
- **Backup:** iptables OUTPUT rules

### DNS Exfiltration
- **Blocked by:** DNS routed to gateway only
- **Backup:** DOCKER-USER chain drops port 53 except to gateway

### Credential Theft from Proxy
- **Blocked by:** Sandboxes only see placeholder values
- **Backup:** Real credentials never enter sandbox environment

### Direct GitHub/API Access
- **Blocked by:** Proxy environment variables enforced
- **Backup:** Network-level blocking of direct connections

## Service Dependencies

```
gateway ─────────────┐
                     ├──> dev (sandbox)
api-proxy ───────────┘
```

Both gateway and api-proxy must be healthy before sandbox starts:

```yaml
depends_on:
  api-proxy:
    condition: service_healthy
  gateway:
    condition: service_healthy
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

2. **Verify ICC disabled:**
   ```bash
   docker network inspect credential-isolation --format '{{.Options}}'
   # Should show: map[com.docker.network.bridge.enable_icc:false]
   ```

3. **Test from sandbox:**
   ```bash
   # Should fail - direct external access blocked
   curl https://github.com

   # Should work - routed through proxy
   git clone https://github.com/owner/repo.git
   ```

4. **Verify credentials not exposed:**
   ```bash
   # In sandbox - should show placeholder
   echo $ANTHROPIC_API_KEY
   # Output: CREDENTIAL_PROXY_PLACEHOLDER
   ```
