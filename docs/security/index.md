# Security Overview

This document provides a high-level overview of Foundry Sandbox security architecture and links to detailed documentation.

## Security Architecture

Foundry Sandbox implements **defense in depth** with multiple security layers:

```
+-------------------+     +-------------------+
|   AI Assistant    |     |    Orchestrator   |
|   (untrusted)     |     |    (trusted)      |
+--------+----------+     +--------+----------+
         |                         |
         v                         v
+---------------------------+    +------------------------------+
|    SANDBOX CONTAINER      |    |    UNIFIED PROXY CONTAINER   |
|                           |    |    (separate container)      |
|  +--------------------+   |    |                              |
|  | Network Isolation  |   |    |  [ALL CREDENTIALS:          |
|  +--------------------+   |    |   GITHUB_TOKEN, API_KEYS]   |
|  +--------------------+   |    |                              |
|  | .git hidden        |   |    |  • Credential injection     |
|  +--------------------+   |    |  • Git API server (:8083)   |
|  +--------------------+   |    |  • DNS filter (dnsmasq)     |
|  | No real creds      |   |    |  • Policy engine            |
|  +--------------------+   |    |                              |
|                           |    +-------------+----------------+
| credential-isolation net ◄├────┤             |
+---------------------------+    |             v
                                 |    +-------------------+
                                 |    |  External APIs    |
                                 |    |  (GitHub, etc)    |
                                 |    +-------------------+
                                 |    proxy-egress network
                                 +-----------------------------+
```

## Key Security Properties

### Credential Isolation

Real credentials (GitHub tokens, API keys) **never enter sandbox containers**:

- Sandboxes receive placeholder values (`CREDENTIAL_PROXY_PLACEHOLDER`)
- Real credentials are held by the unified-proxy container
- The proxy intercepts outbound requests and injects credentials
- Container registration authenticates sandboxes to the proxy

### Network Isolation

Sandboxes have **restricted network access**:

- Internal Docker network with no default gateway
- DNS routed through unified-proxy's DNS filter (enabled by default)
- iptables rules for defense-in-depth

### Filesystem Protection

Container filesystem is **read-only** by default:

- System directories cannot be modified
- Writable tmpfs mounts for `/tmp`, `/home`
- Changes do not persist across container restarts

### Operator Approval

Sensitive operations require **human approval**:

- Operator approval required for sensitive operations (TTY-based check)
- Read-only filesystem prevents destructive filesystem commands
- Unified proxy can block dangerous git operations like force push

## Security Documentation

| Document | Description |
|----------|-------------|
| [Credential Isolation](credential-isolation.md) | Trust boundaries, threats, and explicit non-requirements for credential isolation |
| [Network Isolation](network-isolation.md) | Detailed network architecture and isolation proof |
| [Security Architecture](security-architecture.md) | Security pillars and defense layers |
| [Sandbox Threats](sandbox-threats.md) | AI-as-threat-actor model for sandbox safety |

## Quick Reference

### Security-Relevant Configuration

| Setting | File | Purpose |
|---------|------|---------|
| Network mode | `--network=` flag | Controls network isolation level |
| Repository allowlist | Container registration | Restricts accessible repositories |
| Domain allowlist | `config/allowlist.yaml` | Controls allowed outbound domains |
| Credential injection | `docker-compose.credential-isolation.yml` | Enables credential isolation mode |

### Network Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `limited` | Allowlist only (default) | Normal development |
| `host-only` | Local network only | Isolated development |
| `none` | Loopback only | Maximum isolation |

### Credential Exposure

| Credential | Unified Proxy | Sandbox |
|------------|---------------|---------|
| GITHUB_TOKEN / GH_TOKEN | Yes | No (empty) |
| ANTHROPIC_API_KEY | Yes | Placeholder |
| OPENAI_API_KEY | Yes | Placeholder |
| Other API Keys | Yes | Placeholder |

The unified proxy holds all real credentials and injects them into outbound requests. Sandboxes never receive real tokens.

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers
3. Include steps to reproduce and potential impact
4. Allow time for a fix before public disclosure

## Security Assumptions

This security model assumes:

1. **Docker is trusted** - Container escape vulnerabilities are out of scope
2. **Orchestrator is trusted** - Container registration is a privileged operation
3. **Host is secure** - Host-level security is prerequisite
4. **Network isolation works** - Docker networking and iptables are reliable

If any of these assumptions are violated, the security properties may not hold.
