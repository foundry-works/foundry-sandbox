# Security Overview

This document provides a high-level overview of Foundry Sandbox security architecture and links to detailed documentation.

## Security Architecture

Foundry Sandbox implements **defense in depth** with multiple security layers:

```
+-------------------+     +-------------------+     +-------------------+
|   AI Assistant    |     |    Orchestrator   |     |   External APIs   |
|   (untrusted)     |     |    (trusted)      |     |   (GitHub, etc)   |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                         ^
         v                         v                         |
+--------+-------------------------+-------------------------+----------+
|                           SANDBOX CONTAINER                           |
|  +----------------+  +----------------+  +------------------+          |
|  | Shell Override |  | Read-only Root |  | Network Isolation|          |
|  | (Layer 1)      |  | (Layer 6)      |  | (Layer 5)        |          |
|  +----------------+  +----------------+  +------------------+          |
|                              |                    |                   |
|                              v                    v                   |
|                    +-------------------+  +-------------------+        |
|                    |  Credential       |  |   API Proxy      |        |
|                    |  Gateway          |  |   (mitmproxy)    |        |
|                    |  [GITHUB_TOKEN]   |  |   [API_KEYS]     |        |
|                    +-------------------+  +-------------------+        |
+---------------------------------------------------------------------------+
```

## Key Security Properties

### Credential Isolation

Real credentials (GitHub tokens, API keys) **never enter sandbox containers**:

- Sandboxes receive placeholder values (`CREDENTIAL_PROXY_PLACEHOLDER`)
- Real credentials are held by gateway and API proxy containers
- Proxies inject credentials into outbound requests
- Session tokens authenticate sandboxes to proxies

### Network Isolation

Sandboxes have **restricted network access**:

- Internal Docker network with no default gateway
- Inter-container communication (ICC) disabled
- DNS routed through controlled resolver
- iptables rules for defense-in-depth

### Filesystem Protection

Container filesystem is **read-only** by default:

- System directories cannot be modified
- Writable tmpfs mounts for `/tmp`, `/home`
- Changes do not persist across container restarts

### Command Interception

Dangerous commands are **intercepted with warnings**:

- Shell function overrides catch accidental destructive commands
- `git reset --hard`, `git push --force`, `rm -rf /` blocked by default
- Operator approval required for sensitive operations

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
| Repository allowlist | Gateway session config | Restricts accessible repositories |
| Domain allowlist | `gateway/allowlist.conf` | Controls allowed outbound domains |
| Credential injection | `docker-compose.credential-isolation.yml` | Enables credential isolation mode |

### Network Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `limited` | Allowlist only (default) | Normal development |
| `full` | Unrestricted access | When full internet needed |
| `host-only` | Local network only | Isolated development |
| `none` | Loopback only | Maximum isolation |

### Credential Exposure

| Credential | Gateway | API Proxy | Sandbox |
|------------|---------|-----------|---------|
| GITHUB_TOKEN | Yes | No | Session token only |
| ANTHROPIC_API_KEY | No | Yes | Placeholder |
| OPENAI_API_KEY | No | Yes | Placeholder |

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers
3. Include steps to reproduce and potential impact
4. Allow time for a fix before public disclosure

## Security Assumptions

This security model assumes:

1. **Docker is trusted** - Container escape vulnerabilities are out of scope
2. **Orchestrator is trusted** - Session management is a privileged operation
3. **Host is secure** - Host-level security is prerequisite
4. **Network isolation works** - Docker networking and iptables are reliable

If any of these assumptions are violated, the security properties may not hold.
