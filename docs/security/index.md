# Security Overview

This document provides a high-level overview of Foundry Sandbox security architecture and links to detailed documentation.

## Security Architecture

Foundry Sandbox implements **layered security** with multiple independent controls:

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
|  +--------------------+   |    |  • DNS filter (mitmproxy)   |
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

## Reading Guide

- **Quick orientation** — Continue reading this page for a summary of security properties
- **Security model** — [Security Model](security-model.md) — threats, defenses, and hardening organized by pillar
- **Credential isolation** — [Credential Isolation](credential-isolation.md) — network architecture, trust boundaries, and threat model

## Key Security Properties

- **Credential isolation** — Real credentials never enter sandbox containers; the unified proxy injects them into outbound requests. See [Security Model: Credential Isolation](security-model.md#credential-isolation).
- **Network isolation** — Internal Docker network, DNS filtering, iptables rules, and CAP_NET_RAW dropped. See [Security Model: Network Isolation](security-model.md#network-isolation).
- **Read-only filesystem** — Container filesystem is read-only by default; writable tmpfs for `/tmp` and `/home`. See [Security Model: Read-only Filesystem](security-model.md#read-only-filesystem).
- **Branch isolation** — Each sandbox is restricted to its own git branch via deny-by-default ref validation. See [Security Model: Branch Isolation](security-model.md#branch-isolation).
- **Git safety** — Force-push blocking, protected branches, PR merge prevention, CI/CD file restrictions. See [Security Model: Git Safety](security-model.md#git-safety).
- **Operator approval** — Sensitive operations require human TTY-based approval. See [Security Model: Operational Controls](security-model.md#operational-controls).

## Security Documentation

| Document | Description |
|----------|-------------|
| [Security Model](security-model.md) | Threats, defenses, hardening, and accepted risks — organized by security pillar |
| [Credential Isolation](credential-isolation.md) | Network architecture, trust boundaries, credential exposure matrix, and attack scenarios |

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

## See Also

- [Security Model](security-model.md) — Detailed threats, defenses, and hardening
- [Credential Isolation](credential-isolation.md) — Network architecture and trust boundaries
- [Architecture](../architecture.md) — System components and proxy design
