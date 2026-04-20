# ADR-010: User-Defined Service Credential Injection via Reverse Proxy

**Status:** Accepted
**Date:** 2026-04-20
**Deciders:** Tyler

## Context

The sbx migration removed the old MITM-based `unified-proxy/` (~67k lines), which injected credentials for user-defined services like Tavily, Perplexity, Semantic Scholar, and Zhipu. Docker's `sbx` handles 9 built-in providers, but arbitrary user-defined services have no injection mechanism.

The old system used mitmproxy to intercept HTTPS requests and inject `Authorization` headers. This required custom CA trust, certificate injection, and MITM — all removed with the proxy.

We need a replacement that:
- Injects credentials for arbitrary user-defined HTTP services
- Keeps credentials out of the sandbox VM
- Does not require MITM or custom CA certificates
- Is simple to configure and maintain

## Decision

Extend the existing `foundry-git-safety` Flask server with reverse-proxy routes at `/proxy/<service-slug>/<path>`. The sandbox talks HTTP to the proxy; the proxy reads the real API key from the host environment, adds the configured header, and forwards via HTTPS to the upstream service.

### Routing flow

```
Sandbox → http://host.docker.internal:8083/proxy/tavily/v1/search
         → foundry-git-safety reads TAVILY_API_KEY from host env
         → adds Authorization: Bearer <key>
         → forwards to https://api.tavily.com/v1/search
         → streams response back to sandbox
```

### Why this works

The sandbox already reaches `host.docker.internal:8083` for git operations. No new ports, no new daemons. Credentials never enter the VM.

## Alternatives Considered

### Forward proxy with CONNECT tunneling
A forward HTTP proxy using CONNECT for HTTPS. **Rejected:** CONNECT creates an encrypted tunnel — the proxy cannot inspect or modify traffic inside it. Header injection is impossible without MITM.

### `sbx secret set` for arbitrary services
Push user-defined secrets via `sbx secret set`. **Rejected as primary approach:** Open question U7 — unclear if sbx supports arbitrary service names beyond its 9 built-in providers. We do push secrets this way as a forward-compatible fallback.

### Standalone proxy daemon
Separate proxy process on a new port. **Rejected:** Adds operational complexity (another daemon, port, health check) for no architectural benefit. The git-safety server already runs on the host with Flask infrastructure.

### MITM proxy (restore old approach)
Restore mitmproxy-based MITM. **Rejected:** Violates the project's no-MITM constraint. Required custom CA trust inside VMs, added attack surface, and was the source of significant complexity.

## Consequences

- **Positive:** Simple architecture — no new daemons, reuses existing host-side server
- **Positive:** No MITM, no custom CA, no certificate management
- **Positive:** Credentials never leave the host
- **Negative:** SDKs must support custom base URLs (e.g., `TAVILY_API_BASE`). SDKs that hardcode their API domain will not work without wrapper code.
- **Negative:** The sandbox must know to use the proxy URL instead of the real service domain. This is handled by environment variable injection during `cast new`.
- **Negative:** All user-defined service traffic goes through a single host-side process. A misbehaving service could impact others sharing the same proxy.
