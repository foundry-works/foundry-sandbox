# ADR-012: DNS-Level Filtering Not Achievable with sbx

**Status:** Accepted
**Date:** 2026-04-20
**Deciders:** Tyler Burleigh

## Context

The old unified-proxy included DNS-level filtering (ADR-004): a mitmproxy addon that returned NXDOMAIN for any domain not on the allowlist, backed by iptables rules preventing DNS bypass. This provided defense-in-depth — even if a process inside the sandbox tried to resolve a non-allowlisted domain, it would fail at the DNS layer before any TCP connection was attempted.

The unified-proxy was deleted as part of the sbx migration (ADR-008). sbx handles network policy at the domain/IP level via `sbx policy allow/deny network <spec>`, but does not expose a DNS interception control surface.

## Decision

DNS-level filtering is **not achievable** with the current sbx architecture. Document this as a known gap with no planned remediation.

## Why It's Not Achievable

1. **sbx network policy is domain/IP only.** The `sbx policy` commands operate on domain names and CIDR blocks at the network layer — they control which destinations a sandbox can reach, not how DNS queries are resolved.

2. **No DNS interception surface.** sbx does not expose a way to inject a custom DNS resolver into the microVM, intercept DNS queries, or return NXDOMAIN for specific domains. DNS resolution is handled by the host-side proxy, not the sandbox VM.

3. **No host-side DNS proxy.** Unlike the old docker-compose architecture where the unified-proxy ran as a container alongside the sandbox (with root access to iptables and resolv.conf), the sbx microVM is managed by the sbx daemon. There is no hook to inject a DNS proxy between the VM and the host.

4. **No custom CA or MITM.** sbx does not support TLS interception or custom CA injection, which would be needed for a DNS-based HTTPS filtering approach.

## Compensating Controls

| Layer | Control | Provided By |
|-------|---------|-------------|
| Network | Domain/IP allow-deny | `sbx policy` |
| HTTP | Method/path/body policy | Deep policy sidecar (ADR-011) |
| Git | Branch isolation, push protection | foundry-git-safety |
| Credentials | Network-level injection | sbx + user services proxy (ADR-010) |

The deep policy sidecar (ADR-011) provides HTTP-level request-shape enforcement for proxied services, which covers the most common exfiltration vectors (API calls to non-allowlisted endpoints). This is a stricter control than DNS filtering for HTTP traffic, though it does not cover non-HTTP protocols.

## Residual Risk

A malicious process inside the sandbox could make non-HTTP connections to any domain allowed by sbx's network policy. This is the same risk that existed in the old architecture for any traffic not routed through the proxy.

If sbx adds DNS control surfaces in a future release, this decision should be revisited.

## Consequences

- DNS filtering is listed as deferred in PLAN §5.8 and will not be pursued.
- The old DNS-related shell scripts (`safety/network-firewall.sh`) and red-team module (`tests/redteam/modules/03-dns-filtering.sh`) are legacy artifacts from the old backend.
- U28 ("Is DNS-level filtering achievable inside sbx networking?") is resolved: **no, not with the current architecture.**
