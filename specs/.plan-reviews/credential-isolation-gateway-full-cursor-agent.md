# Review Summary

## Critical Blockers
- **[Architecture]** Token exposure scope not fully constrained
  - **Description:** Session token is passed to sandbox and apparently authorizes git proxying; plan doesn’t define how token is verified beyond container ID + repo list, nor how container ID is authenticated to the gateway.
  - **Impact:** A compromised sandbox could replay the token from another container or spoof container ID in requests, enabling broader repo access.
  - **Fix:** Require the gateway to verify a per-container shared secret or mTLS between sandbox and gateway; bind token to container IP and short TTL; verify container identity using Docker API metadata.

- **[Risk]** DNS allowlist enforcement path is underspecified
  - **Description:** DNS isolation relies on `dnsmasq` and `dns: [gateway]`, but the plan doesn’t specify how to prevent direct DNS to external resolvers if a process uses raw IP or hardcoded resolvers.
  - **Impact:** DNS exfiltration could bypass the allowlist, undermining core objective.
  - **Fix:** Add firewall rules to block UDP/TCP 53 from sandbox to anything except gateway/dnsmasq; ensure proxy enforces IP-based blocks and disable direct egress entirely.

- **[Completeness]** Host CLI ↔ gateway Unix socket lifecycle not fully defined
  - **Description:** Plan mentions Unix socket for `/session/create` but lacks details for ownership, permissions, and cleanup, and how the CLI ensures socket access is restricted.
  - **Impact:** Other local users could create/destroy sessions or obtain tokens if socket permissions are lax.
  - **Fix:** Specify socket permissions (e.g., 0600), owner/group, and a secure directory; document how CLI verifies socket path and how the gateway rotates or cleans stale sockets.

## Major Suggestions
- **[Architecture]** Add explicit threat model for token replay and gateway misuse
  - **Description:** The plan assumes container ID binding is enough without enumerating attacker capabilities.
  - **Impact:** Missing threat assumptions leads to fragile controls.
  - **Fix:** Add a short threat model section clarifying attacker capabilities (sandbox code execution) and explicit controls (IP binding, TTL, request signing).

- **[Sequencing]** Network isolation should precede gateway integration
  - **Description:** Phase 2 introduces gateway before Phase 3 network isolation. This makes it possible to still have direct egress during early testing.
  - **Impact:** Creates a window where credential isolation is incomplete and tests can pass accidentally.
  - **Fix:** Move the internal network + firewall baseline earlier, or add a gating checklist so gateway integration can’t proceed without network isolation enabled.

- **[Feasibility]** Tinyproxy + dnsmasq config drift risk
  - **Description:** Allowlists are duplicated across proxy and DNS; there’s no stated process for keeping them consistent.
  - **Impact:** Allowed domains may fail because DNS blocks a domain that proxy allows, or vice versa.
  - **Fix:** Define a single allowlist source (e.g., one config file) and generate both configs from it.

- **[Risk]** Git Smart HTTP proxying complexity is high
  - **Description:** Proper handling of `Expect: 100-continue`, chunked responses, and large packfiles can be tricky with Flask/requests.
  - **Impact:** Subtle bugs can break git operations or leak tokens via error logs.
  - **Fix:** Consider using a dedicated proxy library or reverse proxy (nginx) for streaming; if keeping Flask, add explicit tests for large repos and 100-continue behavior.

- **[Completeness]** Missing rollback/compatibility plan for Git config rewriting
  - **Description:** Git rewrite rules in `/etc/gitconfig` are global; no mention of how to disable in a running container.
  - **Impact:** Debugging or opt-out scenarios may be difficult.
  - **Fix:** Add a runtime override (env var) to disable rewrite or an alternate gitconfig include that can be toggled.

## Minor Suggestions
- **[Clarity]** Define “repo scope” precisely
  - **Description:** “allowed_repos[]” is referenced but format and matching logic are undefined.
  - **Fix:** Specify exact canonical format (e.g., `owner/repo`), case sensitivity, and match rules.

- **[Feasibility]** Token TTL tied to sandbox lifetime lacks safety margin
  - **Description:** If sandbox persists, tokens never expire.
  - **Fix:** Set a reasonable TTL with refresh on activity and cleanup on destroy.

- **[Completeness]** Log redaction strategy implied but not explicit
  - **Description:** “Don’t log tokens” is mentioned, but logging strategy isn’t specified.
  - **Fix:** Add guidance: strip `Authorization`, `Proxy-Authorization`, and query params; ensure errors never echo headers.

- **[Risk]** IP-based allowlist bypass via direct IP in URLs
  - **Description:** Proxy allowlist is DNS-based; direct IPs could bypass if not blocked.
  - **Fix:** Explicitly block literal IP targets in proxy and firewall.

## Questions
- **[Architecture]** How is container identity authenticated to the gateway?
  - **Context:** Token binding uses container ID, but the gateway needs a trustworthy source of that ID.
  - **Needed:** Exact mechanism (Docker metadata lookup, IP-to-container mapping, signed token).

- **[Sequencing]** What are the dependencies between phases?
  - **Context:** Several phases depend on network topology or gateway availability.
  - **Needed:** A dependency graph or explicit “must precede” notes.

- **[Completeness]** How will gateway tokens be passed on `docker exec` or restart?
  - **Context:** Restart behavior says new tokens are generated, but mechanisms are unclear.
  - **Needed:** Clarify how the CLI updates env vars or recreates the container.

- **[Feasibility]** What is the expected scale (number of sandboxes)?
  - **Context:** One gateway per host may become a bottleneck.
  - **Needed:** Expected concurrency, throughput targets, and whether gateway should be per-sandbox.

## Praise
- **[Completeness]** Clear phase breakdown and verifications
  - **Why:** Each phase has tasks and explicit verification steps, which helps implementers validate outcomes.

- **[Architecture]** Defense-in-depth network model
  - **Why:** Combining Docker internal network, proxy, and host firewall is a strong layered approach.

- **[Risk]** Explicit out-of-scope acknowledgments
  - **Why:** Calling out Git LFS and external submodules prevents hidden surprises.

- **[Clarity]** Well-defined success criteria
  - **Why:** The checklist makes it easy to validate core security guarantees.