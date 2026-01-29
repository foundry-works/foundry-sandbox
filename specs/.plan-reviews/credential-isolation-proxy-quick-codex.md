# Review Summary

## Critical Blockers
Issues that MUST be fixed before this becomes a spec.

- **[Feasibility]** Transparent interception with iptables DNAT in container namespace is underspecified
  - **Description:** The plan assumes `iptables -t nat -A OUTPUT ... DNAT --to-destination ${GATEWAY_IP}:8080` will transparently redirect TLS and that mitmproxy will reconstruct the original destination via SNI. In typical Linux networking, transparent proxying of outbound TLS requires a TPROXY/REDIRECT setup plus policy routing and `SO_ORIGINAL_DST` support (or equivalent), and mitmproxy must be configured to read the original destination. DNAT on OUTPUT may not preserve enough info for transparent mode, and SNI is inside TLS after the TCP connection is established.
  - **Impact:** Traffic may not reach the intended upstream host, or mitmproxy may fail to forward correctly, breaking all API calls.
  - **Fix:** Specify the exact transparent proxy mechanism: either (a) use mitmproxy’s documented transparent mode with `REDIRECT` + `SO_ORIGINAL_DST` and ensure the proxy reads original dst, or (b) use TPROXY with policy routing. Include exact iptables rules, routing tables, and mitmproxy flags that are known to work.

- **[Feasibility]** TLS interception details are incomplete for modern clients
  - **Description:** Several runtimes (Go, Java, some OpenSSL builds, system-level settings) may ignore `REQUESTS_CA_BUNDLE` or `NODE_EXTRA_CA_CERTS`, or pin certificates in SDKs. The plan assumes CA trust is sufficient everywhere.
  - **Impact:** CLI tools or SDKs may fail TLS verification, causing outage or inconsistent behavior.
  - **Fix:** Add an explicit compatibility matrix per provider/CLI/SDK with a validation plan. Identify any known pinning or custom TLS stacks and the required workaround (e.g., `SSL_CERT_DIR`, `NODE_OPTIONS=--use-openssl-ca`, per-CLI config).

- **[Architecture]** Gateway healthcheck design is ambiguous in mitmproxy
  - **Description:** “healthcheck endpoint” is described but not defined for transparent mode. mitmproxy addons don’t automatically create an HTTP endpoint unless explicitly bound, and transparent mode is not an HTTP server.
  - **Impact:** Startup sequencing may never signal healthy, blocking sandbox startup.
  - **Fix:** Specify a separate healthcheck server (e.g., tiny HTTP server in entrypoint) or use mitmproxy’s built-in web server modes, and document port, bind address, and readiness condition.

## Major Suggestions
Significant improvements to strengthen the plan.

- **[Architecture]** Clarify allowlist matching and SNI/Host precedence
  - **Description:** The plan says “SNI determines destination,” but injection is based on host/domain. It is unclear whether you match on SNI, Host header, or absolute URL, and how you handle mismatches.
  - **Impact:** Credential injection could fail or be misapplied when SNI and Host differ (e.g., proxies, CDN, or custom domains).
  - **Fix:** Define a strict matching order (e.g., use SNI if present, else Host, else no injection) and log mismatches.

- **[Risk]** No rollback/disable path for CA trust
  - **Description:** Rollback removes iptables rules but doesn’t remove the trusted CA from system store or env vars.
  - **Impact:** Residual trust in the mitm CA could be a security risk and may affect future TLS behavior.
  - **Fix:** Add uninstall steps to remove CA cert and unset env vars (or rely on ephemeral container FS and document it).

- **[Completeness]** Missing mitigation for non-TCP egress to AI providers beyond UDP/443
  - **Description:** Only UDP/443 is blocked. Some clients may use HTTP/2 over TCP 443 (fine) but also nonstandard ports or proxy settings.
  - **Impact:** Requests can bypass proxy or fail unexpectedly.
  - **Fix:** Explicitly state which egress is allowed/blocked and confirm there are no alternate ports used by supported CLIs.

## Minor Suggestions
Smaller refinements.

- **[Clarity]** Explicitly list the mitmproxy transparent mode flags
  - **Description:** The entrypoint tasks mention “transparent mode” but no concrete flags or command.
  - **Fix:** Add exact mitmproxy command line with `--mode transparent` (or equivalent) and port bindings.

- **[Sequencing]** Phase ordering should mention network namespace requirements
  - **Description:** iptables in a container may need `NET_ADMIN` and specific Docker capabilities.
  - **Fix:** Note required container capabilities in Phase 2/Compose integration.

- **[Completeness]** No log redaction requirements for gateway logs
  - **Description:** Gateway logs may include headers with injected credentials.
  - **Fix:** Add log scrub/disable header logging in mitmproxy or restrict logs.

## Questions
Clarifications needed before proceeding.

- **[Architecture]** How exactly does mitmproxy discover the original destination in transparent mode?
  - **Context:** SNI is part of the TLS handshake; you still need original dst at the TCP layer.
  - **Needed:** The precise iptables + routing + mitmproxy configuration that is known to work in this environment.

- **[Feasibility]** Which CLI tools and SDKs are verified to accept a custom CA without extra flags?
  - **Context:** Some clients require explicit config to trust non-system CAs.
  - **Needed:** A per-tool note (claude, codex, gemini, cursor-agent) on required env vars or flags.

- **[Completeness]** What are the exact Docker capabilities and security implications?
  - **Context:** iptables and DNS interception in container namespaces often require `NET_ADMIN` and possibly `NET_RAW`.
  - **Needed:** Required caps, and confirmation they are acceptable in the sandbox threat model.

- **[Risk]** How are non-HTTP APIs or gRPC over TLS handled?
  - **Context:** Some providers may use gRPC or alternate request formats.
  - **Needed:** Confirmation that mitmproxy handles these flows or that they are out of scope.

- **[Clarity]** How is the CA distributed and rotated?
  - **Context:** Shared volume implies persistence, but rotation/refresh is not addressed.
  - **Needed:** Rotation policy (if any) and expected behavior on gateway restart.

## Praise
What the plan does well.

- **[Completeness]** Clear phased delivery with verification steps
  - **Why:** Each phase has tasks and explicit checks, which makes the implementation testable and incremental.

- **[Architecture]** Strong risk list with targeted mitigations
  - **Why:** Identifies key threats (QUIC, CDN rotation) and provides concrete controls.

- **[Clarity]** Scope boundaries and allowlist are well-defined
  - **Why:** Reduces feature creep and keeps the proxy’s responsibility explicit.