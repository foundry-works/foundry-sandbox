# Review Summary

## Critical Blockers
- **[Architecture]** Transparent MITM on TLS without explicit cert trust strategy
  - **Description:** The plan assumes system CA trust is enough, but many CLIs (Node, Python, Go) use their own trust stores or ship bundled certs. Only Node is mentioned in risks.
  - **Impact:** Tools will fail TLS validation or silently bypass proxy, breaking isolation and functionality.
  - **Fix:** Define a per-runtime trust strategy: export `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` for Python, `GODEBUG=x509roots=1`/`SSL_CERT_FILE` for Go, `NODE_EXTRA_CA_CERTS` for Node, and document/automate in init script; add verification steps for each runtime.

- **[Risk]** Domain-based iptables DNAT breaks with CDN/alt hostnames
  - **Description:** Relying on domain resolution at init time (iptables rules per IP) is brittle for providers using multiple hostnames, CDNs, or SNI-based routing.
  - **Impact:** Requests can bypass the proxy or fail when IPs rotate, undermining isolation.
  - **Fix:** Use a transparent proxy setup that captures all outbound 443 traffic and uses SNI to route; or route via iptables REDIRECT for all 443 and let mitmproxy decide; document exclusions if needed.

- **[Completeness]** No explicit handling of WebSocket/HTTP2/streaming constraints
  - **Description:** Many AI APIs use SSE/HTTP2; mitmproxy in transparent mode may need specific flags for HTTP2 and streaming.
  - **Impact:** API calls might hang, stream incorrectly, or downgrade unexpectedly.
  - **Fix:** Include mitmproxy configuration flags (e.g., `--http2`, `--set stream_large_bodies=...`) and validation steps for streaming responses.

## Major Suggestions
- **[Architecture]** Credential injection design should be per-provider and schema-aware
  - **Description:** Injecting credentials by domain alone risks incorrect header/body placement for different providers or endpoints (e.g., OpenAI vs OpenRouter).
  - **Impact:** Requests fail or accidentally leak credentials to unintended endpoints.
  - **Fix:** Define a provider map: domain patterns + injection method (header vs query param) + required headers; add explicit allowlist for endpoints.

- **[Sequencing]** Compose and networking design depend on gateway IP but no resilience plan
  - **Description:** Static IPs in compose can conflict and are brittle across networks.
  - **Impact:** Startup failures or routing to wrong IP if network overlaps.
  - **Fix:** Use service name DNS (`gateway`) and iptables REDIRECT to gateway port via docker DNS, or define dedicated subnet with validation step and conflict checks.

- **[Feasibility]** Estimated ~190 lines is likely optimistic
  - **Description:** mitmproxy addon, entrypoint, init script, compose override, CLI integration, docs, and tests will exceed 190 lines.
  - **Impact:** Underestimation risks scope creep and quality loss.
  - **Fix:** Update estimate and explicitly allocate lines to each component; include minimal test scaffolding.

- **[Risk]** No rollback or failure behavior in init script
  - **Description:** If gateway is unreachable or iptables fails, plan says "fail fast" but doesn’t define how the sandbox exits or reverts networking.
  - **Impact:** Sandbox may become unusable or misroute traffic.
  - **Fix:** Add explicit failure modes: verify gateway health before iptables, fallback to normal networking, or abort startup with clear error.

## Minor Suggestions
- **[Completeness]** Add docs for new flag and isolation mode
  - **Description:** Only help text updates are mentioned.
  - **Fix:** Update `docs/usage/commands.md` and `docs/security/` with rationale and limitations.

- **[Clarity]** Clarify “transparent HTTPS interception” details
  - **Description:** No explicit statement on proxy port, iptables table (nat PREROUTING vs OUTPUT), and whether UDP/QUIC is blocked.
  - **Fix:** Add a brief technical summary in Phase 2 describing the exact routing path and tables used.

- **[Risk]** QUIC/HTTP3 bypass not addressed
  - **Description:** Some clients may use QUIC over UDP 443 and bypass mitmproxy.
  - **Fix:** Add iptables rules to block UDP/443 or force TCP; document this in risks.

## Questions
- **[Architecture]** How will the proxy handle multiple API keys per provider?
  - **Context:** Some tools support multiple keys or org/project headers.
  - **Needed:** Rules for choosing which key to inject and how to handle org/project headers.

- **[Completeness]** What is the exact list of domains and patterns per provider?
  - **Context:** Providers often use multiple hostnames and regions.
  - **Needed:** A definitive allowlist with wildcard rules and update process.

- **[Risk]** How will credential injection avoid logging secrets in mitmproxy logs?
  - **Context:** mitmproxy may log headers or bodies by default.
  - **Needed:** Logging configuration or redaction strategy.

- **[Feasibility]** Which base mitmproxy image and version is targeted?
  - **Context:** Behavior differs across versions and python dependencies.
  - **Needed:** Explicit image/tag and compatibility expectations.

- **[Sequencing]** Will there be automated tests or only manual CLI checks?
  - **Context:** E2E checks are manual; regressions are likely.
  - **Needed:** Minimal automated tests (e.g., curl to mock endpoint) or justification.

## Praise
- **[Architecture]** Transparent proxy approach keeps client tools unmodified
  - **Why:** It aligns with the mission to avoid SDK/CLI changes and reduces integration burden.

- **[Sequencing]** Phased structure is clear and incremental
  - **Why:** Each phase has tasks and verification, making execution and validation manageable.

- **[Risk]** Risk table includes practical mitigations
  - **Why:** Identifies real-world issues like CA trust and availability with concrete actions.

- **[Completeness]** Scope is explicit with clear out-of-scope items
  - **Why:** Helps prevent scope creep and keeps the plan focused.