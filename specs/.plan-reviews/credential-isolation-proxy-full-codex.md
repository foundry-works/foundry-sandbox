# Review Summary

## Critical Blockers
- **[Architecture]** Transparent HTTPS interception likely fails in Docker without proper TPROXY/REDIRECT plumbing
  - **Description:** The plan assumes mitmproxy “transparent mode” will work with simple DNAT rules. In containers, transparent proxying usually needs iptables REDIRECT to a local port or TPROXY with routing/marking plus policy routing; DNAT to another container often breaks SNI, source IP expectations, or requires additional rules and sysctls.
  - **Impact:** Requests may never reach mitmproxy or may bypass it, causing credential injection to fail or TLS errors.
  - **Fix:** Specify the exact iptables/nftables ruleset (REDIRECT vs TPROXY), required kernel modules/capabilities, and container sysctls. Consider using explicit HTTP(S) proxy via `HTTPS_PROXY`/`ALL_PROXY` as a fallback.

- **[Risk]** Certificate trust chain handling is underspecified for multiple runtimes
  - **Description:** Only Node.js is mentioned. Many CLIs use OpenSSL, libcurl, or language-specific trust stores (Python requests, Go, Java). Installing the mitm CA into the system store may not affect all runtimes.
  - **Impact:** Some tools will fail TLS validation, making the “works unmodified” objective false.
  - **Fix:** Define a matrix of target CLIs and their trust mechanisms; add explicit env vars or config steps (e.g., `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `GODEBUG=x509sha1=1` if needed) and include verification steps per runtime.

- **[Risk]** Credential injection logic lacks provider-specific nuances
  - **Description:** Providers vary in auth headers (e.g., `Authorization: Bearer`, `x-api-key`, `anthropic-version`, `OpenAI-Organization`, `OpenAI-Project`). The plan only says “inject API keys based on request domain.”
  - **Impact:** Silent auth failures or incorrect billing/tenant selection for some providers.
  - **Fix:** Define a per-provider injection map (header name(s), required companion headers, default version headers) and include tests for at least one request per provider.

## Major Suggestions
- **[Completeness]** Missing handling for streaming and HTTP/2
  - **Description:** Many AI SDKs use HTTP/2 and SSE streaming. mitmproxy and transparent interception can behave differently for HTTP/2, and some CLIs may require ALPN/HTTP/2 support.
  - **Impact:** Partial responses, broken streaming, or performance regressions.
  - **Fix:** Explicitly state HTTP/2/streaming support strategy (mitmproxy options, disable HTTP/2, or validate that streaming works). Add a streaming test case per provider that supports it.

- **[Architecture]** Domain-based routing is brittle without DNS pinning or SNI-based matching
  - **Description:** DNAT rules for domains require IP resolution, but provider IPs can change and are shared across domains/CDNs.
  - **Impact:** Requests can bypass the proxy or mis-route to the gateway, especially after IP changes.
  - **Fix:** Use transparent proxying with SNI-based interception or a local DNS resolver that maps target domains to the gateway, and clarify the mechanism.

- **[Sequencing]** Compose wiring depends on cert distribution not yet defined
  - **Description:** The plan references a shared volume for CA cert but does not define ownership, timing, or permissions (gateway generating cert vs sandbox consuming).
  - **Impact:** Race conditions on first boot; sandbox may fail before the cert exists.
  - **Fix:** Add an explicit startup flow: gateway generates cert, writes to shared volume, sandbox waits for file existence with timeout before applying trust.

- **[Feasibility]** Static IP allocation in compose can conflict with user environments
  - **Description:** Hardcoding `172.20.0.2` may collide with existing networks or other overrides.
  - **Impact:** Compose startup failures on some hosts.
  - **Fix:** Use a named network with an IP range configurable via env or compute gateway IP dynamically. Document how to override.

- **[Risk]** Leakage via non-HTTPS or non-targeted endpoints
  - **Description:** Some tools may call auxiliary endpoints (telemetry, model lists, auth) on different domains or use HTTPS with certificate pinning.
  - **Impact:** Credentials might still be exposed (if tool sends them elsewhere) or functionality breaks.
  - **Fix:** Maintain an allowlist of domains per provider and verify coverage. Document behavior for non-matched domains (pass-through vs block).

## Minor Suggestions
- **[Clarity]** “~190 lines of new code total” is speculative
  - **Description:** This estimate is likely too optimistic and may bias planning.
  - **Fix:** Replace with a rough range and call out that mitmproxy addon + init scripts may exceed it.

- **[Completeness]** No rollback or disablement steps in the plan
  - **Description:** Users need a clear path to disable isolation or clean up CA trust if issues occur.
  - **Fix:** Add a “Disable/Uninstall” section with steps to remove CA and revert iptables rules.

- **[Risk]** Lack of logging/auditing in scope could hinder debugging
  - **Description:** Out of scope excludes audit logging, but some minimal logging is needed to diagnose proxy failures.
  - **Fix:** Add a minimal logging strategy (info-level request summaries, redaction of headers) without full audit logging.

## Questions
- **[Architecture]** How will the proxy handle HTTP/2 and streaming SSE responses?
  - **Context:** Many AI CLIs rely on streaming and HTTP/2 for performance and correctness.
  - **Needed:** Confirmation of mitmproxy settings and validation plan for streaming across at least two providers.

- **[Risk]** What is the exact iptables/nftables approach inside the sandbox?
  - **Context:** Transparent interception in containers is sensitive to rule types and kernel capabilities.
  - **Needed:** The precise rules (REDIRECT vs TPROXY), required capabilities, and sysctls.

- **[Completeness]** How are provider-specific headers beyond API keys handled?
  - **Context:** Some providers require version or organization headers to authenticate or route requests.
  - **Needed:** A per-provider header map and defaults.

- **[Sequencing]** How will the sandbox wait for the gateway CA cert before trusting it?
  - **Context:** A race here will cause TLS failures at startup.
  - **Needed:** An explicit wait/timeout strategy and startup ordering guarantees.

- **[Feasibility]** How will this work for tools that set custom CA bundles or do certificate pinning?
  - **Context:** Some CLIs override trust stores or pin certs.
  - **Needed:** A list of targeted CLIs and whether they require special handling.

## Praise
- **[Completeness]** Clear phased breakdown with verification steps
  - **Why:** The plan’s phased structure and per-phase verification criteria make it easier to implement incrementally and detect regressions early.

- **[Architecture]** Strong isolation goal with unmodified CLIs
  - **Why:** Network-level interception avoids SDK changes and reduces integration surface area.

- **[Risk]** Risks section identifies core operational concerns
  - **Why:** CA trust and gateway availability are correctly recognized as high-impact issues.