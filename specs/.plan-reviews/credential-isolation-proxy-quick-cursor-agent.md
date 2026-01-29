# Review Summary

## Critical Blockers
Issues that MUST be fixed before this becomes a spec.

- **[Feasibility]** Transparent proxy via `OUTPUT` DNAT inside container is under-specified
  - **Description:** The plan assumes `iptables -t nat -A OUTPUT ... DNAT` inside the sandbox container works for all outbound 443 and preserves original destination for mitmproxy, but container networking mode/capabilities needed are not defined.
  - **Impact:** The proxy may not intercept traffic at all or may break routing if the container lacks `NET_ADMIN`, runs without iptables, or loses original destination metadata.
  - **Fix:** Specify required container capabilities/privileges (e.g., `NET_ADMIN`), exact network mode, and verify mitmproxy transparent mode compatibility with DNAT on `OUTPUT` in Docker; include alternative if not viable (e.g., `TPROXY`, `REDIRECT`, or host-level rules).

- **[Architecture]** Missing trust/CA distribution mechanism for the sandbox
  - **Description:** The plan mentions a shared volume but does not define how the gateway CA cert is made available to the sandbox container or where it is mounted.
  - **Impact:** CA installation steps in Phase 2 cannot be executed reliably; TLS interception will fail.
  - **Fix:** Define the exact volume, mount path, and file names used by both services (gateway writes path, sandbox reads path), and add to the compose override.

- **[Completeness]** Credential injection addon behavior is not specified for request shapes
  - **Description:** The plan does not specify how to handle existing `Authorization` headers, how to deal with per-provider requirements (e.g., Anthropic uses `x-api-key`, OpenAI uses `Authorization`), or how to avoid leaking upstream credentials when clients already send their own.
  - **Impact:** Proxy may send conflicting headers, break auth, or leak sandbox-supplied values if present.
  - **Fix:** Define explicit rules: overwrite vs. set-if-missing; remove conflicting headers; log redaction; and map for each provider including any required prefixing.

## Major Suggestions
Significant improvements to strengthen the plan.

- **[Risk]** Missing TLS error handling strategy and fallback
  - **Description:** The plan does not address how to detect/handle clients that pin certificates or ignore custom CAs.
  - **Impact:** Some tools may fail silently or degrade, causing partial compatibility.
  - **Fix:** Add a detection plan (mitmproxy error logging), plus a documented fallback mode (disable isolation for specific tools or domains) or a list of known compatible clients.

- **[Architecture]** Domain allowlist is static and may miss required subdomains
  - **Description:** Providers often use multiple domains (e.g., `api.openai.com`, `oaiusercontent.com` for file uploads, `openai.azure.com` for Azure).
  - **Impact:** Requests may bypass injection or fail due to missing auth.
  - **Fix:** Add a maintenance strategy and expand mapping to known required domains, or allow pattern-based allowlist with explicit guardrails.

- **[Sequencing]** Healthcheck and readiness semantics are underspecified
  - **Description:** “Healthcheck returns 200 on /healthz” doesn’t specify how it’s served or whether mitmproxy is fully ready for transparent mode.
  - **Impact:** Sandbox may proceed before proxy is actually intercepting, causing transient failures.
  - **Fix:** Specify readiness criteria (mitmproxy started, cert generated, healthcheck addon loaded) and ensure healthcheck endpoint is served by the proxy itself.

## Minor Suggestions
Smaller refinements.

- **[Clarity]** Rollback section assumes API keys available in sandbox
  - **Description:** It suggests `export ANTHROPIC_API_KEY=...` inside the sandbox to restore direct access.
  - **Fix:** Clarify that this is only for non-isolated mode or document how to re-run without the isolation compose override.

- **[Completeness]** No explicit mention of log redaction in gateway
  - **Description:** Gateway logs could accidentally emit injected headers.
  - **Fix:** Add a logging policy or redaction rule in the addon to prevent secret exposure.

## Questions
Clarifications needed before proceeding.

- **[Architecture]** How will the gateway discover the original destination after DNAT?
  - **Context:** Transparent proxy requires original destination information; Docker NAT and `OUTPUT` DNAT may obscure it.
  - **Needed:** Confirm mitmproxy transparent mode configuration and kernel requirements (e.g., `--mode transparent`, `--set connection_strategy`, `SO_ORIGINAL_DST` availability).

- **[Feasibility]** What container capabilities and security settings are required?
  - **Context:** `iptables` and modifying trust stores typically require elevated permissions.
  - **Needed:** Specify exact Docker capabilities/privileges (`NET_ADMIN`, `SYS_ADMIN`?) and whether this is acceptable in the project’s security posture.

- **[Completeness]** Where exactly is the CA cert stored and mounted?
  - **Context:** The plan references a shared volume but omits the paths used by gateway and sandbox.
  - **Needed:** Provide the precise mount paths and file names used by both services.

- **[Clarity]** What is the behavior when client provides its own API key?
  - **Context:** Some tools may always send `Authorization` or `x-api-key`.
  - **Needed:** Define header precedence and whether the addon removes or replaces client-supplied credentials.

- **[Architecture]** Will non-HTTPs traffic or HTTP/80 be affected?
  - **Context:** The plan only targets 443.
  - **Needed:** Confirm whether HTTP traffic should be intercepted, blocked, or left untouched.

## Praise
What the plan does well.

- **[Completeness]** Clear phased rollout with verification and fidelity reviews
  - **Why:** Each phase has tasks and verification steps, which reduces integration risk.

- **[Risk]** Explicit QUIC/HTTP3 mitigation
  - **Why:** Blocking UDP 443 addresses a common bypass for HTTPS interception.

- **[Clarity]** Concrete provider mapping table
  - **Why:** The domain/header/env var matrix makes credential injection behavior easy to implement and review.