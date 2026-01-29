# Review Summary

## Critical Blockers
None identified

## Major Suggestions
- **[Architecture]** Gateway auth scheme for git HTTP lacks precise credential flow
  - **Description:** The plan specifies a token-based gateway but doesn’t define how the git client will supply credentials over Smart HTTP (e.g., Authorization header vs. git credential helper), nor how the gateway will map token → upstream credentials safely for both fetch and push.
  - **Impact:** Implementers may pick incompatible or insecure flows, causing git operations to fail or leak credentials.
  - **Fix:** Add a concrete protocol: e.g., git credential helper injects `Authorization: Basic <token>` or `password=<token>` and the gateway validates it, then uses its own upstream token (not forwarded). Include explicit request/response headers and mapping behavior.

- **[Architecture]** DNS allowlist + proxy allowlist interaction is under-specified
  - **Description:** Plan sets dnsmasq allowlist and tinyproxy allowlist but doesn’t define precedence or expected behavior for wildcard/CDN domains or IP literals.
  - **Impact:** Inconsistent behavior across tools (curl, npm, pip) and possible bypass or false blocks.
  - **Fix:** Specify DNS resolution path (all queries go to gateway dnsmasq), whether IP-literals are blocked, and how wildcard domains are implemented (dnsmasq regex vs. tinyproxy `allow` patterns). Add test cases for `*.cloudfront.net` and direct-IP requests.

- **[Risk]** Session token binding only to container ID is weak against replay
  - **Description:** Tokens scoped to container ID + repo without additional proof of possession (e.g., per-session secret) and can be exfiltrated from memory.
  - **Impact:** A token leak enables cross-container or post-destruction replay if token revocation fails.
  - **Fix:** Bind token to both container ID and a per-container nonce stored only in gateway, or include a short TTL (e.g., 1–4 hours) with auto-refresh; require token via a header or basic auth and reject stale tokens even if container ID matches.

- **[Completeness]** Observability/audit trail for security-relevant events is missing
  - **Description:** Plan explicitly excludes structured audit logging, but for an isolation gateway this is a core control.
  - **Impact:** Hard to detect abuse or diagnose policy failures.
  - **Fix:** Add minimal structured logging for session create/destroy and denied repo access. Keep tokens redacted; no need for full metrics.

## Minor Suggestions
- **[Feasibility]** Timeouts for large repos may be too short
  - **Description:** 30s connect/300s transfer may fail for large repos over slower links.
  - **Fix:** Make timeouts configurable via env vars; document defaults.

- **[Completeness]** Allowlist doesn’t include common OS package managers
  - **Description:** Only language registries are listed; OS updates or apt/apk/yum might be needed in sandbox images.
  - **Fix:** Decide and document whether OS package managers are supported; if yes, include their domains or note they require custom allowlists.

- **[Sequencing]** Phase dependencies could be clearer
  - **Description:** Gateway + networking + git rewrite are tightly coupled; if Phase 3 blocks egress, Phase 2 tests may fail unless ordering is explicit.
  - **Fix:** Explicitly state a recommended order: build gateway, test in isolation, then enable internal network + proxy.

- **[Clarity]** Error handling for unsupported Git LFS and submodules
  - **Description:** “Clear 501” is mentioned, but only in gateway verification, not in git rewrite behavior.
  - **Fix:** Document how gateway detects LFS endpoints and submodule fetches, and the exact error response returned.

## Questions
- **[Clarity]** How is the gateway’s upstream credential stored and rotated?
  - **Context:** Token handling is central to isolation; storage and rotation impact security and ops.
  - **Needed:** Location (env var, file, secret store), rotation method, and whether multiple upstream tokens are supported.

- **[Architecture]** How do you prevent proxy bypass via DNS-over-HTTPS or raw IPs?
  - **Context:** DNS allowlist helps, but apps can use DoH or literal IPs.
  - **Needed:** Explicit policy: block DoH endpoints, block direct IPs at proxy, or restrict egress to proxy only at network layer.

- **[Feasibility]** How is `gateway.sock` exposed safely to the host CLI?
  - **Context:** Unix socket permissions are critical to prevent sandbox access.
  - **Needed:** File path, ownership/permissions model, and how containers are prevented from mounting it.

- **[Completeness]** How are repo allowlists determined and passed?
  - **Context:** Gateway needs repo scope; unclear how it’s derived from user input.
  - **Needed:** Source of allowed repos (CLI args? workspace config?), and behavior for unknown repos.

## Praise
- **[Architecture]** Strong defense-in-depth approach
  - **Why:** Combining Docker internal network, proxy allowlist, and host firewall rules provides layered controls against egress bypass.

- **[Completeness]** Clear phase breakdown with verification steps
  - **Why:** Each phase includes concrete checks, which makes the plan testable and reduces ambiguity.

- **[Risk]** Explicit out-of-scope for LFS/submodules
  - **Why:** Acknowledging known limitations avoids surprise failures and sets expectations.

- **[Clarity]** Success criteria list is actionable
  - **Why:** The checklist maps directly to real validation commands and expected outcomes.