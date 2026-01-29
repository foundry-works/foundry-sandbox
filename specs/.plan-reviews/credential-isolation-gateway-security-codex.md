# Review Summary

## Critical Blockers
- **[Risk]** Missing mutual authentication for gateway requests
  - **Description:** The sandbox authenticates to the gateway via token+HMAC, but the plan doesn’t specify how the sandbox verifies it is talking to the legitimate gateway (no mTLS, no signed responses, no pinned certs, no socket-only path for in-container calls).
  - **Impact:** A compromised internal service or DNS spoofing inside the Docker network could impersonate the gateway and capture session tokens or return malicious git data.
  - **Fix:** Add gateway identity verification for sandbox clients: mTLS on the internal network with pinned CA, or a signed response challenge using the per-session secret; at minimum, configure the sandbox to connect to a fixed container IP + validate a gateway public key fingerprint.

- **[Risk]** IP-based session binding is brittle and potentially bypassable
  - **Description:** Binding tokens to container IP assumes stable IP and trustworthy source IP. On Docker networks, IP spoofing is possible without strict egress filtering or netfilter rules in place.
  - **Impact:** A compromised container could spoof source IP to hijack another session.
  - **Fix:** Bind to container identity via Docker API-verified container ID and a per-connection HMAC; enforce iptables on the gateway host to drop packets with spoofed source IPs; consider per-session client certificates.

- **[Risk]** Gateway stores GitHub token in environment variable
  - **Description:** The plan puts `GH_TOKEN` in the gateway container env, which is readable via `docker inspect` or `/proc` inside the container.
  - **Impact:** Token exposure if the gateway is compromised or if other host users have docker access.
  - **Fix:** Move GitHub token into a docker secret or mounted read-only file; avoid environment variables for credentials.

- **[Risk]** Lack of rate limiting / abuse controls on gateway endpoints
  - **Description:** The plan explicitly defers rate limiting; yet the gateway is exposed to untrusted sandbox code.
  - **Impact:** DoS against GitHub, gateway resource exhaustion, log flooding, or session brute force.
  - **Fix:** Add per-container and global rate limits, request size limits, and concurrent connection caps on `/git/*` and `/session/*`.

## Major Suggestions
- **[Architecture]** Unix socket access control not fully hardened
  - **Description:** Socket permissions are set to 0600, but no mention of protecting the directory with `0700` or checking for symlink attacks when binding.
  - **Impact:** Local user or process could race/replace socket path to intercept session creation.
  - **Fix:** Ensure parent directory permissions are `0700`, refuse if dir is group/world-writable, and verify the socket path is not a symlink at creation time.

- **[Risk]** DNS and proxy allowlist enforcement may be incomplete
  - **Description:** Plan blocks known DoH endpoints, but new DoH hosts or IP-based DoH endpoints can bypass; also, DNS is only forced through gateway in container config.
  - **Impact:** Data exfiltration via alternate DNS-over-HTTPS or direct IP access.
  - **Fix:** Add explicit proxy policy to block `application/dns-message` and DoH endpoints broadly; enforce egress at host firewall and via container network policy to drop outbound 443 to non-allowlisted IP ranges.

- **[Completeness]** Git hook and config execution not explicitly disabled
  - **Description:** Malicious repos can include hooks or `.gitconfig` settings that execute commands or leak data.
  - **Impact:** Credential leakage or sandbox escape attempts.
  - **Fix:** Disable git hooks in the container (set `core.hooksPath` to a non-existent dir), and sanitize global git config to prevent external helpers.

- **[Risk]** Session token storage inside container is readable by any process user
  - **Description:** Token stored in `/run/secrets/gateway_token` with 0400, but if the container runs as a shared user, any process with that UID can read it.
  - **Impact:** If untrusted processes run as same user, token theft is possible.
  - **Fix:** Use a dedicated, least-privilege user for git operations; mount secrets readable only by that user, and run untrusted tasks as a different UID without access.

- **[Architecture]** Gateway upstream pinning ignores GitHub Enterprise
  - **Description:** Hard-pins to `github.com` only and no config for enterprise instances.
  - **Impact:** Incompatibility or forced disabling of gateway for enterprise users, weakening security posture.
  - **Fix:** Allow a configurable allowlist of GitHub hosts with strict validation and explicit admin approval.

## Minor Suggestions
- **[Clarity]** Error messages could leak internal details
  - **Description:** Proposed errors differentiate 401/403/404 with granular reasons.
  - **Fix:** Standardize external error responses to avoid leaking repo existence; log detailed reasons internally.

- **[Feasibility]** 24h inactivity refresh on any git operation may extend compromised sessions
  - **Description:** Automatic refresh on activity can keep a stolen token alive indefinitely up to 7 days.
  - **Fix:** Tie refresh to successful authenticated git operations and cap per-session usage; consider requiring periodic re-creation from host.

- **[Completeness]** No explicit integrity checks for gateway binary or config
  - **Description:** Gateway config generation and service code lack integrity validation.
  - **Fix:** Include checksum verification on generated configs and pinned dependencies.

## Questions
- **[Completeness]** How is container identity verified beyond IP?
  - **Context:** IP spoofing is possible; container ID validation is mentioned but not defined.
  - **Needed:** Exact mechanism for binding requests to container identity (Docker API verification, client certs, or signed handshake).

- **[Architecture]** What is the threat model for the gateway service itself?
  - **Context:** Gateway holds real credentials and is a high-value target.
  - **Needed:** Hardening details (user privileges, seccomp profile, filesystem mounts, logging redaction guarantees).

- **[Sequencing]** When and where are firewall rules applied?
  - **Context:** If iptables rules are applied after container start, there’s a window of unrestricted egress.
  - **Needed:** Ordering guarantees and validation steps to ensure no race conditions.

- **[Risk]** How are secrets rotated?
  - **Context:** Long-lived GH tokens increase blast radius if leaked.
  - **Needed:** Rotation plan and how sessions are invalidated after rotation.

## Praise
- **[Architecture]** Strong isolation model with layered defenses
  - **Why:** Internal network, ICC disabled, DNS lockdown, and proxy allowlist provide defense-in-depth.

- **[Risk]** Explicitly avoids exposing real credentials in sandbox
  - **Why:** Token-in-tmpfs and no env vars mitigate common leakage paths.

- **[Completeness]** Thoughtful git protocol constraints
  - **Why:** Path allowlist, redirect disabling, and strict validation reduce SSRF and traversal risks.

- **[Clarity]** Detailed verification steps
  - **Why:** Concrete tests make it easier to validate security requirements end-to-end.