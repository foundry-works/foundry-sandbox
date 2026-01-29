# Review Summary

## Critical Blockers
- **[Risk] Token exposure via proxy routing bypass**
  - **Description:** The plan relies on internal networking + proxy, but allows the sandbox to access the gateway directly over HTTP. Without explicit egress enforcement at container-level for *all* traffic except gateway/proxy, a compromised sandbox could still exfiltrate via allowed domains (e.g., covert channels over HTTPS to allowlisted hosts) or use gateway as a pivot if any parsing bugs exist.
  - **Impact:** Credential and data exfiltration despite network isolation, undermining the core objective.
  - **Fix:** Enforce strict egress policy at the container (iptables in container namespace or CNI policy) so the sandbox can only reach gateway + egress proxy IPs/ports; block all other destinations, even if allowlisted DNS would permit them.

- **[Risk] Session binding incomplete without TLS or strong channel binding**
  - **Description:** Tokens are bound to container IP + secret + container ID, but all traffic is HTTP on a shared internal network; a compromised container with same network access could sniff or spoof requests if it can reach the gateway (e.g., via ARP spoofing on the bridge).
  - **Impact:** Token replay or request forgery from another container in the same network.
  - **Fix:** Add mTLS on gateway internal HTTP or use Unix socket proxying only (no TCP port) with a sidecar per sandbox; alternatively add per-container network namespace isolation with no L2 adjacency and enforce `com.docker.network.bridge.enable_ip_masquerade=false` + ebtables ARP spoofing protection.

- **[Risk] Git credential helper reads token file without process isolation**
  - **Description:** The token file is readable by the container user (0400), but any process in the container can read it. If untrusted repo code runs, it can exfiltrate the token and use it to access allowed repos during its TTL.
  - **Impact:** A compromised sandbox can still misuse credentials within allowed repo scope.
  - **Fix:** Use per-process credentials via a helper that returns a short-lived, request-scoped token (e.g., per git command), or store the token in a root-only mount and run git as a less-privileged user with a helper that performs IPC to a local sidecar.

- **[Risk] Allowlist-based DNS/proxy does not prevent covert channels**
  - **Description:** The plan assumes allowlisting domains is sufficient, but exfiltration can occur via request bodies or query strings to allowed domains (e.g., `api.github.com` or CDN endpoints).
  - **Impact:** Data leakage over approved domains, defeating isolation.
  - **Fix:** Constrain egress by protocol and endpoint where possible (e.g., allow only `GET` for package registries, block arbitrary POSTs), and add content-size limits + anomaly detection; for GitHub API, consider blocking or narrowing to specific endpoints used.

## Major Suggestions
- **[Architecture] Lack of integrity protection for allowlist generation**
  - **Description:** `gateway/build-configs.sh` generates dnsmasq/tinyproxy configs from `allowlist.conf`, but no mention of validation, signing, or safe parsing (e.g., handling wildcards and negations).
  - **Impact:** Misconfiguration or injection via malformed allowlist entries could open egress.
  - **Fix:** Add strict parsing, linting, and a CI check that validates the generated configs match expected patterns; consider storing generated config checksums.

- **[Risk] Missing explicit CSRF-like protections on Unix socket endpoints**
  - **Description:** The gateway exposes `/session/create` and `/session/destroy` via Unix socket, but no request auth beyond filesystem permissions is described.
  - **Impact:** Any local process under the same user could create sessions or destroy others.
  - **Fix:** Add an HMAC or nonce-based auth between CLI and gateway, or enforce a dedicated Unix socket path with ownership checks + SO_PEERCRED verification.

- **[Risk] No explicit rate limiting on gateway or proxy**
  - **Description:** Rate limiting is out of scope, but the gateway is a shared service and could be DOSed by a malicious sandbox or repo.
  - **Impact:** Service disruption, token churn, or operational instability.
  - **Fix:** Add basic per-container/IP rate limits on gateway routes and proxy requests; even simple token bucket limits mitigate abuse.

- **[Completeness] Insufficient validation for git smart HTTP request bodies**
  - **Description:** The plan validates URL paths but not request body types beyond content-type header; malicious payloads could trigger upstream anomalies.
  - **Impact:** Unexpected request smuggling or resource exhaustion.
  - **Fix:** Enforce strict `Content-Type` matching, size limits for `git-upload-pack`/`git-receive-pack`, and reject unsupported transfer-encodings.

- **[Architecture] Gateway trust in container IP stability**
  - **Description:** Binding sessions to container IP assumes stable IP and no IP reuse attacks.
  - **Impact:** Potential session confusion if IPs are reused quickly after container teardown.
  - **Fix:** Bind to container ID + per-session secret only; validate container ID via Docker API on each request or cache with short TTL; disallow access if container not alive.

## Minor Suggestions
- **[Clarity] Explicitly define “session secret” storage and access controls**
  - **Description:** The secret is in `/run/secrets/gateway_secret`, but no permissions or mount semantics described.
  - **Fix:** Specify file mode/ownership and confirm it is tmpfs and not exposed to other containers.

- **[Completeness] Audit logs should include request IDs**
  - **Description:** Logs are JSON but lack correlation IDs.
  - **Fix:** Add request IDs for gateway and proxy to trace abuse or failures.

- **[Sequencing] LFS and submodule failures need user-facing documentation**
  - **Description:** Plan mentions 501 errors but not user-facing doc updates.
  - **Fix:** Add explicit documentation in `docs/usage/commands.md` or similar.

## Questions
- **[Risk] How will ARP spoofing or L2 traffic be prevented on the internal bridge?**
  - **Context:** Without L2 controls, another container could impersonate IPs to the gateway.
  - **Needed:** Clarification on L2 isolation (ebtables, macvlan, per-sandbox network) or TLS/mTLS use.

- **[Completeness] Are proxy HTTP methods restricted per domain?**
  - **Context:** Allowlisted domains can still receive arbitrary POSTs for exfiltration.
  - **Needed:** Whether method restrictions and content-size limits will be enforced.

- **[Architecture] How is container identity validated in gateway?**
  - **Context:** The plan references `container_id` but doesn’t specify how the gateway verifies it.
  - **Needed:** Details on Docker API usage, caching, and failure modes.

## Praise
- **[Architecture] Defense-in-depth networking**
  - **Why:** Layered controls (internal network, ICC disabled, DNS lockdown, iptables backup) reduce single-point failures.

- **[Risk] Strong git path allowlisting**
  - **Why:** Limiting to git smart HTTP endpoints and rejecting traversal reduces SSRF and arbitrary requests.

- **[Completeness] Thoughtful token handling**
  - **Why:** Avoiding env vars and `docker inspect` exposure is a solid baseline for secret hygiene.