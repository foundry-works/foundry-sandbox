# Security Hardening

This document summarizes the security hardening measures in the unified proxy and sandbox infrastructure, organized by category. For the threat model and defense-in-depth architecture, see [Threat Model](sandbox-threats.md) and [Security Architecture](security-architecture.md).

## Input Validation

### Path Normalization

URL paths are normalized before any policy check to prevent traversal and encoding bypass:

1. Strip query string and fragment
2. URL-decode once
3. Reject if `%` still present (double-encoding prevention)
4. Resolve `..` segments via `posixpath.normpath` (runs before slash collapsing to correctly resolve relative segments)
5. Collapse repeated slashes (`//` → `/`)
6. Strip trailing slash (except bare `/`)

This logic lives in `security_policies.normalize_path()`, shared between the GitHub gateway and the mitmproxy policy engine.

### Regex Matching

Pattern matching uses `re.fullmatch()` instead of `re.match()` to prevent partial-match bypass. `re.match()` only anchors at the start, so a pattern like `^/repos/[^/]+/[^/]+$` matched with `re.match()` could be bypassed by appending extra path segments.

### Git Identity Sanitization

Git user names and email addresses are sanitized to remove control characters (newlines, null bytes, ASCII control codes) before being used in git operations. This prevents header injection in git commit metadata.

### YAML Serialization

Configuration values are serialized with `yaml.dump()` instead of string interpolation to prevent YAML injection. String interpolation into YAML can produce invalid or malicious YAML if the value contains special characters (`:`, `#`, `[`, etc.).

## Credential Protection

### Placeholder Filtering

Sandbox-supplied headers containing placeholder credential markers (`CRED_PROXY_`, `CREDENTIAL_PROXY_PLACEHOLDER`) are stripped before forwarding to upstream APIs. Filtering uses `startswith()` rather than substring matching to prevent false positives on legitimate values that happen to contain these strings.

### Token-Only and Username-Only Auth Rejection

Git credential helper responses that provide only a `username` without a `password`, or only a `password`/`token` without a `username`, are rejected. Partial credential detection prevents credential confusion attacks where a sandbox supplies one half of a credential pair to influence how the proxy constructs the other.

## Identity and Access Control

### Container Identity Validation

Requests to API gateways must have a valid container identity resolved from the source IP via the container registry. Requests from unregistered IPs receive a 403 response. The `IdentityMiddleware` runs first in the middleware stack to ensure all subsequent middleware (rate limiting, circuit breaking, metrics) operates on authenticated identity.

A null or empty `container_id` is explicitly rejected — it does not fall through to a default or anonymous identity.

### IP Literal Detection

All forms of IP address encoding in hostnames are blocked before domain allowlist evaluation:

| Encoding | Example | Detection |
|---|---|---|
| Dotted decimal | `1.2.3.4` | Regex |
| IPv6 brackets | `[::1]` | Regex |
| Octal | `0177.0.0.1` | Regex |
| Hexadecimal | `0x7f000001` | Regex |
| Integer | `2130706433` | Regex |
| Mixed | `0x7f.0.0.01` | `socket.inet_aton()` fallback |

Detection is implemented in the policy engine's `is_ip_literal()` function and duplicated in Squid ACLs for defense-in-depth.

## Network Resilience

### Circuit Breaker (Fail-Closed)

The circuit breaker transitions to OPEN state when upstream error rate exceeds the threshold. In OPEN state, requests are rejected with a JSON error response rather than being forwarded. This is a fail-closed design — an unhealthy upstream does not cause requests to bypass the proxy and reach the upstream directly.

### ConnectionResetError Handling

Client disconnections during response streaming are caught and handled gracefully. If the response has already been prepared (HTTP headers sent), the handler returns the partially-streamed response rather than raising an unhandled exception. If no response was prepared, a 499 status is returned.

## File System Safety

### Atomic File Writes

Configuration files generated at runtime (Squid domain lists, upgrade state) use the atomic write pattern: write to a temporary file in the same directory, then `os.rename()` to the target path. This prevents consumers from reading partially-written files.

### Symlink Boundary Checks

File operations that reference paths within the workspace or sandbox directories validate that the resolved path (after symlink resolution) stays within the expected boundary. This prevents symlink-based traversal where a sandbox creates a symlink pointing outside its workspace.

### Tempfile Race Condition Prevention

Temporary files used during upgrade operations are created with `tempfile.NamedTemporaryFile` with `delete=False`, written, closed, then atomically renamed. This prevents TOCTOU races where another process could modify the file between creation and use.

## Git Operation Safety

### Diff Argument Order Validation

`git diff` arguments for push file restriction checks use explicit `--` separator and controlled argument ordering to prevent argument injection. Without controlled ordering, a sandbox could craft branch names or file paths that are interpreted as git flags.

### Push File Restrictions

Files matching blocked patterns in `config/push-file-restrictions.yaml` are rejected at push time. The validation runs in the `/git/exec` handler before the push command executes. If `git diff` fails (e.g., invalid refs), the push is rejected (fail-closed). See [Configuration: Push File Restrictions](../configuration.md#push-file-restrictions).

### Merge Blocking

PR merge operations are blocked via early-exit detection that runs before domain matching, credential injection, or policy evaluation:
- REST: `PUT /repos/*/pulls/*/merge`, `PUT /repos/*/pulls/*/auto-merge`
- GraphQL: `mergePullRequest`, `enablePullRequestAutoMerge` mutation keywords in request body

The body keyword scan is intentionally broad — false positives that block legitimate requests are safer than false negatives that allow merges.

## Testing

Security hardening measures are covered by:

- **Unit tests** — `tests/unit/test_policy_engine.py`, `tests/unit/test_github_gateway.py`, `tests/unit/test_gateway_middleware.py`
- **Push restriction tests** — `unified-proxy/tests/unit/test_push_file_restrictions.py`, `unified-proxy/tests/unit/test_commit_file_restrictions.py`
- **Red team modules** — `tests/redteam/modules/18-ip-encoding-bypass.sh`, `tests/redteam/modules/19-merge-early-exit.sh`
- **Integration tests** — `tests/integration/test_api_proxy.py`, `tests/security/test_credential_isolation.py`

## See Also

- [Threat Model](sandbox-threats.md) — What we protect against and why
- [Security Architecture](security-architecture.md) — Defense-in-depth pillars
- [Configuration: Push File Restrictions](../configuration.md#push-file-restrictions) — File restriction patterns
- [ADR-009: API Gateways](../adr/009-api-gateways.md) — Gateway architecture decision
