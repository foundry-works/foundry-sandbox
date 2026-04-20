# ADR-011: Deep Policy Sidecar

**Status:** Accepted
**Date:** 2026-04-20
**Deciders:** Tyler Burleigh

## Context

The GitHub API filter (`github_filter.py`) enforces request-shape policies (method, path, GraphQL body) using hardcoded Python lists. This is the only surviving method/path/body rule set after the `unified-proxy/` removal. PLAN §5.5 calls for generalizing this into a YAML-driven request inspector so any service can have request-shape policies.

## Decision

Build the deep policy sidecar as a Flask Blueprint on the main foundry-git-safety server, using a YAML rule format with priority-ordered evaluation.

### Blueprint vs. separate server

The sidecar runs as a Flask Blueprint (like `user_services_proxy.py`), not a separate `ThreadingHTTPServer` (like `github_filter.py`). Reasons:

- The main server already has rate limiting, Prometheus metrics, and structured logging — a Blueprint inherits all of these.
- A separate server requires separate process management, port allocation, and has no access to the Flask app's shared state.
- The GitHub filter predates the Flask server; it is not the pattern to emulate.

### Simple dot-notation body inspection

Use inline dot-notation traversal (`state`, `query`, `data.state`) instead of `jsonpath-ng`. Rationale:

- The only body inspection today checks top-level JSON keys. No JSONPath is needed.
- Adding a dependency for an off-by-default feature guarded behind Gate D is premature.
- The `body_jsonpath` field semantics can be upgraded later without breaking the schema.

### Per-sandbox rate limiting

Proxy requests share the existing `RateLimiter` from `auth.py`, keyed by `X-Sandbox-Id`. This means proxy and git operations share the same per-sandbox rate budget — a sandbox cannot exceed its limit by switching between git and API calls.

### Circuit breaker

Three-state (closed → open → half-open), per-service-slug. Default: 5 consecutive failures / 30s recovery. Thread-safe via `threading.Lock`.

### Existing GitHub proxy unchanged

The existing `github_filter.py` standalone proxy (port 8084) is not modified. The deep policy sidecar is opt-in via `foundry.yaml` or `--deep-policy` CLI flag. They coexist until a future release removes the standalone proxy.

## Consequences

- **Positive:** Any service can have method/path/body policies via YAML, not just GitHub.
- **Positive:** No new dependencies.
- **Positive:** Existing GitHub proxy continues to work for users who don't opt in.
- **Negative:** PR reopen detection is complex to express in pure YAML; the bundled GitHub policy covers it with a body-value rule but may have edge cases vs. the original Python logic.
- **Negative:** Simple dot-notation body inspection won't cover array indexing or wildcards. Upgrade path exists if needed.
