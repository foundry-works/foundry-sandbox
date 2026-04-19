# ADR-006: Allowlist Layering

## Status

Accepted (merge semantics still applicable; mount paths updated for foundry-git-safety)

Date: 2026-02-19

## Context

The unified proxy enforces network access through an allowlist (`allowlist.yaml`) that declares permitted domains, HTTP endpoints, and blocked paths. Different sandbox configurations need different network access — for example, a CI sandbox may need access to a private registry that the default allowlist does not include.

Today the only way to grant additional access is to replace the entire allowlist file, which is error-prone (the replacement must include all base entries) and creates a maintenance burden when the base allowlist is updated. Sandboxes need an additive extension mechanism that preserves the security properties of the base allowlist while allowing controlled expansion.

Key constraints:

- **Security-critical path.** The allowlist is the proxy's primary access control surface. Any merge logic must be additive-only — extra files can only grant access, never revoke it.
- **Fail-closed.** A configured extra file that is missing or invalid must prevent proxy startup rather than silently falling back to the base allowlist alone.
- **Deterministic output.** The merge result must be fully determined by input ordering with no non-deterministic sorting or normalization.

## Decision

Implement an additive-only allowlist layering mechanism in `load_allowlist_config()` via a new `extra_path` parameter and a pure `merge_allowlist_configs()` function.

### Merge canonicalization rules

| Field | Merge strategy | Dedup rule |
|---|---|---|
| `version` | Use base config version; extra version is validated but ignored | N/A |
| `domains` | Ordered dedup — base entries first, extra appended | Exact string match |
| `http_endpoints` (same host) | Union methods and paths | Methods: uppercased exact match. Paths: exact string match |
| `http_endpoints` (new host) | Append preserving extra ordering | Host: exact string match |
| `blocked_paths` | Append extra after base | No per-host dedup — same host may appear in both base and extra |

### Precedence rules

Resolution order for the extra allowlist file path:

1. **Explicit `extra_path` argument** — highest priority. When passed (even as empty string), the environment variable is not consulted.
2. **`PROXY_ALLOWLIST_EXTRA_PATH` environment variable** — fallback when `extra_path` is `None`.
3. **No extra** — when both are unset/empty, extra loading is skipped (backward-compatible).

In container environments, the env var is set to the container mount path (e.g., `/etc/unified-proxy/allowlist-extra.yaml`).

### Extra file schema relaxation

Extra files use a relaxed schema: `domains`, `http_endpoints`, and `blocked_paths` may all be omitted (each defaults to an empty list for merge purposes). The `version` field is still required. `AllowlistConfig.__post_init__` validation runs only on the final merged result, not on the partial extra input.

### Failure policy

- Extra path is set but file does not exist → `ConfigError` (proxy does not start)
- Extra file exists but contains invalid YAML or schema errors → `ConfigError` (proxy does not start)
- Extra file is missing required `version` field → `ConfigError`

No partial allowlist startup is permitted.

## Consequences

### Positive

- Sandboxes can extend network access without replacing the entire base allowlist
- Additive-only merge guarantees the base allowlist's restrictions are preserved
- Fail-closed policy prevents silent security degradation from misconfigured extras
- Pure merge function is independently testable with no I/O or env var dependencies

### Negative

- Extra files cannot revoke access granted by the base allowlist (by design)
- Blocked paths with the same host in both base and extra are appended as separate entries rather than merged, which may cause minor config duplication

### Neutral

- Existing deployments with no extra file configured see no behavior change
- The `merge_allowlist_configs()` function is available for programmatic use outside the file-loading path

## Alternatives Considered

**Override-based merge (extra can remove base entries).** Rejected because it inverts the security model — an extra file authored by a less-trusted party could weaken the base allowlist. Additive-only is safer and simpler.

**Deep merge with per-host blocked path dedup.** Rejected because it adds complexity with minimal benefit. Duplicate blocked path entries for the same host have no correctness impact — they just match redundantly.

**Separate AllowlistConfig subclass for partial configs.** Rejected to avoid class hierarchy complexity. The `object.__new__` bypass for partial construction during parsing is contained within the private `_parse_extra_allowlist()` helper.

## References

- `unified-proxy/config.py` — `merge_allowlist_configs()`, `_parse_extra_allowlist()`, `load_allowlist_config()`
- `unified-proxy/tests/unit/test_config_merge.py` — merge test suite (16 tests)
- [ADR-003: Policy Engine](003-policy-engine.md) (related access control context)
