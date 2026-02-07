# Phase 2: Pass Sandbox Branch to Proxy Metadata

## 2A. Add `sandbox_branch` to registration metadata

**File:** `commands/new.sh` lines 1184-1188

```bash
metadata_json=$(jq -n \
    --arg repo "$repo_spec" \
    --arg allow_pr "$allow_pr" \
    --arg sandbox_branch "$branch" \
    '{repo: $repo, allow_pr: ($allow_pr == "true"), sandbox_branch: $sandbox_branch}')
```

(`$branch` is in scope — set at lines 837-843, possibly modified at line 988.)

**File:** `commands/start.sh` lines 166-170

```bash
metadata_json=$(jq -n \
    --arg repo "$repo_spec" \
    --arg allow_pr "${SANDBOX_ALLOW_PR:-0}" \
    --arg sandbox_branch "${SANDBOX_BRANCH:-}" \
    '{repo: $repo, allow_pr: ($allow_pr == "1"), sandbox_branch: $sandbox_branch}')
```

(`$SANDBOX_BRANCH` is loaded via `load_sandbox_metadata` at line 23.)

No changes needed to `git_api.py` or `registry.py` — the metadata dict flows through as opaque JSON via `registry.register()` → SQLite → `ContainerConfig.from_row()`.

**Legacy sandboxes:** Sandboxes created before this change may have no `sandbox_branch` in proxy metadata. In this plan, those sandboxes are unsupported and must be re-created.

**Warning for legacy sandboxes:** When the proxy starts and `sandbox_branch` is missing from metadata, log a warning so users understand commands will be denied until the sandbox is re-created:

**File:** `unified-proxy/git_operations.py` — in proxy startup or first `execute_git()` call, when metadata lacks `sandbox_branch`:

```python
if metadata and not metadata.get("sandbox_branch"):
    logger.warning(
        "Sandbox branch identity missing (created before branch isolation support). "
        "Commands requiring git proxy validation will be denied. Recreate sandbox."
    )
```

This runs once per proxy registration (not per command). The existing `register()` handler in `git_api.py` is the right place — add the warning after `ContainerConfig.from_row()` populates the config.

## 2B. Legacy sandbox fail-closed behavior

**Goal:** prevent indefinite "no isolation" operation for pre-Phase-2 sandboxes.

**Files:** `commands/start.sh`, `unified-proxy/git_operations.py`

Enforcement:
1. If `SANDBOX_BRANCH` is missing at startup, fail with a clear error and require sandbox recreation.
2. If command metadata lacks `sandbox_branch`, return:
   - `ValidationError("Sandbox branch identity missing; recreate sandbox to enable isolation")`
3. Do not provide legacy allow/override mode.

## Verification

- New sandbox registration contains `sandbox_branch`
- Startup fails closed when `sandbox_branch` is missing
- Legacy sandboxes without branch identity must be re-created
