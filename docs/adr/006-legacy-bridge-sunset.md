# ADR-006: Legacy Bridge Sunset

## Status

Accepted

Date: 2025-02-10

## Context

The shell-to-Python rewrite introduced a per-module bridge pattern to allow
incremental migration. Each Python module exposes a `bridge_main()` dispatch
table so that shell scripts can call individual Python functions via
`python -m foundry_sandbox.<module> <command> [args...]`. A central
`legacy_bridge.py` adapter also provides `run_legacy_command()` for Python
code that still needs to invoke partially-migrated shell commands.

With the Click CLI now handling all user-facing commands, the bridge layer is
only needed while shell callers still exist. Once all shell callers are
removed, the bridge infrastructure becomes dead code.

### Modules with bridge dispatch tables (12)

1. `api_keys.py`
2. `claude_settings.py`
3. `config.py`
4. `container_io.py`
5. `docker.py`
6. `git.py`
7. `git_worktree.py`
8. `network.py`
9. `opencode_sync.py`
10. `proxy.py`
11. `state.py`
12. `validate.py`

### Central dispatcher

- `legacy_bridge.py` — routes `_bridge_*` calls and provides
  `run_legacy_command()` for Python callers.
- `_bridge.py` — contains the shared `bridge_main()` helper used by all
  12 modules above.

## Decision

Sunset the legacy bridge layer once no shell callers remain. The removal is
gated on migration completion, not a hard calendar deadline.

### Removal conditions

1. **No shell scripts import bridge functions.** Verify with:
   ```
   grep -r '_bridge_' lib/ commands/*.sh 2>/dev/null | grep -v '.pyc'
   ```
2. **No Python code calls `run_legacy_command()`.** Verify with:
   ```
   grep -rn 'run_legacy_command' foundry_sandbox/ --include='*.py'
   ```
3. **All Click commands are self-contained** (no fallback to shell).

### Removal sequence

1. Remove all `if __name__ == "__main__": bridge_main({...})` blocks from
   the 12 modules listed above.
2. Remove per-module `_cmd_*` bridge command functions.
3. Delete `foundry_sandbox/_bridge.py`.
4. Delete `foundry_sandbox/legacy_bridge.py`.
5. Remove any remaining shell scripts under `lib/` that are now dead code.
6. Update tests to remove bridge-specific test cases.

### Timeline

Gated on full migration completion. No hard deadline — remove when the
removal conditions above are met.

## Consequences

### Positive

- Eliminates ~300 lines of bridge boilerplate across 12 modules.
- Removes the subprocess-based calling convention (shell → Python → JSON),
  reducing latency and complexity.
- Simplifies the module public API surface.

### Negative

- Requires a coordinated sweep across all modules in a single PR.
- Any external tooling that calls `python -m foundry_sandbox.<module>` will
  break (none known outside the project).

### Neutral

- The `_bridge.py` / `bridge_main()` pattern is harmless while it exists —
  it adds no runtime cost unless invoked via `__main__`.
