# ADR-007: Deprecate lib/container_config.sh

## Status

Accepted

Date: 2026-02-11

## Context

`lib/container_config.sh` (2,213 lines) contains shell implementations of container configuration functions that now have Python equivalents in the `foundry_sandbox/` package. Maintaining both implementations creates dual-maintenance risk: bug fixes and feature additions must be applied in two places, with two different testing strategies.

The Python migration is functionally complete — all major functions have working Python equivalents:

| Shell function | Python module |
|---|---|
| `copy_file_to_container` | `container_io.py` |
| `copy_dir_to_container` | `container_io.py` |
| `copy_file_to_container_quiet` | `container_io.py` |
| `copy_dir_to_container_quiet` | `container_io.py` |
| `ensure_container_user` | `container_setup.py` |
| `install_pip_requirements` | `container_setup.py` |
| `block_pypi_after_install` | `container_setup.py` |
| `ssh_agent_preflight` | `container_setup.py` |
| `copy_configs_to_container` | `credential_setup.py` |
| `sync_runtime_credentials` | `credential_setup.py` |
| `merge_claude_settings` | `settings_merge.py` |
| `merge_claude_settings_safe` | `settings_merge.py` |
| `prepopulate_foundry_global` | `foundry_plugin.py` |
| `ensure_foundry_mcp_config` | `foundry_plugin.py` |
| Tool config functions | `tool_configs.py` |

However, removing the shell file entirely is risky without production validation of the Python paths, and some downstream scripts may still source it.

## Decision

Mark `lib/container_config.sh` as deprecated with a header comment. All new features and bug fixes will be implemented in the Python modules only. The shell file will be removed after the Python migration is validated in production.

## Consequences

### Positive

- Eliminates ambiguity about which implementation is canonical
- Prevents new shell functions from being added
- Creates a clear migration path toward removal

### Negative

- The deprecated file remains in the repository until removal
- Developers must check both implementations during the transition period

### Neutral

- Existing shell-based workflows continue to function unchanged
- No immediate behavior change for end users

## References

- `foundry_sandbox/container_io.py` — primary copy primitives
- `foundry_sandbox/credential_setup.py` — config orchestration
- `foundry_sandbox/settings_merge.py` — settings merge logic
- ADR-006: Legacy bridge sunset (related migration context)
