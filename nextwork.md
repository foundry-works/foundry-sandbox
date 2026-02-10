# Remaining Work: Harden Security Boundaries and Reduce Technical Debt

## Status

Improvements 1-4 are complete and all 1222 unit tests pass. Improvements 5, 6, and 7 remain.

---

## Improvement 5: Replace bridge calls with direct Python calls in `new.py`

**File:** `foundry_sandbox/commands/new.py`

Replace all `_shell_call` / `_shell_call_capture` bridge calls with direct function calls. There are ~25 call sites. The shared helpers needed were already extracted to `_helpers.py` in Improvement 4.

### Pure-function calls (use helpers from `_helpers.py`):

| Line | Bridge call | Replacement |
|------|------------|-------------|
| ~325 | `_shell_call_capture("_bridge_repo_to_path", ...)` | `repo_url_to_bare_path(repo_url)` (already imported) |
| ~330 | `_shell_call_capture("_bridge_sandbox_name", ...)` | `sandbox_name(bare_path, branch)` from `_helpers` |
| ~335 | `_shell_call_capture("_bridge_find_next_sandbox_name", ...)` | `find_next_sandbox_name(base_name)` from `_helpers` |
| ~340 | `_shell_call_capture("_bridge_container_name", ...)` | `f"sandbox-{name}"` (inline) |
| ~951 | `_shell_call_capture("_bridge_resolve_ssh_agent_sock")` | `resolve_ssh_agent_sock()` from `_helpers` |
| ~1002 | `_shell_call_capture("_bridge_has_opencode_key")` | `"1" if api_keys.has_opencode_key() else ""` |
| ~1309 | `_shell_call_capture("_bridge_generate_sandbox_id", seed)` | `generate_sandbox_id(seed)` from `_helpers` |

### Validation calls (return `(bool, msg)` tuples):

| Line | Bridge call | Replacement |
|------|------------|-------------|
| ~914 | `_shell_call("_bridge_validate_git_url", repo_url)` | `ok, msg = validate_git_url(repo_url); if not ok: log_error(msg); sys.exit(1)` |
| ~920 | `_shell_call("_bridge_check_claude_key_required")` | `ok, msg = api_keys.check_claude_key_required(); ...` |
| ~939 | `_shell_call("_bridge_check_docker_network_capacity", ...)` | `ok, msg = check_docker_network_capacity(...); ...` |
| ~992 | `_shell_call("_bridge_validate_mount_path", src)` | `ok, msg = validate_mount_path(src); ...` |
| ~1294 | `_shell_call("_bridge_validate_git_remotes", ...)` | `ok, msg = validate_git_remotes(...); ...` |

### Side-effecting calls (direct module function calls):

| Line | Bridge call | Replacement |
|------|------------|-------------|
| ~1226 | `_shell_call("_bridge_add_network_to_override", ...)` | `add_network_to_override(network_mode, str(override_file))` |
| ~1235 | `_shell_call("_bridge_prepopulate_foundry_global", ...)` | `foundry_plugin.prepopulate_foundry_global(str(claude_home_path))` |
| ~1238 | `_shell_call("_bridge_show_cli_status")` | `api_keys.show_cli_status()` |
| ~1271 | `_shell_call("_bridge_export_gh_token")` | `token = api_keys.export_gh_token(); if token: os.environ["GITHUB_TOKEN"] = token; os.environ["GH_TOKEN"] = token` |
| ~1337 | `_shell_call("_bridge_fix_proxy_worktree_paths", ...)` | `fix_proxy_worktree_paths(proxy_container, username)` |
| ~1340-1345 | inline repo_spec stripping | `strip_github_url(repo_url)` from `_helpers` |
| ~1358 | `_shell_call("_bridge_compose_down", ...)` | `compose_down(...)` (wrap in try/except) |
| ~1365-1375 | `_shell_call("_bridge_copy_configs_to_container", ...)` | `credential_setup.copy_configs_to_container(container_id, ...)` |
| ~1391 | `_shell_call("_bridge_copy_dir_to_container", ...)` | `container_io.copy_dir_to_container(container_id, src, dst)` |
| ~1393 | `_shell_call("_bridge_copy_file_to_container", ...)` | `container_io.copy_file_to_container(container_id, src, dst)` |
| ~1400 | `_shell_call("_bridge_install_pip_requirements", ...)` | `container_setup.install_pip_requirements(container_id, pip_requirements)` |
| ~1402-1413 | inline network restrictions | `apply_network_restrictions(container_id, network_mode)` from `_helpers` |
| ~1154 | `_shell_call("_bridge_tmux_attach", name, wd or "")` | `tmux.attach(name, wd or "")` — needs paths derivation |

### Cleanup after migration:

- Remove `_repo_to_path`, `_sandbox_name`, `_find_next_sandbox_name`, `_container_name` wrapper functions (lines ~323-341)
- Remove `_shell_call`/`_shell_call_capture` imports if no longer needed
- Update imports at top of file to add: `api_keys`, `container_io`, `container_setup`, `credential_setup`, `foundry_plugin`, `validate` modules

---

## Improvement 7: Add environment save/restore to `new.py`

**File:** `foundry_sandbox/commands/new.py`

Before the env mutations at line ~1013 (`os.environ["SANDBOX_ENABLE_OPENCODE"] = ...`), save the environment and wrap in try/finally:

```python
_saved_env = dict(os.environ)
try:
    os.environ["SANDBOX_ENABLE_OPENCODE"] = enable_opencode_flag
    # ... rest of new() body through the end ...
finally:
    os.environ.clear()
    os.environ.update(_saved_env)
```

This matches `start.py`'s existing pattern at lines 210/470-472.

---

## Improvement 6: Ensure `_new_setup` failures trigger rollback

**File:** `foundry_sandbox/commands/new.py`

**6a.** Define `class _SetupError(Exception): pass` near the top of the file.

**6b.** Replace the 3 `sys.exit(1)` calls inside `_new_setup()` with `raise _SetupError(...)`:
- validate_git_remotes failure (~line 1296-1297)
- generate_sandbox_id failure (~line 1310-1312)
- proxy registration failure (~lines 1357-1362) — remove the inline compose_down since rollback handles it

**6c.** Update the exception handler in `new()` (~lines 1051-1059):
```python
except _SetupError as exc:
    log_error(str(exc))
    log_info("Cleaning up partial sandbox resources...")
    _rollback_new(worktree_path, claude_config_path, container, override_file)
    sys.exit(1)
except SystemExit:
    raise
except Exception as exc:
    log_error(f"Sandbox creation failed: {exc}")
    log_info("Cleaning up partial sandbox resources...")
    _rollback_new(worktree_path, claude_config_path, container, override_file)
    sys.exit(1)
```

---

## Implementation Order

1. **Improvement 5** — new.py bridge migration (largest change)
2. **Improvement 7** — new.py env save/restore (small, do right after 5)
3. **Improvement 6** — new.py rollback fix (small, touches same area as 5)

## Verification

After all changes:

```bash
python -m pytest tests/unit/ -x -q
python -m pytest tests/security/test_fuzzing.py -x -q
python -m pytest tests/unit/test_import_layering.py -x -q
python -c "from foundry_sandbox.cli import main"
python -m foundry_sandbox.cli --help
python -m pytest tests/unit/test_bridge_contract.py -x -q
```
