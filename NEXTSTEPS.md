# Next Steps: Address Review Findings

## Completed

### 1. Split `commands/new.py` into modules
- Created `foundry_sandbox/commands/new_wizard.py` — TUI wizard functions
- Created `foundry_sandbox/commands/new_setup.py` — `_SetupError`, `_rollback_new()`, `_new_setup()`
- Trimmed `new.py` imports, kept `NewDefaults`, `_apply_saved_new_defaults`, `_resolve_repo_input`, `_get_local_branches`, `_generate_branch_name`, and the `new()` Click command
- Fixed circular import with lazy imports in `new_wizard.py`
- All 4 existing tests pass (`tests/unit/test_new_command.py`)
- Also applied item 3's `log_debug` fix for `_generate_branch_name` (line 326-327) during the split

### 2. Add subprocess timeouts to `tmux.py`
- Added `timeout=TIMEOUT_LOCAL_CMD` to all 4 `subprocess.run` calls
- Updated import to include `TIMEOUT_LOCAL_CMD`

### 3. Replace silent `except Exception: pass` with logging
- `commands/_helpers.py`: Added `log_debug("fzf selection failed, falling back")` + import
- `commands/list_cmd.py`: Added `log_debug("Failed to query container status")` and `log_debug("Failed to check tmux session")` + import
- `git_path_fixer.py`: Simplified `except (subprocess.SubprocessError, Exception):` to `except Exception:` + added `log_debug("Failed to detect nested git repos")` + import

### 4. Add chmod mode validation in `container_io.py`
- Added `re.fullmatch(r"[0-7]{3,4}", mode)` validation in `_post_copy_chmod()`
- Added `import re`

### 5. Consolidate YAML strip functions in `network.py`
- Created generic `_strip_yaml_blocks(override_file, block_filters)` helper
- Rewrote `strip_network_config`, `strip_ssh_agent_config`, `strip_claude_home_config`, `strip_timezone_config` as thin wrappers
- All 61 network tests pass

### 6. Rename parity test file
- Renamed `test_git_migration_parity.py` → `test_git_security_invariants.py`
- Updated module docstring to remove "migration parity" language
- All 131 security invariant tests pass

### 7. Increase fuzzing iterations
- Changed all 21 occurrences of `max_examples=50` → `max_examples=200` in `test_fuzzing.py`

## Verification (all passed)
```
python -m pytest tests/unit/ -x -q                                        # 1222 passed
python -m pytest tests/security/test_git_security_invariants.py -x -q      # 131 passed
python -m pytest tests/security/test_fuzzing.py::TestSandboxNameFuzzing -x -q  # 3 passed
python -c "from foundry_sandbox.commands.new import new, NewDefaults, _apply_saved_new_defaults"  # OK
```
