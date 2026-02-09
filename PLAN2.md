# PLAN 2: Python Rewrite & Integration Test Suite

## Context

The foundry-sandbox orchestration layer is ~295KB of shell across 24 library modules (~6,400 lines) and 16 command handlers (~2,500 lines) — 8,901 lines total. The largest file (`container_config.sh`) is 86KB / 2,370 lines. Shell is fragile for this complexity level — hard to test, hard to refactor, and error-prone for security-critical code. Meanwhile, the test suite has strong unit/integration coverage for the unified-proxy (Python) but almost no automated testing for the shell orchestration layer.

This plan proposes an incremental rewrite strategy and a comprehensive test suite expansion.

### Why Rewrite (Not Just Test the Shell)

Item 6 (test suite) addresses the coverage gap independently of the rewrite. But testing alone doesn't fix the root problems that motivate the rewrite:

- **Security-critical string manipulation in bash.** Git policy enforcement, credential placeholder injection, and path validation all rely on bash string operations (`sed`, parameter expansion, regex matching) that are easy to get subtly wrong. The git policy hardening commit (`8141d29`) introduced multiple bugs — addon validation failures, missing `.git` shadow checks, broken worktree paths — that would have been caught by type checking and unit tests in Python but passed silently in shell.
- **86KB monolith can't be refactored.** `container_config.sh` handles user setup, foundry plugin installation, stub management, git path fixing, and credential injection in one file. Shell has no module system, no classes, no interfaces — splitting this requires copying functions between files and manually managing global state. In Python it becomes 7 focused modules with clear APIs.
- **No testability without subprocess.** Shell functions can only be tested by sourcing the entire library and running commands. Mocking is fragile (`function docker() { ... }`). Python modules can be imported, individual functions called, dependencies injected.
- **Existing Python proves the pattern.** `lib/python/` already contains 4 utility modules (471 lines) extracted from shell because the operations were too complex for bash. The rewrite extends this proven pattern to the rest of the orchestration layer.

### Non-Goals

This plan explicitly does **not** attempt to:

- **Change the unified-proxy.** The mitmproxy-based proxy, its addons, and its test suite are out of scope. They are already Python with strong test coverage.
- **Change the Docker image.** The sandbox container image (`Dockerfile`, base image selection, installed packages) is unchanged by this rewrite.
- **Add new features.** The Python rewrite targets strict behavioral parity with the shell version. No new commands, flags, or capabilities are introduced. Feature work happens after migration completes.
- **Change the security model.** Credential isolation, branch isolation, git safety policies, and network egress controls are preserved exactly. The proxy enforces security policy; the orchestration layer configures it.
- **Rewrite the TUI.** The interactive wizard in `commands/new.sh` (branch selection, sparse checkout configuration, etc.) is migrated to Python but not redesigned. Same prompts, same flow, same defaults.
- **Support Windows.** The tool targets Linux and macOS. WSL is incidentally supported but not tested.

---

## Item 5: Rewrite Shell Orchestration in Python

### Current Architecture

```
sandbox.sh (72 lines) — CLI dispatcher (case statement → sources commands/$cmd.sh, calls cmd_$cmd)
  ├── sources 24 lib/*.sh modules (6,366 lines / ~204KB)
  └── routes to commands/*.sh (16 handlers, 2,535 lines / ~91KB)
```

**Largest modules:**
| Module | Lines | Bytes | Responsibility |
|--------|-------|-------|---------------|
| `lib/container_config.sh` | 2,370 | 86KB | Container setup, foundry plugin, stubs, git path fixes |
| `lib/state.sh` | 891 | 27KB | Metadata persistence, sandbox listing, inspection |
| `commands/new.sh` | 1,343 | 49KB | Sandbox creation |
| `lib/proxy.sh` | 420 | 14KB | Proxy registration, health checks |
| `lib/network.sh` | 409 | 11KB | Network isolation modes |
| `lib/api_keys.sh` | 323 | 10KB | API key validation |
| `lib/args.sh` | 281 | — | CLI argument parsing |
| `lib/validate.sh` | 252 | 8KB | Input validation |
| `lib/docker.sh` | 237 | 8KB | Docker operations |
| `lib/utils.sh` | 220 | — | Logging, formatting |

**Existing Python in project:** 4 utility modules in `lib/python/` (471 lines) already extracted from shell (JSON config, Claude settings, OpenCode sync). These are absorbed into the new `foundry_sandbox/` package during Phase 1 (see [lib/python/ Migration](#libpython-migration)).

### Strategy: Incremental Rewrite (Not Big Bang)

A full rewrite is too risky and too large for one effort. Instead, rewrite module-by-module using a **strangler fig** pattern:

1. Establish the Python package, toolchain, and test harness first
2. Migrate one module at a time, starting with the most valuable targets
3. Keep each migrated module independently testable with clear seams
4. Introduce the Python CLI entrypoint in Phase 4 while shell and Python coexist

### Prerequisites

The rewrite introduces a Python package dependency for `sandbox.sh` users. The impact is phased:

- **Phase 1:** No impact. Python modules exist but shell doesn't call them. Users don't need to install anything.
- **Phases 2-3:** Shell wrappers begin calling Python for specific operations (validation, Docker, git). Users must have `python3 >= 3.10` on PATH and run `pip install -e .` (or `pip install -e ".[dev]"` for contributors). If the package is not installed, affected operations fail with a clear error message (see dependency guard below) — unmigrated shell-only codepaths continue to work.
- **Phases 4-5:** The Python CLI becomes the primary entrypoint. `pip install -e .` is required for all users.

**Assumption:** Target users are developers running Docker on Linux or macOS with Python 3.10+ available. macOS users typically have Python via Homebrew or pyenv; Ubuntu 22.04+ ships 3.10. This is the same audience that already runs `docker`, `docker-compose`, `git`, and `jq`.

**Migration tax:** The `pip install` requirement is documented in `docs/getting-started.md` starting in Phase 2, with a version-gated error message in `sandbox.sh` that fires only when a shell→Python bridge call is attempted.

### Transition Mechanics

The cutover follows a **Python-outer, shell-inner** pattern:

**Phase 1:** `sandbox.sh` remains the entrypoint. No user-facing change. Python modules (`state`, `paths`, etc.) are called from shell via `python3 -m foundry_sandbox.<module>` where needed, but primarily exist to be tested and to establish the package structure.

**Phases 2-3:** Shell commands begin importing Python modules for validation, Docker calls, and git operations. Each migrated function gets a thin shell wrapper that calls the Python module (see [Shell↔Python Bridge Protocol](#cross-cutting-shellpython-bridge-protocol)). This lets individual functions migrate without rewriting the whole command handler.

**Phase 4:** A new Python CLI entrypoint (`python3 -m foundry_sandbox.cli`) is introduced alongside `sandbox.sh`. Both work. Each command handler is migrated one at a time: `foundry_sandbox/commands/list_cmd.py` replaces `commands/list.sh`, etc. The Python CLI dispatches to Python for migrated commands and shells out to `sandbox.sh <cmd>` for unmigrated ones. This is the only phase where two entrypoints coexist.

**Phase 5:** After all commands are migrated, `sandbox.sh` becomes a thin wrapper that exec's the Python CLI (`exec python3 -m foundry_sandbox.cli "$@"`). This preserves backward compatibility for existing scripts/docs that reference `sandbox.sh`.

**Dependency guard:** Starting in Phase 1, shell callsites that delegate to Python verify the package and `jq` availability first:

```bash
require_python_module() {
    if ! python3 -c "import $1" 2>/dev/null; then
        echo "Error: Python module '$1' not installed. Run: pip install -e ." >&2
        return 1
    fi
}

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "Error: 'jq' is required but not found. Install it via your package manager." >&2
        return 1
    fi
}

# Example: bridge call with envelope parsing and crash handling
validate_sandbox_name() {
    require_python_module foundry_sandbox || return 1
    require_jq || return 1
    local _response _rc
    _response=$(python3 -m foundry_sandbox.validate validate_sandbox_name "$1" 2>/dev/null)
    _rc=$?
    # Exit code >=2 means Python crashed (no JSON on stdout)
    if [ "$_rc" -ge 2 ]; then
        log_error "Python bridge crashed (exit $_rc). Re-run with SANDBOX_DEBUG=1 for details."
        return 1
    fi
    # Exit code 0 or 1: parse the JSON envelope
    if [ -z "$_response" ]; then
        log_error "Python bridge produced no output (exit $_rc)."
        return 1
    fi
    echo "$_response" | jq -e '.ok' >/dev/null || { echo "$_response" | jq -r '.error.message' >&2; return 1; }
}
```

This fires only when shell code actually calls a Python module (not on every invocation). During Phase 1, most shell paths don't touch Python at all, so users who haven't installed the package can still use unmigrated shell-only codepaths.

**`jq` dependency:** `jq` is already used in `tests/run.sh` and various command handlers, but it is not formally declared as a prerequisite. The `require_jq` guard makes this dependency explicit and fails with a clear message rather than producing garbled output. An alternative (parsing envelopes with `python3 -c "import json; ..."`) was considered but rejected — if Python itself is broken, the envelope parser shouldn't depend on it.

**Rollback:** At any point, reverting to shell is a `git revert` — shell code is not deleted until the Python replacement passes all tests. If migration stalls mid-phase, the project is still functional: shell commands work, Python modules are additive. There is no point of no return until Phase 5 removes shell command handlers.

### Cross-Cutting: Logging

The current shell logging uses `log_info`, `log_warn`, `log_error`, `log_debug`, `log_section`, and `log_step` from `lib/utils.sh`. The Python replacement must match this output format during the transition so mixed shell+Python output is coherent.

Approach:
- `foundry_sandbox/utils.py` implements a `logging.Formatter` that matches the existing shell format (arrows, indentation, color codes via `$TERM`)
- Python modules use stdlib `logging` internally
- During the transition (Phases 2-3), Python functions called from shell inherit the shell's stderr, so output interleaves naturally
- After full migration (Phase 5), the Python logger owns all output

### Cross-Cutting: Shell↔Python Bridge Protocol

During Phases 2-3, shell functions delegate to Python modules via subprocess. Without a defined protocol, each developer invents their own bridge and consistency breaks. All shell↔Python calls follow this contract:

**Invocation:** Shell calls Python via `python3 -m foundry_sandbox.<module> <function> [args...]`. Each module that exposes shell-callable functions has an `if __name__ == "__main__"` dispatcher that produces the envelope format defined below:

```python
# foundry_sandbox/validate.py
import json
import os
import sys
import traceback

def validate_sandbox_name(name: str) -> bool:
    ...

def validate_repo_url(url: str) -> bool:
    ...

def _bridge_main() -> None:
    dispatch = {
        "validate_sandbox_name": lambda args: validate_sandbox_name(args[0]),
        "validate_repo_url": lambda args: validate_repo_url(args[0]),
    }
    func = dispatch.get(sys.argv[1])
    if not func:
        print(json.dumps({"ok": False, "result": None,
              "error": {"code": "unknown_function", "message": f"Unknown function: {sys.argv[1]}"}}))
        sys.exit(1)
    try:
        result = func(sys.argv[2:])
        print(json.dumps({"ok": True, "result": result, "error": None}))
    except (ValueError, RuntimeError) as e:
        print(json.dumps({"ok": False, "result": None,
              "error": {"code": type(e).__name__, "message": str(e)}}))
        if os.environ.get("SANDBOX_DEBUG") == "1":
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    _bridge_main()
```

**I/O contract (single format for all bridge calls):**
- Python writes exactly one JSON object to stdout on both success and failure:
  `{"ok": true|false, "result": ..., "error": {"code": "...", "message": "..."}}`
- Shell checks `ok` first; only reads `result` when `ok=true`
- Exit codes are standardized: `0` success (`ok=true`), `1` expected/handled failure (`ok=false`), `>=2` unexpected runtime failure (no JSON on stdout — shell must handle missing output)
- Tracebacks are suppressed by default and only emitted to stderr when `SANDBOX_DEBUG=1`

This avoids mixed ad hoc patterns (raw strings, exit-code-only, per-call jq parsing) and gives one deterministic parse path.

**Shell wrapper pattern (hardened):**

```bash
# Shared helper for all bridge calls — handles crashes, empty output, and envelope parsing.
_bridge_call() {
    local _module="$1" _func="$2"; shift 2
    require_python_module foundry_sandbox || return 1
    require_jq || return 1
    local _response _rc
    _response=$(python3 -m "foundry_sandbox.${_module}" "$_func" "$@" 2>/dev/null)
    _rc=$?
    if [ "$_rc" -ge 2 ]; then
        log_error "Python bridge crashed (exit $_rc). Re-run with SANDBOX_DEBUG=1 for details."
        return 1
    fi
    if [ -z "$_response" ]; then
        log_error "Python bridge produced no output (exit $_rc)."
        return 1
    fi
    echo "$_response" | jq -e '.ok' >/dev/null || { echo "$_response" | jq -r '.error.message' >&2; return 1; }
    # On success, caller can extract .result from $_response
    BRIDGE_RESULT="$_response"
}

# Example usage:
validate_sandbox_name() {
    _bridge_call validate validate_sandbox_name "$1"
}
```

**Bridge contract test:** A parametrized test (`tests/unit/test_bridge_contract.py`) validates that every bridge-exposed function produces the `{"ok": ..., "result": ..., "error": ...}` envelope on both success and failure paths. This test is added in Phase 1 alongside the first bridge-exposed module.

This pattern is used during transition only. Once a full command handler is migrated to Python (Phase 4), the dispatcher and shell wrappers for its functions are removed.

### Cross-Cutting: Import Latency and Performance

Click and Pydantic are justified for the CLI and metadata models respectively, but both add import overhead (~100-200ms combined). During Phases 2-3, bridge calls from shell pay this cost on every subprocess invocation.

Mitigations:
- **Lazy imports for bridge modules.** Modules callable from shell (`validate.py`, `paths.py`, `api_keys.py`) must not import Click or Pydantic at module level. Use local imports inside functions that need them, or confine heavy dependencies to `cli.py` and `models.py`.
- **Performance gate (Global Gate).** No CLI command's cold-start latency may exceed 500ms on the CI runner (measured as `time python3 -m foundry_sandbox.cli <cmd> --help`). Bridge calls (`python3 -m foundry_sandbox.<module> <func>`) must complete in under 300ms excluding the work itself. A `tests/unit/test_import_latency.py` test enforces this from Phase 1.

### Cross-Cutting: Type Checking

A primary motivation for the rewrite is catching bugs that shell can't detect. To deliver on this, static type checking is enforced from Phase 1:

- All Python code uses type annotations (parameters, returns, class attributes)
- `mypy --strict` runs in CI alongside tests
- `ruff` enforces consistent formatting and catches common errors
- Both are in dev dependencies and configured in `pyproject.toml`

### Cross-Cutting: Dual-Implementation Policy

During Phases 2-4, shell and Python implementations coexist. Without a clear ownership rule, contributors fixing a bug in (say) `validate.sh` must also fix `validate.py`, and drift becomes inevitable. The policy:

1. **Once a Python replacement passes all tests and the shell wrapper delegates to it, delete the shell implementation.** Keep the shell *wrapper* (the thin function that calls `_bridge_call`), but remove the shell *logic*. This makes ownership unambiguous: the Python module is authoritative.

2. **The shell wrapper is a forwarding stub, not a fallback.** If the Python module fails, the wrapper fails — it does not silently fall back to a deleted shell implementation. This ensures failures are visible, not masked.

3. **Bug fixes go to the authoritative implementation only.** If `validate.py` is authoritative, fix bugs there. If `validate.sh` hasn't been migrated yet, fix bugs there. Never fix the same bug in both places.

4. **Shell deletion happens in the same PR as Python integration.** This prevents a window where both implementations exist and can drift. The PR's test suite validates the Python version before the shell logic is removed.

Exception: during Phase 4, when command handlers are being migrated one at a time, the Python CLI falls back to `sandbox.sh` for unmigrated commands. This is the only case where both implementations are intentionally active, and the fallback is explicit (the Python CLI shells out to `sandbox.sh <cmd>`), not implicit.

### Phase 1: Foundation (State + Paths + Package Scaffold)

Create the Python package skeleton and migrate the simplest, most testable modules first. This phase establishes the package structure, build tooling, type checking, and bridge protocol — but does **not** introduce the CLI entrypoint (that's Phase 4, when command handlers are ready to migrate).

**New files:**
```
foundry_sandbox/
├── __init__.py
├── _bridge.py          # Shared bridge dispatcher (used by __main__ blocks)
├── state.py            # Sandbox metadata (replaces lib/state.sh)
├── paths.py            # Path resolution (replaces lib/paths.sh)
├── constants.py        # Configuration defaults (replaces lib/constants.sh)
├── models.py           # Pydantic models for sandbox metadata
└── utils.py            # Logging, formatting (replaces lib/utils.sh, format.sh)
```

**Why start here:**
- `state.sh` (27KB) is pure data management — reads/writes JSON metadata, no Docker calls
- `paths.sh` (1.4KB) is trivial path computation (`path_worktree`, `path_metadata_file`, `derive_sandbox_paths`, etc.)
- These have zero external dependencies beyond filesystem
- Easy to test, easy to validate correctness against shell version
- Forms the foundation other modules depend on

**Why not `cli.py` yet:** The Click-based CLI is only useful once command handlers exist to dispatch to (Phase 4). Including it in Phase 1 adds import weight, creates a second entrypoint before it can do anything, and inflates the phase scope. `_bridge.py` provides the shared `if __name__ == "__main__"` dispatcher pattern that bridge calls need in the interim.

**Key design decisions:**
- Use Click for CLI (Phase 4, widely adopted, composable, testable)
- Use Pydantic for metadata models (validation, serialization) — but **not imported by bridge-callable modules** at module level (see [Import Latency](#cross-cutting-import-latency-and-performance))
- Use `subprocess` for Docker/git calls initially (see [Docker API Strategy](#docker-api-strategy))
- Match existing CLI interface exactly (same subcommands, aliases, flags, defaults, help text shape, exit codes)
- Minimum Python version: 3.10 (so shell→Python callsites work on common Linux/macOS hosts)
- Target runtime in managed sandbox containers/CI: 3.12
- CI tests both 3.10 and 3.12 to catch accidental use of 3.11+ features (see CI matrix below)

**`pyproject.toml` structure:**
```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "foundry-sandbox"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "click>=8.1",
    "pydantic>=2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "pytest-timeout>=2.3",
    "hypothesis>=6.100",
    "mypy>=1.10",
    "ruff>=0.5",
]
test-orchestration = [
    # Orchestration/lifecycle tests — no heavy proxy deps
    "pyyaml>=6.0",
]
test-proxy = [
    # Proxy unit/integration tests — needs Flask, mitmproxy, etc.
    "flask==3.0.0",
    "Werkzeug==3.0.1",
    "gunicorn==21.2.0",
    "requests==2.31.0",
    "httpx>=0.25.0",
    "python-dotenv==1.0.0",
    "mitmproxy>=10.0.0",
    "pyyaml>=6.0",
]

[project.scripts]
sandbox = "foundry_sandbox.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
timeout = 120

[tool.mypy]
strict = true
python_version = "3.10"
packages = ["foundry_sandbox"]

[tool.ruff]
target-version = "py310"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "N", "UP", "B", "SIM", "RUF"]
```

Installed in development via `pip install -e ".[dev,test-orchestration]"` (or `".[dev,test-proxy]"` for proxy tests, or `".[dev,test-orchestration,test-proxy]"` for everything).

#### lib/python/ Migration

The 4 existing modules in `lib/python/` (471 lines) are absorbed into `foundry_sandbox/` during Phase 1:

| Current | Destination | Notes |
|---------|-------------|-------|
| `lib/python/json_config.py` | `foundry_sandbox/config.py` | Merged into config/constants |
| `lib/python/merge_claude_settings.py` | `foundry_sandbox/claude_settings.py` | Standalone module |
| `lib/python/ensure_claude_foundry_mcp.py` | `foundry_sandbox/foundry_plugin.py` (Phase 5) | Moves later with container config |
| `lib/python/sync_opencode_foundry.py` | `foundry_sandbox/opencode_sync.py` | Standalone module |

Shell callsites (`python3 lib/python/...`) are updated to use `python3 -m foundry_sandbox.<module>` or direct imports as the surrounding shell is migrated.

### Phase 2: Docker + Validation

**Migrate:**
```
foundry_sandbox/
├── docker.py           # Docker operations (replaces lib/docker.sh)
├── validate.py         # Input validation (replaces lib/validate.sh)
└── api_keys.py         # API key validation (replaces lib/api_keys.sh)
```

**Why next:**
- `docker.sh` (8KB) wraps `docker` and `docker-compose` CLI calls — straightforward to port
- `validate.sh` (8KB) is pure validation logic — highly testable
- `api_keys.sh` (10KB) is environment variable checking — no side effects

#### Docker API Strategy

Phase 2 uses `subprocess` for Docker/compose calls — this matches the current shell behavior and avoids introducing a new dependency. However, parsing `docker inspect` JSON output and `docker-compose` text output in Python is fragile.

Plan: after Phase 4 stabilizes, evaluate replacing `subprocess` calls with the `docker` Python SDK (`docker-py`) for operations that return structured data (inspect, list, network queries). Keep `subprocess` for `docker-compose` since the SDK doesn't cover compose. This is a Phase 5+ optimization, not a blocker.

### Phase 3: Git + Network

**Migrate:**
```
foundry_sandbox/
├── git.py              # Git operations (replaces lib/git.sh)
├── git_worktree.py     # Worktree management (replaces lib/git_worktree.sh)
└── network.py          # Network isolation (replaces lib/network.sh)
```

### Phase 4: CLI Entrypoint + Commands

Introduce the Click-based CLI entrypoint (`foundry_sandbox/cli.py`) and migrate command handlers one at a time. This is the phase where two entrypoints coexist.

**New files:**
```
foundry_sandbox/
├── cli.py              # Click-based CLI (replaces sandbox.sh dispatcher)
```

**Migrate command handlers one at a time:**
```
foundry_sandbox/commands/
├── __init__.py
├── list_cmd.py         # Simplest command (28 lines of shell)
├── info.py             # System info (24 lines)
├── build.py            # Build images (17 lines)
├── stop.py             # Stop container (24 lines)
├── status.py           # Status checks (89 lines)
├── help_cmd.py         # Usage help (60 lines)
├── config.py           # Configuration management (70 lines)
├── preset.py           # Preset management (51 lines)
├── destroy.py          # Cleanup (82 lines)
├── refresh_creds.py    # Credential refresh (94 lines)
├── destroy_all.py      # Bulk cleanup (106 lines)
├── attach.py           # Tmux attach (123 lines)
├── prune.py            # Prune stale resources (178 lines)
├── start.py            # Start container (203 lines)
├── upgrade.py          # Upgrade sandbox (43 lines)
└── new.py              # Create sandbox (1,343 lines — LAST, largest)
```

**Order:** simplest → most complex. `new.sh` (1,343 lines) is migrated last after all its dependencies are in Python.

#### `new.py` Decomposition

`new.sh` is the largest and highest-risk command handler. Migrating it as a single 1,343-line file would be a lateral move. The decomposition:

| Section | Shell Lines | Python Target | Responsibility |
|---------|-------------|---------------|----------------|
| TUI helpers | ~270 | `foundry_sandbox/tui.py` | `tui_input`, `tui_question`, `tui_confirm`, `tui_choose` — reusable interactive prompts (Click's `prompt`/`confirm` where possible, custom for `gum`-backed choosers) |
| Input resolution | ~60 | `foundry_sandbox/commands/new.py` (top) | `resolve_repo_input`, `get_local_branches`, relative-path expansion |
| Wizard flows | ~400 | `foundry_sandbox/commands/new.py` (middle) | `wizard_repo`, `wizard_branch`, `wizard_working_dir`, `wizard_sparse`, `wizard_network`, `wizard_preset` — sequential multi-page prompts |
| Sandbox creation | ~350 | `foundry_sandbox/commands/new.py` (bottom) | Orchestrates: validate inputs → create worktree → generate compose → start containers → copy configs |
| Sparse checkout | ~150 | `foundry_sandbox/git_worktree.py` (extension) | Sparse-checkout cone patterns, `.git/info/sparse-checkout` management |
| Compose generation | ~113 | `foundry_sandbox/compose.py` (new) | Docker Compose YAML assembly from sandbox config — already partially in `container_config.sh` |

**Highest-risk operations in `new.py`:**
1. **Credential placeholder injection** (calls into `credential_setup.py` from Phase 5) — must never leak real credentials into the sandbox. Tested by `test_credential_isolation.py`.
2. **Worktree creation and branch checkout** — wrong branch = wrong code in sandbox. Tested by `test_git_worktree.py`.
3. **Docker Compose generation** — wrong network mode = broken credential isolation. Tested by `test_network_modes.py`.
4. **Sparse checkout configuration** — wrong cone patterns = missing or excess files in workspace.

Each of these has a dedicated test file that runs against both entrypoints, so behavioral divergence is caught before merge.

### Phase 5: Container Config (The 86KB Monster)

`container_config.sh` is the last and largest migration target (34 functions, 2,370 lines). By this point, all its dependencies are already in Python. Break it into focused modules based on the actual function groupings:

```
foundry_sandbox/
├── container_setup.py       # User setup, directory creation
├── foundry_plugin.py        # Foundry MCP installation and configuration
├── stub_manager.py          # Proxy stub file management, branch context
├── git_path_fixer.py        # Worktree path translation, nested repo detection
├── container_io.py          # Shared copy/tar/exec primitives for container file ops
├── credential_setup.py      # Credential placeholder injection and orchestration
└── tool_configs.py          # Tool-specific configs (OpenCode, Codex, Gemini, gh)
```

#### Function-to-Module Mapping

**`container_setup.py`** (user + environment preparation):
- `ensure_container_user` — verify container user exists
- `install_pip_requirements` — install Python packages from requirements.txt
- `block_pypi_after_install` — iptables DROP rules for PyPI post-install
- `ssh_agent_preflight` — validate SSH agent forwarding

**`foundry_plugin.py`** (foundry MCP lifecycle):
- `prepopulate_foundry_global` — clone/update foundry plugin repo
- `ensure_claude_foundry_mcp` — configure Claude with foundry defaults and permissions
- `ensure_foundry_mcp_config` — register foundry-mcp MCP server
- `ensure_foundry_mcp_workspace_dirs` — create foundry-mcp workspace directories
- `configure_foundry_research_providers` — set deep_research_providers
- `sync_marketplace_manifests` — register marketplace, synthesize manifests

**`stub_manager.py`** (workspace documentation):
- `install_foundry_workspace_docs` — copy CLAUDE.md and AGENTS.md stubs
- `inject_sandbox_branch_context` — inject branch info into CLAUDE.md

**`git_path_fixer.py`** (worktree/proxy path fixes):
- `fix_proxy_worktree_paths` — symlinks and git config for proxy container
- `fix_worktree_paths` — fix .git gitdir refs for username mismatches
- `detect_nested_git_repos` — warn about nested .git shadowing sparse worktree

**`credential_setup.py`** (config and credential orchestration):
- `copy_configs_to_container` — master orchestrator (calls 20+ other functions in sequence)
- `sync_runtime_credentials` — idempotent runtime credential sync
- `merge_claude_settings` — merge host/container settings preserving hooks

**`container_io.py`** (shared container I/O primitives):
- `copy_file_to_container` / `copy_dir_to_container` — low-level tar-pipe utilities
- `copy_file_to_container_quiet` / `copy_dir_to_container_quiet` — stderr-suppressing wrappers
- `docker_exec_json` / `docker_exec_text` — standardized subprocess wrappers for container exec

**`tool_configs.py`** (tool-specific configuration):
- `ensure_claude_onboarding` — skip Claude onboarding
- `ensure_claude_statusline` — configure statusline
- `ensure_github_https_git` — force HTTPS for GitHub git remotes
- `configure_gh_credential_helper` — set gh as git credential helper
- `ensure_codex_config` — Codex defaults
- `ensure_gemini_settings` — Gemini defaults
- `ensure_opencode_settings` — OpenCode defaults
- `ensure_opencode_default_model` — OpenCode model config
- `ensure_opencode_tavily_mcp` — Tavily MCP for OpenCode
- `sync_opencode_foundry` — sync opencode-foundry skills
- `prefetch_opencode_npm_plugins` — pre-download npm plugins
- `sync_opencode_local_plugins_on_first_attach` — sync local plugins

#### Dependency Graph

```
credential_setup.py (orchestrator)
  ├── container_setup.py    (ensure_container_user, ssh_agent_preflight)
  ├── foundry_plugin.py     (ensure_claude_foundry_mcp, ensure_foundry_mcp_config, ...)
  ├── stub_manager.py       (install_foundry_workspace_docs, inject_sandbox_branch_context)
  ├── git_path_fixer.py     (fix_worktree_paths, detect_nested_git_repos)
  ├── tool_configs.py       (all ensure_* and sync_* for individual tools)
  └── container_io.py       (copy/exec primitives)

foundry_plugin.py
  └── container_io.py       (docker exec helper)

tool_configs.py
  └── container_io.py       (copy helpers)
```

The key insight is that `copy_configs_to_container` and `sync_runtime_credentials` are the two orchestrators — they call everything else in sequence. In Python, these become methods on a `ContainerConfigurator` class that takes the module dependencies via constructor injection, making the call graph explicit and testable. `container_io.py` exists specifically to keep the graph acyclic.

### Estimated Scope Per Phase

| Phase | Modules | Shell Lines | Python Lines (est.) | Effort | Notes |
|-------|---------|-------------|---------------------|--------|-------|
| 0: Test Suite | orchestration + security tests | — | ~800 | M | Prerequisite: builds safety net before rewrite begins |
| 1: Foundation | state, paths, constants, utils, format, json, fs, prompt | ~1,240 | ~600 | M | Pure data — compresses well; `cli.py` deferred to Phase 4 |
| 2: Docker + Validation | docker, validate, api_keys, args | ~1,090 | ~550 | S | Validation + subprocess wrappers |
| 3: Git + Network | git, git_worktree, network, proxy | ~1,070 | ~550 | M | Git logic is complex, security-critical |
| 4: CLI + Commands | cli.py + all 16 command handlers + tui.py + compose.py | ~2,540 | ~1,900 | XL | Includes Click CLI, TUI migration, `new.py` decomposition |
| 5: Container Config | container_config (split into 7 modules) | ~2,370 | ~1,100 | L | Large but splits into focused modules |
| — | Remaining small modules (ide, permissions, inspect, tmux, image, host_config, runtime) | ~590 | ~300 | S | `host_config.sh` is an empty stub (6 lines); `runtime.sh` (15 lines) has 2 verbose-mode wrappers absorbed into `utils.py` |

**Effort key:** S = days, M = 1-2 weeks, L = 2-4 weeks, XL = 4-8 weeks. Total estimated effort: **3-5 months of focused work.** This matters for prioritization — if other work takes precedence, the strangler fig pattern means any phase can pause without breaking the project.

Total: ~8,900 shell lines → ~5,800 Python lines (including ~800 lines of new tests in Phase 0). The ~1.5:1 shell-to-Python ratio for the rewrite itself (~8,900 → ~5,000) is less dramatic than typical shell→Python rewrites. This is expected: command handlers include orchestration logic that doesn't simplify, and Python adds explicit error handling, type annotations, Pydantic models, and Click decorators where shell relied on `set -e` and positional args. **The value of the rewrite is testability and type safety, not LOC reduction.**

### Execution Checklist (Definition of Done Per Phase)

This section turns the strategy into an execution contract. A phase is not "done" until every checkbox in that phase is satisfied.

#### Global Gates (Apply to Every Phase)

- `mypy --strict` passes for `foundry_sandbox/` (no new ignores added without rationale)
- `ruff check` passes
- Existing shell smoke tests (`tests/run.sh`) pass
- No net-new security regression in existing security tests (`tests/security/` and `tests/redteam-sandbox.sh`)
- Import latency gate: bridge modules importable in <300ms, CLI `--help` in <500ms (see [Import Latency](#cross-cutting-import-latency-and-performance))
- Updated docs for any user-visible behavior change, even if parity is preserved (help output examples, command docs, migration notes)
- Rollback path documented in PR description (what commit to revert and what functionality it restores)

#### Phase 1 DoD: Foundation (State + Paths + Package Scaffold)

- `foundry_sandbox/` package scaffold exists with `_bridge.py`, `state.py`, `paths.py`, `constants.py`, `models.py`, `utils.py`
- `pyproject.toml` exists with `dev` and `test-orchestration` extras and working editable install
- `lib/python/*` migration map is implemented for the modules assigned to Phase 1 (`json_config`, `merge_claude_settings`, `sync_opencode_foundry`)
- Shell callsites using migrated Python modules invoke `python3 -m foundry_sandbox.<module>`
- Dependency checks are callsite-scoped (no global preamble block in `sandbox.sh`)
- New/updated unit tests validate state read/write, path derivation, and model serialization
- Bridge contract test (`tests/unit/test_bridge_contract.py`) validates envelope format for all bridge-exposed functions
- Import latency test (`tests/unit/test_import_latency.py`) verifies bridge modules import in <300ms
- Backward compatibility check: shell-only codepaths still run without requiring Python package import at startup
- Fixture collision check: verify `tests/conftest.py` fixtures (`cli`, `local_repo`) do not shadow or conflict with existing fixtures in `tests/unit/conftest.py` or `tests/integration/conftest.py` (run `grep -r "def cli\|def local_repo" tests/` before adding)

#### Phase 2 DoD: Docker + Validation

- `foundry_sandbox/docker.py`, `foundry_sandbox/validate.py`, and `foundry_sandbox/api_keys.py` implemented
- Shell wrappers for migrated functions follow the Shell↔Python bridge protocol (exit codes/stdout/stderr contract)
- Validation behavior parity confirmed for positive and negative cases (sandbox names, URLs, required env vars)
- Docker command wrappers preserve current timeout/error behavior and stderr messaging semantics
- Regression tests cover command failure paths (missing Docker daemon, invalid args, missing keys)

#### Phase 3 DoD: Git + Network

- `foundry_sandbox/git.py`, `foundry_sandbox/git_worktree.py`, and `foundry_sandbox/network.py` implemented
- Git path normalization and worktree path translation behavior matches shell output and side effects
- Network mode generation matches existing compose/network policy behavior
- Security invariants validated with explicit tests: branch isolation remains deny-by-default and fail-closed; protected branch/tag deletion protections remain enforced; no regression in cross-sandbox branch visibility filtering

#### Phase 4 DoD: CLI Entrypoint + Command Handlers

- `foundry_sandbox/cli.py` Click-based entrypoint exists and dispatches to migrated Python commands (falls back to `sandbox.sh` for unmigrated ones)
- Python CLI supports command-by-command migration with fallback to shell for unmigrated handlers
- Command migration order follows documented low-risk-to-high-risk sequence; `new` remains last
- For each migrated command, parity diff is recorded against shell for exit code, stdout, stderr, and JSON output schema/field names/order guarantees where applicable
- Aliases (`repeat`, `reattach`) and help semantics match existing CLI UX
- Orchestration test suite passes against both entrypoints: `SANDBOX_CLI=./sandbox.sh` and `SANDBOX_CLI="python3 -m foundry_sandbox.cli"`

#### Phase 5 DoD: Container Config Split

- `container_config.sh` responsibilities are split into the planned modules: `container_setup.py`, `foundry_plugin.py`, `stub_manager.py`, `git_path_fixer.py`, `container_io.py`, `credential_setup.py`, `tool_configs.py`
- `ContainerConfigurator` orchestration class exists with explicit injected dependencies
- All critical flows are covered by tests: credential placeholder injection/runtime sync, git path fixing/nested `.git` detection, and tool config provisioning (Claude/Codex/Gemini/OpenCode/gh)
- No cyclic imports between `credential_setup.py`, `tool_configs.py`, and low-level copy/exec utilities (enforced by module boundaries and import tests)
- final shell wrapper (`sandbox.sh` exec to Python CLI) implemented only after all parity and security gates pass
- shell handler deletion happens in a dedicated commit for clean rollback (`git revert <deletion-commit>`)

#### Phase Exit Artifacts (Required for Sign-Off)

- Phase summary note listing migrated modules/functions and intentionally deferred items
- Test evidence includes command output parity diff report for changed commands and CI links for unit, integration, orchestration, and security jobs
- Security invariants checklist with pass/fail status
- Rollback instructions tested once in a throwaway branch (confirm restore works)

---

## Item 6: Integration Test Suite

### Current Test Coverage

| Area | Coverage | Location |
|------|----------|----------|
| Unified proxy (unit) | Strong — 8,000+ lines | `tests/unit/` |
| Unified proxy (integration) | Good — 1,700+ lines | `tests/integration/` |
| Security (red-team) | Good — 1,238 lines | `tests/redteam-sandbox.sh` |
| Security (unit) | Moderate — 734 lines | `tests/security/` |
| Performance | Good — 1,261 lines | `tests/performance/` |
| **Shell orchestration** | **Almost none** — 31 lines | `tests/run.sh` (6 smoke tests) |
| **CLI commands** | **None** | — |
| **Sandbox lifecycle** | **None** | — |

### Gap: No Automated Testing of Orchestration Layer

The shell orchestration (the part that creates, starts, stops, and destroys sandboxes) has only 6 smoke tests. No tests for:
- Sandbox creation flow
- State persistence and metadata integrity
- Git worktree creation/cleanup
- Docker compose generation
- Proxy registration flow
- Credential placeholder injection
- Network mode configuration
- Error handling and edge cases

### Test Suite Expansion Plan

#### Design: CLI Abstraction for Migration Resilience

Orchestration tests must survive the shell→Python migration without rewriting. All tests interact with the CLI through a fixture that abstracts the entrypoint:

```python
# tests/conftest.py

import os
import shlex
import subprocess
import uuid

@pytest.fixture
def cli():
    """CLI runner that abstracts shell vs Python entrypoint."""
    entrypoint = shlex.split(os.environ.get("SANDBOX_CLI", "./sandbox.sh"))
    def run(cmd, *args, **kwargs):
        return subprocess.run([*entrypoint, cmd, *args], capture_output=True, text=True, **kwargs)
    return run

@pytest.fixture(scope="session")
def local_repo(tmp_path_factory):
    """Create a deterministic local git repo for sandbox lifecycle tests."""
    repo = tmp_path_factory.mktemp("orchestration-repo") / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True)
    (repo / "README.md").write_text("test\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True)
    return str(repo.resolve())
```

During the shell phase, tests run against `./sandbox.sh`. After Phase 4, set `SANDBOX_CLI="python3 -m foundry_sandbox.cli"` to validate the Python version; the fixture parses this via `shlex.split`, so both single-binary and multi-token entrypoints are supported. This is also the mechanism for behavioral equivalence testing (see [Verification](#verification)).

#### Tier 1: Shell Orchestration Tests (Immediate, No Rewrite Needed)

Test the existing shell code using pytest + subprocess. These tests run CLI commands and verify outcomes.

**`tests/orchestration/conftest.py`**
```python
@pytest.fixture
def sandbox_name(cli):
    """Generate unique sandbox name for test isolation."""
    name = f"test-{uuid.uuid4().hex[:8]}"
    yield name
    # Cleanup: destroy sandbox if it still exists
    cli("destroy", name, "--force")
```

Shared fixtures that must be visible to both `tests/orchestration/` and `tests/security/` (for example `cli` and `local_repo`) live in `tests/conftest.py`. All sandbox-creating tests pass `--skip-key-check` (or dedicated CI test credentials) so they are deterministic and do not depend on external GitHub state or real API keys.

**`tests/orchestration/test_lifecycle.py`**
- `test_create_sandbox` — `sandbox.sh new <local_repo> <branch> --skip-key-check` succeeds, metadata written, container running
- `test_stop_start_sandbox` — stop preserves state, start resumes
- `test_destroy_sandbox` — all resources cleaned up (worktree, metadata, container)
- `test_list_sandboxes` — JSON output includes created sandbox
- `test_status_sandbox` — reports correct running/stopped state

**`tests/orchestration/test_state.py`**
- `test_metadata_written_on_create` — metadata.json contains repo, branch, mounts
- `test_metadata_persists_across_stop_start` — metadata survives container lifecycle
- `test_metadata_cleaned_on_destroy` — no orphaned metadata after destroy

**`tests/orchestration/test_git_worktree.py`**
- `test_worktree_created` — worktree exists at expected path after create
- `test_worktree_on_correct_branch` — checked out to specified branch
- `test_worktree_removed_on_destroy` — no orphaned worktrees
- `test_bare_repo_shared` — two sandboxes of same repo share bare repo

**`tests/orchestration/test_network_modes.py`**
- `test_default_network_mode` — credential isolation enabled by default
- `test_no_isolate_credentials_flag` — disables credential isolation
- `test_network_isolation_active` — container cannot reach blocked domains

#### Tier 2: Security Regression Tests (Pytest-Wrapped Red-Team)

**Note:** `tests/security/` already exists with `test_git_policy.py` (pytest-based git policy tests), `test_git_branch_isolation.sh` (shell-based branch isolation tests), and a README. New pytest files are added alongside existing content. The existing shell test is not converted — it continues to run independently.

Convert `redteam-sandbox.sh` test cases into pytest. These tests verify in-container behavior, so they use `docker exec` to run assertions inside a running sandbox:

```python
# tests/security/conftest.py
# NOTE: `cli` and `local_repo` fixtures are inherited from tests/conftest.py — do NOT redefine here.

import subprocess
import uuid
import pytest

@pytest.fixture(scope="module")
def sandbox_name():
    return f"test-{uuid.uuid4().hex[:8]}"

@pytest.fixture(scope="module")
def running_sandbox(cli, local_repo, sandbox_name):
    """Create a sandbox for the test module, exec assertions inside it."""
    # cli and local_repo fixtures provided by tests/conftest.py
    result = cli("new", local_repo, sandbox_name, "--skip-key-check")
    if result.returncode != 0:
        pytest.fail(f"Sandbox creation failed: {result.stderr}")
    yield sandbox_name
    cli("destroy", sandbox_name, "--force")

def docker_exec(sandbox_name, cmd):
    """Run a command inside the sandbox container and return result."""
    container = f"sandbox-{sandbox_name}"
    return subprocess.run(
        ["docker", "exec", container, "bash", "-c", cmd],
        capture_output=True, text=True
    )
```

**`tests/security/test_credential_isolation.py`**
- `test_no_real_credentials_in_env` — `docker exec ... env` has only placeholders
- `test_api_requests_work_via_proxy` — credential injection transparent
- `test_credential_not_in_response_headers` — proxy strips credentials from responses

**`tests/security/test_self_merge_blocked.py`**
- `test_gh_pr_merge_blocked` — 403 response
- `test_auto_merge_enable_blocked` — 403 response
- `test_pr_review_create_blocked` — 403 response
- `test_graphql_merge_mutation_blocked` — 403 response

**`tests/security/test_filesystem_readonly.py`**
- `test_root_filesystem_readonly` — `docker exec ... touch /usr/bin/xxx` fails
- `test_tmpfs_writable` — `/tmp` and `/home/ubuntu` are writable
- `test_workspace_writable` — `/workspace` files can be modified
- `test_git_directory_hidden` — `/workspace/.git` is empty/inaccessible

#### Tier 3: CI Pipeline

**`.github/workflows/test.yml`**

Unit tests and security fuzzing run per-push. These don't need Docker — they import proxy modules directly or test pure Python logic.

```yaml
name: Tests
on: [push, pull_request]
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.12']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev,test-orchestration]"
      - run: python -m pytest tests/unit/ -v --tb=short

  type-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e ".[dev]"
      - run: mypy
      - run: ruff check

  security-fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e ".[dev,test-orchestration]"
      - run: python -m pytest tests/security/test_fuzzing.py -v --tb=short
```

**Integration CI Workflows**

Use a two-tier CI strategy:
- **PR gate:** lightweight orchestration smoke tests on `pull_request`/`push` (fast feedback, catches obvious breakage)
- **Nightly/manual:** full orchestration + security integration matrix (slower, broader, includes hardening checks)

**`.github/workflows/orchestration-smoke.yml`** (PR/push gate)

```yaml
name: Orchestration Smoke
on: [push, pull_request]
concurrency:
  group: orchestration-smoke-${{ github.ref }}
  cancel-in-progress: true
jobs:
  smoke:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e ".[dev,test-orchestration]"
      - run: python -m pytest tests/orchestration/test_lifecycle.py::test_create_sandbox tests/orchestration/test_lifecycle.py::test_stop_start_sandbox tests/orchestration/test_lifecycle.py::test_destroy_sandbox -v --tb=short -x --timeout=120
```

**`.github/workflows/orchestration-tests.yml`** (full suite, nightly/manual)

```yaml
name: Orchestration & Security Integration Tests
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 06:00 UTC
  workflow_dispatch:       # Manual trigger
concurrency:
  group: orchestration-full-${{ github.ref }}
  cancel-in-progress: true
jobs:
  orchestration-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e ".[dev,test-orchestration]"
      - run: python -m pytest tests/orchestration/ -v --tb=short -x --timeout=120
      - name: Cleanup orphaned test sandboxes
        if: always()
        run: |
          ./sandbox.sh list --json 2>/dev/null \
            | python3 -c "import sys,json; [print(s['name']) for s in json.load(sys.stdin) if s['name'].startswith('test-')]" \
            | xargs -I{} ./sandbox.sh destroy {} --force 2>/dev/null || true

  security-integration-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install -e ".[dev,test-orchestration]"
      - run: python -m pytest tests/security/test_credential_isolation.py tests/security/test_self_merge_blocked.py tests/security/test_filesystem_readonly.py -v --tb=short -x --timeout=120
      - name: Cleanup orphaned test sandboxes
        if: always()
        run: |
          ./sandbox.sh list --json 2>/dev/null \
            | python3 -c "import sys,json; [print(s['name']) for s in json.load(sys.stdin) if s['name'].startswith('test-')]" \
            | xargs -I{} ./sandbox.sh destroy {} --force 2>/dev/null || true
```

#### Tier 4: Security Fuzzing

Fuzz the proxy's git operation validation and policy evaluation with randomized inputs. These modules are importable on the host without mitmproxy:

- `git_operations.py` — imports only stdlib + local modules (`git_policies`, `branch_isolation`)
- `git_policies.py` — imports only stdlib (`fnmatch`, `os`, `dataclasses`, `typing`)
- `branch_isolation.py` — imports only stdlib (`logging`, `os`, `re`, `subprocess`, `dataclasses`, `typing`)

**Not fuzzable on host:** `addons/policy_engine.py` imports `mitmproxy` at module level and cannot be imported without it. Policy engine fuzzing runs inside the Docker container or requires `pip install mitmproxy` in the test environment.

**`tests/security/test_fuzzing.py`**

```python
import sys
sys.path.insert(0, "unified-proxy")

from hypothesis import given, strategies as st
from git_operations import validate_command

# Strategy: random argv-style tokens (validate_command expects List[str])
argv_tokens = st.lists(
    st.from_regex(r"[^\x00\s]{1,64}", fullmatch=True),
    min_size=1,
    max_size=8,
)

@given(args=argv_tokens)
def test_git_validation_no_crash(args):
    """Validation should never raise on arbitrary argv tokens."""
    err = validate_command(args)
    assert err is None or getattr(err, "reason", "")

dangerous = st.sampled_from([
    ["push", "--force", "origin", "main"],
    ["push", "origin", ":main"],
    ["-c", "core.hooksPath=/tmp/evil", "status"],
    ["--git-dir=/tmp/evil", "status"],
])

@given(args=dangerous)
def test_git_validation_fail_closed(args):
    """Known dangerous operations must be rejected, not silently accepted."""
    assert validate_command(args) is not None
```

Fuzzing targets (by phase):
- **Now:** `git_operations.py` command validation, `git_policies.py` policy evaluation, `branch_isolation.py` branch validation
- **After Phase 1:** `foundry_sandbox/state.py` metadata serialization round-trips (write → read → compare with Hypothesis `st.dictionaries` of valid metadata fields — catches encoding bugs, missing escaping, and truncation)
- **After Phase 2:**
  - `foundry_sandbox/validate.py` — sandbox name validation with unicode, control characters, path traversal sequences (`../`, `%2e%2e/`), and names that collide with Docker/compose reserved words
  - `foundry_sandbox/validate.py` — URL validation with embedded credentials (`https://user:pass@host`), `file://` protocol, and malformed schemes
  - `foundry_sandbox/api_keys.py` — key format validation with near-miss strings (correct prefix, wrong length; correct length, wrong prefix)
- **After Phase 3:** `foundry_sandbox/git.py` path validation (symlink traversal, worktree name sanitization with shell metacharacters), `foundry_sandbox/git_worktree.py` branch name fuzzing (ref names with `/`, `..`, `@{`, `~`, `^`)
- **Deferred:** `addons/policy_engine.py` API request filtering (requires mitmproxy — fuzz inside container or with full proxy deps installed)

### Test Isolation

Orchestration tests create real sandboxes and mutate host state (Docker containers, git worktrees, metadata files). Safeguards:

- **Serial execution for orchestration tests.** Orchestration tests run in a single process (no `pytest-xdist`; if installed, use `-n 0`). `-x` is used only for fail-fast. Parallel sandbox creation risks port collisions and Docker race conditions. Unit tests and fuzzing tests can run in parallel because they have no Docker or filesystem side effects.
- **Unique naming.** Each test gets a `test-{uuid}` sandbox name via the `sandbox_name` fixture. No shared state between tests.
- **Aggressive timeouts.** `pytest-timeout` with per-test limits (120s default). A hung `docker-compose up` won't block CI indefinitely.
- **Orphan cleanup.** The CI workflow includes a post-run step that filters `test-*` sandboxes from `sandbox.sh list` and destroys them individually. Locally, developers can run `./sandbox.sh destroy-all` after aborted test runs (note: `destroy-all` does not support prefix filtering — it destroys everything, so use it only when no non-test sandboxes are running).
- **CI concurrency.** Multiple PR checks running simultaneously can hit port conflicts and disk pressure from concurrent sandbox creation. CI workflows use GitHub Actions concurrency groups to serialize orchestration tests per branch:
  ```yaml
  concurrency:
    group: orchestration-${{ github.ref }}
    cancel-in-progress: true
  ```
  This ensures only one orchestration test run per branch at a time (newer pushes cancel in-progress runs). Unit tests and fuzzing tests have no concurrency restrictions since they don't use Docker.

### Parity Contract (UX + Functional)

The migration target is strict parity, not "close enough":

- **Functional parity:** same side effects (metadata writes, container lifecycle, worktree behavior, network config, credential flow)
- **UX parity:** same command names, aliases (`repeat`, `reattach`), flags, defaults, help command semantics, machine-readable JSON shape, human-readable output structure, and exit codes
- **Error parity:** same failure conditions and equivalent user-facing error messages for common mistakes

Parity is validated by running the same test matrix against both entrypoints (`sandbox.sh` and Python CLI) and diffing command outcomes (exit code, stdout, stderr) for a canonical command set.

### Security Invariants (Threat-Model Gates)

Any phase that touches security-critical behavior must preserve these invariants from `docs/security/sandbox-threats.md`:

- **Credential isolation invariant:** real credentials never appear in sandbox env/filesystem; placeholders only
- **Branch isolation invariant:** deny-by-default ref validation and ref-listing filtering remain fail-closed
- **Git safety invariant:** protected-branch push protections and branch/tag deletion blocking remain enforced
- **Filesystem/network invariant:** read-only boundaries and egress controls preserve current deny behavior
- **Fail-closed invariant:** missing/invalid sandbox identity or policy metadata blocks sensitive operations

Each invariant must have at least one automated regression test in CI before deleting the corresponding shell codepath.

---

## Sequencing: Tests First (Phase 0)

Item 6 (test suite) and Item 5 (rewrite) are presented as separate work items, but they have a dependency: **the test suite is prerequisite to safe migration.** The orchestration and security tests built in Item 6 become the safety net that validates behavioral equivalence during the rewrite.

Sequence:
1. **Phase 0 (Item 6):** Build orchestration tests and security regression tests against the existing shell. This establishes the baseline behavior that the Python rewrite must match.
2. **Phase 1+ (Item 5):** Begin the rewrite. Every phase runs the Phase 0 test suite against both shell and Python (once the Python CLI exists in Phase 4) to catch divergence.

Phase 0 can start immediately and does not depend on any Python infrastructure. It uses pytest + subprocess to exercise `sandbox.sh` directly. The test suite expansion described in Item 6 *is* Phase 0.

---

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Migration stalls mid-effort** (priorities change, bandwidth shifts) | High | Low | Strangler fig pattern: project is fully functional at every phase boundary. Shell commands work; Python modules are additive. Resume later. |
| **Behavioral divergence discovered late** (Python subtly differs from shell) | Medium | High | Phase 0 test suite catches this. Parity contract requires running the same tests against both entrypoints. `diff` exit codes, stdout, stderr, metadata JSON for canonical operations. |
| **Contributor confusion during transition** (which code to fix?) | Medium | Medium | Dual-implementation policy (see [Cross-Cutting](#cross-cutting-dual-implementation-policy)): authoritative implementation is unambiguous. Shell logic is deleted as soon as Python replacement passes tests. |
| **Performance regression from Python subprocess overhead** | Medium | Low | Import latency gates (300ms bridge, 500ms CLI). Lazy imports for heavy dependencies. Measured in CI with `test_import_latency.py`. |
| **`new.sh` migration introduces regressions** (largest, most complex handler) | Medium | High | Migrated last (Phase 4) after all dependencies are in Python. Decomposed into 6 focused modules. Each high-risk operation (credentials, worktree, compose, sparse) has dedicated tests. |
| **CI flakiness from Docker-based orchestration tests** | High | Medium | Serial execution, unique naming (`test-{uuid}`), aggressive timeouts (120s), concurrency groups per branch, orphan cleanup in `always()` step. |
| **`jq` or Python 3.10 not available on user's host** | Low | Medium | `require_jq` and `require_python_module` guards fail with clear error messages. Unmigrated shell codepaths work without Python during early phases. |

---

## Verification

### Behavioral Equivalence Testing

During migration, each phase must prove the Python version is equivalent to shell in both behavior and UX. Automated approach:

```bash
# Run orchestration tests against shell (baseline)
SANDBOX_CLI=./sandbox.sh python -m pytest tests/orchestration/ -v --tb=short

# Run orchestration tests against Python CLI
SANDBOX_CLI="python3 -m foundry_sandbox.cli" python -m pytest tests/orchestration/ -v --tb=short
```

Both runs must produce the same pass/fail results. For parity-critical commands, also compare exit code, stdout, and stderr. For state-producing operations (create, start, stop), compare:
- Metadata JSON structure and fields
- Docker container configuration (`docker inspect`)
- Git worktree state (`git worktree list`)
- File permissions and ownership in generated configs

This comparison is automated as a CI job during Phases 4-5 (once the Python CLI exists).

### For the test suite (Item 6):
```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=foundry_sandbox --cov-report=html

# Run bridge contract and latency tests
python -m pytest tests/unit/test_bridge_contract.py tests/unit/test_import_latency.py -v

# Run security tests only
python -m pytest tests/security/ -v

# Run orchestration tests (requires Docker)
python -m pytest tests/orchestration/ -v

# Type checking
mypy
ruff check
```

### For the Python rewrite (Item 5):
Each phase should pass:
1. All new Python unit tests pass
2. `mypy --strict` and `ruff check` pass with no errors
3. Existing shell smoke tests still pass (backward compatibility)
4. Orchestration tests pass against both `./sandbox.sh` and `python3 -m foundry_sandbox.cli` (once Phase 4 begins)
5. Red-team tests pass inside created sandboxes
6. No functional or UX differences detected in equivalence comparison

### Rollback Strategy

The strangler fig pattern means rollback is always possible:

- **Phases 1-3:** Rollback is commit-scoped, not directory deletion. Revert only the phase's shell integration commits (wrappers/callsites) so shell behavior is restored first; then optionally remove now-unused Python modules in a follow-up commit.
- **Phase 4 (highest risk):** Both `sandbox.sh` and the Python CLI coexist. If a Python command handler has a bug, remove it from the Python CLI — the shell version still works. The Python CLI falls back to shelling out to `sandbox.sh` for any command without a Python handler.
- **Phase 5:** Shell command handlers are removed only after: (a) all orchestration tests pass against the Python CLI, (b) red-team tests pass, (c) manual smoke test of full lifecycle. Shell code remains in git history. Rollback = `git revert` the deletion commit.

If migration stalls mid-effort (priorities change, team bandwidth), the project remains fully functional. Shell commands continue to work. Completed Python modules are used where integrated. There is no point-of-no-return until shell command handlers are deleted in Phase 5.

---

## Files Created (Summary)

**Item 5 (Python rewrite — Phase 1 only as starting point):**
- `foundry_sandbox/__init__.py`
- `foundry_sandbox/_bridge.py`
- `foundry_sandbox/state.py`
- `foundry_sandbox/paths.py`
- `foundry_sandbox/constants.py`
- `foundry_sandbox/models.py`
- `foundry_sandbox/utils.py`
- `foundry_sandbox/config.py` (absorbs `lib/python/json_config.py`)
- `foundry_sandbox/claude_settings.py` (absorbs `lib/python/merge_claude_settings.py`)
- `foundry_sandbox/opencode_sync.py` (absorbs `lib/python/sync_opencode_foundry.py`)
- `pyproject.toml` (project config, build system, dev dependencies, mypy + ruff config)

**Item 6 (Test suite):**
- `tests/conftest.py` (shared `cli` and `local_repo` fixtures)
- `tests/unit/test_bridge_contract.py` (envelope format validation for all bridge functions)
- `tests/unit/test_import_latency.py` (import time gate for bridge modules)
- `tests/orchestration/conftest.py`
- `tests/orchestration/test_lifecycle.py`
- `tests/orchestration/test_state.py`
- `tests/orchestration/test_git_worktree.py`
- `tests/orchestration/test_network_modes.py`
- `tests/security/conftest.py` (sandbox-scoped fixtures only; inherits `cli`/`local_repo` from root)
- `tests/security/test_credential_isolation.py`
- `tests/security/test_self_merge_blocked.py`
- `tests/security/test_filesystem_readonly.py`
- `tests/security/test_fuzzing.py`
- `.github/workflows/test.yml`
- `.github/workflows/orchestration-smoke.yml`
- `.github/workflows/orchestration-tests.yml`
