# PLAN 2: Python Rewrite & Integration Test Suite

## Context

The foundry-sandbox orchestration layer is 264KB of shell across 24 library modules and 17 command handlers. The largest file (`container_config.sh`) is 88KB alone. Shell is fragile for this complexity level — hard to test, hard to refactor, and error-prone for security-critical code. Meanwhile, the test suite has strong unit/integration coverage for the unified-proxy (Python) but almost no automated testing for the shell orchestration layer.

This plan proposes an incremental rewrite strategy and a comprehensive test suite expansion.

---

## Item 5: Rewrite Shell Orchestration in Python

### Current Architecture

```
sandbox.sh (72 lines) — CLI dispatcher
  ├── sources 24 lib/*.sh modules (264KB total)
  └── routes to commands/*.sh (17 handlers, ~8,600 lines)
```

**Largest modules:**
| Module | Size | Responsibility |
|--------|------|---------------|
| `lib/container_config.sh` | 88KB | Container setup, foundry plugin, stubs, git path fixes |
| `lib/state.sh` | 27KB | Metadata persistence, sandbox listing, inspection |
| `commands/new.sh` | 49KB | Sandbox creation (1,343 lines) |
| `lib/proxy.sh` | 13KB | Proxy registration, health checks |
| `lib/network.sh` | 11KB | Network isolation modes |
| `lib/api_keys.sh` | 10KB | API key validation |
| `lib/docker.sh` | 8KB | Docker operations |
| `lib/validate.sh` | 8KB | Input validation |

**Existing Python in project:** 4 utility modules in `lib/python/` already extracted from shell (JSON config, Claude settings, OpenCode sync). These prove Python works in this project.

### Strategy: Incremental Rewrite (Not Big Bang)

A full rewrite is too risky and too large for one effort. Instead, rewrite module-by-module using a **strangler fig** pattern:

1. Create a Python CLI (`cast`) that wraps the existing shell commands
2. Migrate one module at a time, starting with the most valuable targets
3. Each migrated module is independently testable
4. Shell and Python coexist during transition

### Phase 1: Foundation (CLI + State + Paths)

Create the Python application skeleton and migrate the simplest, most testable modules first.

**New files:**
```
src/
├── __init__.py
├── cli.py              # Click-based CLI (replaces sandbox.sh dispatcher)
├── state.py            # Sandbox metadata (replaces lib/state.sh)
├── paths.py            # Path resolution (replaces lib/paths.sh)
├── constants.py        # Configuration defaults (replaces lib/constants.sh)
├── models.py           # Pydantic models for sandbox metadata
└── utils.py            # Logging, formatting (replaces lib/utils.sh, format.sh)
```

**Why start here:**
- `state.sh` (27KB) is pure data management — reads/writes JSON metadata, no Docker calls
- `paths.sh` (1.4KB) is trivial path computation
- These have zero external dependencies beyond filesystem
- Easy to test, easy to validate correctness against shell version
- Forms the foundation other modules depend on

**Key design decisions:**
- Use Click for CLI (widely adopted, composable, testable)
- Use Pydantic for metadata models (validation, serialization)
- Use `subprocess` for Docker/git calls (don't over-abstract early)
- Match existing CLI interface exactly (`cast new`, `cast list`, etc.)

### Phase 2: Docker + Validation

**Migrate:**
```
src/
├── docker.py           # Docker operations (replaces lib/docker.sh)
├── validate.py         # Input validation (replaces lib/validate.sh)
└── api_keys.py         # API key validation (replaces lib/api_keys.sh)
```

**Why next:**
- `docker.sh` (8KB) wraps `docker` and `docker-compose` CLI calls — straightforward to port
- `validate.sh` (8KB) is pure validation logic — highly testable
- `api_keys.sh` (10KB) is environment variable checking — no side effects

### Phase 3: Git + Network

**Migrate:**
```
src/
├── git.py              # Git operations (replaces lib/git.sh)
├── git_worktree.py     # Worktree management (replaces lib/git_worktree.sh)
└── network.py          # Network isolation (replaces lib/network.sh)
```

### Phase 4: Commands

**Migrate command handlers one at a time:**
```
src/commands/
├── __init__.py
├── list_cmd.py         # Simplest command (28 lines of shell)
├── status.py           # Status checks (89 lines)
├── info.py             # System info (24 lines)
├── destroy.py          # Cleanup (82 lines)
├── start.py            # Start container (203 lines)
├── stop.py             # Stop container (24 lines)
├── attach.py           # Tmux attach (123 lines)
└── new.py              # Create sandbox (1,343 lines — LAST, largest)
```

**Order:** simplest → most complex. `new.sh` (1,343 lines) is migrated last after all its dependencies are in Python.

### Phase 5: Container Config (The 88KB Monster)

`container_config.sh` is the last and largest migration target. By this point, all its dependencies are already in Python. Break it into focused modules:

```
src/
├── container_setup.py       # User setup, directory creation
├── foundry_plugin.py        # Foundry MCP installation
├── stub_manager.py          # Proxy stub file management
├── git_path_fixer.py        # Worktree path translation
└── credential_setup.py      # Credential placeholder injection
```

### Estimated Scope Per Phase

| Phase | Shell Lines Replaced | New Python Lines (est.) | Testability Gain |
|-------|---------------------|------------------------|-----------------|
| 1: Foundation | ~3,500 | ~800 | State + paths fully testable |
| 2: Docker + Validation | ~2,600 | ~600 | Validation logic testable |
| 3: Git + Network | ~2,100 | ~500 | Git worktree logic testable |
| 4: Commands | ~2,200 | ~1,000 | Command logic testable |
| 5: Container Config | ~3,000 | ~1,200 | Setup logic testable |

Total: ~14,400 shell lines → ~4,100 Python lines (3.5:1 compression typical for shell→Python)

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
| **Shell orchestration** | **Almost none** — 31 lines | `tests/run.sh` (5 smoke tests) |
| **CLI commands** | **None** | — |
| **Sandbox lifecycle** | **None** | — |

### Gap: No Automated Testing of Orchestration Layer

The 264KB shell orchestration (the part that creates, starts, stops, and destroys sandboxes) has only 5 smoke tests. No tests for:
- Sandbox creation flow
- State persistence and metadata integrity
- Git worktree creation/cleanup
- Docker compose generation
- Proxy registration flow
- Credential placeholder injection
- Network mode configuration
- Error handling and edge cases

### Test Suite Expansion Plan

#### Tier 1: Shell Orchestration Tests (Immediate, No Rewrite Needed)

Test the existing shell code using pytest + subprocess. These tests run `sandbox.sh` commands and verify outcomes.

**New file: `tests/orchestration/conftest.py`**
```python
@pytest.fixture
def sandbox_name():
    """Generate unique sandbox name for test isolation."""
    name = f"test-{uuid.uuid4().hex[:8]}"
    yield name
    # Cleanup: destroy sandbox if it still exists
    subprocess.run(["./sandbox.sh", "destroy", name, "--force"], capture_output=True)
```

**New file: `tests/orchestration/test_lifecycle.py`**
- `test_create_sandbox` — `cast new` succeeds, metadata written, container running
- `test_stop_start_sandbox` — stop preserves state, start resumes
- `test_destroy_sandbox` — all resources cleaned up (worktree, metadata, container)
- `test_list_sandboxes` — JSON output includes created sandbox
- `test_status_sandbox` — reports correct running/stopped state

**New file: `tests/orchestration/test_state.py`**
- `test_metadata_written_on_create` — metadata.json contains repo, branch, mounts
- `test_metadata_persists_across_stop_start` — metadata survives container lifecycle
- `test_metadata_cleaned_on_destroy` — no orphaned metadata after destroy

**New file: `tests/orchestration/test_git_worktree.py`**
- `test_worktree_created` — worktree exists at expected path after create
- `test_worktree_on_correct_branch` — checked out to specified branch
- `test_worktree_removed_on_destroy` — no orphaned worktrees
- `test_bare_repo_shared` — two sandboxes of same repo share bare repo

**New file: `tests/orchestration/test_network_modes.py`**
- `test_default_network_mode` — credential isolation enabled by default
- `test_no_isolate_credentials_flag` — disables credential isolation
- `test_network_isolation_active` — container cannot reach blocked domains

#### Tier 2: Security Regression Tests (Pytest-Wrapped Red-Team)

Convert `redteam-sandbox.sh` test cases into pytest for CI integration:

**New file: `tests/security/test_credential_isolation.py`**
- `test_no_real_credentials_in_env` — container env has only placeholders
- `test_api_requests_work_via_proxy` — credential injection transparent
- `test_credential_not_in_response_headers` — proxy strips credentials from responses

**New file: `tests/security/test_self_merge_blocked.py`**
- `test_gh_pr_merge_blocked` — 403 response
- `test_auto_merge_enable_blocked` — 403 response
- `test_pr_review_create_blocked` — 403 response
- `test_graphql_merge_mutation_blocked` — 403 response

**New file: `tests/security/test_filesystem_readonly.py`**
- `test_root_filesystem_readonly` — `touch /usr/bin/xxx` fails
- `test_tmpfs_writable` — `/tmp` and `/home/ubuntu` are writable
- `test_workspace_writable` — `/workspace` files can be modified
- `test_git_directory_hidden` — `/workspace/.git` is empty/inaccessible

#### Tier 3: CI Pipeline

**New file: `.github/workflows/test.yml`**

```yaml
name: Tests
on: [push, pull_request]
jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python -m pytest tests/unit/ -v --tb=short

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r requirements.txt
      - run: python -m pytest tests/security/ -v --tb=short

  # Orchestration tests require Docker — run on self-hosted or with docker service
  orchestration-tests:
    runs-on: ubuntu-latest
    services:
      docker:
        image: docker:dind
    steps:
      - uses: actions/checkout@v4
      - run: python -m pytest tests/orchestration/ -v --tb=short -x
```

#### Tier 4: Security Fuzzing

**New file: `tests/security/test_fuzzing.py`**

Fuzz the git operations validation with randomized inputs:
- Random git subcommands (valid + invalid)
- Random flag combinations
- Path traversal variants (`../`, symlinks, null bytes)
- Config key injection variants
- Oversized inputs
- Unicode/encoding edge cases

```python
@pytest.mark.parametrize("payload", generate_fuzz_payloads(1000))
def test_git_validation_no_crash(payload):
    """Ensure git validation never crashes on arbitrary input."""
    try:
        result = validate_command(payload)
    except ValidationError:
        pass  # Expected — validation correctly rejected
    except Exception as e:
        pytest.fail(f"Unexpected exception on fuzz input {payload!r}: {e}")
```

### Test Dependencies (New)

Add to `requirements.txt` or `requirements-dev.txt`:
```
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-xdist>=3.0.0    # Parallel test execution
pytest-timeout>=2.0.0   # Prevent hanging tests
hypothesis>=6.0.0       # Property-based testing / fuzzing
```

---

## Verification

### For the test suite (Item 6):
```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=unified-proxy --cov-report=html

# Run security tests only
python -m pytest tests/security/ -v

# Run orchestration tests (requires Docker)
python -m pytest tests/orchestration/ -v
```

### For the Python rewrite (Item 5):
Each phase should pass:
1. All new Python unit tests pass
2. Existing shell smoke tests still pass (backward compatibility)
3. Manual `cast new` / `cast destroy` workflow works identically
4. Red-team tests pass inside created sandboxes

### Files Created (Summary)

**Item 5 (Python rewrite — Phase 1 only as starting point):**
- `src/__init__.py`
- `src/cli.py`
- `src/state.py`
- `src/paths.py`
- `src/constants.py`
- `src/models.py`
- `src/utils.py`
- `pyproject.toml` (project config)

**Item 6 (Test suite):**
- `tests/orchestration/conftest.py`
- `tests/orchestration/test_lifecycle.py`
- `tests/orchestration/test_state.py`
- `tests/orchestration/test_git_worktree.py`
- `tests/orchestration/test_network_modes.py`
- `tests/security/test_credential_isolation.py`
- `tests/security/test_self_merge_blocked.py`
- `tests/security/test_filesystem_readonly.py`
- `tests/security/test_fuzzing.py`
- `.github/workflows/test.yml`
- `requirements-dev.txt`
