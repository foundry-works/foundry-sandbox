# Contributing Guide

This guide covers how to contribute to Foundry Sandbox.

## Code Organization

```
foundry-sandbox/
├── install.sh              # Installation script
├── pyproject.toml          # Python package definition (entry point: cast)
│
├── foundry_sandbox/        # Python package (orchestration layer)
│   ├── cli.py              # Click CLI group with alias resolution
│   ├── constants.py        # Configuration defaults
│   ├── models.py           # Pydantic data models (SbxSandboxMetadata)
│   ├── paths.py            # Path resolution (SandboxPaths)
│   ├── utils.py            # Logging/formatting helpers
│   ├── sbx.py              # sbx CLI wrapper (all subprocess calls)
│   ├── git_safety.py       # Git safety integration bridge
│   ├── git.py              # Git operations with retry
│   ├── git_worktree.py     # Worktree management
│   ├── state.py            # Metadata persistence (JSON, atomic writes)
│   ├── validate.py         # Input validation
│   ├── api_keys.py         # API key validation
│   └── commands/           # Click command implementations
│       ├── new.py          # cast new (dispatches to new_sbx.py)
│       ├── new_sbx.py      # sbx sandbox creation logic
│       ├── attach.py       # cast attach (sbx exec streaming)
│       ├── start.py        # cast start (sbx run)
│       ├── stop.py         # cast stop (sbx stop)
│       ├── destroy.py      # cast destroy (sbx rm + cleanup)
│       ├── destroy_all.py  # cast destroy-all
│       ├── list_cmd.py     # cast list (sbx ls enrichment)
│       ├── config.py       # cast config
│       ├── refresh_creds.py # cast refresh-creds (sbx secret)
│       ├── help_cmd.py     # cast help
│       └── git_mode.py     # cast git-mode
│
├── foundry-git-safety/     # Standalone git safety package
│   ├── foundry_git_safety/
│   │   ├── cli.py          # CLI entry point (start/stop/status/validate)
│   │   ├── server.py       # Flask git API server (port 8083)
│   │   ├── auth.py         # HMAC auth, nonce store, rate limiter
│   │   ├── policies.py     # Command allowlist, protected branches
│   │   ├── operations.py   # Git command execution
│   │   ├── branch_isolation.py  # Cross-sandbox branch isolation
│   │   └── schemas/        # Pydantic config models
│   └── tests/              # 727 tests (unit, integration, security)
│
├── foundry_sandbox/assets/ # Assets injected into sandboxes
│   ├── git-wrapper-sbx.sh  # Git wrapper for sbx networking
│   └── proxy-sign.sh       # HMAC request signing helper
│
├── tests/                  # Test suite
│
└── docs/                   # Documentation (you are here)
```

## CI Pipeline

CI runs via GitHub Actions on every push and PR. The main workflow is `.github/workflows/test.yml`.

### Test Jobs

| Job | What it runs |
|-----|-------------|
| `unit` | Root package tests: `pytest tests/unit/` |
| `lint` | ruff lint + format check |
| `git-safety-unit` | `foundry-git-safety` unit tests: `pytest tests/unit/` |
| `git-safety-security` | `foundry-git-safety` security tests: `pytest tests/security/` |
| `git-safety-integration` | `foundry-git-safety` integration tests: `pytest tests/integration/` |

All five jobs must pass before merge (gated by the `all-pass` job).

### Pytest Isolation

The root package and `foundry-git-safety` have separate `pyproject.toml` files and must be tested independently. Running both in the same pytest invocation causes import collisions. Each CI job `cd`s into the correct directory before running pytest.

### Running Tests Locally

```bash
# Run the same checks as CI
./scripts/ci-local.sh

# Include integration tests
./scripts/ci-local.sh --all

# Show all results (don't stop at first failure)
./scripts/ci-local.sh --no-fail-fast

# Run only foundry-git-safety tests
cd foundry-git-safety && pytest tests/unit/ -v
```

Always run `./scripts/ci-local.sh` before committing to catch CI failures early.

### Additional Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `release.yml` | `v*` tags | GitHub release + PyPI publish |
| `sbx-drift.yml` | Schedule | Detect sbx CLI version drift |
