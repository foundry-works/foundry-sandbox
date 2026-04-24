# Test Suite

## Test Tree

```text
tests/
  unit/         fast unit tests (CI)
  smoke/        live sbx smoke tests (manual — requires sbx + KVM)
  chaos/        shell fault-injection modules (manual — requires sbx + KVM)
  redteam/      security checks (manual — requires running sandbox)
  run.sh        local test runner helper
```

foundry-git-safety has its own test tree under `foundry-git-safety/tests/`:

```text
foundry-git-safety/tests/
  unit/         fast unit tests (CI)
  security/     policy and auth security tests (CI)
  integration/  integration tests (CI)
```

## What Runs in CI

The GitHub Actions workflow (`.github/workflows/test.yml`) runs on every push to
`main` and on every pull request. It covers:

| Job | What it runs |
|-----|-------------|
| `unit` | `pytest tests/unit/` with coverage for `foundry_sandbox` |
| `lint` | mypy, ruff, shellcheck |
| `git-safety-unit` | `pytest tests/unit/` for `foundry_git_safety` |
| `git-safety-security` | `pytest tests/security/` for `foundry git safety` |
| `git-safety-integration` | `pytest tests/integration/` for `foundry_git safety` |
| `smoke-gate` | installed-wheel packaging and `cast diagnose`/`cast config` checks |

These jobs run on `ubuntu-latest` and require no special hardware or
infrastructure beyond a standard Python environment.

## Manual Test Suites

The following suites **do not** run in ordinary PR CI. They require a live
`sbx` microVM environment with KVM support and a running `foundry-git-safety`
server on the host.

### Live sbx Smoke Tests

```bash
pytest tests/smoke/ -v -m requires_sbx
```

Prerequisites:

- `sbx` CLI installed and daemon running
- KVM support on the host (`/dev/kvm` available)
- `foundry-git-safety` server running
- At least one sandbox created via `cast new`

These tests exercise the full sandbox lifecycle: create, provision git safety,
run git commands through the wrapper, verify push blocking, and destroy.

### Red-Team Security Tests

```bash
# Run all modules inside a running sandbox:
./tests/redteam/runner.sh

# Run a single module:
./tests/redteam/runner.sh --module 04-git-security

# TAP/JUnit output:
./tests/redteam/runner.sh --output-format tap --output-dir /tmp/results
```

Prerequisites:

- Live `sbx` sandbox with git wrapper installed at `/usr/local/bin/git`
- `foundry-git-safety` server running on the host
- Set `GIT_SHADOW_ENABLED=1` for full git shadow mode tests (modules 04, 11)

See `tests/redteam/README.md` for the full module list (14 active modules).

### Chaos Tests

```bash
./tests/chaos/runner.sh

# Run a single module:
./tests/chaos/runner.sh --module <name>

# With output format:
./tests/chaos/runner.sh --output-format tap --output-dir /tmp/results
```

Prerequisites:

- `sbx` CLI installed and daemon running
- `foundry-git-safety` server running
- At least one sandbox created via `cast new`

## Quick Local Commands

```bash
# Fast — runs in CI, no special setup:
pytest tests/unit/ -v
cd foundry-git-safety && pytest tests/unit tests/security tests/integration -v

# Local smoke check (installed-wheel):
./tests/run.sh

# Full local CI check:
./scripts/ci-local.sh
```
