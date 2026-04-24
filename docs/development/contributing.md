# Contributing Guide

This guide reflects the current repo layout and local workflow in this checkout.

## Repo Layout

```text
foundry-sandbox/
  foundry_sandbox/            Python package and CLI
    commands/                 Click subcommands
    assets/                   Scripts injected into sandboxes
  config/                     Example configuration files
  docs/                       User and operator docs
  scripts/                    Local CI and benchmark helpers
  tests/
    unit/                     Fast unit tests
    smoke/                    Live `sbx` smoke tests
    chaos/                    Fault-injection shell modules
    redteam/                  Sandbox security tests
```

Key modules:

| Path | Purpose |
|------|---------|
| `foundry_sandbox/cli.py` | root Click entry point |
| `foundry_sandbox/commands/` | CLI command implementations |
| `foundry_sandbox/sbx.py` | subprocess wrapper around `sbx` |
| `foundry_sandbox/git_safety.py` | bridge to `foundry-git-safety` |
| `foundry_sandbox/state.py` | metadata, presets, and last-used state |
| `foundry_sandbox/assets/git-wrapper.sh` | sandbox git wrapper |

## Local Checks

Run the same local helper used by contributors:

```bash
./scripts/ci-local.sh
./scripts/ci-local.sh --all
./scripts/ci-local.sh --no-fail-fast
```

Useful direct test entry points:

```bash
pytest tests/unit/ -v
pytest tests/smoke/ -v -m requires_sbx
./tests/chaos/runner.sh
./tests/redteam/runner.sh
```

## GitHub Workflows

Current workflows in this repo:

| Workflow | Purpose |
|----------|---------|
| `test.yml` | CI checks |
| `release.yml` | release and publish flow |
| `sbx-drift.yml` | detect `sbx` version drift |

## Documentation Policy

Keep the maintained current-state docs in sync when behavior changes:

- `README.md`
- `docs/getting-started.md`
- `docs/foundry-and-sbx.md`
- `docs/sbx-compatibility.md`
- `docs/usage/commands.md`
- `docs/usage/workflows.md`
- `docs/configuration.md`
- `docs/operations.md`
- `docs/security/security-model.md`
