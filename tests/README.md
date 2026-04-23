# Test Suite

This file documents the test layout that exists in this repo today.

## Current Test Tree

```text
tests/
  unit/         fast unit tests
  smoke/        live `sbx` smoke tests
  chaos/        shell fault-injection modules
  redteam/      security checks intended to run in a sandbox
  run.sh        local test runner helper
```

## Common Entry Points

```bash
pytest tests/unit/ -v
pytest tests/smoke/ -v -m requires_sbx
./tests/chaos/runner.sh
./tests/redteam/runner.sh
./tests/run.sh
```

## Notes

- `tests/redteam/runner.sh` is intended to run inside a sandbox
- `tests/smoke/` and some chaos cases require a working standalone `sbx` setup
- the root `pyproject.toml` already defines the active pytest markers and defaults

For operator-facing guidance, prefer the docs under `docs/` rather than treating this file as a product manual.
