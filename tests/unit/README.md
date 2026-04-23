# Unit Tests

Python unit tests for the `cast` CLI and supporting modules.

## Running Tests

```bash
pytest tests/unit/ -v
pytest tests/unit/test_new.py -v
pytest tests/unit/test_cli.py::TestCLIGroup::test_cli_shows_help_with_no_args -v
```

The repo-wide pytest defaults and markers live in `pyproject.toml`.

## Scope

- Keep unit tests fast and isolated.
- Mock subprocess, filesystem, and network-facing behavior where practical.
- Prefer focused coverage of CLI contracts, validation, and security-sensitive
  helpers.
