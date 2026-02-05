# Unit Tests

Unit tests for individual functions and modules in isolation.

## Structure

Tests should mirror the source directory structure. For example:
- `lib/config.sh` → `tests/unit/test_config.sh`
- `lib/docker.sh` → `tests/unit/test_docker.sh`

## Running Tests

```bash
# Run all unit tests
./tests/unit/run.sh

# Run specific test file
./tests/unit/test_config.sh
```

## Guidelines

- Tests should be fast (no network, no containers)
- Mock external dependencies
- One assertion per test when practical
- Use descriptive test names
