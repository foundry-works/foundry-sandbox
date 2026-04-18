# Integration Tests

Integration tests that verify components work together correctly.

## Structure

Tests are organized by feature or workflow:
- `test_sandbox_lifecycle.sh` - Sandbox creation, usage, teardown
- `test_credential_flow.sh` - Credential injection and isolation
- `test_proxy_routing.sh` - Proxy request routing

## Running Tests

```bash
# Run all integration tests
./tests/integration/run.sh

# Run specific test
./tests/integration/test_sandbox_lifecycle.sh
```

## Requirements

- Docker must be running
- May require network access
- Some tests spin up containers (slower)

## Guidelines

- Clean up resources after each test
- Use unique names to avoid conflicts
- Test realistic workflows
