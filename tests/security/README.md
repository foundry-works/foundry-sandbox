# Security Tests

Security validation tests including red-team scenarios.

## Structure

- `test_credential_isolation.sh` - Verify credentials cannot leak between sandboxes
- `test_escape_prevention.sh` - Container escape prevention
- `test_network_isolation.sh` - Network segmentation validation
- `redteam/` - Adversarial test scenarios

## Running Tests

```bash
# Run all security tests
./tests/security/run.sh

# Run red-team tests (must be run inside sandbox)
./tests/security/redteam/run.sh
```

## Guidelines

- Test both positive (allowed) and negative (blocked) cases
- Document threat model for each test
- Tests should be safe to run (no actual exploitation)
- Reference `docs/security/sandbox-threats.md` for threat model
