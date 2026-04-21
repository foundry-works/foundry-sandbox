# foundry-sandbox

MicroVM-based sandbox environment for running Claude Code with isolated credentials.

## Development

- `foundry_sandbox/` - Python CLI package (`cast` entry point via pyproject.toml)
- `stubs/` - Stub files injected into sandboxes (CLAUDE.md, etc.)
- `tests/` - Test scripts including security red-team tests

## Testing

```bash
./tests/redteam-sandbox.sh  # Security validation (run inside sandbox)
```

## Documentation

- `docs/README.md` - Documentation index
- `docs/architecture.md` - System architecture
- `docs/configuration.md` - Configuration options
- `docs/getting-started.md` - Setup guide
- `docs/usage/` - Commands and workflows
- `docs/security/` - Security model and threat analysis

**Important:** Read `docs/security/security-model.md` to understand the threat model and security boundaries before making changes to sandbox isolation.
