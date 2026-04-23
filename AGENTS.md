# foundry-sandbox

Git policy and workflow layer for AI coding agents running in Docker `sbx` microVMs. `sbx` provides the microVM, network policy, and credential injection; foundry-sandbox adds the git wrapper, policy server, and `cast` CLI workflows.

## Development

- `foundry_sandbox/` - Python CLI package (`cast` entry point via pyproject.toml)
- `foundry_sandbox/assets/` - Assets injected into sandboxes (git wrapper, proxy-sign)
- `tests/` - Test scripts including security red-team tests

## Testing

```bash
./tests/redteam/runner.sh  # Security validation (run inside sandbox)
```

## Documentation

- `docs/configuration.md` - Configuration options
- `docs/getting-started.md` - Setup guide
- `docs/usage/` - Commands and workflows
- `docs/security/security-model.md` - Threat model and security boundaries

**Important:** Read `docs/security/security-model.md` to understand the threat model and security boundaries before making changes to sandbox isolation.
