# foundry-sandbox

Docker-based sandbox environment for running Claude Code with isolated credentials.

## Development

- `sandbox.sh` - Main entry point for sandbox management
- `lib/` - Shell library modules
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

**Important:** Read `docs/security/sandbox-threats.md` to understand the threat model and security boundaries before making changes to sandbox isolation.

**Important:** Read docs in `docs/adr` for decision records on architecture.

<sandbox-context>
## Sandbox Context
- **Repository**: foundry-works/foundry-sandbox
- **Branch**: `tyler/foundry-sandbox-20260208-1643`
- **Based on**: `tylerburleigh/hardening-and-rewrite`

When creating PRs, target `tylerburleigh/hardening-and-rewrite` as the base branch.
</sandbox-context>
