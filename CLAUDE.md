# foundry-sandbox

Docker-based sandbox environment for running Claude Code with isolated credentials.

## Development

- `foundry_sandbox/` - Python CLI package (`cast` entry point via pyproject.toml)
- `unified-proxy/` - Credential isolation proxy (mitmproxy addons, git API)
- `stubs/` - Stub files injected into sandboxes (CLAUDE.md, etc.)
- `tests/` - Test scripts including security red-team tests

## Pre-commit

Always run `./scripts/ci-local.sh` before committing to catch CI failures locally. Use `--all` to include integration tests, `--no-fail-fast` to see all results.

## Testing

```bash
./scripts/ci-local.sh        # Local CI validation (run before commit)
./tests/redteam-sandbox.sh   # Security validation (run inside sandbox)
```

Run `./scripts/ci-local.sh` before pushing to catch CI failures early.

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
- **Branch**: `tyler/foundry-sandbox-20260209-0718`
- **Based on**: `tylerburleigh/hardening-and-rewrite`

When creating PRs, target `tylerburleigh/hardening-and-rewrite` as the base branch.
</sandbox-context>
