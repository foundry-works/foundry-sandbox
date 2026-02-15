# foundry-sandbox

Docker-based sandbox environment for running Claude Code with isolated credentials.

## Development

- `foundry_sandbox/` - Python CLI package (`cast` entry point via pyproject.toml)
- `unified-proxy/` - Credential isolation proxy (mitmproxy addons, git API)
- `stubs/` - Stub files injected into sandboxes (CLAUDE.md, etc.)
- `tests/` - Test scripts including security red-team tests

**Important:** Never commit `CLAUDE.md` if it contains `<sandbox-context>` tags. These are injected at runtime by the sandbox and are specific to a session — they must not be checked into any branch.

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

## Releasing

1. Bump the version in `pyproject.toml`
2. Add a new section to `CHANGELOG.md` with the version and date
3. Commit, push to `main`
4. Create a git tag: `git tag v<version> && git push origin v<version>`

The `.github/workflows/release.yml` workflow triggers on `v*` tags and handles both the GitHub release and PyPI publish automatically. **Do not** create the GitHub release manually with `gh release create` — the workflow does this and will fail if the release already exists.