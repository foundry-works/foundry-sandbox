# foundry-sandbox

Git policy and workflow layer for AI coding agents running in Docker `sbx` microVMs. `sbx` provides the microVM, network policy, and credential injection; foundry-sandbox adds the git wrapper, policy server (`foundry-git-safety`), and `cast` CLI workflows.

## Development

- `foundry_sandbox/` - Python CLI package (`cast` entry point via pyproject.toml)
- `foundry-git-safety/` - Git safety server (policy engine, HMAC auth, branch isolation)
- `tests/` - Test scripts including security red-team tests

## Pre-commit

Always run `./scripts/ci-local.sh` before committing to catch CI failures locally. Use `--all` to include integration tests, `--no-fail-fast` to see all results.

## Testing

```bash
./scripts/ci-local.sh        # Local CI validation (run before commit)
./tests/redteam/runner.sh    # Security validation (run inside sandbox)
```

Run `./scripts/ci-local.sh` before pushing to catch CI failures early.

Redteam tests **must** be run inside a sandbox. See `tests/redteam/README.md` for the current module layout.

## Documentation

- `docs/configuration.md` - Configuration options
- `docs/getting-started.md` - Setup guide
- `docs/usage/` - Commands and workflows
- `docs/security/security-model.md` - Threat model and security boundaries

**Important:** Read `docs/security/security-model.md` to understand the threat model and security boundaries before making changes to sandbox isolation.

## Git Mode

`cast git-mode <sandbox-name> --mode <host|sandbox>` toggles a sandbox's git config between host-friendly and proxy-compatible layouts:

- **`--mode host`** — sets `core.worktree` to the real host path so IDE and shell tools work normally
- **`--mode sandbox`** — sets `core.worktree` to `/git-workspace` (container path) for proxy-routed git operations

The command validates paths, updates `.git/config.worktree`, and syncs the running sandbox immediately. The sandbox name is auto-detected if you run it from inside a worktree.

## Releasing

1. Bump the version in `pyproject.toml`
2. Add a new section to `CHANGELOG.md` with the version and date
3. Commit, push to `main`
4. Create a git tag: `git tag v<version> && git push origin v<version>`

The `.github/workflows/release.yml` workflow triggers on `v*` tags and handles both the GitHub release and PyPI publish automatically. **Do not** create the GitHub release manually with `gh release create` — the workflow does this and will fail if the release already exists.
