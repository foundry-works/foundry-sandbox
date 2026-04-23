# Getting Started

This guide covers the current supported flow: install the CLI, authenticate on the host, create a sandbox, then attach to it.

## Prerequisites

- Standalone Docker `sbx`
- Git
- Python 3.10+
- Host authentication for the tools you want to use inside the sandbox

Foundry Sandbox requires the standalone `sbx` CLI. It intentionally rejects Docker Desktop's `docker sandbox` plugin shim.

Verify the basics:

```bash
sbx version
git --version
python3 --version
```

## Install

### Recommended

```bash
curl -fsSL https://raw.githubusercontent.com/foundry-works/foundry-sandbox/main/install.sh | bash
```

### From PyPI

```bash
pipx install foundry-sandbox
```

### From Source

```bash
pip install -e .
```

The package installs the `cast` CLI and the `foundry-git-safety[server]` dependency.

## Authenticate on the Host

`cast new` requires Claude auth unless you explicitly pass `--skip-key-check`.

```bash
# Required: one of these
export CLAUDE_CODE_OAUTH_TOKEN="..."
# or
export ANTHROPIC_API_KEY="..."

# Recommended for private repos and push
gh auth login
# or
export GITHUB_TOKEN="ghp_..."

# Optional
export OPENAI_API_KEY="..."
export ZHIPU_API_KEY="..."
```

If you update host credentials after sandboxes are already running, push them into `sbx` again with:

```bash
cast refresh-creds --all
```

If the repo uses `foundry.yaml`, preview the resolved config before creating a
sandbox:

```bash
cast new . feature-login main --plan
```

## Create Your First Sandbox

Create a sandbox from a GitHub repo:

```bash
cast new owner/repo feature-login main
```

For remote repos, pass the base branch explicitly unless you know it is `main`.
When `[from-branch]` is omitted for a remote repo, the current implementation
falls back to `main`.

Create one from the current local repo:

```bash
cast new . feature-login main
```

For local repos, Foundry can usually infer a sensible base branch from the
current checkout and `origin/HEAD`.

What `cast new` does:

1. Validates `sbx` and required auth.
2. Ensures a local repo checkout exists.
3. Creates an `sbx` sandbox and repo-local worktree.
4. Starts `foundry-git-safety` if needed — the host-side policy server that validates git commands from the sandbox.
5. Generates a per-sandbox HMAC secret, registers the sandbox with the policy server, injects the git wrapper at `/usr/local/bin/git`, and writes sandbox metadata.
6. Resolves `foundry.yaml` layers and applies compiled artifacts such as git-safety overlays, proxy-backed env vars, `/workspace/.mcp.json`, and `/workspace/.claude/`.
7. Prints the sandbox name, worktree path, and next commands.

Steps 4 and 5 are what Foundry adds on top of `sbx`; steps 1–3 are ordinary `sbx` operations. `cast new` does not attach automatically.

## Attach

Use the sandbox name printed by `cast new`:

```bash
cast attach repo-feature-login
```

Useful variants:

```bash
cast attach --last
cast attach repo-feature-login --with-ide
cast attach repo-feature-login --ide-only cursor
```

Once attached, your working tree is available at `/workspace`.

## Work Inside the Sandbox

```bash
cd /workspace
git status
claude
codex
gemini
opencode
```

## Reconnect, Stop, Start, Destroy

```bash
cast list
cast status repo-feature-login
cast stop repo-feature-login
cast start repo-feature-login
cast destroy repo-feature-login --yes
```

`cast start` repairs the git wrapper if needed. `cast start --watchdog` also starts wrapper-integrity monitoring.

If `cast start` reports that the sandbox started without git safety
enforcement, treat that sandbox as degraded. Verify with
`cast status repo-feature-login` before doing git work inside it.

## Non-Interactive Mode

Use `SANDBOX_NONINTERACTIVE=1` for CI and scripted runs:

```bash
SANDBOX_NONINTERACTIVE=1 cast destroy repo-feature-login
```

This suppresses prompts and implies assume-yes behavior.

## IDE Convenience

Set a preferred IDE once in `~/.foundry/foundry.yaml`:

```yaml
version: "1"

ide:
  preferred: cursor
  args: ["--reuse-window"]
  auto_open_on_attach: true
```

Then `cast attach` opens Cursor automatically, or use `cast open` to open the worktree without attaching a shell:

```bash
cast open repo-feature-login
cast open --last
cast open repo-feature-login --ide zed
```
