# Command Reference

This page documents the current `cast` CLI surface from the code in this repo.

## Core Flow

```bash
cast new owner/repo feature-login main
cast attach repo-feature-login
cast stop repo-feature-login
cast start repo-feature-login
cast destroy repo-feature-login --yes
```

`cast new` creates the sandbox and prints next steps. It does not open a shell automatically.

## Lifecycle Commands

### `cast new`

Create a sandbox and provision git safety.

```bash
cast new <repo> [branch] [from-branch] [options]
cast new --last
cast new --preset <name>
```

Notes:

- If `[branch]` is omitted, Foundry generates one automatically.
- If `[from-branch]` is omitted for a remote repo, the current implementation
  falls back to `main`.
- For local repo inputs such as `.`, Foundry can infer the current branch or
  `origin/HEAD` more accurately.

Key options:

| Option | Purpose |
|--------|---------|
| `--agent <type>` | `claude`, `codex`, `copilot`, `gemini`, `kiro`, `opencode`, `shell` |
| `-c`, `--copy HOST:CONTAINER` | Copy a host file into the sandbox once |
| `-r`, `--pip-requirements PATH` | Install Python dependencies |
| `--wd PATH` | Initial working directory inside the repo |
| `--allow-pr`, `--with-pr` | Allow PR-related operations |
| `--with-opencode` | Enable OpenCode-related setup intent |
| `--with-zai` | Requires `ZHIPU_API_KEY` |
| `--save-as NAME` | Save these CLI args as a preset |
| `--name NAME` | Override the generated sandbox name |
| `--template TAG` | Use a specific `sbx` template; `none` disables template use |
| `--skip-key-check` | Skip the Claude auth precheck |
| `--plan` | Dry-run: show resolved foundry.yaml config without creating sandbox |

Examples:

```bash
cast new owner/repo feature-login main
cast new owner/repo feature-login develop
cast new . feature-login main
cast new owner/repo feature-login --agent codex
cast new owner/repo feature-login -r requirements.txt
cast new owner/repo feature-login --wd packages/api
cast new owner/repo feature-login --save-as myproject
cast new owner/repo feature-login --plan
cast new --preset myproject
cast new --last
```

### `cast attach`

Attach to a sandbox. If the sandbox is stopped, `cast attach` starts it first.

```bash
cast attach [name]
cast attach --last
```

Options:

| Option | Purpose |
|--------|---------|
| `--last` | Reattach to the last sandbox |
| `--with-ide [name]` | Launch an IDE and still open a terminal |
| `--ide-only [name]` | Launch an IDE and skip the terminal |
| `--no-ide` | Skip the IDE prompt |

Examples:

```bash
cast attach repo-feature-login
cast attach --last
cast attach repo-feature-login --with-ide
cast attach repo-feature-login --ide-only cursor
```

### `cast start`

Start a stopped sandbox.

```bash
cast start <name> [--watchdog]
```

Behavior:

- ensures `foundry-git-safety` is running
- starts the sandbox via `sbx run`
- verifies wrapper integrity and repairs it if needed
- reinstalls configured pip requirements

`--watchdog` also starts continuous wrapper-integrity monitoring.

If wrapper repair fails, the sandbox may still start in a degraded state with
git safety disabled. Check `cast status <name>` before trusting git
enforcement.

### `cast stop`

Stop a running sandbox but keep its worktree and metadata:

```bash
cast stop <name>
```

### `cast destroy`

Destroy one sandbox:

```bash
cast destroy <name> [--keep-worktree] [--force] [--yes]
```

`--keep-worktree` removes the sandbox but leaves the repo worktree and metadata in place.

### `cast destroy-all`

Destroy every sandbox known to either `sbx` or the local metadata registry:

```bash
cast destroy-all [--keep-worktree]
```

Interactive mode:

1. confirms once with `click.confirm`
2. then requires the literal phrase `destroy all`

`SANDBOX_NONINTERACTIVE=1` skips prompts.

## Status and Inspection

### `cast list`

List all sandboxes:

```bash
cast list
cast list --json
```

### `cast status`

Show status for one sandbox or all sandboxes:

```bash
cast status
cast status <name>
cast status --json
cast status <name> --json
```

Single-sandbox output includes branch, repo, git-safety state, and wrapper verification metadata when available.

### `cast config`

Print local config paths and basic checks:

```bash
cast config
cast config --json
```

### `cast diagnose`

Collect diagnostics from `sbx`, git safety, the decision log, and wrapper tamper counters:

```bash
cast diagnose
cast diagnose --json
```

## Maintenance Commands

### `cast refresh-creds`

Push host credentials into `sbx` host-side secrets:

```bash
cast refresh-creds [name]
cast refresh-creds --last
cast refresh-creds --all
```

### `cast watchdog`

Run wrapper-integrity monitoring in the foreground:

```bash
cast watchdog
cast watchdog --interval 30
```

The current default poll interval is 10 seconds.

### `cast git-mode`

Switch a sandbox worktree between host and sandbox git path layouts:

```bash
cast git-mode [name] --mode host
cast git-mode [name] --mode sandbox
```

Use this when host-side IDE tooling and sandbox-side git expectations need different `core.worktree` values.

### `cast preset`

Manage saved presets:

```bash
cast preset list
cast preset show <name>
cast preset save <name> [--sandbox <sandbox-name>]
cast preset delete <name>
```

`cast new --save-as` stores CLI flags only. `cast preset save` also snapshots a running sandbox into an `sbx` template.

### `cast help`

Show help:

```bash
cast help
cast --help
```

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SANDBOX_HOME` | `~/.sandboxes` | Base directory for metadata and presets |
| `SANDBOX_VERBOSE` | unset | Show `sbx` subprocess commands |
| `SANDBOX_DEBUG` | unset | Extra debug logging |
| `SANDBOX_ASSUME_YES` | unset | Skip confirmations |
| `SANDBOX_NONINTERACTIVE` | unset | Disable prompts and imply assume-yes |
| `CLAUDE_CODE_OAUTH_TOKEN` | - | Claude auth |
| `ANTHROPIC_API_KEY` | - | Claude / Anthropic auth |
| `GITHUB_TOKEN`, `GH_TOKEN` | - | GitHub auth |
| `OPENAI_API_KEY` | - | OpenAI / Codex auth |
| `ZHIPU_API_KEY` | - | Required for `--with-zai` |
| `GIT_API_SECRETS_PATH` | `~/.foundry/secrets/sandbox-hmac` | HMAC secret directory |
| `FOUNDRY_DATA_DIR` | `~/.foundry/data/git-safety` | Git-safety registration directory |
| `FOUNDRY_USER_SERVICES_PATH` | unset | Override path to `user-services.yaml` |
