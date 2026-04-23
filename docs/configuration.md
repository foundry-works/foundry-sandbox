# Configuration

This page documents the configuration surface that is verified in this repo today: host authentication, credential refresh, host-side paths, user-service configuration, and the main environment variables that affect `cast`.

## Host Authentication

### Required for `cast new`

`cast new` checks for Claude auth unless you pass `--skip-key-check`.

Set one of:

```bash
export CLAUDE_CODE_OAUTH_TOKEN="..."
# or
export ANTHROPIC_API_KEY="..."
```

### Common Optional Credentials

```bash
export GITHUB_TOKEN="ghp_..."     # private repos and push
export OPENAI_API_KEY="..."       # Codex / OpenAI tooling
export ZHIPU_API_KEY="..."        # required for --with-zai
```

`GH_TOKEN` is also accepted as a fallback for GitHub.

## Refreshing Credentials

Running sandboxes use `sbx` host-side secrets. If you rotate host credentials after a sandbox is already up, refresh them:

```bash
cast refresh-creds repo-feature-login
cast refresh-creds --last
cast refresh-creds --all
```

The current implementation pushes:

- `anthropic` from `ANTHROPIC_API_KEY`
- `github` from `GITHUB_TOKEN` or `GH_TOKEN`
- `openai` from `OPENAI_API_KEY`
- any user-defined services declared in `config/user-services.yaml`

## Sandbox Creation Options

These `cast new` options change sandbox setup and are persisted in metadata and presets:

| Option | Purpose |
|--------|---------|
| `--wd PATH` | Initial working directory inside the repo |
| `-r`, `--pip-requirements PATH` | Install Python dependencies inside the sandbox |
| `-c`, `--copy HOST:CONTAINER` | Copy a host file into the sandbox once at creation time |
| `--allow-pr` | Allow PR-oriented operations |
| `--template TAG` | Use a specific `sbx` template instead of the default wrapper template |
| `--with-opencode` | Enable OpenCode-related setup intent; warns if host auth is missing |
| `--with-zai` | Enable ZAI-related setup intent; requires `ZHIPU_API_KEY` |

## User-Defined Services

For APIs that are not handled directly by the built-in `sbx` secret flow,
Foundry can inject proxy URLs into the sandbox instead of raw secrets.

Search order for the config file:

1. explicit path passed by code
2. `FOUNDRY_USER_SERVICES_PATH`
3. `config/user-services.yaml`

Start from the bundled example:

```bash
cp config/user-services.yaml.example config/user-services.yaml
```

Example:

```yaml
version: "1"

services:
  - name: Tavily
    env_var: TAVILY_API_KEY
    domain: api.tavily.com
    header: Authorization
    format: bearer
```

At sandbox creation time, Foundry injects a proxy URL such as:

```text
TAVILY_API_KEY=http://host.docker.internal:8083/proxy/tavily
```

Important behavior:

- The configured `env_var` inside the sandbox contains a proxy URL, not an API key.
- The real secret stays on the host.
- Requests to the proxy are authenticated with sandbox HMAC headers.
- This works best for direct HTTP clients or tools that can adapt to a custom
  proxy/base URL flow.
- SDKs that assume `*_API_KEY` always contains a raw token will usually need
  extra adaptation or a different integration path.

For manual requests inside the sandbox, use the installed `proxy-sign` helper to
generate the required headers for `/proxy/...` endpoints.

## MCP Servers

Declare MCP servers in `foundry.yaml` under the `mcp_servers` key. At sandbox
creation, Foundry writes a `/workspace/.mcp.json` inside the sandbox with the
compiled configuration.

### Builtin servers

Curated servers that ship with Foundry. No manual setup required.

Available builtins: `github`, `filesystem`, `memory`.

```yaml
version: "1"

mcp_servers:
  - name: github
    type: builtin
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "${from_host:GITHUB_TOKEN}"

  - name: filesystem
    type: builtin

  - name: memory
    type: builtin
```

Each builtin resolves to an `npx` command from `@modelcontextprotocol`.

### `${from_host:VAR}` substitution

Env values containing `${from_host:VAR_NAME}` are replaced with a proxy URL at
compile time. The real credential stays on the host. The host env var must be
set when `cast new` runs (fail-fast).

```yaml
env:
  API_KEY: "${from_host:MY_API_KEY}"
# resolves to: http://host.docker.internal:8083/proxy/my-api-key
```

### Proxy servers

For APIs that are not covered by a builtin, use `type: proxy`. The MCP server
in the sandbox points at the Foundry proxy, which authenticates and forwards
requests to the real service.

```yaml
mcp_servers:
  - name: internal-api
    type: proxy
    host_env: INTERNAL_API_KEY
    target: api.internal.com
```

The `host_env` field names the host environment variable that holds the real
credential. The `target` field is the upstream domain the proxy routes to.

## Claude Code

Configure Claude Code skills, commands, hooks, and permissions in `foundry.yaml`
under the `claude_code` key. At sandbox creation, Foundry writes the compiled
configuration into `/workspace/.claude/` inside the sandbox.

### Skills

Install skills from a local directory or a git repository.

```yaml
version: "1"

claude_code:
  skills:
    # From a host directory — all files are copied into the sandbox
    - source: /path/to/my-skills/security-review

    # From a git repository — cloned at sandbox creation time
    - git: https://github.com/user/cool-skill

    # From a git repo with a subdirectory path
    - git: https://github.com/user/skill-collection.git
      path: skills/review
```

Host-directory skills are copied as `FileWrite` artifacts. Git-based skills are
cloned as `PostStep` commands (run after all other artifacts are applied).

### Commands

Copy Claude Code command files from the host into the sandbox:

```yaml
claude_code:
  commands:
    - /path/to/commands/explain.md
    - /path/to/commands/review.md
```

Each file is written to `/workspace/.claude/commands/<filename>`.

### Hooks and Permissions

Hooks and permissions are compiled into `/workspace/.claude/settings.json`:

```yaml
claude_code:
  hooks:
    PreToolUse:
      - match: Bash
        command: audit-log.sh
    Stop:
      - match: "*"
        command: cleanup.sh

  permissions:
    allow:
      - WebSearch
      - "Bash(grep:*)"
    deny:
      - "Bash(rm -rf:*)"
```

The compiled `settings.json` follows Claude Code's native format. Only
non-empty sections are included.

## Host Paths

The current host-side layout is:

```text
~/.sandboxes/
  sandboxes/<name>/metadata.json
  presets/
  .last-cast-new.json
  .last-attach.json

<repo>/.sbx/<sandbox>-worktrees/<branch>/

~/.foundry/
  secrets/sandbox-hmac/<sandbox>
  data/git-safety/sandboxes/<sandbox>.json
  logs/decisions.jsonl
  template-image-digest
```

## Environment Variables

### `cast` Runtime

| Variable | Default | Purpose |
|----------|---------|---------|
| `SANDBOX_HOME` | `~/.sandboxes` | Base directory for metadata and presets |
| `SANDBOX_VERBOSE` | unset | Print `sbx` subprocess commands |
| `SANDBOX_DEBUG` | unset | Enable additional debug logging |
| `SANDBOX_ASSUME_YES` | unset | Skip confirmations |
| `SANDBOX_NONINTERACTIVE` | unset | Disable prompts and imply assume-yes behavior |

### Git Safety / Host Services

| Variable | Default | Purpose |
|----------|---------|---------|
| `GIT_API_SECRETS_PATH` | `~/.foundry/secrets/sandbox-hmac` | HMAC secret directory |
| `FOUNDRY_DATA_DIR` | `~/.foundry/data/git-safety` | Git-safety registration directory |
| `FOUNDRY_USER_SERVICES_PATH` | unset | Override path to `user-services.yaml` |

### Common Credentials

| Variable | Purpose |
|----------|---------|
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude auth |
| `ANTHROPIC_API_KEY` | Claude / Anthropic auth |
| `GITHUB_TOKEN`, `GH_TOKEN` | GitHub clone/push/PR auth |
| `OPENAI_API_KEY` | OpenAI / Codex auth |
| `ZHIPU_API_KEY` | Required for `--with-zai` |
