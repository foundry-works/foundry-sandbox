# Configuration

This page documents the current configuration surface verified in this repo.
The primary declarative input is `foundry.yaml`.

## `foundry.yaml`

Foundry resolves configuration in this order:

1. packaged builtin defaults
2. `~/.foundry/foundry.yaml`
3. `<repo>/foundry.yaml`

Use `cast new ... --plan` to inspect the resolved config and generated artifacts
before creating a sandbox:

```bash
cast new . feature-login main --plan
```

Example:

```yaml
version: "1"

git_safety:
  protected_branches:
    add:
      - refs/heads/staging
  file_restrictions:
    blocked_patterns_add:
      - db/migrations/
  allow_pr_operations: false

user_services:
  - name: Tavily
    env_var: TAVILY_API_KEY
    domain: api.tavily.com

mcp_servers:
  - name: github
    type: builtin
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: "${from_host:GITHUB_TOKEN}"

claude_code:
  commands:
    - /path/to/commands/review.md
```

Merge behavior:

- `mcp_servers` and `user_services` concatenate across layers
- `git_safety.protected_branches.add` and
  `git_safety.file_restrictions.blocked_patterns_add` only append
- `allow_third_party_mcp` and `git_safety.allow_pr_operations` tighten via AND
  semantics across layers
- `claude_code` skills, commands, hooks, and permissions merge additively
- a repo `foundry.yaml` can add config, but it cannot override tighter
  user-layer gates

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
- any resolved `foundry.yaml` secret refs from:
  `user_services`, proxy MCP `host_env`, and `${from_host:VAR}` MCP env values

## Sandbox Creation Options

These `cast new` options change sandbox setup and are persisted in metadata and presets:

| Option | Purpose |
|--------|---------|
| `--wd PATH` | Initial working directory inside the repo |
| `-r`, `--pip-requirements PATH` | Install Python dependencies inside the sandbox |
| `-c`, `--copy HOST:CONTAINER` | Copy a host file into the sandbox once at creation time |
| `--allow-pr` | Request PR-oriented operations; resolved config can still tighten this |
| `--template TAG` | Use a specific `sbx` template instead of the default wrapper template |
| `--with-opencode` | Enable OpenCode-related setup intent; warns if host auth is missing |
| `--with-zai` | Enable ZAI-related setup intent; requires `ZHIPU_API_KEY` |
| `--plan` | Show resolved `foundry.yaml` layers and compiled artifacts without creating a sandbox |

## Git Safety Overlay

Use the `git_safety` section in `foundry.yaml` to tighten sandbox git policy:

```yaml
git_safety:
  protected_branches:
    add:
      - refs/heads/staging
      - refs/heads/release
  file_restrictions:
    blocked_patterns_add:
      - ".env.production"
      - "db/migrations/"
  allow_pr_operations: false
```

Behavior:

- `protected_branches.add` and `blocked_patterns_add` are additive-only
- `allow_pr_operations` can tighten existing PR permission, but cannot loosen it
- `cast new --allow-pr` and `git_safety.allow_pr_operations` combine via AND
  semantics: `false` anywhere wins

## User-Defined Services

For APIs that are not handled directly by the built-in `sbx` secret flow,
declare proxy-backed service env vars in `foundry.yaml` under `user_services`.

Example:

```yaml
version: "1"

user_services:
  - name: Tavily
    env_var: TAVILY_API_KEY
    domain: api.tavily.com
    header: Authorization
    format: bearer
    methods: [GET, POST]
    paths: ["/search*", "/extract*"]
    scheme: https
    port: 443
```

At sandbox creation time, Foundry injects a proxy URL such as:

```text
TAVILY_API_KEY=http://host.docker.internal:8083/proxy/tavily
```

Important behavior:

- The configured `env_var` inside the sandbox contains a proxy URL, not an API key.
- The real secret stays on the host.
- Requests to the proxy are authenticated with sandbox HMAC headers.
- `format` controls how the credential is injected:
  `bearer` adds `Bearer <secret>` to `header`,
  `header` writes the raw secret to `header`,
  and `query` appends the secret as a query parameter named by `header`.
- `methods` and `paths` optionally restrict which requests the proxy accepts.
- `scheme` and `port` let you target non-default upstream transport settings.
- This works best for direct HTTP clients or tools that can adapt to a custom
  proxy/base URL flow.
- SDKs that assume `*_API_KEY` always contains a raw token will usually need
  extra adaptation or a different integration path.

For manual requests inside the sandbox, use the installed `proxy-sign` helper to
generate the required headers for `/proxy/...` endpoints.

## MCP Servers

Declare MCP servers in `foundry.yaml` under the `mcp_servers` key. At sandbox
creation, Foundry writes a `/workspace/.mcp.json` inside the sandbox with the
compiled configuration. Treat `foundry.yaml` as the source of truth, not the
generated `.mcp.json` inside the sandbox.

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
in the sandbox points at the Foundry proxy.

```yaml
mcp_servers:
  - name: internal-api
    type: proxy
    host_env: INTERNAL_API_KEY
    target: api.internal.com
```

The `host_env` field names the host environment variable that holds the real
credential. The `target` field identifies the intended upstream service domain.

### npm servers (third-party)

Third-party MCP servers distributed as npm packages. Requires the
`allow_third_party_mcp` gate to be set to `true`.

```yaml
version: "1"

allow_third_party_mcp: true

mcp_servers:
  - name: my-mcp-server
    type: npm
    package: "@example/mcp-server"
    env:
      API_KEY: "${from_host:MY_API_KEY}"
```

At sandbox creation, Foundry installs the package globally via
`npm install -g` (as root) and writes a `.mcp.json` entry that starts the
server via `npx`. Env values support the same `${from_host:VAR}` substitution
as builtins.

### Supply-chain gates

The `allow_third_party_mcp` flag controls whether npm-type MCP servers are
allowed. It is **ANDed across all config layers**:

```text
builtin-defaults  (unset → defaults to false)
~/.foundry/foundry.yaml  (user can enable)
repo/foundry.yaml  (repo cannot override user false)
```

Any layer setting `allow_third_party_mcp: false` blocks npm servers across the
entire resolved config. A repo `foundry.yaml` cannot re-enable it if the user's
`~/.foundry/foundry.yaml` sets it to `false`.

Example — user blocks, repo tries to allow:

```yaml
# ~/.foundry/foundry.yaml
version: "1"
allow_third_party_mcp: false
```

```yaml
# repo/foundry.yaml
version: "1"
allow_third_party_mcp: true  # ignored — user layer wins
mcp_servers:
  - name: risky
    type: npm
    package: risky-pkg  # validation error at resolve time
```

## Claude Code

Configure Claude Code skills, commands, hooks, and permissions in `foundry.yaml`
under the `claude_code` key. At sandbox creation, Foundry writes the compiled
configuration into `/workspace/.claude/` inside the sandbox. Keep
`foundry.yaml` as the source of truth for those files.

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
  foundry.yaml
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

### Common Credentials

| Variable | Purpose |
|----------|---------|
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude auth |
| `ANTHROPIC_API_KEY` | Claude / Anthropic auth |
| `GITHUB_TOKEN`, `GH_TOKEN` | GitHub clone/push/PR auth |
| `OPENAI_API_KEY` | OpenAI / Codex auth |
| `ZHIPU_API_KEY` | Required for `--with-zai` |
