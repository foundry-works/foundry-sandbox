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

- `mcp_servers` and `user_services` concatenate across trusted layers
- `git_safety.protected_branches.add` and
  `git_safety.file_restrictions.blocked_patterns_add` only append
- `allow_third_party_mcp` and `git_safety.allow_pr_operations` tighten via AND
  semantics across user/repo layers; packaged defaults are neutral
- `claude_code` skills, commands, hooks, and permissions merge additively
- a repo `foundry.yaml` can add config, but it cannot override tighter
  user-layer gates
- host-bound declarations are user-only: repo `foundry.yaml` files cannot
  declare `user_services`, proxy MCP servers, `${from_host:...}` env values,
  or host-path Claude skills/commands

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
declare proxy-backed service env vars in your user `~/.foundry/foundry.yaml`
under `user_services`.

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

`${from_host:...}` is user-only. Repo `foundry.yaml` files are rejected if they
try to request host secrets.

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
allowed. It is **ANDed across user and repo config layers**:

```text
packaged defaults  (neutral)
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

## IDE Preferences (User-Only)

Configure your preferred IDE in `~/.foundry/foundry.yaml`. This section is
**user-only** — repo-level `foundry.yaml` files cannot set it.

```yaml
version: "1"

ide:
  preferred: cursor
  args: ["--reuse-window"]
  auto_open_on_attach: true
```

Fields:

| Field | Default | Purpose |
|-------|---------|---------|
| `preferred` | `""` | IDE alias (`cursor`, `zed`, `code`), absolute executable path, or bare command on `PATH` |
| `args` | `[]` | Extra arguments passed when launching the IDE |
| `auto_open_on_attach` | `false` | If `true`, `cast attach` opens the IDE automatically unless `--no-ide` is passed |

Resolution order for `preferred`:

1. If the value contains `/`, treated as an explicit executable path (must exist and be executable)
2. If it matches a known alias (`cursor`, `zed`, `code`), uses alias-aware launch behavior
3. Otherwise, resolved as a bare command on `PATH`

If a repo `foundry.yaml` includes an `ide:` section, Foundry ignores it and emits a warning.

## Dev Profiles

Define named dev profiles in `foundry.yaml` under the `profiles` key. Profiles
set defaults for `cast dev` that CLI flags override.

```yaml
version: "1"

profiles:
  claude-python:
    agent: claude
    wd: packages/api
    ide: cursor
    pip_requirements: requirements-dev.txt
    template: foundry-git-wrapper:latest

  full-stack:
    agent: claude
    wd: .
    ide: cursor
    packages:
      pip: requirements-dev.txt
      apt: [jq, ripgrep]
      npm: [typescript]
    template: foundry-git-wrapper:latest
```

Fields:

| Field | Purpose |
|-------|---------|
| `agent` | Default agent type (`claude`, `codex`, `copilot`, `gemini`, `kiro`, `opencode`, `shell`) |
| `wd` | Default working directory inside the repo |
| `ide` | Default IDE (user config only — stripped from repo profiles) |
| `pip_requirements` | Default pip requirements file (legacy — use `packages.pip` instead) |
| `packages` | Typed package bootstrap config (see below) |
| `template` | Default sandbox template tag |

All fields are optional. An empty profile is valid and provides no defaults.

### Package Bootstrap

The `packages` field on a profile controls dependency installation inside the
sandbox. Packages are installed at sandbox creation time and re-installed on
restart.

```yaml
profiles:
  python-dev:
    packages:
      pip: requirements-dev.txt       # str = requirements file path
      uv: pyproject.toml              # str = requirements file path
      apt: [jq, ripgrep]             # list of system package names
      npm: [typescript, prettier]    # list of npm package names
```

Fields:

| Field | Type | Purpose |
|-------|------|---------|
| `pip` | `str` or `list[str]` | `str` installs from a requirements file (`pip install -r`). `list` installs named packages. |
| `uv` | `str` or `list[str]` | Same as `pip` but uses `uv pip install`. Requires `uv` in the sandbox. |
| `apt` | `list[str]` | System packages installed via `apt-get install -y`. |
| `npm` | `list[str]` | Global npm packages installed via `npm install -g`. |

Install order: `apt` → `pip` → `uv` → `npm` (system packages first so Python
and Node tools can find their C dependencies).

#### System packages gate

`apt` and `npm` bootstrap require the `allow_system_packages` gate to be set
to `true`. This gate uses AND semantics across user and repo config layers.
Any user/repo layer setting it to `false` blocks system package installation.

```yaml
version: "1"

allow_system_packages: true

profiles:
  full-stack:
    packages:
      apt: [jq]
      npm: [typescript]
```

`pip` and `uv` bootstrap do not require this gate — they have the same trust
level as the existing `--pip-requirements` flag.

#### Legacy `pip_requirements`

The `pip_requirements` field on profiles continues to work. If a profile sets
both `pip_requirements` and `packages.pip`, the `packages.pip` value wins. The
`--pip-requirements` CLI flag is also bridged into the packages system.

### Where profiles can live

Profiles can appear in both user config (`~/.foundry/foundry.yaml`) and repo
config (`<repo>/foundry.yaml`).

Merge behavior:

- Profiles with **different names** across layers are all available.
- For the **same name**, the user-layer profile wins entirely (not field-by-field).
- The `ide` field in repo profiles is **stripped** (IDE config is user-only).

### Resolution order

When `cast dev . --profile work` runs:

1. Resolve `foundry.yaml` config (builtin -> user -> repo layers).
2. Look up profile `work` in the merged `profiles` dict.
3. CLI flags override profile fields. Unset flags use profile defaults.
4. If neither CLI nor profile sets a field, the hardcoded default applies.

### `default` profile

The profile name `default` is special. `cast dev` uses `--profile default`
when no `--profile` flag is given. If `profiles.default` is not defined, the
empty profile is used (all defaults from CLI). This preserves backward
compatibility.

### Unknown profiles

If `--profile <name>` is given and `<name>` is not defined in any config layer,
`cast dev` exits with an error listing available profiles.

## Tooling Bundles

Tooling bundles are named, reusable tooling sets that expand into Claude skills,
Claude commands, MCP servers, and package prerequisites. They let you define a
tooling setup once and reference it from any profile.

### Schema

Define bundles under `tooling_bundles` in `foundry.yaml`:

```yaml
version: "1"
allow_third_party_mcp: true
allow_system_packages: true

tooling_bundles:
  github-toolkit:
    mcp_servers:
      - name: github
        type: builtin
        env:
          GITHUB_PERSONAL_ACCESS_TOKEN: "${from_host:GITHUB_TOKEN}"
    skills:
      - source: ~/.foundry/skills/team-review

  python-dev:
    packages:
      pip: [debugpy, pytest-watch]
      apt: [jq, ripgrep]
    permissions:
      allow: ["Bash(python *)", "Bash(pytest *)"]

  research-agent:
    mcp_servers:
      - name: tavily-search
        type: npm
        package: "@anthropic/mcp-tavily"
        env:
          TAVILY_API_KEY: "${from_host:TAVILY_API_KEY}"
    commands:
      - ~/.foundry/commands/deep-research.md
```

Each `ToolingBundle` can contain:

| Field | Type | Purpose |
|-------|------|---------|
| `skills` | `list[SkillSource]` | Claude skills (from host path or git URL) |
| `commands` | `list[str]` | Claude command files (host paths) |
| `mcp_servers` | `list[McpServer]` | MCP server declarations (builtin, proxy, npm) |
| `packages` | `PackageBootstrap` | Package prerequisites (pip, uv, apt, npm) |
| `permissions` | `Permissions` | Claude Code permissions (allow/deny lists) |
| `hooks` | `dict[str, list[HookRule]]` | Claude Code hooks |

### Referencing bundles from profiles

Profiles reference bundles via a `tooling` field:

```yaml
profiles:
  default:
    agent: claude
    tooling: [github-toolkit, python-dev]

  research:
    agent: claude
    tooling: [github-toolkit, research-agent]
```

### Expansion

When a profile is activated, its bundles are expanded into the standard config
surfaces before artifact compilation:

- `skills` → merged into `claude_code.skills`
- `commands` → merged into `claude_code.commands`
- `mcp_servers` → merged into top-level `mcp_servers`
- `packages` → additively merged with profile packages
- `permissions` → concatenated allow/deny lists
- `hooks` → merged per-key with rule concatenation

The existing compilers (`compile_mcp_servers`, `compile_claude_code`,
`bootstrap_packages`) are unchanged — bundles are a pre-compilation step.

### Conflict handling

| Surface | Rule |
|---------|------|
| MCP servers (same name) | Warning logged, later definition wins |
| Skills | Concatenate (idempotent by path) |
| Commands | Concatenate (idempotent by path) |
| Packages | Additive merge per type, deduped |
| Permissions | Concatenate allow/deny lists |
| Hooks | Merge per-key, concatenate rules |

### Gates

Bundles are subject to the same gates as direct config:

- `mcp_servers` with `type: npm` require `allow_third_party_mcp: true`.
- `packages` with `apt` or `npm` require `allow_system_packages: true`.

These gates use AND semantics across user and repo config layers. Any user/repo
layer setting `false` blocks the capability.

### Merge across layers

Bundles follow the same merge rule as profiles:

- Bundles with **different names** across layers are all available.
- For the **same name**, the user-layer bundle wins entirely.

### Where bundles can live

Bundles can appear in both user config (`~/.foundry/foundry.yaml`) and repo
config (`<repo>/foundry.yaml`). Repo bundles cannot reference host paths or
host credentials; put host-path skills, command files, proxy MCP declarations,
and `${from_host:VAR}` env values in user config.

### Generated files

The `.claude/` directory contents and `.mcp.json` produced by bundle expansion
are compiled artifacts, not source of truth. They are regenerated on each
sandbox creation from the declarative config. Do not edit them directly.

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
