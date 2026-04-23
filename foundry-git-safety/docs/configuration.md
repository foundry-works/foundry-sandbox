# Configuration Reference

## foundry.yaml

The primary configuration file, read from the workspace root or the path specified by `FOUNDRY_CONFIG_PATH`.

### Top-level schema

```yaml
version: "1"
user_services:
  - ...
git_safety:
  server: ...
  protected_branches: ...
  file_restrictions: ...
  branch_isolation: ...
  rate_limits: ...
```

### user_services

Top-level proxy credential declarations consumed by the user-services proxy.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Human-readable service name |
| `env_var` | string | required | Host environment variable holding the real credential |
| `domain` | string | required | Upstream service domain |
| `header` | string | `Authorization` | Header name, or query parameter name when `format: query` |
| `format` | string | `bearer` | Credential transport: `bearer`, `header`, or `query` |
| `methods` | list of strings | `[]` | Optional allowed HTTP methods |
| `paths` | list of strings | `[]` | Optional allowed path globs |
| `scheme` | string | `https` | Upstream scheme |
| `port` | integer | `0` | Upstream port override; `0` means default for scheme |

### server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `127.0.0.1` | Server bind address |
| `port` | integer | `8083` | Server bind port (1-65535) |
| `secrets_path` | string | `~/.foundry/secrets/sandbox-hmac` | Directory containing per-sandbox HMAC secret files |
| `data_dir` | string | `~/.foundry/data/git-safety` | Directory for server state (metadata files) |

### protected_branches

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable protected branch enforcement |
| `patterns` | list of strings | `["refs/heads/main", "refs/heads/master", "refs/heads/release/*", "refs/heads/production"]` | Branch name patterns (fnmatch syntax) |

### file_restrictions

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `blocked_patterns` | list of strings | `[".github/workflows/", ".github/actions/", "Makefile", "Justfile", "Taskfile.yml", ".pre-commit-config.yaml", "CODEOWNERS", ".github/FUNDING.yml", ".env*"]` | File patterns that trigger a hard block |
| `warned_patterns` | list of strings | `["package.json", "pyproject.toml", "requirements.txt", "requirements-*.txt", "Gemfile", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "docker-compose*.yml", "Dockerfile"]` | File patterns that trigger a warning |
| `warn_action` | string | `"reject"` | Warning behavior: `"reject"` (default, blocks push) or `"log"` (allow with warning) |

**Pattern semantics:**
- Trailing `/` matches directory prefix (`.github/workflows/` matches all files in that directory)
- `*` and `?` are glob wildcards (`*.yml` matches any YAML file)
- No prefix is a basename exact match (`Makefile` matches only `Makefile`)

### branch_isolation

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable branch isolation |
| `well_known_branches` | list of strings | `["main", "master", "develop", "production"]` | Branches visible to all sandboxes |
| `well_known_prefixes` | list of strings | `["release/", "hotfix/"]` | Branch prefixes visible to all sandboxes |

### rate_limits

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `burst` | integer | `300` | Per-sandbox burst capacity |
| `sustained` | integer | `120` | Per-sandbox sustained rate (requests per minute) |
| `global_ceiling` | integer | `1000` | Global requests per minute across all sandboxes |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FOUNDRY_CONFIG_PATH` | (none) | Path to `foundry.yaml` |
| `FOUNDRY_FILE_RESTRICTIONS_PATH` | (none) | Path to `push-file-restrictions.yaml` |
| `FOUNDRY_DATA_DIR` | `~/.foundry/data/git-safety` | Server state directory |
| `GIT_API_SECRETS_PATH` | `~/.foundry/secrets/sandbox-hmac` | HMAC secrets directory |
| `GIT_PROTECTED_BRANCHES_ENABLED` | (none) | Override protected branch enforcement |
| `GIT_PROTECTED_BRANCHES_PATTERNS` | (none) | Comma-separated protected patterns |
| `GIT_CLIENT_WORKSPACE_ROOT` | (none) | Client-side workspace root for path translation |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_FORMAT` | `json` | Logging format (`json` or `text`) |
| `LOG_INCLUDE_TIMESTAMP` | `true` | Include timestamp in log output |
| `LOG_INCLUDE_LOCATION` | `true` | Include source location in log output |

These defaults assume standalone host usage. Containerized deployments can still override them with `FOUNDRY_DATA_DIR` and `GIT_API_SECRETS_PATH`.

## Protected Branch Pattern Syntax

Patterns use Python `fnmatch` syntax:
- `refs/heads/main` — exact match
- `refs/heads/release/*` — matches any single path component (e.g., `refs/heads/release/v1.0`)
- `refs/heads/release/**` — matches multiple path components

Pattern matching is precedence-layered: metadata > environment variables > defaults.

## File Restriction Pattern Syntax

Three pattern types:
1. **Directory prefix** (ends with `/`): `.github/workflows/` matches all files recursively under that directory
2. **Glob wildcard**: `*.txt` matches any file with `.txt` extension
3. **Basename exact**: `Makefile` matches only files named exactly `Makefile`

Path traversal attempts (e.g., `../.github/workflows/ci.yml`) are normalized before matching.
