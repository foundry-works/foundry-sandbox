# foundry-git-safety

Standalone git safety layer for sandbox environments. Validates, filters, and audits git operations to prevent unauthorized access to protected branches and sensitive files.

## Overview

foundry-git-safety runs as an authenticated TCP server that sits between sandboxed git clients and the real git binary. Every git command is validated against a deny-by-default allowlist before execution, with additional layers for branch isolation, protected branch enforcement, and output filtering.

**Security model:**
- **Deny-by-default command allowlist** — only explicitly allowed git commands run
- **Branch isolation** — sandbox agents see only their own branch and well-known branches
- **Protected branch enforcement** — pushes to `main`, `master`, `release/*`, `production` are blocked
- **File restriction enforcement** — pushes modifying `.github/workflows/`, CI configs, etc. are blocked
- **Output filtering** — cross-sandbox branch names are stripped from git output
- **HMAC authentication** — every request is authenticated with per-sandbox secrets
- **Audit logging** — all operations logged with structured JSON

```
┌─────────────┐    HTTP POST     ┌──────────────────┐    subprocess    ┌──────────┐
│  git wrapper │ ──────────────► │  git safety       │ ──────────────► │ git      │
│  (in sandbox) │ ◄────────────── │  server           │ ◄────────────── │ binary   │
└─────────────┘   JSON response  └──────────────────┘   stdout/stderr   └──────────┘
                                    │
                                    ├─ HMAC auth + nonce replay protection
                                    ├─ Command allowlist + flag blocklist
                                    ├─ Branch isolation (input validation)
                                    ├─ Protected branch enforcement
                                    ├─ File restriction enforcement
                                    ├─ Output filtering (branch name redaction)
                                    └─ Rate limiting (per-sandbox + global)
```

## Installation

```bash
# Core package (CLI + validation)
pip install foundry-git-safety

# With server dependencies (Flask)
pip install foundry-git-safety[server]

# Development dependencies (pytest, mypy, ruff)
pip install foundry-git-safety[dev]
```

## Quick Start

```bash
# Validate configuration
foundry-git-safety validate

# Start the server (foreground)
foundry-git-safety start --foreground --port 8083

# Start as daemon
foundry-git-safety start --port 8083 --pid-file /run/foundry-git-safety.pid

# Check status
foundry-git-safety status

# Stop the server
foundry-git-safety stop
```

## Configuration

foundry-git-safety reads `foundry.yaml` from the workspace root. See `foundry_git_safety/default_config/foundry.yaml.example` for a complete example with all options.

```yaml
version: "1.0"
git_safety:
  server:
    host: "127.0.0.1"
    port: 8083
    secrets_path: "/run/secrets/sandbox-hmac"
    data_dir: "/var/lib/foundry-git-safety"

  protected_branches:
    enabled: true
    patterns:
      - "refs/heads/main"
      - "refs/heads/master"
      - "refs/heads/release/*"
      - "refs/heads/production"

  file_restrictions:
    blocked_patterns:
      - ".github/workflows/"
      - ".github/actions/"
      - "Makefile"
      - "Justfile"
      - "Taskfile.yml"
      - ".pre-commit-config.yaml"
      - "CODEOWNERS"
      - ".github/FUNDING.yml"
      - ".env*"
    warned_patterns:
      - "package.json"
      - "pyproject.toml"
    warn_action: "reject"  # "reject" (default, blocks push) or "log"

  branch_isolation:
    enabled: true
    well_known_branches: ["main", "master", "develop", "production"]
    well_known_prefixes: ["release/", "hotfix/"]

  rate_limits:
    burst: 300
    sustained: 120
    global_ceiling: 1000
```

### Environment Variable Overrides

| Variable | Description |
|----------|-------------|
| `GIT_PROTECTED_BRANCHES_ENABLED` | Override protected branch enforcement (`true`/`false`) |
| `GIT_PROTECTED_BRANCHES_PATTERNS` | Comma-separated protected branch patterns |
| `FOUNDRY_CONFIG_PATH` | Path to `foundry.yaml` |
| `FOUNDRY_FILE_RESTRICTIONS_PATH` | Path to `push-file-restrictions.yaml` |
| `FOUNDRY_DATA_DIR` | Data directory for server state |
| `GIT_CLIENT_WORKSPACE_ROOT` | Override workspace root path for git operations |
| `GIT_API_SECRETS_PATH` | Path to HMAC secrets directory |
| `LOG_LEVEL` | Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LOG_FORMAT` | Log format (`json` or `text`) |

## API Reference

### POST `/git/exec`

Execute a validated git command.

**Request:**
```json
{
  "args": ["status", "--short"],
  "cwd": "/workspace",
  "stdin_b64": null
}
```

**Authentication headers:**
| Header | Description |
|--------|-------------|
| `X-Sandbox-Id` | Sandbox identifier |
| `X-Request-Timestamp` | Unix timestamp (seconds) |
| `X-Request-Nonce` | Unique request nonce (UUID) |
| `X-Request-Signature` | HMAC-SHA256 signature |

**Response (200):**
```json
{
  "exit_code": 0,
  "stdout": " M src/main.py",
  "stderr": "",
  "truncated": false
}
```

**Error responses:**
| Status | Condition |
|--------|-----------|
| 400 | Invalid JSON or malformed request |
| 401 | Authentication failure (missing/invalid HMAC) |
| 413 | Request body exceeds 256KB |
| 422 | Command blocked by policy |
| 429 | Rate limit exceeded |

### GET `/health`

Health check endpoint. Returns `200` with `{"status": "ok"}`.

## GitHub API Filtering

The built-in GitHub API proxy blocks dangerous operations:

**Always blocked:**
- PR merges (REST and GraphQL)
- Release creation
- Git ref creation/mutation/deletion
- Webhook management
- Deploy key management
- Branch protection modification
- Secrets/variables access
- PR review self-approval
- PR/issue close via API

**Conditionally blocked (require `allow_pr_operations: true`):**
- PR creation
- PR comment operations
- PR review submission

**Always allowed:**
- All GET requests to allowed endpoints
- Issue creation and commenting
- Content upload (git blobs, trees, commits, tags)

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run unit tests
pytest tests/unit/

# Run security tests only
pytest -m security

# Run all tests
pytest

# Type checking
mypy foundry_git_safety/

# Linting
ruff check .
```

## License

MIT
