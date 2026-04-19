# Security Model

## Threat Model

The primary threat is an **untrusted AI agent** running inside a sandboxed environment with git access. The agent may:

1. Attempt to push to protected branches (`main`, `release/*`, etc.)
2. Modify CI/CD configuration files (`.github/workflows/`, `Makefile`)
3. Access other sandbox branches (cross-tenant data leakage)
4. Use dangerous git flags (`--force`, `--git-dir`, `-c core.hooksPath`)
5. Bypass security via GitHub API operations (merge PRs, modify branch protection)
6. Replay or spoof authentication requests

## Trust Boundaries

```
┌──────────────────────────────────────────────────┐
│  UNTRUSTED (sandbox)                             │
│  ┌────────────┐   ┌────────────┐                 │
│  │ AI agent   │──►│ git wrapper│──── HTTP ────►  │──► git safety server
│  └────────────┘   └────────────┘                 │    (TRUSTED)
└──────────────────────────────────────────────────┘
```

- **Sandbox** → untrusted; the agent has full shell access
- **Network** → HMAC-authenticated HTTP; replay-protected with nonces
- **Server** → trusted; validates all requests before execution
- **Git binary** → trusted; only invoked with validated arguments

## Security Layers

### Layer 1: HMAC Authentication

Every request requires a valid HMAC-SHA256 signature computed over a canonical request string (`method\npath\nbody_hash\ntimestamp\nnonce`). Nonces are tracked per-sandbox with TTL-based eviction to prevent replay attacks. Timestamps must be within a 5-minute clock window.

### Layer 2: Command Allowlist

Only explicitly allowed git commands can execute. The allowlist covers common safe operations (`status`, `log`, `diff`, `add`, `commit`, `push`, `fetch`, `branch`, `checkout`, etc.). Any command not on the list is rejected.

### Layer 3: Flag Blocklist

Dangerous flags are blocked per-command:
- `--git-dir` / `--work-tree`: blocked globally (path traversal vector)
- `--force` / `--force-with-lease`: blocked for push
- `-i` / `--interactive`: blocked for rebase (editor escape)
- `-D`: blocked for branch (force deletion)
- `-c core.hooksPath` / `-c credential.helper`: blocked (code execution / credential theft)

### Layer 4: Branch Isolation

Sandbox agents can only interact with their own branch (`sandbox/<id>`) and well-known branches (`main`, `master`, `develop`, `production`, `release/*`, `hotfix/*`). This is enforced on:
- **Input**: checkout, switch, fetch, push, log, diff, tag, worktree commands are validated
- **Output**: branch listings, ref enumerations, log decorations, stderr messages are filtered
- **SHA reachability**: SHA arguments are verified as ancestors of allowed branches

### Layer 5: Protected Branch Enforcement

Direct pushes (create, update, delete) to protected branches are blocked. The only exception is an atomic bootstrap mechanism that allows the first `refs/heads/main` creation via an O_EXCL lock file.

### Layer 6: File Restriction Enforcement

Pushes and commits that modify restricted files are blocked:
- **Blocked**: `.github/workflows/`, `.github/actions/`, `Makefile`, `.pre-commit-config.yaml`
- **Warned**: `package.json`, `pyproject.toml`, `docker-compose.yml`, etc. (configurable as log or reject)

Fails closed: if the config cannot be loaded or the diff cannot be computed, the operation is blocked.

### Layer 7: GitHub API Filtering

A dedicated HTTP proxy blocks dangerous GitHub API operations:
- REST: PR merges, release creation, ref mutations, webhook/secret/deploy-key access
- GraphQL: merge mutations, auto-merge, PR review self-approval
- Body inspection: PR/issue close, PR review approval

### Layer 8: Rate Limiting

Three tiers prevent abuse:
- **Per-IP throttle**: 100 requests per minute per IP (pre-auth)
- **Per-sandbox token bucket**: 300 burst, 120 sustained per minute
- **Global ceiling**: 1000 requests per minute across all sandboxes

## Fail-Closed Principles

1. **Deny-by-default**: Unknown commands, flags, and paths are rejected
2. **Config failure = block**: If configuration cannot be loaded, operations are blocked
3. **Diff failure = block**: If file diffs cannot be computed, pushes are blocked
4. **Parse failure = block**: Malformed JSON, pkt-line data, or request bodies are rejected
5. **Output filtering**: Unrecognized git output formats are passed through without modification (worst case: minor information leak, never data corruption)

## Audit Logging

All git operations are logged with structured JSON:
- Request ID, sandbox ID, source IP
- Command arguments (sanitized)
- Decision (allow/deny) with reason
- Exit code, truncated stdout/stderr
- Policy version for schema evolution

Sensitive data (stdin, HMAC secrets, authorization headers) is never included in audit logs.
