# sbx secret ls

List stored secrets.

## Usage

```bash
sbx secret ls [sandbox] [OPTIONS]
```

## Description

List secrets stored for a sandbox or globally. By default, lists all secrets (both global and sandbox-scoped). Use `--global` to list only global secrets, or specify a sandbox name to list secrets scoped to that sandbox.

## Options

| Option | Description |
|--------|-------------|
| `-g, --global` | Only list global secrets |
| `--service <service>` | Filter by service name |

## Examples

```bash
# List all secrets
sbx secret ls

# List only global secrets
sbx secret ls -g

# List secrets for a specific sandbox
sbx secret ls my-sandbox

# List secrets filtered by service
sbx secret ls --service github
```
