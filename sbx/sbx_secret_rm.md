# sbx secret rm

Remove a stored secret.

## Usage

```bash
sbx secret rm [-g | sandbox] [service]
```

## Description

Remove a secret that was previously stored. You can remove a global secret or a secret scoped to a specific sandbox. By default, the command prompts for confirmation before deleting.

## Options

| Option | Description |
|--------|-------------|
| `-f, --force` | Delete without confirmation |
| `-g, --global` | Remove a global secret |

## Examples

```bash
# Remove a global secret
sbx secret rm -g github

# Remove a secret scoped to a sandbox
sbx secret rm my-sandbox openai

# Remove a global secret without confirmation
sbx secret rm -g github -f
```
