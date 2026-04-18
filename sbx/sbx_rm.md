# sbx rm

Remove one or more sandboxes.

## Usage

```bash
sbx rm [SANDBOX...] [flags]
```

## Description

Remove sandboxes. This stops running sandboxes, removes their containers, cleans up associated Git worktrees, and deletes sandbox state. Removed sandboxes cannot be recovered unless they were previously saved with `sbx save`.

## Options

| Option | Description |
|--------|-------------|
| `--all` | Remove all sandboxes |
| `-f, --force` | Skip confirmation prompt |

## Examples

```bash
# Remove a specific sandbox
sbx rm my-sandbox

# Remove multiple sandboxes
sbx rm sandbox1 sandbox2 sandbox3

# Remove all sandboxes without confirmation
sbx rm --all -f

# Remove a sandbox forcefully
sbx rm my-sandbox -f
```
