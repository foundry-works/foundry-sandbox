# sbx stop

Stop one or more running sandboxes.

## Usage

```bash
sbx stop SANDBOX [SANDBOX...]
```

## Description

Stop sandboxes without removing them. Stopped sandboxes retain their state and can be restarted with `sbx run`. Use `sbx rm` to permanently remove a sandbox.

## Examples

```bash
# Stop a single sandbox
sbx stop my-sandbox

# Stop multiple sandboxes
sbx stop sandbox1 sandbox2 sandbox3
```
