# sbx policy reset

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Remove all custom policies and restart the daemon. |
| Usage    | `sbx policy reset [flags]`                   |

## Description

Remove all custom policies and restart the daemon. This will stop any running sandboxes.

## Options

| Option       | Default | Description                        |
| ------------ | ------- | ---------------------------------- |
| `-f, --force` |         | Skip confirmation prompt           |
| `-D, --debug` |         | Enable debug logging               |

## Examples

Reset with confirmation:

```bash
$ sbx policy reset
```

Reset without confirmation:

```bash
$ sbx policy reset --force
```
