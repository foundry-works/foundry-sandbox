# sbx template rm

|              |                                      |
| ------------ | ------------------------------------ |
| Description  | Remove a template image               |
| Usage        | `sbx template rm TAG [flags]`         |

## Description

Remove a template image from the sandbox runtime's image store.

## Global options

| Option         | Default | Description              |
| -------------- | ------- | ------------------------ |
| `-D, --debug`  |         | Enable debug logging     |

## Examples

```bash
# Remove a template image
sbx template rm myimage:v1.0
```
