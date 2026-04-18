# sbx policy rm network

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Remove a network policy.                     |
| Usage    | `sbx policy rm network [flags]`              |

## Description

Remove a network policy rule by its ID or by matching resource values.

## Options

| Option        | Default | Description                                    |
| ------------- | ------- | ---------------------------------------------- |
| `--id`        |         | Remove the policy rule with this ID             |
| `--resource`  |         | Remove policy rules matching these resource values (comma-separated) |
| `-D, --debug` |         | Enable debug logging                            |

## Examples

Remove by resource:

```bash
$ sbx policy rm network --resource example.com
```

Remove by rule ID:

```bash
$ sbx policy rm network --id abc123
```

Remove by both:

```bash
$ sbx policy rm network --id abc123 --resource example.com
```
