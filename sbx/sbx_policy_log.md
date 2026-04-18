# sbx policy log

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Show policy log entries.                     |
| Usage    | `sbx policy log [SANDBOX] [flags]`           |

## Description

Show policy log entries for all sandboxes, or filter by a specific sandbox name.

## Options

| Option       | Default | Description                                      |
| ------------ | ------- | ------------------------------------------------ |
| `--json`     |         | Format output as JSON                             |
| `--limit`    | `0`     | Maximum number of log entries to show (0 = all)   |
| `-q, --quiet` |         | Only show sandbox names                           |
| `--type`     | `all`   | Type of policy to show (`all` or `network`)       |
| `-D, --debug` |         | Enable debug logging                              |

## Examples

Show all policy logs:

```bash
$ sbx policy log
```

Show logs for a specific sandbox:

```bash
$ sbx policy log my-sandbox
```

Show logs in JSON format:

```bash
$ sbx policy log --json
```

Show limited entries:

```bash
$ sbx policy log --limit 10
```
