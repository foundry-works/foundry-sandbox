# sbx policy set-default

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Set the default policy applied to sandboxes. |
| Usage    | `sbx policy set-default <allow-all|balanced|deny-all> [flags]` |

## Description

Set the default policy applied to all sandboxes. This must be run before adding custom allow or deny rules. The default policy determines the baseline behavior for network access.

Available policies:

- **allow-all** - Allow all outbound network traffic by default
- **balanced** - Allow common development traffic (package registries, APIs, etc.) and block everything else
- **deny-all** - Block all outbound network traffic by default

## Options

| Option       | Default | Description          |
| ------------ | ------- | -------------------- |
| `-D, --debug` |         | Enable debug logging |

## Examples

Set default to allow-all:

```bash
$ sbx policy set-default allow-all
```

Set default to balanced:

```bash
$ sbx policy set-default balanced
```

Set default to deny-all:

```bash
$ sbx policy set-default deny-all
```
