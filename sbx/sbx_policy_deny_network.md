# sbx policy deny network

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Add a policy that blocks sandboxes from accessing specified network resources. |
| Usage    | `sbx policy deny network RESOURCES [flags]`  |

## Description

Add a policy that blocks sandboxes from accessing specified network resources.

RESOURCES is a comma-separated list of hostnames, domains, or IP addresses.

## Options

| Option       | Default | Description          |
| ------------ | ------- | -------------------- |
| `-D, --debug` |         | Enable debug logging |

## Examples

Block a specific host:

```bash
$ sbx policy deny network malicious.example.com
```

Block all outbound traffic:

```bash
$ sbx policy deny network "**"
```
