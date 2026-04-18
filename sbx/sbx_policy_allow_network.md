# sbx policy allow network

|          |                                              |
| -------- | -------------------------------------------- |
| Description | Add a policy that permits sandboxes to access specified network resources. |
| Usage    | `sbx policy allow network RESOURCES [flags]` |

## Description

Add a policy that permits sandboxes to access specified network resources.

RESOURCES is a comma-separated list of hostnames, domains, or IP addresses. Supports:

- Exact domain names (e.g., `example.com`)
- Wildcard subdomains (e.g., `*.example.com`)
- Port suffixes (e.g., `example.com:443`)
- `"**"` to allow all traffic not on the deny list

## Options

| Option       | Default | Description          |
| ------------ | ------- | -------------------- |
| `-D, --debug` |         | Enable debug logging |

## Examples

Allow a single host:

```bash
$ sbx policy allow network example.com
```

Allow multiple hosts:

```bash
$ sbx policy allow network example.com,api.example.com
```

Allow all subdomains:

```bash
$ sbx policy allow network "*.example.com"
```

Allow all traffic:

```bash
$ sbx policy allow network "**"
```
