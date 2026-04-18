# sbx secret set

Store a secret.

## Usage

```bash
sbx secret set [-g | sandbox] [service]
```

## Description

Store a secret for use by sandboxes. Secrets can be scoped globally (available to all sandboxes) or to a specific sandbox. The secret value is read from stdin, or can be provided via the `--token` flag.

Available services: `anthropic`, `aws`, `github`, `google`, `groq`, `mistral`, `nebius`, `openai`, `xai`.

## Options

| Option | Description |
|--------|-------------|
| `-f, --force` | Overwrite existing secret without confirmation |
| `-g, --global` | Store as a global secret |
| `--oauth` | Start OAuth flow (openai/global only) |
| `-t, --token <token>` | Provide the secret value via flag |

## Examples

```bash
# Store a global GitHub secret (reads from stdin)
sbx secret set -g github

# Pipe a secret value
echo "$ANTHROPIC_API_KEY" | sbx secret set -g anthropic

# Store a secret with the token flag
sbx secret set -g github -t "$(gh auth token)"

# Use OAuth flow for OpenAI
sbx secret set -g openai --oauth

# Store a secret scoped to a specific sandbox
sbx secret set my-sandbox anthropic
```
