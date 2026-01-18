#!/bin/bash
# Credential Redaction Layer (UX PROTECTION ONLY)
# Installed to /etc/profile.d/ for all bash sessions
#
# NOTE: This is NOT a security boundary. Commands can bypass these wrappers via:
#   /usr/bin/env, command env, \env, etc.
#
# This layer provides automatic redaction of sensitive credentials in output
# from common inspection commands to help a non-adversarial AI avoid
# accidentally exposing API keys, tokens, and other secrets.

# =============================================================================
# Redaction patterns for common API key formats
# =============================================================================

# Patterns matched:
# - Anthropic: sk-ant-api03-... (40+ chars)
# - OpenAI: sk-... (40+ chars)
# - Generic: API_KEY=..., TOKEN=..., SECRET=..., PASSWORD=...
# - Bearer tokens: Bearer ...
# - AWS: AKIA... (20 chars for access key ID)
_REDACT_PATTERNS='sk-ant-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|(ANTHROPIC_API_KEY|OPENAI_API_KEY|API_KEY|AUTH_TOKEN|SECRET_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|PASSWORD)=[^[:space:]]+|Bearer [a-zA-Z0-9_-]+'

# Redact sensitive patterns from stdin
_redact_output() {
    sed -E "s/($_REDACT_PATTERNS)/[REDACTED]/g"
}

# =============================================================================
# Command wrappers that apply redaction
# =============================================================================

# Wrap env to redact API keys from environment output
env() {
    command env "$@" | _redact_output
}

# Wrap printenv to redact API keys
printenv() {
    command printenv "$@" | _redact_output
}

# Wrap set (when used to show variables) to redact sensitive values
# Note: set is a shell builtin, so we use a function that calls builtin
# This only catches explicit 'set' calls, not subshell set operations

# Export functions for subshells
export -f _redact_output env printenv
