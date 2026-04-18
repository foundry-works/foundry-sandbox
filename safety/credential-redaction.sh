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
#
# Pattern sources: gitleaks (https://github.com/gitleaks/gitleaks)

# =============================================================================
# Redaction patterns for common API key formats
# Organized by category for maintainability
# =============================================================================

# Cloud Providers
_PATTERN_AWS='(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}'
_PATTERN_AWS_SECRET='[a-zA-Z0-9+/]{40}'  # Base64-ish, 40 chars
_PATTERN_GCP='AIza[a-zA-Z0-9_-]{35}'
_PATTERN_AZURE='[a-zA-Z0-9_~.]{3}[0-9]Q~[a-zA-Z0-9_~.-]{31,34}'

# AI/LLM Providers
_PATTERN_ANTHROPIC='sk-ant-[a-zA-Z0-9_-]{20,}'
_PATTERN_OPENAI='sk-(proj-|svcacct-)?[a-zA-Z0-9_-]{20,}'
_PATTERN_GOOGLE_AI='AIza[a-zA-Z0-9_-]{35}'
_PATTERN_COHERE='[a-zA-Z0-9]{40}'  # Cohere API keys

# Code Hosting
_PATTERN_GITHUB='(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}'
_PATTERN_GITHUB_PAT='github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}'
_PATTERN_GITHUB_APP='(ghs|ghr)_[a-zA-Z0-9]{36}'
_PATTERN_GITLAB='glpat-[a-zA-Z0-9_-]{20}'
_PATTERN_GITLAB_RUNNER='GR1348941[a-zA-Z0-9_-]{20}'
_PATTERN_BITBUCKET='ATBB[a-zA-Z0-9]{32}'

# Payment
_PATTERN_STRIPE='(sk|rk|pk)_(test|live|prod)_[a-zA-Z0-9]{10,99}'
_PATTERN_SQUARE='sq0(atp|csp)-[0-9A-Za-z_-]{22,43}'
_PATTERN_PAYPAL='access_token\$[a-zA-Z0-9_-]+'

# Communication
_PATTERN_SLACK='xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z-]*'
_PATTERN_SLACK_WEBHOOK='hooks\.slack\.com/(services|workflows)/[A-Za-z0-9+/]{43,56}'
_PATTERN_TWILIO='(SK|AC)[0-9a-fA-F]{32}'
_PATTERN_SENDGRID='SG\.[a-zA-Z0-9=_.-]{66}'
_PATTERN_MAILGUN='key-[a-zA-Z0-9]{32}'
_PATTERN_MAILCHIMP='[a-f0-9]{32}-us[0-9]{1,2}'
_PATTERN_DISCORD_WEBHOOK='discord(app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+'
_PATTERN_DISCORD_TOKEN='[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'

# Package Registries
_PATTERN_NPM='npm_[A-Za-z0-9]{36}'
_PATTERN_PYPI='pypi-[A-Za-z0-9_-]{40,}'
_PATTERN_RUBYGEMS='rubygems_[a-f0-9]{48}'
_PATTERN_NUGET='oy2[a-z0-9]{43}'

# Infrastructure/DevOps
_PATTERN_TERRAFORM='[a-z0-9]{14}\.atlasv1\.[a-z0-9_=-]{60,70}'
_PATTERN_DIGITALOCEAN='dop_v1_[a-z0-9]{64}'
_PATTERN_HEROKU='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
_PATTERN_VAULT='hvs\.[a-zA-Z0-9_-]{24,}'
_PATTERN_DOPPLER='dp\.st\.[a-z0-9_-]{40,}'
_PATTERN_NETLIFY='[a-zA-Z0-9_-]{40,}'  # Netlify personal access tokens
_PATTERN_VERCEL='[a-zA-Z0-9]{24}'

# Database
_PATTERN_POSTGRES='postgres(ql)?://[^:]+:[^@]+@'
_PATTERN_MYSQL='mysql://[^:]+:[^@]+@'
_PATTERN_MONGODB='mongodb(\+srv)?://[^:]+:[^@]+@'
_PATTERN_REDIS='redis://[^:]+:[^@]+@'

# Generic/Crypto
_PATTERN_JWT='eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
_PATTERN_PRIVATE_KEY='-----BEGIN[A-Z ]*PRIVATE KEY-----'
_PATTERN_BEARER='Bearer [a-zA-Z0-9_.-]+'
_PATTERN_BASIC_AUTH='Basic [a-zA-Z0-9+/=]+'

# Generic env var patterns (KEY=value, TOKEN=value, etc.)
_PATTERN_GENERIC_ENV='(API_KEY|API_SECRET|AUTH_TOKEN|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|PASSWORD|CREDENTIAL|CLIENT_SECRET|APP_SECRET|SIGNING_SECRET)[=:][^[:space:]]+'

# Specific service env vars
_PATTERN_SERVICE_ENV='(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|STRIPE_SECRET_KEY|DATABASE_URL|REDIS_URL)[=:][^[:space:]]+'

# =============================================================================
# Combined pattern for sed
# =============================================================================
_REDACT_PATTERNS="${_PATTERN_AWS}|${_PATTERN_GCP}|${_PATTERN_AZURE}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_ANTHROPIC}|${_PATTERN_OPENAI}|${_PATTERN_GOOGLE_AI}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_GITHUB}|${_PATTERN_GITHUB_PAT}|${_PATTERN_GITHUB_APP}|${_PATTERN_GITLAB}|${_PATTERN_GITLAB_RUNNER}|${_PATTERN_BITBUCKET}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_STRIPE}|${_PATTERN_SQUARE}|${_PATTERN_PAYPAL}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_SLACK}|${_PATTERN_SLACK_WEBHOOK}|${_PATTERN_TWILIO}|${_PATTERN_SENDGRID}|${_PATTERN_MAILGUN}|${_PATTERN_MAILCHIMP}|${_PATTERN_DISCORD_WEBHOOK}|${_PATTERN_DISCORD_TOKEN}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_NPM}|${_PATTERN_PYPI}|${_PATTERN_RUBYGEMS}|${_PATTERN_NUGET}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_TERRAFORM}|${_PATTERN_DIGITALOCEAN}|${_PATTERN_VAULT}|${_PATTERN_DOPPLER}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_POSTGRES}|${_PATTERN_MYSQL}|${_PATTERN_MONGODB}|${_PATTERN_REDIS}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_JWT}|${_PATTERN_PRIVATE_KEY}|${_PATTERN_BEARER}|${_PATTERN_BASIC_AUTH}"
_REDACT_PATTERNS="${_REDACT_PATTERNS}|${_PATTERN_GENERIC_ENV}|${_PATTERN_SERVICE_ENV}"

# Redact sensitive patterns from stdin
_redact_output() {
    sed -E "s#${_REDACT_PATTERNS}#[REDACTED]#g"
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

# Wrap curl - filter verbose/debug output which can leak auth headers
curl() {
    # Check if verbose/debug flags are present (auth headers appear in stderr)
    if [[ "$*" =~ (-v|--verbose|-D|--dump-header|--trace) ]]; then
        command curl "$@" 2>&1 | _redact_output
    else
        command curl "$@"
    fi
}

# Wrap wget - filter verbose/debug output which can leak auth headers
wget() {
    # Check if verbose/debug flags are present
    if [[ "$*" =~ (-v|--verbose|-d|--debug) ]]; then
        command wget "$@" 2>&1 | _redact_output
    else
        command wget "$@"
    fi
}

# Wrap export (when listing) to redact sensitive values
# Note: This only catches 'export -p' style listing, not setting
export() {
    if [[ "$#" -eq 0 ]] || [[ "$1" == "-p" ]]; then
        builtin export "$@" | _redact_output
    else
        builtin export "$@"
    fi
}

# Export functions for subshells
export -f _redact_output env printenv curl wget
