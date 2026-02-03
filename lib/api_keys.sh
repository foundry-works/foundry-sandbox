#!/bin/bash
# API key validation utilities

# Claude authentication - at least one required
AI_PROVIDER_KEYS=(
    "CLAUDE_CODE_OAUTH_TOKEN"
    "ANTHROPIC_API_KEY"
)

# Colors (defined locally for use in install.sh which doesn't load other libs)
_API_KEYS_RED='\033[0;31m'
_API_KEYS_GREEN='\033[0;32m'
_API_KEYS_YELLOW='\033[1;33m'
_API_KEYS_NC='\033[0m'

# Check if at least one AI provider key is set
# Returns: 0 if found, 1 if none
check_any_ai_key() {
    for key in "${AI_PROVIDER_KEYS[@]}"; do
        if [ -n "${!key:-}" ]; then
            return 0
        fi
    done
    return 1
}

# ============================================================================
# CLI-specific key detection functions
# ============================================================================

# Check if Claude authentication is available
# Returns: 0 if found, 1 if not
has_claude_key() {
    [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] || [ -n "${ANTHROPIC_API_KEY:-}" ]
}

# Check if Gemini OAuth credentials exist
# Returns: 0 if found, 1 if not
has_gemini_key() {
    if [ -f "$HOME/.gemini/oauth_creds.json" ]; then
        return 0
    fi
    if [ -n "${GEMINI_API_KEY:-}" ] && [ "${GEMINI_API_KEY}" != "CREDENTIAL_PROXY_PLACEHOLDER" ]; then
        return 0
    fi
    return 1
}

# Check if OpenCode auth file exists
# Returns: 0 if found, 1 if not
has_opencode_key() {
    [ -f "$HOME/.local/share/opencode/auth.json" ]
}

# Check if Codex authentication is available
# Returns: 0 if found, 1 if not
has_codex_key() {
    [ -f "$HOME/.codex/auth.json" ] || [ -n "${OPENAI_API_KEY:-}" ]
}

# Check if ZAI (Zhipu) API key is available
# Returns: 0 if found, 1 if not
has_zai_key() {
    [ -n "${ZHIPU_API_KEY:-}" ] \
        && [ "${ZHIPU_API_KEY}" != "CREDENTIAL_PROXY_PLACEHOLDER" ] \
        && [ "${ZHIPU_API_KEY}" != "PROXY_PLACEHOLDER_OPENCODE" ]
}

# Warn if multiple Claude auth modes are configured
warn_claude_auth_conflict() {
    if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -n "${ANTHROPIC_API_KEY:-}" ]; then
        echo -e "${_API_KEYS_YELLOW}Note: Both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY are set.${_API_KEYS_NC}"
        echo "  Claude Code will prefer OAuth; consider unsetting one to avoid ambiguity."
        echo ""
    fi
}

# Check if OpenCode is explicitly enabled and authenticated
# Returns: 0 if enabled and auth present, 1 otherwise
opencode_enabled() {
    [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ] && has_opencode_key
}

# ============================================================================
# Claude mandatory check and optional CLI warnings
# ============================================================================

# Check that Claude authentication is present (mandatory)
# Returns: 0 if present, 1 if missing
check_claude_key_required() {
    if ! has_claude_key; then
        echo -e "${_API_KEYS_RED}Error: Claude Code requires authentication.${_API_KEYS_NC}"
        echo ""
        echo "Set one of:"
        echo "  - CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)"
        echo "  - ANTHROPIC_API_KEY"
        echo ""
        return 1
    fi
    warn_claude_auth_conflict
    return 0
}

# Show warnings for optional CLIs that are not configured
show_optional_cli_warnings() {
    local warned=false

    if ! has_gemini_key; then
        echo -e "${_API_KEYS_YELLOW}Note: Gemini CLI not configured${_API_KEYS_NC}"
        echo "  Run 'gemini auth' or set GEMINI_API_KEY"
        warned=true
    fi

    if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ]; then
        if ! has_opencode_key; then
            echo -e "${_API_KEYS_YELLOW}Note: OpenCode CLI not configured${_API_KEYS_NC}"
            echo "  Run 'opencode auth login' to authenticate"
            warned=true
        fi
    fi

    if ! has_codex_key; then
        echo -e "${_API_KEYS_YELLOW}Note: Codex CLI not configured${_API_KEYS_NC}"
        echo "  Run 'codex auth' or set OPENAI_API_KEY"
        warned=true
    fi

    if [ "$warned" = "true" ]; then
        echo ""
    fi
}

# Display CLI configuration status for sandbox setup
# Shows which CLIs are configured (not warnings, just status)
show_cli_status() {
    # Claude (always configured at this point - checked earlier)
    log_step "Claude: configured"

    # GitHub CLI
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        log_step "GitHub CLI: configured"
    else
        log_step "GitHub CLI: not configured"
    fi

    # Gemini
    if has_gemini_key; then
        log_step "Gemini: configured"
    else
        log_step "Gemini: not configured"
    fi

    # Codex
    if has_codex_key; then
        log_step "Codex: configured"
    else
        log_step "Codex: not configured"
    fi

    # OpenCode (only if enabled)
    if [ "$SANDBOX_ENABLE_OPENCODE" = "1" ]; then
        if has_opencode_key; then
            log_step "OpenCode: configured"
        else
            log_step "OpenCode: not configured"
        fi
    fi

    # Search providers
    local search_providers=""
    [ -n "${TAVILY_API_KEY:-}" ] && search_providers="Tavily"
    [ -n "${PERPLEXITY_API_KEY:-}" ] && {
        [ -n "$search_providers" ] && search_providers="$search_providers, "
        search_providers="${search_providers}Perplexity"
    }
    if [ -n "$search_providers" ]; then
        log_step "Search: $search_providers"
    else
        log_step "Search: not configured"
    fi
}

# Check if at least one search provider is configured
# Requires: TAVILY_API_KEY OR PERPLEXITY_API_KEY
# Returns: 0 if found, 1 if none
check_any_search_key() {
    # Tavily
    if [ -n "${TAVILY_API_KEY:-}" ]; then
        return 0
    fi
    # Perplexity
    if [ -n "${PERPLEXITY_API_KEY:-}" ]; then
        return 0
    fi
    return 1
}

# Display warning about missing AI provider keys
show_missing_ai_keys_warning() {
    echo -e "${_API_KEYS_YELLOW}Warning: Claude authentication not found.${_API_KEYS_NC}"
    echo ""
    echo "Expected one of:"
    echo "  - CLAUDE_CODE_OAUTH_TOKEN (run: claude setup-token)"
    echo "  - ANTHROPIC_API_KEY"
    echo ""
}

# Display warning about missing search provider keys
show_missing_search_keys_warning() {
    echo -e "${_API_KEYS_YELLOW}Warning: No search provider API keys found.${_API_KEYS_NC}"
    echo "Deep research features (foundry-mcp) will be unavailable."
    echo ""
    echo "Expected at least one of:"
    echo "  - TAVILY_API_KEY"
    echo "  - PERPLEXITY_API_KEY"
    echo ""
}

# Display warning about missing keys (both AI and search)
show_missing_keys_warning() {
    local missing_ai=false
    local missing_search=false

    if ! check_any_ai_key; then
        missing_ai=true
        show_missing_ai_keys_warning
    fi

    if ! check_any_search_key; then
        missing_search=true
        show_missing_search_keys_warning
    fi

    if [ "$missing_ai" = "true" ] || [ "$missing_search" = "true" ]; then
        echo "Set the required environment variables before running:"
        echo "  export CLAUDE_CODE_OAUTH_TOKEN=\"your-token\""
        echo "  export ANTHROPIC_API_KEY=\"your-key\""
        echo "  export TAVILY_API_KEY=\"your-key\""
        echo ""
        echo "See .env.example for all supported keys."
        echo ""
    fi
}

# Display warning and prompt to continue
# Returns: 0 to continue, 1 to abort
prompt_missing_keys() {
    show_missing_keys_warning
    read -p "Continue without API keys? [y/N]: " response
    case "$response" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# Full API key check with prompt
# Use this in scripts to check keys and prompt if missing
# Arguments:
#   $1 - context message (e.g., "Installation", "Sandbox creation")
# Returns: 0 to proceed, 1 to abort
check_api_keys_with_prompt() {
    local context="${1:-Operation}"
    local has_ai_key=false
    local has_search_key=false

    # Keys are expected to be set in the environment
    if check_any_ai_key; then
        has_ai_key=true
    fi
    if check_any_search_key; then
        has_search_key=true
    fi
    if [ "$has_ai_key" = "true" ]; then
        warn_claude_auth_conflict
    fi

    # All keys present
    if [ "$has_ai_key" = "true" ] && [ "$has_search_key" = "true" ]; then
        echo -e "  ${_API_KEYS_GREEN}✓${_API_KEYS_NC} API keys configured"
        return 0
    fi

    # AI key present but no search key - just warn, don't prompt
    if [ "$has_ai_key" = "true" ] && [ "$has_search_key" = "false" ]; then
        echo -e "  ${_API_KEYS_GREEN}✓${_API_KEYS_NC} AI provider keys configured"
        show_missing_search_keys_warning
        return 0
    fi

    # No AI key - prompt to continue
    if ! prompt_missing_keys; then
        echo -e "${_API_KEYS_RED}${context} cancelled.${_API_KEYS_NC}"
        return 1
    fi

    echo -e "${_API_KEYS_YELLOW}Continuing without API keys...${_API_KEYS_NC}"
    return 0
}

# Extract gh CLI token from system keyring/keychain
# Sets GH_TOKEN (and GITHUB_TOKEN if unset) when gh is authenticated
# Returns: 0 if token exported, 1 if not available
export_gh_token() {
    if [ -n "${GITHUB_TOKEN:-}" ] || [ -n "${GH_TOKEN:-}" ]; then
        if [ -z "${GITHUB_TOKEN:-}" ] && [ -n "${GH_TOKEN:-}" ]; then
            export GITHUB_TOKEN="$GH_TOKEN"
        fi
        return 0
    fi

    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        local token
        token=$(gh auth token 2>/dev/null)
        if [ -n "$token" ]; then
            export GH_TOKEN="$token"
            if [ -z "${GITHUB_TOKEN:-}" ]; then
                export GITHUB_TOKEN="$token"
            fi
            return 0
        fi
    fi
    return 1
}
