#!/bin/bash
# API key validation utilities

# AI provider keys - at least one required
# Note: Gemini uses OAuth via ~/.gemini/oauth_creds.json (from `gemini auth`), not an API key
AI_PROVIDER_KEYS=(
    "CLAUDE_CODE_OAUTH_TOKEN"
    "CURSOR_API_KEY"
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
    echo -e "${_API_KEYS_YELLOW}Warning: No AI provider API keys found.${_API_KEYS_NC}"
    echo ""
    echo "Expected at least one of:"
    echo "  - CLAUDE_CODE_OAUTH_TOKEN (Claude Code)"
    echo "  - OPENAI_API_KEY (OpenAI/Codex)"
    echo "  - CURSOR_API_KEY (Cursor)"
    echo "  - ~/.gemini/oauth_creds.json (Gemini CLI via 'gemini auth')"
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
