#!/bin/bash
set -u

# Create home directories (needed because /home/ubuntu is tmpfs with read-only root)
# These would normally be created by Dockerfile but tmpfs is empty on each start
mkdir -p "$HOME/.claude" \
         "$HOME/.config/gh" \
         "$HOME/.gemini" \
         "$HOME/.codex" \
         "$HOME/.ssh" \
         "$HOME/.local/bin" \
         "$HOME/.cache" \
         "$HOME/.npm" \
         "$HOME/.foundry-mcp/cache" \
         "$HOME/.foundry-mcp/errors" \
         "$HOME/.foundry-mcp/metrics"

# Only create OpenCode directories if enabled
if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ]; then
    mkdir -p "$HOME/.config/opencode" \
             "$HOME/.local/share/opencode"
fi

# Fix ownership of directories that Docker may have created as root
# Note: credential-isolation now mounts stubs to /etc/proxy-stubs/ and symlinks them,
# avoiding the root ownership issue. This loop is kept as a safety net for other mounts.
for dir in "$HOME/.codex" "$HOME/.local" "$HOME/.local/share" "$HOME/.gemini"; do
    if [ -d "$dir" ] && [ "$(stat -c '%U' "$dir" 2>/dev/null)" = "root" ]; then
        sudo chown "$(id -u):$(id -g)" "$dir" 2>/dev/null || true
    fi
done
# Fix OpenCode directory ownership only if enabled
if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ]; then
    for dir in "$HOME/.local/share/opencode" "$HOME/.config/opencode"; do
        if [ -d "$dir" ] && [ "$(stat -c '%U' "$dir" 2>/dev/null)" = "root" ]; then
            sudo chown "$(id -u):$(id -g)" "$dir" 2>/dev/null || true
        fi
    done
fi

# Ensure Claude Code temp dir exists (defaulted via docker-compose)
if [ -n "${CLAUDE_CODE_TMPDIR:-}" ]; then
    mkdir -p "$CLAUDE_CODE_TMPDIR" 2>/dev/null || true
fi

# Set up npm prefix for user-local installs
npm config set prefix "$HOME/.local" 2>/dev/null || true

# Suppress Ubuntu's "To run a command as administrator" hint
touch ~/.sudo_as_admin_successful

# Add foundry-upgrade alias for easy MCP plugin updates
echo "alias foundry-upgrade='pip install --pre --upgrade foundry-mcp'" >> ~/.bashrc

# Claude Code with ZAI GLM models (opt-in; requires ZHIPU_API_KEY on host)
# Requires global-agent for Node.js proxy support (installed in Dockerfile)
# Unset CLAUDE_CODE_OAUTH_TOKEN to avoid auth conflict with ANTHROPIC_API_KEY
# In credential isolation, ZHIPU_API_KEY is a placeholder and the proxy injects
# the real key. Only guard on explicit enablement + non-empty value.
if [ "${SANDBOX_ENABLE_ZAI:-0}" = "1" ]; then
    if [ -z "${ZHIPU_API_KEY:-}" ]; then
        echo "Warning: SANDBOX_ENABLE_ZAI=1 but ZHIPU_API_KEY is not set; claude-zai disabled."
    elif [ "${ZHIPU_API_KEY}" = "CREDENTIAL_PROXY_PLACEHOLDER" ] || [ "${ZHIPU_API_KEY}" = "PROXY_PLACEHOLDER_OPENCODE" ]; then
        if [ "${SANDBOX_GATEWAY_ENABLED:-}" != "true" ]; then
            echo "Warning: SANDBOX_ENABLE_ZAI=1 but proxy is not enabled; placeholder key cannot be injected."
        fi
    fi
fi
if [ "${SANDBOX_ENABLE_ZAI:-0}" = "1" ] && [ -n "${ZHIPU_API_KEY:-}" ]; then
cat >> ~/.bashrc << 'CLAUDE_ZAI_ALIAS'
claude-zai() {
    GLOBAL_AGENT_HTTP_PROXY="http://unified-proxy:8080" \
    GLOBAL_AGENT_HTTPS_PROXY="http://unified-proxy:8080" \
    GLOBAL_AGENT_NO_PROXY="localhost,127.0.0.1" \
    NODE_OPTIONS="--require /usr/lib/node_modules/global-agent/bootstrap.js" \
    CLAUDE_CODE_OAUTH_TOKEN= \
    ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic" \
    ANTHROPIC_API_KEY="${ZHIPU_API_KEY:-PROXY_PLACEHOLDER_OPENCODE}" \
    API_TIMEOUT_MS=3000000 \
    ANTHROPIC_DEFAULT_OPUS_MODEL="GLM-4.7" \
    ANTHROPIC_DEFAULT_SONNET_MODEL="GLM-4.7" \
    ANTHROPIC_DEFAULT_HAIKU_MODEL="GLM-4.5-Air" \
    claude "$@"
}
CLAUDE_ZAI_ALIAS
fi

# Wrapper for gh CLI to handle auth status in credential isolation mode
# Shows helpful message instead of "invalid token" error (expected with proxy architecture)
cat >> ~/.bashrc << 'GH_WRAPPER'
gh() {
    if [[ "$1" == "auth" && "$2" == "status" ]]; then
        echo "github.com"
        echo "  ✓ Credential isolation mode active"
        echo "  - GitHub operations work via proxy credential injection"
        echo "  - Real token is never exposed inside sandbox"
        echo "  - Test with: gh repo view"
        return 0
    fi
    command gh "$@"
}
GH_WRAPPER

# API keys are expected to be passed via environment variables (docker-compose)

# CLI tools are pre-installed in the image
# To update manually: npm update -g @anthropic-ai/claude-code @google/gemini-cli @openai/codex opencode-ai

# tavily-mcp is now baked into the Docker image (npm blocked in credential isolation)
# This is a fallback for older images - use SANDBOX_ENABLE_TAVILY flag from host
if [ "${SANDBOX_ENABLE_TAVILY:-0}" = "1" ] || { [ -n "${TAVILY_API_KEY:-}" ] && [ "${TAVILY_API_KEY}" != "CREDENTIAL_PROXY_PLACEHOLDER" ]; }; then
    if ! command -v tavily-mcp >/dev/null 2>&1; then
        echo "Installing tavily-mcp (Tavily enabled)..."
        npm install -g tavily-mcp >/dev/null 2>&1 || echo "Warning: tavily-mcp install failed (may be blocked by firewall)"
    fi
fi

# Ensure Claude onboarding is marked complete (required for auth to work)
CLAUDE_JSON="$HOME/.claude.json"
if [ -f "$CLAUDE_JSON" ]; then
    if ! grep -q '"hasCompletedOnboarding": true' "$CLAUDE_JSON"; then
        echo "Setting hasCompletedOnboarding in Claude config..."
        tmp=$(mktemp)
        jq '. + {"hasCompletedOnboarding": true}' "$CLAUDE_JSON" > "$tmp" && mv "$tmp" "$CLAUDE_JSON"
    fi
else
    # Create minimal config if it doesn't exist
    echo '{"hasCompletedOnboarding": true}' > "$CLAUDE_JSON"
fi

# Note: Git worktree path fixes are handled by the host script (foundry_sandbox/container_setup.py)
# after copying the repos directory, ensuring the bare repo exists before fixing paths.

# Network mode is applied AFTER plugin registration by the host setup script.
# This allows plugin/MCP registration to access GitHub if needed.
# To apply network mode manually: sudo network-mode <limited|host-only|none>
# The host script will call this after copy_configs_to_container completes.

# Copy proxy stub files when in credential isolation mode
# Stubs are in a named volume (populated by populate_stubs_volume) with original filenames
# Volume mount avoids Docker Desktop VirtioFS/gRPC-FUSE staleness issues
if [ "${SANDBOX_GATEWAY_ENABLED:-}" = "true" ]; then
    if [ -f "/etc/proxy-stubs/stub-auth-codex.json" ]; then
        cp /etc/proxy-stubs/stub-auth-codex.json "$HOME/.codex/auth.json"
    fi
    if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ]; then
        if [ -f "/etc/proxy-stubs/stub-auth-opencode.json" ]; then
            cp /etc/proxy-stubs/stub-auth-opencode.json "$HOME/.local/share/opencode/auth.json"
        fi
    fi
    if [ -f "/etc/proxy-stubs/stub-auth-gemini.json" ]; then
        cp /etc/proxy-stubs/stub-auth-gemini.json "$HOME/.gemini/oauth_creds.json"
    fi
    if [ -f "/etc/proxy-stubs/stub-gemini-accounts.json" ]; then
        cp /etc/proxy-stubs/stub-gemini-accounts.json "$HOME/.gemini/google_accounts.json"
    fi
    if [ -f "/etc/proxy-stubs/stub-gemini-settings.json" ]; then
        cp /etc/proxy-stubs/stub-gemini-settings.json "$HOME/.gemini/settings.json"
    fi
    if [ "${SANDBOX_ENABLE_OPENCODE:-0}" = "1" ]; then
        if [ -f "/etc/proxy-stubs/stub-opencode-config.json" ]; then
            cp /etc/proxy-stubs/stub-opencode-config.json "$HOME/.config/opencode/opencode.json"
        fi
    fi
    if [ -f "/etc/proxy-stubs/stub-gh-hosts.yml" ]; then
        cp /etc/proxy-stubs/stub-gh-hosts.yml "$HOME/.config/gh/hosts.yml"
    fi
fi

# Remove legacy gateway gitconfig (unified-proxy uses HTTP_PROXY for git)
if [ -f "/etc/gitconfig" ] && grep -q "gateway:8080" /etc/gitconfig 2>/dev/null; then
    echo "Removing legacy gateway gitconfig..."
    sudo rm -f /etc/gitconfig 2>/dev/null || rm -f /etc/gitconfig 2>/dev/null || true
fi

# Git hardening: disable hooks and fsmonitor to prevent malicious repos from executing code
# Gate behind SANDBOX_GIT_HOOKS_ENABLED (default 0 = hooks disabled for security)
# IMPORTANT: Use /usr/bin/git directly to bypass the git-wrapper.sh proxy.
# The wrapper intercepts all commands when WORKDIR is /workspace and proxies them
# to the git API, which rejects config writes (read-only policy). Using the real
# git binary ensures hardening is applied to the sandbox user's global gitconfig.
if [ "${SANDBOX_GIT_HOOKS_ENABLED:-0}" != "1" ]; then
    /usr/bin/git config --global core.hooksPath /dev/null
    /usr/bin/git config --global init.templateDir ''
    /usr/bin/git config --global core.fsmonitor false
    /usr/bin/git config --global core.fsmonitorHookVersion 0
    /usr/bin/git config --global receive.denyCurrentBranch refuse
fi

# Git shadow mode: /workspace/.git is hidden from the sandbox
# The git wrapper at /usr/local/bin/git proxies all commands to the git API server
if [ "${GIT_SHADOW_ENABLED:-}" = "true" ]; then
    # Verify .git is hidden. Worktrees use a .git file (gitdir pointer) which is
    # overlaid with /dev/null via bind mount. Non-worktree repos would use tmpfs.
    if [ -f "/workspace/.git" ] && [ ! -s "/workspace/.git" ]; then
        echo "Git shadow mode active: /workspace/.git hidden (bind mount)"
    elif [ -d "/workspace/.git" ] && mountpoint -q /workspace/.git 2>/dev/null; then
        echo "Git shadow mode active: /workspace/.git hidden (tmpfs overlay)"
    else
        echo "Warning: Git shadow mode enabled but /workspace/.git may be accessible"
    fi

    # Verify git wrapper is installed (bind-mounted by docker-compose).
    if [ -x "/usr/local/bin/git" ] && head -1 /usr/local/bin/git 2>/dev/null | grep -q "bash"; then
        echo "Git wrapper installed at /usr/local/bin/git"
    else
        echo "Error: Git wrapper not found or not executable at /usr/local/bin/git"
        exit 1
    fi

    # Validate HMAC secret mount and configure wrapper secret discovery.
    export GIT_HMAC_SECRETS_DIR="/run/secrets/sandbox-hmac"
    if [ ! -d "${GIT_HMAC_SECRETS_DIR}" ]; then
        echo "Error: HMAC secrets directory not found at ${GIT_HMAC_SECRETS_DIR}"
        exit 1
    fi

    # Set HMAC secret file path for explicit SANDBOX_ID mode.
    SANDBOX_ID="${SANDBOX_ID:-}"
    if [ -n "${SANDBOX_ID}" ]; then
        export GIT_HMAC_SECRET_FILE="${GIT_HMAC_SECRETS_DIR}/${SANDBOX_ID}"
        if [ ! -r "${GIT_HMAC_SECRET_FILE}" ]; then
            echo "Error: HMAC secret file is not readable at ${GIT_HMAC_SECRET_FILE}"
            exit 1
        fi
        echo "HMAC secret accessible for sandbox ${SANDBOX_ID}"
    else
        secret_count=$(find "${GIT_HMAC_SECRETS_DIR}" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d '[:space:]')
        if [ "${secret_count}" != "1" ]; then
            echo "Error: Expected exactly 1 HMAC secret file in ${GIT_HMAC_SECRETS_DIR}, found ${secret_count}"
            exit 1
        fi
        echo "HMAC secret discovery enabled (single secret file detected)"
    fi
fi

# Configure DNS to use unified-proxy when in credential isolation mode
# This enables domain allowlisting - only approved domains can be resolved
# Note: In credential-isolation mode, DNS is configured by entrypoint-root.sh (as root)
# before this script runs. This block handles non-credential-isolation proxy mode.
if [ "${SANDBOX_GATEWAY_ENABLED:-}" = "true" ]; then
    # Check if DNS is already configured (by root wrapper)
    if grep -q "unified-proxy" /etc/resolv.conf 2>/dev/null || grep -q "172\." /etc/resolv.conf 2>/dev/null; then
        echo "DNS already configured for unified-proxy"
    else
        echo "Configuring DNS to use unified-proxy..."
        # Resolve unified-proxy hostname using Docker's internal DNS (127.0.0.11)
        PROXY_IP=$(getent hosts unified-proxy | awk '{print $1}' | head -1)
        if [ -n "$PROXY_IP" ]; then
            echo "Unified proxy IP: $PROXY_IP"
            # Configure resolv.conf to use unified-proxy as DNS server
            # This requires sudo permission (see safety/sudoers-allowlist)
            echo "nameserver $PROXY_IP" | sudo tee /etc/resolv.conf > /dev/null 2>&1 || \
                echo "Warning: Could not write to /etc/resolv.conf (read-only?)"
            echo "DNS configured to use unified-proxy at $PROXY_IP"
        else
            echo "Warning: Could not resolve unified-proxy hostname, using default DNS"
        fi
    fi
fi

# Trust mitmproxy CA when mounted (explicit proxy mode)
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    echo "Configuring CA trust for proxy..."

    if [ "${SANDBOX_CA_MODE:-}" = "combined" ]; then
        # Combined bundle mode (credential-isolation with read-only FS).
        # Env vars (NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, etc.) are set
        # via docker-compose.credential-isolation.yml.
        if [ ! -f "/certs/ca-certificates.crt" ]; then
            echo "FATAL: SANDBOX_CA_MODE=combined but /certs/ca-certificates.crt not found"
            echo "The proxy container may not be running or failed to generate the combined bundle."
            exit 1
        fi
        echo "Combined CA bundle available at /certs/ca-certificates.crt"

        # Defensive: set CA env vars here as a safety net in case compose-level
        # env vars are missing. These are no-ops if already set by compose.
        export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-/certs/ca-certificates.crt}"
        export REQUESTS_CA_BUNDLE="${REQUESTS_CA_BUNDLE:-/certs/ca-certificates.crt}"
        export SSL_CERT_FILE="${SSL_CERT_FILE:-/certs/ca-certificates.crt}"
        export CURL_CA_BUNDLE="${CURL_CA_BUNDLE:-/certs/ca-certificates.crt}"
        export GIT_SSL_CAINFO="${GIT_SSL_CAINFO:-/certs/ca-certificates.crt}"
    else
        # Legacy path: no combined bundle (standalone proxy or non-isolation mode).
        export NODE_EXTRA_CA_CERTS="/certs/mitmproxy-ca.pem"
        export REQUESTS_CA_BUNDLE="/certs/mitmproxy-ca.pem"
        export SSL_CERT_FILE="/certs/mitmproxy-ca.pem"
        export CURL_CA_BUNDLE="/certs/mitmproxy-ca.pem"
        export GIT_SSL_CAINFO="/certs/mitmproxy-ca.pem"
        if command -v update-ca-certificates >/dev/null 2>&1; then
            if [ "$(id -u)" = "0" ]; then
                cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
                update-ca-certificates >/dev/null 2>&1 || true
            elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
                sudo cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
                sudo update-ca-certificates >/dev/null 2>&1 || true
            elif [ -w "/usr/local/share/ca-certificates" ]; then
                cp "/certs/mitmproxy-ca.pem" "/usr/local/share/ca-certificates/mitmproxy-ca.crt" 2>/dev/null || true
                update-ca-certificates >/dev/null 2>&1 || true
            fi
        fi
    fi
fi

# Execute the command passed to the container.
# When no command is provided (e.g., docker-compose overrides entrypoint without a command),
# default to an interactive bash shell so the container doesn't exit immediately.
if [ "$#" -eq 0 ]; then
    set -- /bin/bash
fi
exec "$@"
