#!/bin/bash

# Create home directories (needed because /home/ubuntu is tmpfs with read-only root)
# These would normally be created by Dockerfile but tmpfs is empty on each start
mkdir -p "$HOME/.claude" \
         "$HOME/.config/gh" \
         "$HOME/.gemini" \
         "$HOME/.config/opencode" \
         "$HOME/.local/share/opencode" \
         "$HOME/.codex" \
         "$HOME/.ssh" \
         "$HOME/.local/bin" \
         "$HOME/.cache" \
         "$HOME/.npm" \
         "$HOME/.foundry-mcp/cache" \
         "$HOME/.foundry-mcp/errors" \
         "$HOME/.foundry-mcp/metrics"

# Fix ownership of directories that Docker may have created as root
# Note: credential-isolation now mounts stubs to /etc/proxy-stubs/ and symlinks them,
# avoiding the root ownership issue. This loop is kept as a safety net for other mounts.
for dir in "$HOME/.codex" "$HOME/.local" "$HOME/.local/share" "$HOME/.local/share/opencode" "$HOME/.gemini"; do
    if [ -d "$dir" ] && [ "$(stat -c '%U' "$dir" 2>/dev/null)" = "root" ]; then
        sudo chown "$(id -u):$(id -g)" "$dir" 2>/dev/null || true
    fi
done

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

# Claude Code with ZAI GLM models (uses ZHIPU_API_KEY from environment)
# Requires global-agent for Node.js proxy support (installed in Dockerfile)
# Unset CLAUDE_CODE_OAUTH_TOKEN to avoid auth conflict with ANTHROPIC_API_KEY
cat >> ~/.bashrc << 'CLAUDE_ZAI_ALIAS'
claude-zai() {
    GLOBAL_AGENT_HTTP_PROXY="http://api-proxy:8080" \
    GLOBAL_AGENT_HTTPS_PROXY="http://api-proxy:8080" \
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

# API keys are expected to be passed via environment variables (docker-compose)

# CLI tools are pre-installed in the image
# To update manually: npm update -g @anthropic-ai/claude-code @google/gemini-cli @openai/codex opencode-ai

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

# Note: Git worktree path fixes are handled by the host script (lib/container_config.sh)
# after copying the repos directory, ensuring the bare repo exists before fixing paths.

# Network mode is applied AFTER plugin registration by the host setup script.
# This allows plugin/MCP registration to access GitHub if needed.
# To apply network mode manually: sudo network-mode <limited|host-only|none>
# The host script will call this after copy_configs_to_container completes.

# Copy proxy stub files when in gateway mode
# Stubs are in a named volume (populated by populate_stubs_volume) with original filenames
# Volume mount avoids Docker Desktop VirtioFS/gRPC-FUSE staleness issues
if [ "$SANDBOX_GATEWAY_ENABLED" = "true" ]; then
    if [ -f "/etc/proxy-stubs/stub-auth-codex.json" ]; then
        cp /etc/proxy-stubs/stub-auth-codex.json "$HOME/.codex/auth.json"
    fi
    if [ -f "/etc/proxy-stubs/stub-auth-opencode.json" ]; then
        cp /etc/proxy-stubs/stub-auth-opencode.json "$HOME/.local/share/opencode/auth.json"
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
    if [ -f "/etc/proxy-stubs/stub-opencode-config.json" ]; then
        cp /etc/proxy-stubs/stub-opencode-config.json "$HOME/.config/opencode/opencode.json"
    fi
fi

# Apply gateway gitconfig conditionally
# When SANDBOX_GATEWAY_ENABLED=true, route GitHub URLs through the gateway
# Otherwise, use direct GitHub access
if [ "$SANDBOX_GATEWAY_ENABLED" = "true" ] && [ -f "/etc/gitconfig.gateway" ]; then
    echo "Gateway mode enabled - configuring git URL rewriting..."
    sudo cp /etc/gitconfig.gateway /etc/gitconfig 2>/dev/null || \
        cp /etc/gitconfig.gateway /etc/gitconfig 2>/dev/null || true
else
    # Remove any gateway gitconfig to allow direct GitHub access
    if [ -f "/etc/gitconfig" ] && grep -q "gateway:8080" /etc/gitconfig 2>/dev/null; then
        echo "Gateway mode disabled - removing git URL rewriting..."
        sudo rm -f /etc/gitconfig 2>/dev/null || rm -f /etc/gitconfig 2>/dev/null || true
    fi
fi

# Configure DNS to use gateway's dnsmasq when in gateway mode
# This enables domain allowlisting - only approved domains can be resolved
# Note: In credential-isolation mode, DNS is configured by entrypoint-root.sh (as root)
# before this script runs. This block handles non-credential-isolation gateway mode.
if [ "$SANDBOX_GATEWAY_ENABLED" = "true" ]; then
    # Check if DNS is already configured (by root wrapper)
    if grep -q "gateway" /etc/resolv.conf 2>/dev/null || grep -q "172\." /etc/resolv.conf 2>/dev/null; then
        echo "DNS already configured for gateway"
    else
        echo "Configuring DNS to use gateway..."
        # Resolve gateway hostname using Docker's internal DNS (127.0.0.11)
        GATEWAY_IP=$(getent hosts gateway | awk '{print $1}' | head -1)
        if [ -n "$GATEWAY_IP" ]; then
            echo "Gateway IP: $GATEWAY_IP"
            # Configure resolv.conf to use gateway as DNS server
            # This requires sudo permission (see safety/sudoers-allowlist)
            echo "nameserver $GATEWAY_IP" | sudo tee /etc/resolv.conf > /dev/null 2>&1 || \
                echo "Warning: Could not write to /etc/resolv.conf (read-only?)"
            echo "DNS configured to use gateway at $GATEWAY_IP"
        else
            echo "Warning: Could not resolve gateway hostname, using default DNS"
        fi
    fi
fi

# Trust mitmproxy CA when mounted (explicit proxy mode)
if [ -f "/certs/mitmproxy-ca.pem" ]; then
    echo "Configuring CA trust for proxy..."
    export NODE_EXTRA_CA_CERTS="/certs/mitmproxy-ca.pem"
    export REQUESTS_CA_BUNDLE="/certs/mitmproxy-ca.pem"
    export SSL_CERT_FILE="/certs/mitmproxy-ca.pem"
    export CURL_CA_BUNDLE="/certs/mitmproxy-ca.pem"
    if command -v update-ca-certificates >/dev/null 2>&1; then
        if [ "$(id -u)" = "0" ]; then
            # Running as root, no sudo needed
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

# Execute the command passed to the container
exec "$@"
