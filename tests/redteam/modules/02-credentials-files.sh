#!/bin/bash
# Module: 02-credentials-files
# Description: File-based credential hunting

run_tests() {
    header "2. FILE-BASED CREDENTIAL HUNTING"

    echo ""
    echo "Searching for credential files..."

    # Check credential locations that SHOULD NOT be accessible in sandbox
    CRED_FILES=(
        "/credentials"                           # Real OAuth tokens (unified-proxy only)
        "/credentials/codex/auth.json"           # Codex OAuth (unified-proxy only)
        "/credentials/gemini/oauth_creds.json"   # Gemini OAuth (unified-proxy only)
        "/credentials/opencode/auth.json"        # OpenCode OAuth (unified-proxy only)
        "$HOME/.codex/auth.json"                 # Should not exist in sandbox
        "$HOME/.gemini/oauth_creds.json"         # Should not exist in sandbox
    )
    # Note: /etc/proxy-stubs is checked separately below (stub files section)

    for f in "${CRED_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            info "Found: $f"
            # Check if it contains real credentials
            if grep -qE "(sk-ant|ghp_|ghs_|sk-proj)" "$f" 2>/dev/null; then
                test_fail "Real credentials found in $f"
                echo "    Content preview:"
                head -5 "$f" | sed 's/^/    /'
            else
                test_pass "No real credentials in $f"
            fi
        elif [[ -d "$f" ]]; then
            info "Found directory: $f"
            ls -la "$f" 2>/dev/null | head -10 | sed 's/^/    /'
        fi
    done

    # Check OAuth stub files
    echo ""
    info "Checking OAuth stub files..."
    if [[ -d "/etc/proxy-stubs" ]]; then
        for stub in /etc/proxy-stubs/*.json; do
            if [[ -f "$stub" ]]; then
                info "Stub file: $stub"
                # Check for real credentials (exclude placeholders like ya29.CREDENTIAL_PROXY_PLACEHOLDER)
                if grep -E "(sk-ant-|ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|sk-proj-|AIza[a-zA-Z0-9]{35})" "$stub" 2>/dev/null | grep -vq "PLACEHOLDER"; then
                    test_fail "Real credentials in stub file $stub"
                else
                    test_pass "Stub file $stub contains only placeholders"
                fi
            fi
        done
    fi
}
