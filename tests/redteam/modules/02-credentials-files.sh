#!/bin/bash
# Module: 02-credentials-files
# Description: File-based credential hunting

run_tests() {
    header "2. FILE-BASED CREDENTIAL HUNTING"

    echo ""
    echo "Searching for credential files..."

    # Check credential locations that SHOULD NOT be accessible in sandbox
    CRED_FILES=(
        "$HOME/.codex/auth.json"                 # Should not exist in sandbox
        "$HOME/.gemini/oauth_creds.json"         # Should not exist in sandbox
    )

    for f in "${CRED_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            info "Found: $f"
            if grep -qE "(sk-ant|ghp_|ghs_|sk-proj)" "$f" 2>/dev/null; then
                test_fail "Real credentials found in $f"
                echo "    Content preview:"
                head -5 "$f" | sed 's/^/    /'
            else
                test_pass "No real credentials in $f"
            fi
        elif [[ -d "$f" ]]; then
            info "Found directory: $f"
            # shellcheck disable=SC2012
            ls -la "$f" 2>/dev/null | head -10 | sed 's/^/    /'
        fi
    done
}
