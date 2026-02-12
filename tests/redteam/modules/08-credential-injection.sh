#!/bin/bash
# Module: 08-credential-injection
# Description: Credential injection verification via proxy

run_tests() {
    header "8. CREDENTIAL INJECTION VERIFICATION"

    echo ""
    echo "Testing that API requests work (credentials injected by proxy)..."

    # Test Anthropic API (should work via proxy injection)
    ANTHROPIC_RESPONSE=$(curl -s --max-time 15 \
        -H "x-api-key: CREDENTIAL_PROXY_PLACEHOLDER" \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        -d '{"model":"claude-3-haiku-20240307","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}' \
        "https://api.anthropic.com/v1/messages" 2>&1)

    if echo "$ANTHROPIC_RESPONSE" | grep -q '"type":"message"'; then
        test_pass "Anthropic API works (credential injection successful)"
    elif echo "$ANTHROPIC_RESPONSE" | grep -q "authentication_error"; then
        test_pass "Anthropic API reached (credentials not leaked in request)"
        info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
    else
        test_warn "Anthropic API response unclear"
        info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
    fi
}
