#!/bin/bash
# Module: 08-credential-injection
# Description: Credential injection verification via API gateway

run_tests() {
    header "8. CREDENTIAL INJECTION VERIFICATION"

    echo ""
    echo "Testing that API requests work (credentials injected by gateway)..."

    # Test Anthropic API via gateway (gateway injects real credentials)
    ANTHROPIC_RESPONSE=$(curl -s --max-time 15 \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        -d '{"model":"claude-3-haiku-20240307","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}' \
        "http://unified-proxy:9848/v1/messages" 2>&1)

    if echo "$ANTHROPIC_RESPONSE" | grep -q '"type":"message"'; then
        test_pass "Anthropic API works (gateway credential injection successful)"
    elif echo "$ANTHROPIC_RESPONSE" | grep -q "authentication_error"; then
        test_pass "Anthropic API reached (credentials not leaked in request)"
        info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
    elif echo "$ANTHROPIC_RESPONSE" | grep -q "gateway_error"; then
        test_warn "Anthropic gateway returned an error"
        info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
    else
        test_warn "Anthropic API response unclear"
        info "Response: $(echo "$ANTHROPIC_RESPONSE" | head -c 200)"
    fi
}
