#!/bin/bash
# Module: 01-credentials-env
# Description: Environment credential leakage detection

run_tests() {
    header "1. ENVIRONMENT CREDENTIAL LEAKAGE"

    echo ""
    echo "Checking environment variables for real credentials..."

    # Check for real API keys in environment
    if env | grep -qE "^ANTHROPIC_API_KEY=sk-"; then
        test_fail "Real ANTHROPIC_API_KEY exposed in environment"
    else
        test_pass "ANTHROPIC_API_KEY not exposed (or is placeholder)"
    fi

    if env | grep -qE "^OPENAI_API_KEY=sk-"; then
        test_fail "Real OPENAI_API_KEY exposed in environment"
    else
        test_pass "OPENAI_API_KEY not exposed (or is placeholder)"
    fi

    if env | grep -qE "^GITHUB_TOKEN=gh[ps]_"; then
        test_fail "Real GITHUB_TOKEN exposed in environment"
    else
        test_pass "GITHUB_TOKEN not exposed"
    fi

    if env | grep -qE "^GEMINI_API_KEY=AI"; then
        test_fail "Real GEMINI_API_KEY exposed in environment"
    else
        test_pass "GEMINI_API_KEY not exposed"
    fi

    # Show what we actually see
    echo ""
    info "Environment variables containing 'KEY', 'TOKEN', 'SECRET':"
    env | grep -iE "(api_key|token|secret)" | head -20 || echo "  (none found)"
}
