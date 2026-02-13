#!/bin/bash
# Module: 13-credential-patterns
# Description: Additional credential pattern scanning

run_tests() {
    header "20. ADDITIONAL CREDENTIAL PATTERNS"

    echo ""
    echo "Scanning for additional credential patterns in environment and files..."

    # Check environment for high-entropy secrets
    info "Checking environment for credential patterns..."

    # Slack tokens
    if env | grep -qE "xox[baprs]-[0-9a-zA-Z-]+"; then
        test_fail "Slack token pattern found in environment"
    else
        test_pass "No Slack tokens in environment"
    fi

    # Private key patterns in environment (unusual but check)
    if env | grep -qE "BEGIN (RSA|EC|OPENSSH|PRIVATE) "; then
        test_fail "Private key material found in environment"
    else
        test_pass "No private key material in environment"
    fi

    # Generic high-entropy check for KEY/TOKEN/SECRET vars
    SUSPICIOUS_VARS=$(env | grep -iE "^[^=]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[^=]*=" | \
        grep -vE "(PLACEHOLDER|PROXY|PATH|LESS|COLORS)" | \
        awk -F= 'length($2) > 32 {print $1}')
    if [[ -n "$SUSPICIOUS_VARS" ]]; then
        test_warn "High-entropy values in sensitive-named vars: $SUSPICIOUS_VARS"
    else
        test_pass "No suspicious high-entropy credential variables"
    fi

    # Scan common locations for credential files
    echo ""
    info "Scanning for credential files..."

    # GCP service account files
    if find /tmp /home -name "*.json" -exec grep -l '"type":\s*"service_account"' {} \; 2>/dev/null | head -1 | grep -q .; then
        test_fail "GCP service account JSON found"
    else
        test_pass "No GCP service account files found"
    fi

    # Private keys in accessible locations
    if find /tmp /home -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | head -1 | grep -q .; then
        FOUND_KEYS=$(find /tmp /home -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | head -5)
        test_warn "Private key files found: $FOUND_KEYS"
    else
        test_pass "No private key files in /tmp or /home"
    fi
}
