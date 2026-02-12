#!/bin/bash
# Module: 12-tls-filesystem
# Description: TLS inspection, filesystem isolation, and capability verification

run_tests() {
    # ---- Section 17: Certificate and TLS Inspection ----
    header "17. CERTIFICATE AND TLS INSPECTION"

    echo ""
    echo "Checking TLS/certificate configuration..."

    # Check what CA certs are trusted
    info "Custom CA certificates:"
    if [[ -f /certs/mitmproxy-ca.pem ]]; then
        test_pass "mitmproxy CA certificate present (expected for HTTPS interception)"
        openssl x509 -in /certs/mitmproxy-ca.pem -noout -subject -issuer 2>/dev/null | sed 's/^/    /'
    else
        test_warn "mitmproxy CA not found at /certs/mitmproxy-ca.pem"
    fi

    # Test that mitmproxy is intercepting HTTPS traffic
    echo ""
    info "Testing certificate validation..."

    # Test 1: curl should FAIL without mitmproxy CA (proves interception is active)
    if ! curl -sf --cacert /etc/ssl/certs/ca-certificates.crt --max-time 10 "https://api.anthropic.com/" >/dev/null 2>&1; then
        test_pass "HTTPS interception active (system CA rejects mitmproxy cert)"
    else
        test_fail "HTTPS interception NOT active (system CA accepted connection)"
    fi

    # Test 2: curl should complete TLS handshake with mitmproxy CA (proves proxy setup works)
    CURL_OUT=$(curl -s --cacert /certs/mitmproxy-ca.pem --max-time 10 -w "%{ssl_verify_result}" -o /dev/null "https://api.anthropic.com/" 2>&1)
    if [[ "$CURL_OUT" == "0" ]]; then
        test_pass "mitmproxy CA trust working (TLS handshake succeeds)"
    else
        test_warn "mitmproxy CA trust issue (ssl_verify_result=$CURL_OUT)"
    fi

    # ---- Section 18: Filesystem Isolation ----
    header "18. FILESYSTEM ISOLATION"

    echo ""
    echo "Testing read-only root filesystem and tmpfs constraints..."

    # Detect credential-isolation mode
    CREDENTIAL_ISOLATION_MODE=false
    if [ -n "${SANDBOX_GATEWAY_ENABLED:-}" ] || [ -f /run/secrets/gateway_token ]; then
        CREDENTIAL_ISOLATION_MODE=true
        info "Credential-isolation mode detected (SANDBOX_GATEWAY_ENABLED or gateway_token present)"
    fi

    # Test writes to protected paths
    for path in "/usr/bin/test-file" "/etc/test-file" "/opt/test-file"; do
        if touch "$path" 2>/dev/null; then
            rm -f "$path" 2>/dev/null
            if [ "$CREDENTIAL_ISOLATION_MODE" = "true" ]; then
                test_warn "Write to $path allowed (expected in credential-isolation mode)"
            else
                test_fail "Write succeeded to protected path: $path"
            fi
        else
            test_pass "Write blocked to protected path: $path"
        fi
    done

    # Test writes to allowed tmpfs paths
    for path in "/tmp/test-file" "/var/tmp/test-file"; do
        if touch "$path" 2>/dev/null; then
            rm -f "$path"
            test_pass "Write allowed to tmpfs: $path"
        else
            test_warn "Write failed to tmpfs: $path (might be read-only mode)"
        fi
    done

    # Test sensitive file access
    CURRENT_USER=$(whoami)
    if [[ -r /etc/shadow ]]; then
        if [ "$CURRENT_USER" = "root" ]; then
            test_warn "/etc/shadow readable (running as root)"
        elif [ "$CREDENTIAL_ISOLATION_MODE" = "true" ]; then
            test_warn "/etc/shadow readable (credential-isolation starts as root)"
        else
            test_fail "/etc/shadow readable as $CURRENT_USER"
        fi
    else
        test_pass "/etc/shadow not readable"
    fi

    if [[ -d /root ]] && ls /root/ >/dev/null 2>&1; then
        ROOT_CONTENTS=$(ls -A /root/ 2>/dev/null | wc -l)
        if [[ $ROOT_CONTENTS -gt 0 ]]; then
            test_warn "/root/ accessible with $ROOT_CONTENTS items"
        else
            test_pass "/root/ empty or inaccessible"
        fi
    else
        test_pass "/root/ not accessible"
    fi

    # Test tmpfs size limit (try to write >512MB to /tmp)
    echo ""
    info "Testing tmpfs size limits..."
    if dd if=/dev/zero of=/tmp/large-test bs=1M count=600 2>/dev/null; then
        rm -f /tmp/large-test
        test_fail "Wrote 600MB to /tmp (tmpfs limit not enforced)"
    else
        rm -f /tmp/large-test 2>/dev/null
        test_pass "Large file write to /tmp failed (tmpfs limit working)"
    fi

    # ---- Section 19: Capability Verification ----
    header "19. CAPABILITY VERIFICATION"

    echo ""
    echo "Testing dropped Linux capabilities..."

    # Test CAP_NET_RAW (should be dropped - prevents raw sockets, ping without setuid)
    info "Testing CAP_NET_RAW (should be dropped)..."

    # Method 1: Try ping (needs CAP_NET_RAW if not setuid)
    if ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
        # Ping worked - check if it's setuid or we have CAP_NET_RAW
        if [[ -u /bin/ping ]] || [[ -u /usr/bin/ping ]]; then
            test_pass "ping works via setuid (CAP_NET_RAW not needed)"
        else
            test_warn "ping works without setuid (CAP_NET_RAW may be present)"
        fi
    else
        test_pass "ping failed (CAP_NET_RAW dropped or ping not setuid)"
    fi

    # Method 2: Try creating raw socket with Python if available
    if command -v python3 &>/dev/null; then
        RAW_SOCKET_TEST=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.close()
    print('SUCCESS')
except PermissionError:
    print('EPERM')
except Exception as e:
    print(f'ERROR:{e}')
" 2>&1)
        if [[ "$RAW_SOCKET_TEST" == "EPERM" ]]; then
            test_pass "Raw socket creation blocked (CAP_NET_RAW dropped)"
        elif [[ "$RAW_SOCKET_TEST" == "SUCCESS" ]]; then
            test_fail "Raw socket creation succeeded (CAP_NET_RAW present!)"
        else
            test_warn "Raw socket test inconclusive: $RAW_SOCKET_TEST"
        fi
    else
        info "Python3 not available for raw socket test"
    fi

    # Test access to sensitive kernel interfaces
    if [[ -r /proc/kcore ]]; then
        if [ "$CREDENTIAL_ISOLATION_MODE" = "true" ]; then
            test_warn "/proc/kcore readable (known limitation - network isolation is primary boundary)"
        else
            test_fail "/proc/kcore is readable"
        fi
    else
        test_pass "/proc/kcore not readable"
    fi

    if [[ -d /sys/kernel/security ]] && ls /sys/kernel/security/ >/dev/null 2>&1; then
        test_warn "/sys/kernel/security is accessible"
    else
        test_pass "/sys/kernel/security not accessible"
    fi
}
