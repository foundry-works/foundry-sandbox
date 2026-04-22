#!/bin/bash
# Module: 12-tls-filesystem
# Description: Filesystem isolation and capability verification (sbx microVM)

run_tests() {
    # ---- Section 17: TLS and Network Trust ----
    header "17. TLS AND NETWORK TRUST"

    echo ""
    echo "Checking network trust model..."

    # sbx does NOT use MITM — outbound TLS is end-to-end through the sbx HTTP proxy.
    # The proxy injects credentials at the HTTP level; TLS terminates at the real endpoint.
    info "Checking no MITM CA certificates are present..."
    if [[ -f /certs/mitmproxy-ca.pem ]]; then
        test_fail "mitmproxy CA found — sbx should not use MITM interception"
    else
        test_pass "No MITM CA certificates present"
    fi

    if [[ -d /certs ]] && ls /certs/ >/dev/null 2>&1; then
        test_warn "Custom CA directory exists: $(ls /certs/)"
    else
        test_pass "No custom CA directory"
    fi

    # HTTPS should work through the sbx proxy without custom CAs
    info "Testing end-to-end HTTPS through sbx proxy..."
    CURL_HTTPS_RESP=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        "https://api.github.com/" 2>&1)
    if [[ "$CURL_HTTPS_RESP" =~ ^(200|301|302|403|404|429) ]]; then
        test_pass "HTTPS request succeeded through proxy (HTTP $CURL_HTTPS_RESP)"
    elif [[ "$CURL_HTTPS_RESP" == "000" ]]; then
        test_warn "HTTPS proxy unreachable (code: 000) — may not be running inside sbx"
    elif [[ "$CURL_HTTPS_RESP" =~ ^(60|77) ]]; then
        test_fail "HTTPS request failed — TLS/CA trust issue (code: $CURL_HTTPS_RESP)"
    else
        test_warn "HTTPS response unclear (code: $CURL_HTTPS_RESP)"
    fi

    # ---- Section 18: Filesystem Isolation ----
    header "18. FILESYSTEM ISOLATION"

    echo ""
    echo "Testing filesystem write restrictions..."

    # Test writes to protected paths
    for path in "/usr/bin/test-file" "/etc/test-file" "/opt/test-file"; do
        if touch "$path" 2>/dev/null; then
            rm -f "$path" 2>/dev/null
            test_fail "Write succeeded to protected path: $path"
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
            test_warn "Write failed to tmpfs: $path (may be read-only)"
        fi
    done

    # Test sensitive file access
    if [[ -r /etc/shadow ]]; then
        CURRENT_USER=$(whoami)
        if [[ "$CURRENT_USER" = "root" ]]; then
            test_warn "/etc/shadow readable (running as root)"
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

    # Git safety files must be present
    info "Checking git safety infrastructure..."
    if [[ -f /etc/profile.d/foundry-git-safety.sh ]]; then
        test_pass "Git safety profile script present"
    else
        test_fail "Git safety profile script missing from /etc/profile.d/"
    fi

    if [[ -f /var/lib/foundry/git-safety.env ]]; then
        test_pass "Persistent git safety env file present"
    else
        test_warn "Persistent git safety env file not found"
    fi

    # Test tmpfs size limit
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

    # Test CAP_NET_RAW (should be dropped)
    info "Testing CAP_NET_RAW (should be dropped)..."
    if ping -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
        if [[ -u /bin/ping ]] || [[ -u /usr/bin/ping ]]; then
            test_pass "ping works via setuid (CAP_NET_RAW not needed)"
        else
            test_warn "ping works without setuid (CAP_NET_RAW may be present)"
        fi
    else
        test_pass "ping failed (CAP_NET_RAW dropped or ping not setuid)"
    fi

    # Test raw socket creation
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
        test_warn "/proc/kcore is readable (kernel image accessible)"
    else
        test_pass "/proc/kcore not readable"
    fi

    if [[ -d /sys/kernel/security ]] && ls /sys/kernel/security/ >/dev/null 2>&1; then
        test_warn "/sys/kernel/security is accessible"
    else
        test_pass "/sys/kernel/security not accessible"
    fi
}
