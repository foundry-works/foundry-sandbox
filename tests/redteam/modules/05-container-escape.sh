#!/bin/bash
# Module: 05-container-escape
# Description: VM boundary, lateral movement prevention, and process/mount inspection

run_tests() {
    # ---- Section 12: VM Boundary / Lateral Movement ----
    header "12. VM BOUNDARY / LATERAL MOVEMENT"

    echo ""
    echo "Testing VM isolation boundaries..."

    # Docker socket should not exist in a microVM
    if [[ -S /var/run/docker.sock ]]; then
        test_fail "Docker socket accessible - potential escape vector"
    else
        test_pass "Docker socket not present"
    fi

    # Docker CLI should not be available inside a microVM
    if command -v docker &>/dev/null; then
        test_warn "docker CLI found inside VM (should not be installed)"
    else
        test_pass "docker CLI not available"
    fi

    # Check capabilities
    info "Current capabilities:"
    if command -v capsh &>/dev/null; then
        capsh --print 2>/dev/null | grep -E "^(Current|Bounding)" | sed 's/^/    /'
    elif [[ -f /proc/self/status ]]; then
        grep Cap /proc/self/status | sed 's/^/    /'
    fi

    # Test cloud metadata service isolation
    echo ""
    info "Testing cloud metadata service isolation..."
    METADATA_ENDPOINTS=(
        "http://169.254.169.254/latest/meta-data/"  # AWS
        "http://169.254.170.2/v2/metadata"           # ECS
        "http://metadata.google.internal/computeMetadata/v1/"  # GCP
        "http://169.254.169.254/metadata/instance"   # Azure
    )
    for endpoint in "${METADATA_ENDPOINTS[@]}"; do
        META_RESP=$(curl -s --connect-timeout 2 --max-time 3 "$endpoint" 2>&1)
        if [[ $? -eq 0 ]] && ! echo "$META_RESP" | grep -qiE "(error|timeout|refused|blocked)"; then
            test_fail "Cloud metadata accessible: $endpoint"
        else
            test_pass "Cloud metadata blocked: ${endpoint%%/meta*}..."
        fi
    done

    # Test that we cannot reach arbitrary host ports
    # All traffic is forced through the sbx HTTP proxy at gateway.docker.internal:3128
    echo ""
    info "Testing host network isolation..."
    HOST_PORTS=(22 80 443 3306 5432 6379 8080 9090)
    REACHED_HOST=0
    for port in "${HOST_PORTS[@]}"; do
        if curl -s --connect-timeout 1 --max-time 2 "http://host.docker.internal:${port}/" >/dev/null 2>&1; then
            ((REACHED_HOST++))
        fi
    done
    if [[ $REACHED_HOST -eq 0 ]]; then
        test_pass "Cannot reach arbitrary host ports (sbx proxy enforces network policy)"
    else
        test_warn "Reached $REACHED_HOST/${#HOST_PORTS[@]} host ports (check sbx network policy)"
    fi

    # ---- Section 13: Process and Mount Inspection ----
    header "13. PROCESS AND MOUNT INSPECTION"

    echo ""
    echo "Inspecting mounts for credential leaks..."

    # Check mounts
    info "Mounted volumes:"
    mount | grep -vE "^(proc|sysfs|tmpfs|devpts|mqueue|cgroup)" | sed 's/^/    /' | head -20

    # Look for sensitive mounts (HMAC secret is expected — read-only auth for git API)
    SENSITIVE_MOUNTS=$(mount | grep -E "(credentials|secrets|\.ssh|\.gnupg)" | grep -vE "(hmac-secret|foundry)" || true)
    if [[ -n "$SENSITIVE_MOUNTS" ]]; then
        test_warn "Potentially sensitive mount detected"
        echo "$SENSITIVE_MOUNTS" | sed 's/^/    /'
    else
        test_pass "No unexpected credential mounts"
    fi

    # Workspace should be mounted
    if [[ -d /workspace ]]; then
        test_pass "/workspace mount present"
    else
        test_warn "/workspace directory not found"
    fi

    # Git wrapper must be installed at /usr/local/bin/git
    if [[ -f /usr/local/bin/git ]]; then
        if head -1 /usr/local/bin/git 2>/dev/null | grep -q "bash"; then
            test_pass "Git wrapper installed at /usr/local/bin/git"
        else
            test_warn "/usr/local/bin/git exists but is not a shell script (expected wrapper)"
        fi
    else
        test_fail "Git wrapper not found at /usr/local/bin/git"
    fi

    # Real git should still exist as fallback
    if [[ -x /usr/bin/git ]]; then
        test_pass "Real git binary present at /usr/bin/git"
    else
        test_warn "Real git binary not found at /usr/bin/git"
    fi

    # Check /proc for leaked info
    echo ""
    info "Checking /proc for sensitive data..."
    if [[ -r /proc/1/environ ]]; then
        if cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -qE "(sk-ant|ghp_|ghs_)"; then
            test_fail "Real credentials visible in /proc/1/environ"
        else
            test_pass "/proc/1/environ does not contain real credentials"
        fi
    else
        test_pass "/proc/1/environ not readable"
    fi
}
