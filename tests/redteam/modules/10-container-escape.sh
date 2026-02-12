#!/bin/bash
# Module: 10-container-escape
# Description: Container escape, lateral movement, and process/mount inspection

run_tests() {
    # ---- Section 12: Container Escape / Lateral Movement ----
    header "12. CONTAINER ESCAPE / LATERAL MOVEMENT"

    echo ""
    echo "Testing container boundaries..."

    # Check if we can access Docker socket
    if [[ -S /var/run/docker.sock ]]; then
        test_fail "Docker socket accessible - potential container escape"
    else
        test_pass "Docker socket not accessible"
    fi

    # Check capabilities
    info "Current capabilities:"
    if command -v capsh &>/dev/null; then
        capsh --print 2>/dev/null | grep -E "^(Current|Bounding)" | sed 's/^/    /'
    elif [[ -f /proc/self/status ]]; then
        grep Cap /proc/self/status | sed 's/^/    /'
    fi

    # Check if we can ping other containers (ICC test)
    echo ""
    echo "Testing inter-container communication..."
    if ping -c 1 -W 2 unified-proxy >/dev/null 2>&1; then
        test_warn "Can ping unified-proxy container (expected for proxy)"
    else
        test_pass "Cannot ping unified-proxy container"
    fi

    if ping -c 1 -W 2 unified-proxy >/dev/null 2>&1; then
        test_warn "Can ping unified-proxy container (expected for proxy)"
    else
        test_pass "Cannot ping unified-proxy container"
    fi

    # Test for sandbox-to-sandbox isolation (should not be able to reach other sandboxes)
    echo ""
    echo "Testing sandbox-to-sandbox isolation..."

    # Try common sandbox naming patterns
    SANDBOX_PATTERNS=("sandbox-" "dev-" "test-" "worker-")
    for pattern in "${SANDBOX_PATTERNS[@]}"; do
        # Try to discover other containers via DNS/network
        OTHER_RESULT=$(getent hosts "${pattern}1" 2>/dev/null || true)
        if [[ -n "$OTHER_RESULT" ]]; then
            OTHER_IP=$(echo "$OTHER_RESULT" | awk '{print $1}')
            # Try to connect to the other sandbox
            if curl -s --connect-timeout 2 --max-time 3 "http://${OTHER_IP}:8080/" >/dev/null 2>&1; then
                test_fail "Can reach other sandbox container: ${pattern}1 ($OTHER_IP)"
            else
                test_pass "Cannot reach other sandbox: ${pattern}1 (DNS resolved but connection blocked)"
            fi
        fi
    done

    # Test container metadata service isolation (Kubernetes/ECS)
    echo ""
    info "Testing container metadata service isolation..."
    METADATA_ENDPOINTS=(
        "http://169.254.169.254/latest/meta-data/"  # AWS
        "http://169.254.170.2/v2/metadata"           # ECS
        "http://metadata.google.internal/computeMetadata/v1/"  # GCP
        "http://169.254.169.254/metadata/instance"   # Azure
    )
    for endpoint in "${METADATA_ENDPOINTS[@]}"; do
        META_RESP=$(curl -s --connect-timeout 2 --max-time 3 "$endpoint" 2>&1)
        if [[ $? -eq 0 ]] && ! echo "$META_RESP" | grep -qiE "(error|timeout|refused|blocked)"; then
            test_fail "Container metadata accessible: $endpoint"
        else
            test_pass "Container metadata blocked: ${endpoint%%/meta*}..."
        fi
    done

    # ---- Section 13: Process and Mount Inspection ----
    header "13. PROCESS AND MOUNT INSPECTION"

    echo ""
    echo "Inspecting mounts for credential leaks..."

    # Check mounts
    info "Mounted volumes:"
    mount | grep -vE "^(proc|sysfs|tmpfs|devpts|mqueue|cgroup)" | sed 's/^/    /' | head -20

    # Look for sensitive mounts (exclude known safe mounts from credential isolation:
    # /run/secrets/sandbox-hmac is the HMAC auth secret for git API, read-only)
    SENSITIVE_MOUNTS=$(mount | grep -E "(credentials|secrets|\.ssh|\.gnupg)" | grep -vE "(sandbox-hmac)" || true)
    if [[ -n "$SENSITIVE_MOUNTS" ]]; then
        test_warn "Potentially sensitive mount detected"
        echo "$SENSITIVE_MOUNTS" | sed 's/^/    /'
    else
        test_pass "No obvious credential mounts"
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
