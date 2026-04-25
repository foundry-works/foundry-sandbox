#!/bin/bash
# Module: 05-container-escape
# Description: VM boundary, lateral movement prevention, and process/mount inspection

run_tests() {
    # ---- Section 12: VM Boundary / Lateral Movement ----
    header "12. VM BOUNDARY / LATERAL MOVEMENT"

    echo ""
    echo "Testing VM isolation boundaries..."

    # Docker socket: in sbx microVMs, a private Docker daemon runs inside the VM
    # (Docker-in-Docker). This is expected and isolated by the VM boundary.
    # A host-mounted socket would be a real escape vector.
    if [[ -S /var/run/docker.sock ]]; then
        # Check if this is a VM-local daemon (expected) vs host mount (escape)
        DOCKER_SOCK_SOURCE=$(mount | grep "/var/run/docker.sock" | grep -o "source.*" || true)
        if [[ -n "$DOCKER_SOCK_SOURCE" ]]; then
            test_fail "Docker socket is host-mounted: $DOCKER_SOCK_SOURCE"
        elif mount | grep -q "/var/lib/docker"; then
            test_pass "Docker socket present but VM-local (DinD, isolated by VM boundary)"
        else
            test_warn "Docker socket present — verify VM-local (not host-mounted)"
        fi
    else
        test_pass "Docker socket not present"
    fi

    # Docker CLI is expected in DinD microVMs (needed for docker build/compose).
    # The socket test above already confirms it's VM-local, not host-mounted.
    if command -v docker &>/dev/null; then
        if [[ -S /var/run/docker.sock ]]; then
            test_pass "docker CLI present with VM-local daemon (DinD)"
        else
            test_warn "docker CLI present without socket (unusual)"
        fi
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
        CURL_EXIT=$?
        if [[ $CURL_EXIT -eq 0 ]] && ! echo "$META_RESP" | grep -qiE "(error|timeout|refused|blocked|no such host|lookup|could not resolve|name resolution|temporary failure)"; then
            # Verify the response actually contains metadata (not just empty or proxy noise)
            if echo "$META_RESP" | grep -qiE "(ami-|instance-id|computeMetadata|project-id|subscription)"; then
                test_fail "Cloud metadata accessible: $endpoint"
            else
                test_pass "Cloud metadata blocked: ${endpoint%%/meta*}... (no metadata in response)"
            fi
        else
            test_pass "Cloud metadata blocked: ${endpoint%%/meta*}..."
        fi
    done

    # Test that we cannot reach arbitrary host ports.
    # All traffic is forced through the sbx HTTP proxy at gateway.docker.internal:3128.
    # The proxy returns HTTP 500 with "connection refused" for unreachable host ports,
    # so we must distinguish proxy errors from real host service responses.
    echo ""
    info "Testing host network isolation..."
    HOST_PORTS=(22 80 443 3306 5432 6379 8080 9090)
    REACHED_HOST=0
    REACHED_PORTS=()
    for port in "${HOST_PORTS[@]}"; do
        RESP=$(curl -s --connect-timeout 1 --max-time 2 -w "\n%{http_code}" "http://host.docker.internal:${port}/" 2>&1)
        HTTP_CODE=$(echo "$RESP" | tail -1)
        BODY=$(echo "$RESP" | head -n -1)
        # HTTP 500 with "connection refused" = proxy blocked, not a real service
        if [[ "$HTTP_CODE" =~ ^(200|301|302|403|404|401)$ ]] && ! echo "$BODY" | grep -qi "connection refused"; then
            ((REACHED_HOST++))
            REACHED_PORTS+=("$port")
        fi
    done
    if [[ $REACHED_HOST -eq 0 ]]; then
        test_pass "Cannot reach arbitrary host ports (sbx proxy enforces network policy)"
    else
        # Port 9090 is the sbx daemon management API — expected but worth noting
        NON_SBX_PORTS=()
        for p in "${REACHED_PORTS[@]}"; do
            [[ "$p" != "9090" ]] && NON_SBX_PORTS+=("$p")
        done
        if [[ ${#NON_SBX_PORTS[@]} -eq 0 ]]; then
            test_pass "Only sbx management port reachable (9090) — no host services exposed"
        else
            test_warn "Reached host ports: ${REACHED_PORTS[*]} (check sbx network policy)"
        fi
    fi

    # ---- Section 13: Process and Mount Inspection ----
    header "13. PROCESS AND MOUNT INSPECTION"

    echo ""
    echo "Inspecting mounts for credential leaks..."

    # Check mounts
    info "Mounted volumes:"
    mount | grep -vE "^(proc|sysfs|tmpfs|devpts|mqueue|cgroup)" | sed 's/^/    /' | head -20

    # Look for sensitive mounts (HMAC secret is expected — read-only auth for git API)
    SENSITIVE_MOUNTS=$(mount | grep -E "(credentials|secrets|\.ssh|\.gnupg)" | grep -vE "(hmac-secret|foundry|/run/secrets)" || true)
    if [[ -n "$SENSITIVE_MOUNTS" ]]; then
        test_warn "Potentially sensitive mount detected"
        printf '%s\n' "$SENSITIVE_MOUNTS" | sed 's/^/    /'
    else
        test_pass "No unexpected credential mounts"
    fi

    # Workspace mount — cast sandboxes mount the repo at the original host path
    # (e.g. /home/user/repo), not /workspace. Check for either convention.
    if [[ -d /workspace ]]; then
        test_pass "/workspace mount present"
    elif mount | grep -q "type virtiofs\|type bind"; then
        test_pass "Repo mounted via virtiofs (cast layout)"
    else
        test_warn "No /workspace or repo mount found"
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
