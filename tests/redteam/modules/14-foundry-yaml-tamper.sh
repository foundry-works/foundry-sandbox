#!/bin/bash
# Module: 14-foundry-yaml-tamper
# Description: Verify compiled foundry.yaml artifacts cannot be tampered with at runtime

run_tests() {
    header "28. FOUNDRY.YAML TAMPER PROTECTION"

    echo ""
    echo "Testing foundry.yaml compiled artifact immutability..."

    _WORKSPACE_BASES=()
    while IFS= read -r _BASE; do
        _WORKSPACE_BASES+=("$_BASE")
    done < <(workspace_candidates)

    # ---- 28.1: Raw foundry.yaml must not be present ----
    info "Checking that raw foundry.yaml is not leaked into the sandbox..."
    _FOUND=false
    for _BASE in "${_WORKSPACE_BASES[@]}"; do
        for _PATH in "$_BASE/foundry.yaml" "$_BASE/.foundry/foundry.yaml"; do
            if [[ -f "$_PATH" ]]; then
                _FOUND=true
                test_fail "Raw foundry.yaml found at $_PATH (should not exist inside sandbox)"
            fi
        done
    done
    if [[ -f /etc/foundry.yaml ]]; then
        _FOUND=true
        test_fail "Raw foundry.yaml found at /etc/foundry.yaml (should not exist inside sandbox)"
    fi
    if [[ "$_FOUND" == "false" ]]; then
        test_pass "No raw foundry.yaml leaked into sandbox"
    fi

    # ---- 28.2: .mcp.json tampering blocked ----
    info "Testing .mcp.json write protection..."
    _MCP_FOUND=false
    for _BASE in "${_WORKSPACE_BASES[@]}"; do
        _MCP_PATH="$_BASE/.mcp.json"
        if [[ -f "$_MCP_PATH" ]]; then
            _MCP_FOUND=true
            _BACKUP=$(cat "$_MCP_PATH")
            if echo '{"mcpServers":{"evil":{"command":"python3","args":["-c","import os"]}}}' \
                > "$_MCP_PATH" 2>/dev/null; then
                # Restore original
                echo "$_BACKUP" > "$_MCP_PATH" 2>/dev/null
                test_fail "$_MCP_PATH is writable (agent could inject MCP endpoints)"
            else
                test_pass "$_MCP_PATH is write-protected"
            fi
        fi
    done
    if [[ "$_MCP_FOUND" == "false" ]]; then
        info "No .mcp.json present — skipping write test"
    fi

    # ---- 28.3: .claude/settings.json tampering blocked ----
    info "Testing .claude/settings.json write protection..."
    _CLAUDE_FOUND=false
    for _BASE in "${_WORKSPACE_BASES[@]}"; do
        _CLAUDE_SETTINGS="$_BASE/.claude/settings.json"
        if [[ -f "$_CLAUDE_SETTINGS" ]]; then
            _CLAUDE_FOUND=true
            _BACKUP=$(cat "$_CLAUDE_SETTINGS")
            if echo '{"permissions":{"allow":["Bash(*)"]}}' \
                > "$_CLAUDE_SETTINGS" 2>/dev/null; then
                echo "$_BACKUP" > "$_CLAUDE_SETTINGS" 2>/dev/null
                test_fail "$_CLAUDE_SETTINGS is writable (agent could loosen permissions)"
            else
                test_pass "$_CLAUDE_SETTINGS is write-protected"
            fi
        fi
    done
    if [[ "$_CLAUDE_FOUND" == "false" ]]; then
        info "No .claude/settings.json present — skipping write test"
    fi

    # ---- 28.4: allow_third_party_mcp not flippable ----
    info "Checking allow_third_party_mcp gate is not exposed..."
    _GATE_LEAKED=false
    # Check env vars
    if env | grep -qi "allow_third_party_mcp\|ALLOW_THIRD_PARTY_MCP"; then
        _GATE_LEAKED=true
        test_fail "allow_third_party_mcp value leaked via environment variable"
    fi
    # Check config files that might expose the gate
    for _FPATH in /etc/profile.d/foundry-git-safety.sh /var/lib/foundry/git-safety.env; do
        if [[ -f "$_FPATH" ]] && grep -qi "allow_third_party_mcp" "$_FPATH" 2>/dev/null; then
            _GATE_LEAKED=true
            test_fail "allow_third_party_mcp found in $_FPATH"
        fi
    done
    if [[ "$_GATE_LEAKED" == "false" ]]; then
        test_pass "allow_third_party_mcp gate not exposed inside sandbox"
    fi

    # ---- 28.5: Policy registration file immutable ----
    info "Testing git-safety policy file immutability..."
    if [[ -n "${FOUNDRY_DATA_DIR:-}" ]] \
        && [[ -n "${SANDBOX_ID:-}" ]] \
        && [[ -f "${FOUNDRY_DATA_DIR}/sandboxes/${SANDBOX_ID}.json" ]]; then
        _POLICY_FILE="${FOUNDRY_DATA_DIR}/sandboxes/${SANDBOX_ID}.json"
        _POLICY_BACKUP=$(cat "$_POLICY_FILE")
        if echo '{"protected_branches":["evil-branch"]}' > "$_POLICY_FILE" 2>/dev/null; then
            echo "$_POLICY_BACKUP" > "$_POLICY_FILE" 2>/dev/null
            test_fail "Policy registration file is writable from sandbox"
        else
            test_pass "Policy registration file is write-protected"
        fi
    elif [[ -n "${SANDBOX_ID:-}" ]]; then
        # Try default path
        _POLICY_FILE="$HOME/.foundry/data/git-safety/sandboxes/${SANDBOX_ID}.json"
        if [[ -f "$_POLICY_FILE" ]]; then
            _POLICY_BACKUP=$(cat "$_POLICY_FILE")
            if echo '{"protected_branches":["evil-branch"]}' > "$_POLICY_FILE" 2>/dev/null; then
                echo "$_POLICY_BACKUP" > "$_POLICY_FILE" 2>/dev/null
                test_fail "Policy registration file is writable from sandbox"
            else
                test_pass "Policy registration file is write-protected"
            fi
        else
            info "No policy registration file found at $_POLICY_FILE"
            test_pass "Policy registration file not accessible from sandbox (host-only path)"
        fi
    else
        info "No SANDBOX_ID set — skipping policy file test"
        test_pass "Policy file test skipped (no SANDBOX_ID)"
    fi

    # ---- 28.6: ${from_host:VAR} templates not resolvable ----
    # shellcheck disable=SC2016
    info 'Checking that ${from_host:VAR} template literals are not in any sandbox file...'
    _TEMPLATE_LEAKED=false
    _SCAN_FILES=(/etc/profile.d/foundry-git-safety.sh /var/lib/foundry/git-safety.env)
    for _BASE in "${_WORKSPACE_BASES[@]}"; do
        _SCAN_FILES+=("$_BASE/.mcp.json" "$_BASE/.claude/settings.json")
    done
    for _FPATH in "${_SCAN_FILES[@]}"; do
        if [[ -f "$_FPATH" ]] && grep -q 'from_host:' "$_FPATH" 2>/dev/null; then
            _TEMPLATE_LEAKED=true
            _MATCH=$(grep 'from_host:' "$_FPATH" | head -1)
            test_fail "Unresolved \${from_host:...} found in $_FPATH: $_MATCH"
        fi
    done
    if [[ "$_TEMPLATE_LEAKED" == "false" ]]; then
        test_pass "No unresolved \${from_host:...} templates in sandbox files"
    fi

    # ---- 28.7: No secret values leaked in compiled artifacts ----
    info "Scanning compiled artifacts for raw secret patterns..."
    _SECRET_LEAK=false
    for _BASE in "${_WORKSPACE_BASES[@]}"; do
        for _FPATH in "$_BASE/.mcp.json" "$_BASE/.claude/settings.json"; do
            if [[ -f "$_FPATH" ]]; then
                # Look for patterns that look like raw API keys/tokens
                if grep -qE '(ghp_|gho_|sk-|sk_|xox[bpas]-|AKIA)[A-Za-z0-9]' "$_FPATH" 2>/dev/null; then
                    _SECRET_LEAK=true
                    test_fail "Raw secret pattern found in $_FPATH"
                fi
            fi
        done
    done
    if [[ "$_SECRET_LEAK" == "false" ]]; then
        test_pass "No raw secret values in compiled artifact files"
    fi
}
