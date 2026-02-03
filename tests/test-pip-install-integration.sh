#!/bin/bash
# Integration test for install_pip_requirements function
# Requires a running sandbox container

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Source required libraries
source "$SCRIPT_DIR/lib/constants.sh"
source "$SCRIPT_DIR/lib/utils.sh"
source "$SCRIPT_DIR/lib/runtime.sh"
source "$SCRIPT_DIR/lib/fs.sh"
source "$SCRIPT_DIR/lib/docker.sh"
source "$SCRIPT_DIR/lib/container_config.sh"

# Find a running sandbox container
CONTAINER=$(docker ps --filter "name=sandbox-" --format "{{.Names}}" 2>/dev/null | head -1)

if [ -z "$CONTAINER" ]; then
    echo "ERROR: No sandbox container found. Start one with 'cast new' first."
    exit 1
fi

echo "Using container: $CONTAINER"
echo ""

passed=0
failed=0

assert_pass() {
    local description="$1"
    echo "PASS: $description"
    passed=$((passed + 1))
}

assert_fail() {
    local description="$1"
    local details="$2"
    echo "FAIL: $description"
    [ -n "$details" ] && echo "  Details: $details"
    failed=$((failed + 1))
}

echo "=== Test 1: Empty path returns early ==="
output=$(install_pip_requirements "$CONTAINER" "" 2>&1)
if [ $? -eq 0 ] && [ -z "$output" ]; then
    assert_pass "Empty path returns silently"
else
    assert_fail "Empty path should return silently" "Got output: $output"
fi

echo ""
echo "=== Test 2: Auto mode with no requirements.txt ==="
# First, make sure there's no requirements.txt in /workspace
docker exec "$CONTAINER" rm -f /workspace/requirements.txt 2>/dev/null || true
output=$(install_pip_requirements "$CONTAINER" "auto" 2>&1)
if [ $? -eq 0 ]; then
    if echo "$output" | grep -q "No requirements.txt found"; then
        assert_pass "Auto mode without file logs debug message"
    else
        # It's in debug mode, so message might not appear
        assert_pass "Auto mode without file returns gracefully (no debug output)"
    fi
else
    assert_fail "Auto mode without file should return 0"
fi

echo ""
echo "=== Test 3: Workspace-relative path that doesn't exist ==="
output=$(install_pip_requirements "$CONTAINER" "nonexistent-requirements.txt" 2>&1)
if [ $? -eq 0 ]; then
    if echo "$output" | grep -q "not found"; then
        assert_pass "Missing workspace file shows warning"
    else
        assert_pass "Missing workspace file returns gracefully"
    fi
else
    assert_fail "Missing workspace file should return 0"
fi

echo ""
echo "=== Test 4: Host path that doesn't exist ==="
output=$(install_pip_requirements "$CONTAINER" "/tmp/nonexistent-sandbox-test-reqs.txt" 2>&1)
if [ $? -eq 0 ]; then
    if echo "$output" | grep -q "not found"; then
        assert_pass "Missing host file shows warning"
    else
        assert_pass "Missing host file returns gracefully"
    fi
else
    assert_fail "Missing host file should return 0"
fi

echo ""
echo "=== Test 5: Auto mode WITH requirements.txt ==="
# Create a simple requirements.txt in the container's workspace
# Note: We can't test actual installation against a running container with network restrictions
# The install happens during 'cast new' BEFORE network restrictions are applied
docker exec "$CONTAINER" sh -c 'echo "# test package" > /workspace/requirements.txt'
output=$(install_pip_requirements "$CONTAINER" "auto" 2>&1)
exit_code=$?
echo "Output: $output"
echo "Exit code: $exit_code"

if [ $exit_code -eq 0 ]; then
    if echo "$output" | grep -q "Auto-detected requirements.txt"; then
        assert_pass "Auto mode detects requirements.txt"
    else
        assert_fail "Auto mode should log detection" "No detection message"
    fi

    # Verify pip was invoked (even if packages can't be fetched due to network restrictions)
    if echo "$output" | grep -q "Installing Python packages"; then
        assert_pass "pip install command was invoked"
    else
        assert_fail "pip install should be invoked" "No install message"
    fi
else
    assert_fail "Auto mode with file should return 0" "Exit code: $exit_code"
fi

# Clean up
docker exec "$CONTAINER" rm -f /workspace/requirements.txt 2>/dev/null || true

echo ""
echo "=== Test 6: Host path that exists ==="
# Create a temp requirements file on the host
TEMP_REQ=$(mktemp)
echo "# comment only, no packages" > "$TEMP_REQ"

output=$(install_pip_requirements "$CONTAINER" "$TEMP_REQ" 2>&1)
exit_code=$?
echo "Output: $output"
echo "Exit code: $exit_code"

if [ $exit_code -eq 0 ]; then
    if echo "$output" | grep -q "Installing Python packages"; then
        assert_pass "Host path shows install message"
    else
        assert_fail "Host path should log installation" "No install message"
    fi

    # Verify the file was copied to /tmp/sandbox-requirements.txt
    if echo "$output" | grep -q "/tmp/sandbox-requirements.txt"; then
        assert_pass "Host file copied to container /tmp"
    else
        assert_fail "Host file should be copied to /tmp" "Path not mentioned"
    fi
else
    assert_fail "Host path install should return 0" "Exit code: $exit_code"
fi

rm -f "$TEMP_REQ"

echo ""
echo "=== Test 7: Workspace-relative path that exists ==="
# Create a requirements file in a subdirectory
docker exec "$CONTAINER" mkdir -p /workspace/requirements
docker exec "$CONTAINER" sh -c 'echo "# empty requirements" > /workspace/requirements/dev.txt'

output=$(install_pip_requirements "$CONTAINER" "requirements/dev.txt" 2>&1)
exit_code=$?
echo "Output: $output"
echo "Exit code: $exit_code"

if [ $exit_code -eq 0 ]; then
    if echo "$output" | grep -q "Installing Python packages"; then
        assert_pass "Workspace relative path shows install message"
    else
        assert_fail "Workspace relative path should log installation" "No install message"
    fi

    # Verify the correct path was used
    if echo "$output" | grep -q "/workspace/requirements/dev.txt"; then
        assert_pass "Correct workspace path used"
    else
        assert_fail "Workspace path should be /workspace/requirements/dev.txt" "Wrong path"
    fi
else
    assert_fail "Workspace path install should return 0" "Exit code: $exit_code"
fi

# Clean up
docker exec "$CONTAINER" rm -rf /workspace/requirements 2>/dev/null || true

echo ""
echo "=== Test 8: Tilde path expansion ==="
# Create a temp requirements file in user's home
TILDE_REQ="$HOME/.sandbox-test-requirements.txt"
echo "# tilde test" > "$TILDE_REQ"

output=$(install_pip_requirements "$CONTAINER" "~/.sandbox-test-requirements.txt" 2>&1)
exit_code=$?
echo "Output: $output"
echo "Exit code: $exit_code"

if [ $exit_code -eq 0 ]; then
    if echo "$output" | grep -q "Installing Python packages"; then
        assert_pass "Tilde path shows install message"
    else
        assert_fail "Tilde path should log installation" "No install message"
    fi
else
    assert_fail "Tilde path install should return 0" "Exit code: $exit_code"
fi

rm -f "$TILDE_REQ"

echo ""
echo "========================================"
echo "Results: $passed passed, $failed failed"
echo "========================================"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
