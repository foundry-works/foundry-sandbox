#!/bin/bash

# Test suite for validate_mount_path function
# Tests credential path isolation validation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/validate.sh"

TESTS_PASSED=0
TESTS_FAILED=0
TEMP_DIR=""

# Setup - create temporary directory for test files
setup() {
    TEMP_DIR=$(mktemp -d)
    trap cleanup EXIT
}

# Cleanup - remove temporary test files
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

# Test result helpers
test_pass() {
    echo "  ✓ PASS: $1"
    ((TESTS_PASSED++))
}

test_fail() {
    echo "  ✗ FAIL: $1"
    ((TESTS_FAILED++))
}

# Test 1: Direct dangerous paths should be blocked
test_direct_dangerous_paths() {
    echo "Test 1: Direct dangerous paths are blocked"

    # Test ~/.ssh blocked
    if validate_mount_path "$HOME/.ssh" 2>/dev/null; then
        test_fail "Should block $HOME/.ssh"
    else
        test_pass "Blocks $HOME/.ssh"
    fi

    # Test ~/.aws blocked
    if validate_mount_path "$HOME/.aws" 2>/dev/null; then
        test_fail "Should block $HOME/.aws"
    else
        test_pass "Blocks $HOME/.aws"
    fi

    # Test ~/.docker blocked
    if validate_mount_path "$HOME/.docker" 2>/dev/null; then
        test_fail "Should block $HOME/.docker"
    else
        test_pass "Blocks $HOME/.docker"
    fi
}

# Test 2: Symlinks to dangerous paths should be blocked
test_symlink_to_dangerous() {
    echo "Test 2: Symlinks to dangerous paths are blocked"

    # Create symlink to ~/.ssh
    local ssh_symlink="$TEMP_DIR/ssh-link"
    ln -s "$HOME/.ssh" "$ssh_symlink" 2>/dev/null

    if [ -L "$ssh_symlink" ]; then
        if validate_mount_path "$ssh_symlink" 2>/dev/null; then
            test_fail "Should block symlink to $HOME/.ssh"
        else
            test_pass "Blocks symlink to ~/.ssh"
        fi
    else
        test_fail "Could not create test symlink"
    fi

    # Create symlink to ~/.aws
    local aws_symlink="$TEMP_DIR/aws-link"
    ln -s "$HOME/.aws" "$aws_symlink" 2>/dev/null

    if [ -L "$aws_symlink" ]; then
        if validate_mount_path "$aws_symlink" 2>/dev/null; then
            test_fail "Should block symlink to $HOME/.aws"
        else
            test_pass "Blocks symlink to ~/.aws"
        fi
    else
        test_fail "Could not create test symlink for aws"
    fi
}

# Test 3: Docker socket should be blocked
test_docker_socket_blocked() {
    echo "Test 3: Docker socket paths are blocked"

    # Test /var/run/docker.sock blocked
    if validate_mount_path "/var/run/docker.sock" 2>/dev/null; then
        test_fail "Should block /var/run/docker.sock"
    else
        test_pass "Blocks /var/run/docker.sock"
    fi

    # Test /run/docker.sock blocked
    if validate_mount_path "/run/docker.sock" 2>/dev/null; then
        test_fail "Should block /run/docker.sock"
    else
        test_pass "Blocks /run/docker.sock"
    fi
}

# Test 4: Parent directories of dangerous paths should be blocked
test_parent_directory_blocked() {
    echo "Test 4: Parent directories of dangerous paths are blocked"

    # Test $HOME blocked (parent of ~/.ssh, ~/.aws, etc)
    if validate_mount_path "$HOME" 2>/dev/null; then
        test_fail "Should block $HOME (parent of credential dirs)"
    else
        test_pass "Blocks $HOME (parent of credential dirs)"
    fi

    # Test /var/run blocked (parent of docker.sock)
    if validate_mount_path "/var/run" 2>/dev/null; then
        test_fail "Should block /var/run (parent of docker.sock)"
    else
        test_pass "Blocks /var/run (parent of docker.sock)"
    fi
}

# Test 5: Safe paths should be allowed
test_safe_paths_allowed() {
    echo "Test 5: Safe paths are allowed"

    # Test /tmp allowed
    if validate_mount_path "/tmp" 2>/dev/null; then
        test_pass "Allows /tmp"
    else
        test_fail "Should allow /tmp"
    fi

    # Test a custom safe directory
    local safe_dir="$TEMP_DIR/safe-mount"
    mkdir -p "$safe_dir"
    if validate_mount_path "$safe_dir" 2>/dev/null; then
        test_pass "Allows safe custom directory"
    else
        test_fail "Should allow safe custom directory"
    fi

    # Test /opt allowed
    if validate_mount_path "/opt" 2>/dev/null; then
        test_pass "Allows /opt"
    else
        test_fail "Should allow /opt"
    fi
}

# Test 6: Paths inside dangerous directories should be blocked
test_paths_inside_dangerous() {
    echo "Test 6: Paths inside dangerous directories are blocked"

    # Test $HOME/.ssh/id_rsa blocked (inside dangerous dir)
    if validate_mount_path "$HOME/.ssh/id_rsa" 2>/dev/null; then
        test_fail "Should block path inside $HOME/.ssh"
    else
        test_pass "Blocks paths inside $HOME/.ssh"
    fi

    # Test $HOME/.aws/credentials blocked (inside dangerous dir)
    if validate_mount_path "$HOME/.aws/credentials" 2>/dev/null; then
        test_fail "Should block path inside $HOME/.aws"
    else
        test_pass "Blocks paths inside $HOME/.aws"
    fi
}

# Test 7: Relative paths should be handled correctly
test_relative_paths() {
    echo "Test 7: Relative paths are validated correctly"

    # Change to home directory and test relative path to .ssh
    pushd "$HOME" > /dev/null 2>&1
    if validate_mount_path ".ssh" 2>/dev/null; then
        test_fail "Should block relative path .ssh"
    else
        test_pass "Blocks relative path to .ssh"
    fi
    popd > /dev/null 2>&1
}

# Run all tests
setup
test_direct_dangerous_paths
test_symlink_to_dangerous
test_docker_socket_blocked
test_parent_directory_blocked
test_safe_paths_allowed
test_paths_inside_dangerous
test_relative_paths

# Print summary
echo ""
echo "========================================"
echo "Test Results: $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "========================================"

if [ $TESTS_FAILED -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
