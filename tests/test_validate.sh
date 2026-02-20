#!/bin/bash
# Test path validation feature
# Tests dangerous path detection, symlink handling, safe path validation, and argument parsing

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Source required libraries
source "$SCRIPT_DIR/lib/constants.sh"
source "$SCRIPT_DIR/lib/utils.sh"
source "$SCRIPT_DIR/lib/fs.sh"
source "$SCRIPT_DIR/lib/validate.sh"
source "$SCRIPT_DIR/lib/args.sh"
source "$SCRIPT_DIR/lib/json.sh"
source "$SCRIPT_DIR/lib/paths.sh"
source "$SCRIPT_DIR/lib/state.sh"

passed=0
failed=0

# Test helper: assert dangerous path
assert_dangerous() {
    local description="$1"
    local path="$2"
    if is_dangerous_mount_path "$path"; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected dangerous, got safe)"
        failed=$((failed + 1))
    fi
}

# Test helper: assert safe path
assert_safe() {
    local description="$1"
    local path="$2"
    if is_dangerous_mount_path "$path"; then
        echo "FAIL: $description (expected safe, got dangerous)"
        failed=$((failed + 1))
    else
        echo "PASS: $description"
        passed=$((passed + 1))
    fi
}

# Test helper: assert equality
assert_eq() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected '$expected', got '$actual')"
        failed=$((failed + 1))
    fi
}

echo "=== Direct Dangerous Path Tests ==="

# Test that ~/.ssh is detected as dangerous
assert_dangerous "~/.ssh is detected as dangerous" "$HOME/.ssh"

# Test that ~/.aws is detected as dangerous
assert_dangerous "~/.aws is detected as dangerous" "$HOME/.aws"

# Test that /var/run/docker.sock is detected as dangerous
assert_dangerous "/var/run/docker.sock is detected as dangerous" "/var/run/docker.sock"

# Test that /run/docker.sock is detected as dangerous
assert_dangerous "/run/docker.sock is detected as dangerous" "/run/docker.sock"

echo ""
echo "=== Subdirectory Tests ==="

# Test that $HOME/.ssh/id_rsa (subpath of dangerous dir) is detected as dangerous
assert_dangerous "$HOME/.ssh/id_rsa is detected as dangerous" "$HOME/.ssh/id_rsa"

# Test that $HOME/.aws/credentials is detected as dangerous
assert_dangerous "$HOME/.aws/credentials is detected as dangerous" "$HOME/.aws/credentials"

# Test that $HOME/.config/gcloud/application_default_credentials.json is detected as dangerous
assert_dangerous "$HOME/.config/gcloud/application_default_credentials.json is detected as dangerous" "$HOME/.config/gcloud/application_default_credentials.json"

# Test that $HOME/.azure/credentials is detected as dangerous
assert_dangerous "$HOME/.azure/credentials is detected as dangerous" "$HOME/.azure/credentials"

# Test that $HOME/.kube/config is detected as dangerous
assert_dangerous "$HOME/.kube/config is detected as dangerous" "$HOME/.kube/config"

echo ""
echo "=== Symlink Tests ==="

# Create a temporary directory for symlink testing
TEMP_TEST_DIR=$(mktemp -d)

# Create a temporary directory that symlinks to $HOME/.ssh
SYMLINK_PATH="$TEMP_TEST_DIR/ssh_link"
ln -s "$HOME/.ssh" "$SYMLINK_PATH" 2>/dev/null

# Test that the symlink path is detected as dangerous
if [ -L "$SYMLINK_PATH" ]; then
    assert_dangerous "Symlink to $HOME/.ssh is detected as dangerous" "$SYMLINK_PATH"
else
    echo "SKIP: Symlink test (cannot create symlink, may require root)"
    passed=$((passed + 1))
fi

# Create a symlink to /var/run/docker.sock
DOCKER_SOCK_LINK="$TEMP_TEST_DIR/docker_sock_link"
ln -s "/var/run/docker.sock" "$DOCKER_SOCK_LINK" 2>/dev/null

# Test that the symlink to docker.sock is detected as dangerous
if [ -L "$DOCKER_SOCK_LINK" ]; then
    assert_dangerous "Symlink to /var/run/docker.sock is detected as dangerous" "$DOCKER_SOCK_LINK"
else
    echo "SKIP: Docker socket symlink test (cannot create symlink)"
    passed=$((passed + 1))
fi

# Clean up temp directory
rm -rf "$TEMP_TEST_DIR"

echo ""
echo "=== Safe Path Tests ==="

# Test that /tmp/myproject is allowed
assert_safe "/tmp/myproject is safe" "/tmp/myproject"

# Test that $HOME/projects is allowed
assert_safe "$HOME/projects is safe" "$HOME/projects"

# Test that /workspace is allowed
assert_safe "/workspace is safe" "/workspace"

# Test that $HOME/Documents is allowed
assert_safe "$HOME/Documents is safe" "$HOME/Documents"

# Test that /opt/myapp is allowed
assert_safe "/opt/myapp is safe" "/opt/myapp"

echo ""
echo "=== Argument Parsing Tests ==="

# Test that --allow-dangerous-mount flag is parsed correctly
parse_new_args "user/repo" "--allow-dangerous-mount"
assert_eq "--allow-dangerous-mount flag sets NEW_ALLOW_DANGEROUS_MOUNT" "true" "$NEW_ALLOW_DANGEROUS_MOUNT"

# Test that it defaults to false when not provided
parse_new_args "user/repo" "branch"
assert_eq "--allow-dangerous-mount defaults to false" "false" "$NEW_ALLOW_DANGEROUS_MOUNT"

# Test that it's true when flag is passed with other args
parse_new_args "user/repo" "--allow-dangerous-mount" "user/repo"
assert_eq "--allow-dangerous-mount with other args" "true" "$NEW_ALLOW_DANGEROUS_MOUNT"

echo ""
echo "========================================"
echo "Results: $passed passed, $failed failed"
echo "========================================"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
