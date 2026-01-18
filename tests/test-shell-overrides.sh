#!/bin/bash
# Test shell override guardrails
# Tests bypass vectors for Layer 1 (UX) safety overrides

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../safety/shell-overrides.sh"

passed=0
failed=0

# Test helper: expect command to fail (be blocked)
expect_blocked() {
    local description="$1"
    shift
    if "$@" 2>&1 | grep -q "BLOCKED"; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected BLOCKED)"
        failed=$((failed + 1))
    fi
}

# Test helper: expect command to succeed (pass through)
expect_allowed() {
    local description="$1"
    shift
    local output
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -q "BLOCKED"; then
        echo "FAIL: $description (unexpected BLOCKED)"
        failed=$((failed + 1))
    else
        echo "PASS: $description"
        passed=$((passed + 1))
    fi
}

# Test helper: expect _check_dangerous_cmd to detect danger
expect_dangerous() {
    local description="$1"
    local cmd="$2"
    if _check_dangerous_cmd "$cmd" >/dev/null; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected dangerous)"
        failed=$((failed + 1))
    fi
}

# Test helper: expect _check_dangerous_cmd to allow
expect_safe() {
    local description="$1"
    local cmd="$2"
    if _check_dangerous_cmd "$cmd" >/dev/null; then
        echo "FAIL: $description (unexpected dangerous)"
        failed=$((failed + 1))
    else
        echo "PASS: $description"
        passed=$((passed + 1))
    fi
}

echo "=== _check_dangerous_cmd() unit tests ==="

# rm patterns
expect_dangerous "detects rm -rf" "rm -rf /tmp"
expect_dangerous "detects rm -fr" "rm -fr /tmp"
expect_dangerous "detects rm --recursive --force" "rm --recursive --force /tmp"
expect_dangerous "detects rm --force --recursive" "rm --force --recursive /tmp"
expect_dangerous "detects rm -r --force" "rm -r --force /tmp"
expect_dangerous "detects rm --recursive -f" "rm --recursive -f /tmp"
expect_safe "allows rm without flags" "rm file.txt"
expect_safe "allows rm -f only" "rm -f file.txt"
expect_safe "allows rm -r only" "rm -r dir/"

# git patterns
expect_dangerous "detects git reset --hard" "git reset --hard HEAD"
expect_dangerous "detects git reset --merge" "git reset --merge"
expect_dangerous "detects git clean -f" "git clean -f"
expect_dangerous "detects git clean -fd" "git clean -fd"
expect_dangerous "detects git push --force" "git push --force origin main"
expect_dangerous "detects git checkout -b" "git checkout -b new-branch "
expect_dangerous "detects git checkout --" "git checkout -- file.txt"
expect_dangerous "detects git switch" "git switch main"
expect_dangerous "detects git restore" "git restore file.txt"
expect_dangerous "detects git branch -D" "git branch -D feature"
expect_dangerous "detects git stash drop" "git stash drop"
expect_dangerous "detects git stash clear" "git stash clear"
expect_dangerous "detects git filter-branch" "git filter-branch --tree-filter"
expect_safe "allows git status" "git status"
expect_safe "allows git commit" "git commit -m 'message'"
expect_safe "allows git push (no force)" "git push origin main"
expect_safe "allows git push --force-with-lease" "git push --force-with-lease origin main"
expect_safe "allows git restore --staged" "git restore --staged file.txt"
expect_safe "allows git branch -d" "git branch -d feature"

# gh patterns
expect_dangerous "detects gh repo delete" "gh repo delete owner/repo"
expect_dangerous "detects gh release delete" "gh release delete v1.0"
expect_safe "allows gh repo view" "gh repo view"
expect_safe "allows gh pr create" "gh pr create --title test"

# dd patterns
expect_dangerous "detects dd of=/dev/sda" "dd if=/dev/zero of=/dev/sda"
expect_dangerous "detects dd of=/dev/null" "dd if=/dev/zero of=/dev/null"
expect_safe "allows dd to file" "dd if=/dev/zero of=./test.img bs=1M count=1"

echo ""
echo "=== rm() direct call tests ==="

expect_blocked "rm -rf /" rm -rf /
expect_blocked "rm -rf ~" rm -rf ~
expect_blocked "rm -fr /" rm -fr /
expect_blocked "rm -r -f /" rm -r -f /
expect_blocked "rm --recursive --force /" rm --recursive --force /
expect_blocked "rm -r --force /" rm -r --force /
expect_blocked "rm -rf . (dot)" rm -rf .
expect_blocked "rm -rf .. (dotdot)" rm -rf ..
expect_allowed "rm --help" rm --help 2>/dev/null || true

echo ""
echo "=== bash -c bypass tests (rm) ==="

expect_blocked "bash -c 'rm -rf /'" bash -c "rm -rf /"
expect_blocked "bash -c 'rm --recursive --force'" bash -c "rm --recursive --force /tmp"
expect_allowed "bash -c 'echo hello'" bash -c "echo hello"
expect_allowed "bash --version" bash --version

echo ""
echo "=== bash -c bypass tests (git) ==="

expect_blocked "bash -c 'git reset --hard'" bash -c "git reset --hard HEAD"
expect_blocked "bash -c 'git clean -f'" bash -c "git clean -f"
expect_blocked "bash -c 'git push --force'" bash -c "git push --force origin main"
expect_blocked "bash -c 'git checkout -b'" bash -c "git checkout -b branch "
expect_blocked "bash -c 'git switch'" bash -c "git switch main"
expect_blocked "bash -c 'git restore'" bash -c "git restore file.txt"
expect_blocked "bash -c 'git branch -D'" bash -c "git branch -D feature"
expect_blocked "bash -c 'git filter-branch'" bash -c "git filter-branch --tree-filter"
expect_allowed "bash -c 'git status'" bash -c "git status"
expect_allowed "bash -c 'git push --force-with-lease'" bash -c "git push --force-with-lease origin"

echo ""
echo "=== bash -c bypass tests (gh) ==="

expect_blocked "bash -c 'gh repo delete'" bash -c "gh repo delete owner/repo"
expect_blocked "bash -c 'gh release delete'" bash -c "gh release delete v1.0"
expect_allowed "bash -c 'gh repo view'" bash -c "gh repo view"

echo ""
echo "=== sh -c bypass tests ==="

expect_blocked "sh -c 'rm -rf /'" sh -c "rm -rf /"
expect_blocked "sh -c 'git reset --hard'" sh -c "git reset --hard HEAD"
expect_blocked "sh -c 'git push --force'" sh -c "git push --force origin"
expect_blocked "sh -c 'gh repo delete'" sh -c "gh repo delete owner/repo"
expect_allowed "sh -c 'echo hello'" sh -c "echo hello"

echo ""
echo "=== eval bypass tests ==="

expect_blocked "eval 'rm -rf /'" eval "rm -rf /"
expect_blocked "eval 'git reset --hard'" eval "git reset --hard HEAD"
expect_blocked "eval 'git push --force'" eval "git push --force origin"
expect_blocked "eval 'gh repo delete'" eval "gh repo delete owner/repo"
expect_allowed "eval 'echo hello'" eval "echo hello"

echo ""
echo "=== dd guardrail tests ==="

expect_blocked "dd of=/dev/sda" dd if=/dev/zero of=/dev/sda
expect_blocked "dd of=/dev/null" dd if=/dev/zero of=/dev/null
expect_allowed "dd --help" dd --help 2>/dev/null || true

echo ""
echo "=== _is_protected_path() unit tests ==="

# Helper to test protected path detection
expect_protected() {
    local description="$1"
    local path="$2"
    if _is_protected_path "$path" >/dev/null 2>&1; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected protected)"
        failed=$((failed + 1))
    fi
}

expect_not_protected() {
    local description="$1"
    local path="$2"
    if _is_protected_path "$path" >/dev/null 2>&1; then
        echo "FAIL: $description (unexpected protected)"
        failed=$((failed + 1))
    else
        echo "PASS: $description"
        passed=$((passed + 1))
    fi
}

# Root and system paths
expect_protected "/ is protected" "/"
expect_protected "/etc is protected" "/etc"
expect_protected "/usr is protected" "/usr"
expect_protected "/var is protected" "/var"
expect_protected "/home is protected" "/home"
expect_protected "/bin is protected" "/bin"
expect_protected "/sbin is protected" "/sbin"
expect_protected "/lib is protected" "/lib"
expect_protected "/boot is protected" "/boot"
expect_protected "/tmp is protected" "/tmp"
expect_protected "/opt is protected" "/opt"
expect_protected "/root is protected" "/root"

# HOME paths
expect_protected "~ is protected" ~
expect_protected "\$HOME is protected" "$HOME"

# Not protected paths (safe to delete)
expect_not_protected "/tmp/test-dir is not protected" "/tmp/test-dir"
expect_not_protected "/home/user/project is not protected" "/home/user/project"
expect_not_protected "./somefile is not protected" "./somefile"

echo ""
echo "=== Shell variable expansion bypass tests ==="

# These tests verify that when a shell variable expands to a protected path,
# the rm() function correctly blocks it (because it sees the expanded value)

# Set up test variables
TEST_ROOT="/"
TEST_HOME="$HOME"
TEST_ETC="/etc"

# Direct rm with variable (variable is expanded by shell before rm() sees it)
expect_blocked "rm -rf \$TEST_ROOT (expanded to /)" rm -rf $TEST_ROOT
expect_blocked "rm -rf \$TEST_HOME (expanded to \$HOME)" rm -rf $TEST_HOME
expect_blocked "rm -rf \$TEST_ETC (expanded to /etc)" rm -rf $TEST_ETC

echo ""
echo "=== git variable expansion tests ==="

# Variables in git commands are expanded before git() sees them
FORCE_FLAG="--force"
expect_blocked "git push with \$FORCE_FLAG variable" git push $FORCE_FLAG origin main

HARD_FLAG="--hard"
expect_blocked "git reset with \$HARD_FLAG variable" git reset $HARD_FLAG HEAD

ACTION="drop"
expect_blocked "git stash with \$ACTION variable" git stash $ACTION

echo ""
echo "=== gh variable expansion tests ==="

ACTION="delete"
expect_blocked "gh repo with \$ACTION variable" gh repo $ACTION owner/repo
expect_blocked "gh release with \$ACTION variable" gh release $ACTION v1.0

echo ""
echo "=== dd variable expansion tests ==="

DEVICE="/dev/sda"
expect_blocked "dd with \$DEVICE variable" dd if=/dev/zero of=$DEVICE

echo ""
echo "=== Extra whitespace variation tests ==="

# Test that multiple spaces between command and flags are handled
expect_dangerous "rm   -rf (multiple spaces)" "rm   -rf /tmp"
expect_dangerous "rm -rf   / (multiple spaces before path)" "rm -rf   /"
expect_dangerous "rm  -r  -f (multiple spaces between flags)" "rm  -r  -f /"

# Tab characters
expect_dangerous "rm with tab before flags" "rm	-rf /tmp"

echo ""
echo "=== Flag ordering comprehensive tests ==="

# All short flag orderings
expect_dangerous "rm -rf (standard)" "rm -rf /tmp"
expect_dangerous "rm -fr (reversed)" "rm -fr /tmp"
expect_dangerous "rm -vrf (verbose prefix)" "rm -vrf /tmp"
expect_dangerous "rm -rfv (verbose suffix)" "rm -rfv /tmp"
expect_dangerous "rm -fvr (verbose middle)" "rm -fvr /tmp"

# Separated flags in different orders
expect_dangerous "rm -r -f (separated)" "rm -r -f /tmp"
expect_dangerous "rm -f -r (separated reversed)" "rm -f -r /tmp"
expect_dangerous "rm -v -r -f (verbose separated)" "rm -v -r -f /tmp"

# Long options in different orders
expect_dangerous "rm --recursive --force" "rm --recursive --force /tmp"
expect_dangerous "rm --force --recursive" "rm --force --recursive /tmp"

# Mixed short and long
expect_dangerous "rm -r --force" "rm -r --force /tmp"
expect_dangerous "rm --recursive -f" "rm --recursive -f /tmp"
expect_dangerous "rm -f --recursive" "rm -f --recursive /tmp"
expect_dangerous "rm --force -r" "rm --force -r /tmp"

echo ""
echo "=== Protected system directory tests ==="

# Test that all protected system directories are blocked
expect_blocked "rm -rf /etc" rm -rf /etc
expect_blocked "rm -rf /usr" rm -rf /usr
expect_blocked "rm -rf /var" rm -rf /var
expect_blocked "rm -rf /home" rm -rf /home
expect_blocked "rm -rf /bin" rm -rf /bin
expect_blocked "rm -rf /sbin" rm -rf /sbin
expect_blocked "rm -rf /lib" rm -rf /lib
expect_blocked "rm -rf /boot" rm -rf /boot
expect_blocked "rm -rf /opt" rm -rf /opt
expect_blocked "rm -rf /root" rm -rf /root

echo ""
echo "=== Credential file warning tests ==="

# Test helper: expect warning message
expect_warning() {
    local description="$1"
    shift
    local output
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -q "WARNING.*credential"; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected WARNING)"
        failed=$((failed + 1))
    fi
}

# Test helper: expect no warning
expect_no_warning() {
    local description="$1"
    shift
    local output
    output=$("$@" 2>&1) || true
    if echo "$output" | grep -q "WARNING.*credential"; then
        echo "FAIL: $description (unexpected WARNING)"
        failed=$((failed + 1))
    else
        echo "PASS: $description"
        passed=$((passed + 1))
    fi
}

# Create temp files for testing
TEMP_DIR=$(mktemp -d)
touch "$TEMP_DIR/.env"
touch "$TEMP_DIR/.api_keys"
touch "$TEMP_DIR/credentials.json"
touch "$TEMP_DIR/.secrets"
touch "$TEMP_DIR/regular-file.txt"

# Test credential file detection
expect_warning "cat .env triggers warning" cat "$TEMP_DIR/.env"
expect_warning "cat .api_keys triggers warning" cat "$TEMP_DIR/.api_keys"
expect_warning "cat credentials.json triggers warning" cat "$TEMP_DIR/credentials.json"
expect_warning "cat .secrets triggers warning" cat "$TEMP_DIR/.secrets"
expect_no_warning "cat regular-file.txt no warning" cat "$TEMP_DIR/regular-file.txt"

# Test _is_credential_file function directly
expect_cred_file() {
    local description="$1"
    local path="$2"
    if _is_credential_file "$path" 2>/dev/null; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected credential file)"
        failed=$((failed + 1))
    fi
}

expect_not_cred_file() {
    local description="$1"
    local path="$2"
    if _is_credential_file "$path" 2>/dev/null; then
        echo "FAIL: $description (unexpected credential file)"
        failed=$((failed + 1))
    else
        echo "PASS: $description"
        passed=$((passed + 1))
    fi
}

expect_cred_file "_is_credential_file detects .env" ".env"
expect_cred_file "_is_credential_file detects .api_keys" ".api_keys"
expect_cred_file "_is_credential_file detects project/.env" "project/.env"
expect_cred_file "_is_credential_file detects credentials.json" "credentials.json"
expect_cred_file "_is_credential_file detects .netrc" ".netrc"
expect_cred_file "_is_credential_file detects .npmrc" ".npmrc"
expect_cred_file "_is_credential_file detects .pypirc" ".pypirc"
expect_not_cred_file "_is_credential_file allows regular files" "config.json"
expect_not_cred_file "_is_credential_file allows readme" "README.md"
expect_not_cred_file "_is_credential_file allows source files" "main.py"

# Clean up
rm -rf "$TEMP_DIR"

echo ""
echo "========================================"
echo "Results: $passed passed, $failed failed"
echo "========================================"

if [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
