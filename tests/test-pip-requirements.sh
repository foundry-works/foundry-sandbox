#!/bin/bash
# Test pip requirements feature
# Tests argument parsing, metadata storage, and install function logic

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

# Test helper: assert not empty
assert_not_empty() {
    local description="$1"
    local value="$2"
    if [ -n "$value" ]; then
        echo "PASS: $description"
        passed=$((passed + 1))
    else
        echo "FAIL: $description (expected non-empty value)"
        failed=$((failed + 1))
    fi
}

echo "=== Argument Parsing Tests ==="

# Test --pip-requirements with value
parse_new_args "user/repo" "--pip-requirements" "requirements.txt"
assert_eq "--pip-requirements with value" "requirements.txt" "$NEW_PIP_REQUIREMENTS"

# Test --pip-requirements=value
parse_new_args "user/repo" "--pip-requirements=requirements-dev.txt"
assert_eq "--pip-requirements=value" "requirements-dev.txt" "$NEW_PIP_REQUIREMENTS"

# Test -r with value
parse_new_args "user/repo" "-r" "requirements.txt"
assert_eq "-r with value" "requirements.txt" "$NEW_PIP_REQUIREMENTS"

# Test -r=value
parse_new_args "user/repo" "-r=requirements-dev.txt"
assert_eq "-r=value" "requirements-dev.txt" "$NEW_PIP_REQUIREMENTS"

# Test --pip-requirements without value (should default to auto)
parse_new_args "user/repo" "--pip-requirements"
assert_eq "--pip-requirements without value defaults to auto" "auto" "$NEW_PIP_REQUIREMENTS"

# Test --pip-requirements with empty value
parse_new_args "user/repo" "--pip-requirements="
assert_eq "--pip-requirements= defaults to auto" "auto" "$NEW_PIP_REQUIREMENTS"

# Test -r without value (should default to auto)
parse_new_args "user/repo" "-r"
assert_eq "-r without value defaults to auto" "auto" "$NEW_PIP_REQUIREMENTS"

# Test no pip-requirements flag
parse_new_args "user/repo" "branch"
assert_eq "no --pip-requirements flag" "" "$NEW_PIP_REQUIREMENTS"

# Test pip-requirements with other flags
parse_new_args "user/repo" "--network" "limited" "--pip-requirements" "reqs.txt" "--sparse"
assert_eq "--pip-requirements with other flags" "reqs.txt" "$NEW_PIP_REQUIREMENTS"
assert_eq "other flags still work (network)" "limited" "$NEW_NETWORK_MODE"
assert_eq "other flags still work (sparse)" "true" "$NEW_SPARSE_CHECKOUT"

echo ""
echo "=== Metadata Storage Tests ==="

# Create temp directory for metadata tests
TEMP_DIR=$(mktemp -d)
export SANDBOX_HOME="$TEMP_DIR"

# Mock the path_metadata_file function to use temp dir
path_metadata_file() {
    echo "$TEMP_DIR/$1.json"
}

# Test writing metadata with pip_requirements
SANDBOX_NETWORK_MODE="limited"
SANDBOX_SYNC_SSH="0"
SANDBOX_SSH_MODE="disabled"

write_sandbox_metadata "test-sandbox" "https://github.com/user/repo" "main" "develop" "/workspace/subdir" "0" "requirements.txt"

# Read the metadata file and check pip_requirements
METADATA_FILE="$TEMP_DIR/test-sandbox.json"
if [ -f "$METADATA_FILE" ]; then
    echo "PASS: Metadata file created"
    passed=$((passed + 1))

    # Check pip_requirements field in JSON
    if grep -q '"pip_requirements":"requirements.txt"' "$METADATA_FILE"; then
        echo "PASS: pip_requirements written to metadata"
        passed=$((passed + 1))
    else
        echo "FAIL: pip_requirements not found in metadata"
        echo "Content: $(cat "$METADATA_FILE")"
        failed=$((failed + 1))
    fi
else
    echo "FAIL: Metadata file not created"
    failed=$((failed + 1))
fi

# Test loading metadata
_metadata_load_from_file "$METADATA_FILE" "json"
assert_eq "pip_requirements loaded from metadata" "requirements.txt" "$SANDBOX_PIP_REQUIREMENTS"
assert_eq "other fields loaded (repo_url)" "https://github.com/user/repo" "$SANDBOX_REPO_URL"
assert_eq "other fields loaded (branch)" "main" "$SANDBOX_BRANCH"

# Test with empty pip_requirements
write_sandbox_metadata "test-sandbox-2" "https://github.com/user/repo" "main" "develop" "" "0" ""
METADATA_FILE_2="$TEMP_DIR/test-sandbox-2.json"
_metadata_load_from_file "$METADATA_FILE_2" "json"
assert_eq "empty pip_requirements handled" "" "$SANDBOX_PIP_REQUIREMENTS"

# Test with auto pip_requirements
write_sandbox_metadata "test-sandbox-3" "https://github.com/user/repo" "main" "develop" "" "0" "auto"
METADATA_FILE_3="$TEMP_DIR/test-sandbox-3.json"
_metadata_load_from_file "$METADATA_FILE_3" "json"
assert_eq "auto pip_requirements preserved" "auto" "$SANDBOX_PIP_REQUIREMENTS"

# Test with host path pip_requirements
write_sandbox_metadata "test-sandbox-4" "https://github.com/user/repo" "main" "develop" "" "0" "/home/user/requirements.txt"
METADATA_FILE_4="$TEMP_DIR/test-sandbox-4.json"
_metadata_load_from_file "$METADATA_FILE_4" "json"
assert_eq "host path pip_requirements preserved" "/home/user/requirements.txt" "$SANDBOX_PIP_REQUIREMENTS"

# Test with tilde path pip_requirements
write_sandbox_metadata "test-sandbox-5" "https://github.com/user/repo" "main" "develop" "" "0" "~/requirements.txt"
METADATA_FILE_5="$TEMP_DIR/test-sandbox-5.json"
_metadata_load_from_file "$METADATA_FILE_5" "json"
assert_eq "tilde path pip_requirements preserved" "~/requirements.txt" "$SANDBOX_PIP_REQUIREMENTS"

echo ""
echo "=== JSON Escaping Tests ==="

# Test special characters in pip_requirements path
write_sandbox_metadata "test-sandbox-special" "https://github.com/user/repo" "main" "develop" "" "0" "path/with spaces/requirements.txt"
METADATA_FILE_SPECIAL="$TEMP_DIR/test-sandbox-special.json"
_metadata_load_from_file "$METADATA_FILE_SPECIAL" "json"
assert_eq "path with spaces preserved" "path/with spaces/requirements.txt" "$SANDBOX_PIP_REQUIREMENTS"

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
