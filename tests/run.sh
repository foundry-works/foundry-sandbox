#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

failures=0

run_test() {
    local name="$1"
    local cmd="$2"
    echo "==> $name"
    if ! eval "$cmd"; then
        echo "FAIL: $name"
        failures=$((failures + 1))
    fi
}

run_test "help" "$SCRIPT_DIR/sandbox.sh help >/dev/null"
run_test "list json" "$SCRIPT_DIR/sandbox.sh list --json >/dev/null"
run_test "status json" "$SCRIPT_DIR/sandbox.sh status --json >/dev/null"
run_test "config json" "$SCRIPT_DIR/sandbox.sh config --json >/dev/null"
run_test "info json" "$SCRIPT_DIR/sandbox.sh info --json >/dev/null"
run_test "shell-overrides" "$SCRIPT_DIR/tests/test-shell-overrides.sh"
run_test "pip-requirements" "$SCRIPT_DIR/tests/test-pip-requirements.sh"

if [ "$failures" -gt 0 ]; then
    echo "$failures test(s) failed"
    exit 1
fi

echo "All tests passed"
