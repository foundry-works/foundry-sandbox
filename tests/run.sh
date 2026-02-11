#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${SANDBOX_CLI:-$SCRIPT_DIR/sandbox.sh}"

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

validate_json() {
    python3 -c "import json,sys; json.load(sys.stdin)"
}

run_test "help" "$CLI help >/dev/null"
run_test "list json" "$CLI list --json | validate_json"
run_test "status json" "$CLI status --json | validate_json"
run_test "config json" "$CLI config --json | validate_json"
run_test "info json" "$CLI info --json | validate_json"
run_test "pip-requirements" "$SCRIPT_DIR/tests/test-pip-requirements.sh"
run_test "cast entry point" "python3 -c 'from foundry_sandbox.cli import main; assert callable(main)'"

if [ "$failures" -gt 0 ]; then
    echo "$failures test(s) failed"
    exit 1
fi

echo "All tests passed"
