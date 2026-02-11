#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLI="${SANDBOX_CLI:-$SCRIPT_DIR/sandbox.sh}"

failures=0

run_test() {
    local name="$1"
    shift
    echo "==> $name"
    if ! "$@"; then
        echo "FAIL: $name"
        failures=$((failures + 1))
    fi
}

validate_json() {
    python3 -c "import json,sys; json.load(sys.stdin)"
}

run_test "help"             bash -c "$CLI help >/dev/null"
run_test "list json"        bash -c "$CLI list --json | validate_json"
run_test "status json"      bash -c "$CLI status --json | validate_json"
run_test "config json"      bash -c "$CLI config --json | validate_json"
run_test "info json"        bash -c "$CLI info --json | validate_json"
run_test "pip-requirements" bash "$SCRIPT_DIR/tests/test-pip-requirements.sh"
run_test "cast entry point" python3 -c 'from foundry_sandbox.cli import main; assert callable(main)'

if [ "$failures" -gt 0 ]; then
    echo "$failures test(s) failed"
    exit 1
fi

echo "All tests passed"
