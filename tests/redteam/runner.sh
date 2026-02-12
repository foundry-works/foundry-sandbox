#!/bin/bash
# Red team test runner - discovers and executes modules
# Usage:
#   runner.sh                           Run all modules
#   runner.sh --module 03-dns-filtering Run single module
#   runner.sh --output-format junit     Output JUnit XML
#   runner.sh --output-format tap       Output TAP format
#   runner.sh --output-dir ./results    Write structured output here

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness.sh
source "$SCRIPT_DIR/harness.sh"

# --- Argument parsing ---
MODULE_FILTER=""
OUTPUT_FORMAT="text"
OUTPUT_DIR="$SCRIPT_DIR/results"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --module)
            MODULE_FILTER="$2"
            shift 2
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Usage: runner.sh [--module <name>] [--output-format text|tap|junit] [--output-dir <dir>]" >&2
            exit 2
            ;;
    esac
done

# --- Set up structured output ---
mkdir -p "$OUTPUT_DIR"

if [[ "$OUTPUT_FORMAT" == "tap" ]] || [[ "$OUTPUT_FORMAT" == "all" ]]; then
    TAP_FILE="$OUTPUT_DIR/redteam.tap"
    > "$TAP_FILE"
fi

if [[ "$OUTPUT_FORMAT" == "junit" ]] || [[ "$OUTPUT_FORMAT" == "all" ]]; then
    JUNIT_FILE="$OUTPUT_DIR/redteam-junit.xml"
fi

# --- Module discovery ---
MODULES_DIR="$SCRIPT_DIR/modules"
MODULE_COUNT=0
MODULE_FAIL=0

for module_file in "$MODULES_DIR"/*.sh; do
    [[ -f "$module_file" ]] || continue

    module_name="$(basename "$module_file" .sh)"

    # Apply filter if set
    if [[ -n "$MODULE_FILTER" ]] && [[ "$module_name" != "$MODULE_FILTER" ]]; then
        continue
    fi

    # Source the module (defines run_tests function)
    # shellcheck source=/dev/null
    source "$module_file"

    # Verify run_tests is defined
    if ! declare -f run_tests >/dev/null 2>&1; then
        echo "ERROR: Module $module_name does not define run_tests()" >&2
        continue
    fi

    # Run the module
    section_start "$module_name"
    run_tests
    section_end

    # Clean up the function for next module
    unset -f run_tests

    ((MODULE_COUNT++))
done

# --- Check we ran something ---
if [[ $MODULE_COUNT -eq 0 ]]; then
    if [[ -n "$MODULE_FILTER" ]]; then
        echo "ERROR: No module found matching '$MODULE_FILTER'" >&2
        echo "Available modules:" >&2
        ls "$MODULES_DIR"/*.sh 2>/dev/null | xargs -I{} basename {} .sh | sed 's/^/  /' >&2
        exit 2
    else
        echo "ERROR: No modules found in $MODULES_DIR/" >&2
        exit 2
    fi
fi

# --- Summary ---
print_summary
finalize_output

# --- Exit code ---
if [[ $FAIL -gt 0 ]]; then
    exit 1
else
    exit 0
fi
