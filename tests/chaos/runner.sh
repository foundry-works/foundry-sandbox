#!/usr/bin/env bash
# Chaos test runner for foundry-sandbox
# Discovers and executes chaos test modules against a live sbx environment.
#
# Usage:
#   ./tests/chaos/runner.sh [OPTIONS]
#
# Options:
#   --module <name>     Run only the specified module
#   --output-format     Output format: text (default), tap, junit
#   --output-dir <dir>  Directory for output files
#   --help              Show this help
#
# Prerequisites:
#   - sbx CLI installed and daemon running
#   - foundry-git-safety server running
#   - At least one sandbox created via `cast new`

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"

# Source the red-team harness for test_pass/test_fail/test_warn functions
source "${REPO_ROOT}/tests/redteam/harness.sh"

# Defaults
MODULE_FILTER=""
OUTPUT_FORMAT="text"
OUTPUT_DIR=""

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# //' | sed 's/^#//'
    exit 0
}

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
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Prerequisites check
if ! command -v sbx &>/dev/null; then
    echo "ERROR: sbx CLI not found. Install sbx before running chaos tests." >&2
    exit 1
fi

if ! foundry-git-safety status &>/dev/null 2>&1; then
    # Fallback: check if the HTTP endpoint is responding
    if ! curl -sf http://localhost:8083/health &>/dev/null; then
        echo "ERROR: foundry-git-safety server is not running." >&2
        echo "Start it with: foundry-git-safety start" >&2
        exit 1
    fi
    info "Note: PID file missing but server responding on :8083 (foreground mode)"
fi

info "Chaos test runner starting"
info "Output format: ${OUTPUT_FORMAT}"
if [[ -n "${OUTPUT_DIR}" ]]; then
    mkdir -p "${OUTPUT_DIR}"
    info "Output dir: ${OUTPUT_DIR}"
fi

# Discover modules
modules=()
if [[ -n "${MODULE_FILTER}" ]]; then
    target="${MODULES_DIR}/${MODULE_FILTER}.sh"
    if [[ -f "${target}" ]]; then
        modules+=("${target}")
    else
        echo "ERROR: Module not found: ${MODULE_FILTER}" >&2
        exit 1
    fi
else
    for mod in "${MODULES_DIR}"/*.sh; do
        [[ -f "${mod}" ]] && modules+=("${mod}")
    done
fi

if [[ ${#modules[@]} -eq 0 ]]; then
    echo "No chaos test modules found in ${MODULES_DIR}" >&2
    exit 1
fi

info "Found ${#modules[@]} module(s)"

for mod in "${modules[@]}"; do
    mod_name="$(basename "${mod}" .sh)"
    info "Running module: ${mod_name}"
    section_start "${mod_name}"

    # Source the module (provides run_tests function)
    # shellcheck source=/dev/null
    source "${mod}"

    # Run the module's tests
    run_tests

    # Unset the function to avoid collisions
    unset -f run_tests

    section_end "${mod_name}"
done

# Summary
echo ""
echo "=== Chaos Test Summary ==="
echo "PASS:  ${PASS:-0}"
echo "FAIL:  ${FAIL:-0}"
echo "WARN:  ${WARN:-0}"
echo "========================="

if [[ "${FAIL:-0}" -gt 0 ]]; then
    exit 1
fi
exit 0
