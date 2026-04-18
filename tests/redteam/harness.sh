#!/bin/bash
# Shared test harness for red team modules
# Provides assertions, counters, and structured output formatters

set -u

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Counters ---
PASS=0
FAIL=0
WARN=0
TEST_NUM=0

# --- Output targets (set by runner) ---
TAP_FILE=""
JUNIT_FILE=""

# --- Results accumulator for JUnit ---
declare -a _JUNIT_RESULTS=()
_CURRENT_MODULE=""
_MODULE_START_TIME=""

# --- Assertions ---
header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

test_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
    _emit_tap "ok" "$1"
    _junit_record "pass" "$1"
}

test_fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $1"
    ((FAIL++))
    _emit_tap "not ok" "$1"
    _junit_record "fail" "$1"
}

test_warn() {
    echo -e "  ${YELLOW}⚠ WARN${NC}: $1"
    ((WARN++))
    _emit_tap "ok" "$1 # TODO warning"
    _junit_record "warn" "$1"
}

info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

# --- Structured output: TAP ---
_emit_tap() {
    local status="$1" description="$2"
    ((TEST_NUM++))
    if [ -n "$TAP_FILE" ]; then
        echo "${status} ${TEST_NUM} - ${description}" >> "$TAP_FILE"
    fi
}

# --- Structured output: JUnit ---
_junit_record() {
    local status="$1" description="$2"
    _JUNIT_RESULTS+=("${status}|${_CURRENT_MODULE}|${description}")
}

# --- Module timing ---
section_start() {
    _CURRENT_MODULE="${1:-unknown}"
    _MODULE_START_TIME=$(date +%s%N 2>/dev/null || date +%s)
}

section_end() {
    _MODULE_START_TIME=""
}

# --- Summary output ---
print_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}PASSED${NC}: $PASS"
    echo -e "  ${RED}FAILED${NC}: $FAIL"
    echo -e "  ${YELLOW}WARNINGS${NC}: $WARN"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""

    if [[ $FAIL -gt 0 ]]; then
        echo -e "${RED}⚠ SECURITY ISSUES DETECTED - Review failed tests above${NC}"
    elif [[ $WARN -gt 3 ]]; then
        echo -e "${YELLOW}⚠ Multiple warnings - Review for potential issues${NC}"
    else
        echo -e "${GREEN}✓ Credential isolation appears effective${NC}"
    fi
}

# --- TAP finalization ---
_finalize_tap() {
    if [ -n "$TAP_FILE" ]; then
        # Prepend TAP header
        local tmp
        tmp=$(mktemp)
        {
            echo "TAP version 13"
            echo "1..${TEST_NUM}"
            cat "$TAP_FILE"
        } > "$tmp"
        mv "$tmp" "$TAP_FILE"
    fi
}

# --- JUnit XML generation ---
_emit_junit_summary() {
    if [ -z "$JUNIT_FILE" ]; then
        return
    fi

    local total=$((PASS + FAIL + WARN))
    local failures=$FAIL

    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo "<testsuites tests=\"${total}\" failures=\"${failures}\">"
        echo "  <testsuite name=\"redteam\" tests=\"${total}\" failures=\"${failures}\">"

        for entry in "${_JUNIT_RESULTS[@]}"; do
            local status="${entry%%|*}"
            local rest="${entry#*|}"
            local module="${rest%%|*}"
            local desc="${rest#*|}"

            # Escape XML special characters
            desc="${desc//&/&amp;}"
            desc="${desc//</&lt;}"
            desc="${desc//>/&gt;}"
            desc="${desc//\"/&quot;}"

            echo "    <testcase classname=\"redteam.${module}\" name=\"${desc}\">"
            if [[ "$status" == "fail" ]]; then
                echo "      <failure message=\"${desc}\"/>"
            elif [[ "$status" == "warn" ]]; then
                echo "      <system-out>WARNING: ${desc}</system-out>"
            fi
            echo "    </testcase>"
        done

        echo "  </testsuite>"
        echo "</testsuites>"
    } > "$JUNIT_FILE"
}

# --- Finalize all output ---
finalize_output() {
    _finalize_tap
    _emit_junit_summary
}
