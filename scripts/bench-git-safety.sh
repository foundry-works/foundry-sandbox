#!/usr/bin/env bash
# Benchmark script for foundry-git-safety server latency
#
# Measures end-to-end latency for git operations through the full stack:
# wrapper → sbx proxy → git-safety server → git execution → response
#
# Prerequisites:
#   - sbx CLI installed and running
#   - foundry-git-safety server running
#   - A sandbox with a git repo checked out
#
# Usage:
#   ./scripts/bench-git-safety.sh [--sandbox <name>] [--samples <N>] [--output-dir <dir>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Defaults
SANDBOX_NAME=""
SAMPLES=20
WARMUP=3
OUTPUT_DIR="${SCRIPT_DIR}/bench-results"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sandbox) SANDBOX_NAME="$2"; shift 2 ;;
        --samples) SAMPLES="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--sandbox <name>] [--samples <N>] [--output-dir <dir>]"
            echo ""
            echo "If --sandbox is not provided, creates a temporary sandbox for benchmarking."
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Prerequisites
if ! command -v sbx &>/dev/null; then
    echo "ERROR: sbx CLI not found" >&2; exit 1
fi

if ! curl -sf http://127.0.0.1:8083/health &>/dev/null; then
    echo "ERROR: foundry-git-safety server not reachable" >&2; exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# Auto-detect sandbox if not specified
if [[ -z "${SANDBOX_NAME}" ]]; then
    echo "No sandbox specified. Listing available sandboxes:"
    sbx ls 2>/dev/null || true
    echo ""
    read -rp "Enter sandbox name (or Ctrl-C to abort): " SANDBOX_NAME
fi

info() { echo "[INFO] $*"; }

# System info
SBX_VERSION=$(sbx --version 2>/dev/null || echo "unknown")
KERNEL=$(uname -r)
LOAD_AVG=$(cat /proc/loadavg 2>/dev/null | cut -d' ' -f1-3 || echo "unknown")

info "Benchmark configuration:"
info "  Sandbox: ${SANDBOX_NAME}"
info "  Samples: ${SAMPLES} (warmup: ${WARMUP})"
info "  sbx version: ${SBX_VERSION}"
info "  Kernel: ${KERNEL}"
info "  Load: ${LOAD_AVG}"
echo ""

# Timing function: returns elapsed milliseconds
time_ms() {
    # $1: start_ns, $2: end_ns
    echo $(( ($2 - $1) / 1000000 ))
}

# Measure a single operation
measure() {
    local op_name="$1"
    shift
    local samples=()

    # Warmup
    info "Warming up ${op_name} (${WARMUP} iterations)..."
    for _ in $(seq 1 "${WARMUP}"); do
        sbx exec "${SANDBOX_NAME}" -- "$@" &>/dev/null || true
    done

    # Measure
    info "Measuring ${op_name} (${SAMPLES} iterations)..."
    for _ in $(seq 1 "${SAMPLES}"); do
        start_ns=$(date +%s%N)
        sbx exec "${SANDBOX_NAME}" -- "$@" &>/dev/null
        exit_code=$?
        end_ns=$(date +%s%N)
        elapsed=$(( (end_ns - start_ns) / 1000000 ))  # ms
        samples+=("${elapsed}")
    done

    # Compute stats
    local sorted
    sorted=$(printf '%s\n' "${samples[@]}" | sort -n)
    local arr=()
    while IFS= read -r line; do arr+=("$line"); done <<< "${sorted}"

    local n=${#arr[@]}
    local sum=0 min=${arr[0]} max=${arr[-1]}
    for v in "${arr[@]}"; do sum=$((sum + v)); done
    local mean=$((sum / n))
    local p50_idx=$((n / 2))
    local p95_idx=$(( (n * 95) / 100 ))
    local p99_idx=$(( (n * 99) / 100 ))
    local p50=${arr[$p50_idx]}
    local p95=${arr[$p95_idx]:-${arr[-1]}}
    local p99=${arr[$p99_idx]:-${arr[-1]}}

    printf "  %-20s  mean=%4dms  p50=%4dms  p95=%4dms  p99=%4dms  min=%4dms  max=%4dms\n" \
        "${op_name}" "${mean}" "${p50}" "${p95}" "${p99}" "${min}" "${max}"

    # Store for JSON output
    STATS_JSON="${STATS_JSON}
    \"${op_name}\": {
      \"samples\": [$(printf '%s,' "${samples[@]}" | sed 's/,$//')],
      \"mean\": ${mean},
      \"p50\": ${p50},
      \"p95\": ${p95},
      \"p99\": ${p99},
      \"min\": ${min},
      \"max\": ${max}
    },"
}

STATS_JSON=""

echo "=== Git Safety Latency Benchmark ==="
echo ""

measure "status" git status
measure "log" git log --oneline -10
measure "diff" git diff HEAD~1
measure "fetch" git fetch origin
measure "remote-v" git remote -v

echo ""
echo "=== Results Summary ==="
echo "See ${OUTPUT_DIR}/${TIMESTAMP}.json for full results"

# Write JSON results
cat > "${OUTPUT_DIR}/${TIMESTAMP}.json" <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "sbx_version": "${SBX_VERSION}",
  "kernel": "${KERNEL}",
  "load_avg": "${LOAD_AVG}",
  "sandbox": "${SANDBOX_NAME}",
  "samples": ${SAMPLES},
  "warmup": ${WARMUP},
  "operations": {${STATS_JSON%,}
  }
}
EOF

info "Results written to ${OUTPUT_DIR}/${TIMESTAMP}.json"
