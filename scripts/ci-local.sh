#!/usr/bin/env bash
set -euo pipefail

# Local CI validation — mirrors .github/workflows/test.yml
# Usage: ./scripts/ci-local.sh [--no-fail-fast]

FAIL_FAST=true

for arg in "$@"; do
  case "$arg" in
    --no-fail-fast) FAIL_FAST=false ;;
    -h|--help)
      echo "Usage: $0 [--no-fail-fast]"
      echo "  --no-fail-fast  Continue past failures instead of stopping"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--no-fail-fast]" >&2
      exit 1
      ;;
  esac
done

# -- tracking --
declare -a PASSED=()
declare -a FAILED=()
declare -a SKIPPED=()

run_step() {
  local name="$1"
  shift

  echo ""
  echo "========================================"
  echo "  $name"
  echo "========================================"

  if "$@"; then
    PASSED+=("$name")
    echo "  -> PASS: $name"
  else
    FAILED+=("$name")
    echo "  -> FAIL: $name"
    if $FAIL_FAST; then
      print_summary
      exit 1
    fi
  fi
}

skip_step() {
  local name="$1"
  local reason="$2"
  SKIPPED+=("$name ($reason)")
  echo ""
  echo "========================================"
  echo "  SKIP: $name — $reason"
  echo "========================================"
}

print_summary() {
  echo ""
  echo "========================================"
  echo "  SUMMARY"
  echo "========================================"
  for s in "${PASSED[@]+"${PASSED[@]}"}"; do
    echo "  PASS: $s"
  done
  for s in "${FAILED[@]+"${FAILED[@]}"}"; do
    echo "  FAIL: $s"
  done
  for s in "${SKIPPED[@]+"${SKIPPED[@]}"}"; do
    echo "  SKIP: $s"
  done
  echo "========================================"
}

# -- steps --

# 1. Ruff
if command -v ruff &>/dev/null; then
  run_step "Ruff" ruff check .
else
  skip_step "Ruff" "ruff not found"
fi

# 2. Mypy
if command -v mypy &>/dev/null; then
  run_step "Mypy" mypy --strict foundry_sandbox/
else
  skip_step "Mypy" "mypy not found"
fi

# 3. Shellcheck
if command -v shellcheck &>/dev/null; then
  run_shellcheck() {
    # Copied verbatim from CI lint job
    shellcheck entrypoint.sh entrypoint-root.sh stubs/git-wrapper.sh \
    && shellcheck -e SC2163 tests/run.sh \
    && shellcheck -e SC2317,SC2155,SC2034,SC1091,SC2162,SC2064,SC2129 install.sh \
    && shellcheck -e SC2034 uninstall.sh \
    && shellcheck -e SC2163 safety/credential-redaction.sh \
    && shellcheck -e SC2015 safety/network-firewall.sh \
    && shellcheck -e SC1091,SC2086 scripts/build-foundry-template.sh
  }
  run_step "Shellcheck" run_shellcheck
else
  skip_step "Shellcheck" "shellcheck not found"
fi

# 4. Unit tests
if command -v pytest &>/dev/null; then
  run_step "Unit tests" pytest tests/unit/ -q --tb=short
else
  skip_step "Unit tests" "pytest not found"
fi

# 5. foundry-git-safety unit tests
if command -v pytest &>/dev/null; then
  run_step "git-safety unit" bash -c 'cd foundry-git-safety && pip install -q -e ".[dev]" && pytest tests/unit/ -q --tb=short'
else
  skip_step "git-safety unit" "pytest not found"
fi

# 6. foundry-git-safety security tests
if command -v pytest &>/dev/null; then
  run_step "git-safety security" bash -c 'cd foundry-git-safety && pytest tests/security/ -q --tb=short'
else
  skip_step "git-safety security" "pytest not found"
fi

# 7. foundry-git-safety integration tests
if command -v pytest &>/dev/null; then
  run_step "git-safety integration" bash -c 'cd foundry-git-safety && pytest tests/integration/ -q --tb=short'
else
  skip_step "git-safety integration" "pytest not found"
fi

# -- done --
print_summary

if [ ${#FAILED[@]} -gt 0 ]; then
  exit 1
fi
