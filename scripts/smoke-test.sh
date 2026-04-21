#!/usr/bin/env bash
set -euo pipefail

# Local smoke test runner — requires sbx binary and KVM support.
# Builds wheels, installs into a clean venv, and runs all smoke tests.
# Usage: ./scripts/smoke-test.sh [--skip-build]

SKIP_BUILD=false

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    -h|--help)
      echo "Usage: $0 [--skip-build]"
      echo "  --skip-build  Skip wheel building; use current editable install"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Check sbx availability
if ! command -v sbx &>/dev/null; then
  echo "ERROR: sbx binary not found. Install from https://github.com/docker/sbx-releases" >&2
  exit 1
fi

echo "=== sbx version ==="
sbx --version

if $SKIP_BUILD; then
  echo ""
  echo "=== Running smoke tests (editable install) ==="
  pytest tests/smoke/ -v --tb=short -m slow
else
  # Build wheels and install into clean venv
  TMPDIR=$(mktemp -d)
  WHEELS_DIR="$TMPDIR/wheels"
  VENV_DIR="$TMPDIR/smoke-venv"
  mkdir -p "$WHEELS_DIR"

  cleanup() {
    rm -rf "$TMPDIR"
  }
  trap cleanup EXIT

  echo ""
  echo "=== Building wheels ==="
  python3 -m build --outdir "$WHEELS_DIR" .
  python3 -m build --outdir "$WHEELS_DIR" foundry-git-safety/

  echo ""
  echo "=== Installing into clean venv ==="
  python3 -m venv "$VENV_DIR"
  source "$VENV_DIR/bin/activate"
  pip install -q "$WHEELS_DIR"/foundry_git_safety-*.whl
  pip install -q "$WHEELS_DIR"/foundry_sandbox-*.whl
  pip install -q pytest

  echo ""
  echo "=== Running packaging assertions ==="
  pytest tests/unit/test_packaging.py -v --tb=short

  echo ""
  echo "=== Running git-safety packaging assertions ==="
  (cd foundry-git-safety && pytest tests/unit/test_packaging.py -v --tb=short)

  echo ""
  echo "=== Running migration smoke tests ==="
  pytest tests/smoke/test_migration_smoke.py -v --tb=short -m slow

  echo ""
  echo "=== Running live sbx smoke tests ==="
  pytest tests/smoke/test_live_sbx.py -v --tb=short -m slow
fi

echo ""
echo "=== All smoke tests passed ==="
