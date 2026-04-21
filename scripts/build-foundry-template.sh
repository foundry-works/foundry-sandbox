#!/usr/bin/env bash
set -euo pipefail

# Build a foundry git-wrapper template for sbx sandboxes.
#
# Creates a temporary sandbox, installs the git wrapper script at
# /usr/local/bin/git, saves the sandbox as a reusable template, then
# cleans up the temporary sandbox.
#
# Usage:
#   scripts/build-foundry-template.sh              # build template
#   scripts/build-foundry-template.sh --force      # rebuild even if exists
#   scripts/build-foundry-template.sh --check-staleness  # rebuild if base image changed

TEMPLATE_TAG="foundry-git-wrapper:latest"
SEED_NAME="foundry-template-seed-$$"
WRAPPER_SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/foundry_sandbox/assets/git-wrapper-sbx.sh"
DIGEST_FILE="${HOME}/.foundry/template-image-digest"

cleanup() {
  if sbx ls --json 2>/dev/null | grep -q "\"${SEED_NAME}\""; then
    echo "Cleaning up seed sandbox: ${SEED_NAME}"
    sbx rm "${SEED_NAME}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Resolve project root
cd "$(dirname "$0")/.."
WRAPPER_SCRIPT="$(pwd)/foundry_sandbox/assets/git-wrapper-sbx.sh"

if [ ! -f "${WRAPPER_SCRIPT}" ]; then
  echo "Error: wrapper script not found at ${WRAPPER_SCRIPT}" >&2
  exit 1
fi

# --check-staleness: rebuild only if base image digest changed
FORCE=false
CHECK_STALENESS=false
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    --check-staleness) CHECK_STALENESS=true ;;
    -h|--help)
      echo "Usage: $0 [--force] [--check-staleness]"
      echo "  --force            Rebuild even if template already exists"
      echo "  --check-staleness  Rebuild only if base image digest changed"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

# Skip if template already exists (unless --force or --check-staleness)
if [ "$FORCE" = false ] && [ "$CHECK_STALENESS" = false ]; then
  if sbx template ls 2>/dev/null | grep -q "foundry-git-wrapper"; then
    echo "Template ${TEMPLATE_TAG} already exists. Use --force to rebuild."
    exit 0
  fi
fi

# --check-staleness: compare current digest with stored digest
if [ "$CHECK_STALENESS" = true ]; then
  if [ ! -f "${DIGEST_FILE}" ]; then
    echo "No stored digest found. Building template."
  else
    # Get current base image for shell agent
    CURRENT_DIGEST=""
    if command -v sbx &>/dev/null; then
      # sbx doesn't expose image digests directly; use sbx --version as proxy
      CURRENT_DIGEST="$(sbx --version 2>/dev/null || echo unknown)"
    fi
    STORED_DIGEST="$(cat "${DIGEST_FILE}" 2>/dev/null || echo "")"
    if [ "${CURRENT_DIGEST}" = "${STORED_DIGEST}" ]; then
      # Also check template still exists
      if sbx template ls 2>/dev/null | grep -q "foundry-git-wrapper"; then
        echo "Template up to date (sbx version: ${CURRENT_DIGEST})."
        exit 0
      fi
    fi
    echo "Template stale or missing. Rebuilding (stored=${STORED_DIGEST}, current=${CURRENT_DIGEST})."
  fi
fi

echo "Building template: ${TEMPLATE_TAG}"
echo "  Wrapper: ${WRAPPER_SCRIPT}"

# 1. Create seed sandbox
echo "  Creating seed sandbox..."
sbx create --name "${SEED_NAME}" shell /tmp

# 2. Install wrapper script
echo "  Installing git wrapper..."
WRAPPER_CONTENT="$(cat "${WRAPPER_SCRIPT}")"
sbx exec "${SEED_NAME}" -u root -- tee /usr/local/bin/git <<< "${WRAPPER_CONTENT}" >/dev/null
sbx exec "${SEED_NAME}" -u root -- chmod 755 /usr/local/bin/git

# 3. Verify installation
VERIFY="$(sbx exec "${SEED_NAME}" -- which git 2>/dev/null || true)"
if [ "${VERIFY}" != "/usr/local/bin/git" ]; then
  echo "Error: wrapper verification failed (which git returned: ${VERIFY})" >&2
  exit 1
fi

# 4. Save as template
echo "  Saving template..."
sbx template save "${SEED_NAME}" "${TEMPLATE_TAG}"

# 5. Store digest for staleness checks
mkdir -p "$(dirname "${DIGEST_FILE}")"
sbx --version 2>/dev/null > "${DIGEST_FILE}" || true

echo "  Template ${TEMPLATE_TAG} built successfully."
