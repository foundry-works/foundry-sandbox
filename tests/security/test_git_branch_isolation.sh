#!/usr/bin/env bash
# Security regression tests for git branch isolation.
#
# Verifies that known leak channels (reflog, notes, for-each-ref --format,
# log --source) do not expose another sandbox's private branch names.
#
# Each test case emits PASS/FAIL output suitable for CI gating.
# Exit code: 0 if all pass, 1 if any fail.
#
# Usage:
#   ./tests/security/test_git_branch_isolation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS_COUNT=0
FAIL_COUNT=0

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  FAIL: $1"
}

# Run a Python snippet that returns exit 0 for pass, 1 for fail.
# Args: test_name python_expression
run_check() {
    local name="$1"
    local expr="$2"
    if python3 -c "
import sys, os
from unittest import mock
for mod in ('mitmproxy', 'mitmproxy.http', 'mitmproxy.ctx', 'mitmproxy.flow', 'mitmproxy.dns'):
    if mod not in sys.modules:
        sys.modules[mod] = mock.MagicMock()
sys.path.insert(0, os.path.join('${REPO_ROOT}', 'unified-proxy'))
from branch_isolation import validate_branch_isolation, _filter_ref_listing_output
SANDBOX_A = 'sandbox/alice'
SANDBOX_B = 'sandbox/bob'
META_A = {'sandbox_branch': SANDBOX_A}
$expr
" 2>/dev/null; then
        pass "$name"
    else
        fail "$name"
    fi
}

echo "=== Branch Isolation Security Regression Tests ==="
echo ""

# -----------------------------------------------------------------------
# 1. Reflog leak channel
# -----------------------------------------------------------------------
echo "[Reflog Isolation]"

run_check "reflog: blocks cross-sandbox ref" "
err = validate_branch_isolation(['reflog', 'show', SANDBOX_B], META_A)
assert err is not None, 'reflog should block cross-sandbox ref'
"

run_check "reflog: allows own branch" "
err = validate_branch_isolation(['reflog', 'show', SANDBOX_A], META_A)
assert err is None, 'reflog should allow own branch'
"

run_check "reflog: blocks cross-sandbox via refs/heads" "
err = validate_branch_isolation(['reflog', 'show', 'refs/heads/' + SANDBOX_B], META_A)
assert err is not None, 'reflog should block cross-sandbox via refs/heads'
"

# -----------------------------------------------------------------------
# 2. Notes leak channel
# -----------------------------------------------------------------------
echo ""
echo "[Notes Isolation]"

run_check "notes: blocks --ref to cross-sandbox branch" "
err = validate_branch_isolation(['notes', '--ref=' + SANDBOX_B, 'list'], META_A)
assert err is not None, 'notes --ref should block cross-sandbox branch'
"

run_check "notes: allows --ref to own branch" "
err = validate_branch_isolation(['notes', '--ref=' + SANDBOX_A, 'list'], META_A)
assert err is None, 'notes --ref should allow own branch'
"

# -----------------------------------------------------------------------
# 3. for-each-ref --format leak channel
# -----------------------------------------------------------------------
echo ""
echo "[for-each-ref Output Filtering]"

run_check "for-each-ref: output hides cross-sandbox branch" "
output = 'abc1234 refs/heads/' + SANDBOX_A + '\ndef5678 refs/heads/' + SANDBOX_B + '\n111aaaa refs/tags/v1.0\n'
result = _filter_ref_listing_output(output, ['for-each-ref'], SANDBOX_A)
assert 'refs/heads/' + SANDBOX_B not in result, 'for-each-ref should hide cross-sandbox'
assert 'refs/heads/' + SANDBOX_A in result, 'for-each-ref should keep own branch'
assert 'refs/tags/v1.0' in result, 'for-each-ref should keep tags'
"

run_check "for-each-ref: full refs/heads path hides cross-sandbox" "
output = 'refs/heads/' + SANDBOX_A + '\nrefs/heads/' + SANDBOX_B + '\nrefs/heads/main\n'
result = _filter_ref_listing_output(output, ['for-each-ref', '--format=%(refname)'], SANDBOX_A)
assert 'refs/heads/' + SANDBOX_B not in result, 'for-each-ref full path should hide cross-sandbox'
assert 'refs/heads/' + SANDBOX_A in result, 'for-each-ref full path should keep own branch'
"

# -----------------------------------------------------------------------
# 4. log --source leak channel
# -----------------------------------------------------------------------
echo ""
echo "[log --source Filtering]"

run_check "log --source: redacts cross-sandbox branch name" "
output = 'abc1234\trefs/heads/' + SANDBOX_B + '\tcommit msg\n'
result = _filter_ref_listing_output(output, ['log', '--source'], SANDBOX_A)
assert SANDBOX_B not in result, 'log --source should redact cross-sandbox'
assert '[redacted]' in result, 'log --source should replace with [redacted]'
"

run_check "log --source: preserves own branch" "
output = 'abc1234\trefs/heads/' + SANDBOX_A + '\tcommit msg\n'
result = _filter_ref_listing_output(output, ['log', '--source'], SANDBOX_A)
assert SANDBOX_A in result, 'log --source should preserve own branch'
"

# -----------------------------------------------------------------------
# 5. log --decorate leak channel
# -----------------------------------------------------------------------
echo ""
echo "[log --decorate Filtering]"

run_check "log --decorate: hides cross-sandbox decoration" "
output = 'abc1234 (HEAD -> ' + SANDBOX_A + ', origin/' + SANDBOX_B + ') msg\n'
result = _filter_ref_listing_output(output, ['log', '--oneline', '--decorate'], SANDBOX_A)
assert SANDBOX_B not in result, 'log --decorate should hide cross-sandbox'
assert 'HEAD -> ' + SANDBOX_A in result, 'log --decorate should keep own branch'
"

# -----------------------------------------------------------------------
# 6. branch -a output filtering
# -----------------------------------------------------------------------
echo ""
echo "[branch -a Output Filtering]"

run_check "branch -a: hides cross-sandbox branch" "
output = '* ' + SANDBOX_A + '\n  ' + SANDBOX_B + '\n  main\n'
result = _filter_ref_listing_output(output, ['branch', '-a'], SANDBOX_A)
assert SANDBOX_B not in result, 'branch -a should hide cross-sandbox'
assert SANDBOX_A in result, 'branch -a should keep own branch'
assert 'main' in result, 'branch -a should keep well-known branches'
"

# -----------------------------------------------------------------------
# 7. show-ref output filtering
# -----------------------------------------------------------------------
echo ""
echo "[show-ref Output Filtering]"

run_check "show-ref: hides cross-sandbox ref" "
output = 'abc1234 refs/heads/' + SANDBOX_A + '\ndef5678 refs/heads/' + SANDBOX_B + '\n'
result = _filter_ref_listing_output(output, ['show-ref'], SANDBOX_A)
assert 'refs/heads/' + SANDBOX_B not in result, 'show-ref should hide cross-sandbox'
assert 'refs/heads/' + SANDBOX_A in result, 'show-ref should keep own branch'
"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed ==="

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "SECURITY REGRESSION DETECTED"
    exit 1
fi

echo "All security regression tests passed."
exit 0
