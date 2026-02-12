# Red Team Script Refactor Plan

## Goal

Restructure `tests/redteam-sandbox.sh` (1532 lines, 26 sections, ~150 assertions) into a modular test suite with structured output, while keeping bash as the implementation language.

## Why bash stays

The red team tests exercise the actual attack surface using attacker tools (`curl`, `nslookup`, raw sockets, `/proc` inspection, `mount`, `iptables`, `git` hooks). Python would add abstraction that masks real attack vectors. The Python security tests in `tests/security/` already cover the structured/pytest side — these two suites complement each other.

## Current problems

1. **Single 1532-line file** — hard to navigate, hard to add tests, hard to review changes
2. **No structured output** — colored terminal text only, no machine-readable results
3. **No selective execution** — must run all 26 sections or nothing
4. **Duplicated test harness** — `test_pass`/`test_fail`/`header` helpers mixed with test logic
5. **No test manifest** — new sections added by appending to bottom, no index

## Target structure

```
tests/redteam/
├── runner.sh                        # Entry point: sources harness, discovers/runs modules
├── harness.sh                       # Shared helpers: assertions, counters, output formatters
├── modules/
│   ├── 01-credentials-env.sh        # Section 1: Environment credential leakage (11 tests)
│   ├── 02-credentials-files.sh      # Section 2: File-based credential hunting (8 tests)
│   ├── 03-dns-filtering.sh          # Section 3: DNS filtering (6 tests)
│   ├── 04-network-isolation.sh      # Section 4: Network isolation (5 tests)
│   ├── 05-proxy-egress.sh           # Section 5: Proxy-layer egress filtering (4 tests)
│   ├── 06-direct-ip-egress.sh       # Section 6: Direct IP egress (4 tests)
│   ├── 07-proxy-admin.sh            # Section 7: Proxy admin UI exposure (1 test)
│   ├── 08-credential-injection.sh   # Section 8: Credential injection verification (3 tests)
│   ├── 09-git-security.sh           # Sections 9-11: Git security, hooks, shadow, marketplace
│   ├── 10-container-escape.sh       # Sections 12-13: Container escape, process/mount inspection
│   ├── 11-github-api.sh             # Sections 14-16: GitHub API filter, policy bypass, registration
│   ├── 12-tls-filesystem.sh         # Sections 17-19: TLS, filesystem isolation, capabilities
│   ├── 13-credential-patterns.sh    # Section 20: Additional credential patterns (6 tests)
│   ├── 14-network-bypass.sh         # Sections 21-22: Network bypass, sensitive paths
│   ├── 15-self-merge.sh             # Section 23: Self-merge prevention (6 tests)
│   ├── 16-readonly-fs.sh            # Section 24: Read-only filesystem & CA trust (7 tests)
│   └── 17-workflow-push.sh          # Section 25: Workflow push blocking
└── results/                         # Output directory (gitignored)
    └── .gitkeep
```

### Module grouping rationale

The 26 sections collapse into 17 modules by grouping closely related sections:

| Module | Sections | Why grouped |
|--------|----------|-------------|
| 09-git-security.sh | 9, 10, 10b, 11 | Shared git repo state, all test git attack surface |
| 10-container-escape.sh | 12, 13 | Both probe container boundaries (escape + /proc) |
| 11-github-api.sh | 14, 15, 16 | All test API proxy filtering rules |
| 12-tls-filesystem.sh | 17, 18, 19 | All test container hardening (certs, fs, caps) |
| 14-network-bypass.sh | 21, 22 | Both test network boundary evasion |

Standalone sections stay standalone. Each module lands at ~60-120 lines.

## Implementation phases

### Phase 1: Extract harness

Create `tests/redteam/harness.sh` with:

```bash
#!/bin/bash
# Shared test harness for red team modules

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

# --- Output target (set by runner) ---
JUNIT_FILE=""
TAP_FILE=""

# --- Assertions (unchanged signatures) ---
header()    { ... }
test_pass() { ... }
test_fail() { ... }
test_warn() { ... }
info()      { ... }

# --- New: structured output ---
_emit_tap() {
    # Writes TAP line to $TAP_FILE if set
    local status="$1" description="$2"
    ((TEST_NUM++))
    if [ -n "$TAP_FILE" ]; then
        echo "${status} ${TEST_NUM} - ${description}" >> "$TAP_FILE"
    fi
}

_emit_junit_summary() {
    # Called once at end, writes JUnit XML to $JUNIT_FILE
    # Reads from accumulated results array
}

# --- New: timing ---
_module_start_time=""
section_start() { _module_start_time=$(date +%s%N); }
section_end()   { ... } # calculates duration, stores for JUnit
```

Key: `test_pass`/`test_fail`/`test_warn` call `_emit_tap` internally. Existing terminal output is unchanged. Structured output is additive.

### Phase 2: Create runner

Create `tests/redteam/runner.sh`:

```bash
#!/bin/bash
# Red team test runner - discovers and executes modules

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/harness.sh"

# --- Argument parsing ---
# --module <name>         Run only this module (e.g. "03-dns-filtering")
# --output-format <fmt>   Output format: text (default), tap, junit
# --output-dir <dir>      Where to write structured output (default: results/)

# --- Module discovery ---
# Iterate modules/*.sh in sorted order
# For each: source it, call run_tests

# --- Summary ---
# Print colored summary (same as today)
# If --output-format junit: call _emit_junit_summary
# Exit 1 if FAIL > 0
```

### Phase 3: Extract modules (mechanical)

Each module follows this contract:

```bash
#!/bin/bash
# Module: 01-credentials-env
# Description: Environment credential leakage detection

run_tests() {
    header "1. ENVIRONMENT CREDENTIAL LEAKAGE"

    # ... existing test logic, verbatim cut from monolith ...
}
```

Extraction process per module:
1. Cut the section(s) from `redteam-sandbox.sh`
2. Paste into module file, wrap in `run_tests()`
3. Run full suite, verify identical PASS/FAIL/WARN counts

This is mechanical work — no logic changes.

### Phase 4: Backward compatibility wrapper

Replace `tests/redteam-sandbox.sh` with a thin wrapper:

```bash
#!/bin/bash
# Backward-compatible wrapper — delegates to modular runner
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/redteam/runner.sh" "$@"
```

### Phase 5: CI integration update

Update `.github/workflows/redteam-tests.yml`:

```yaml
- name: Run red team tests inside sandbox
  run: |
    docker cp tests/redteam/ ${{ steps.sandbox.outputs.container }}:/tmp/redteam/
    docker exec ${{ steps.sandbox.outputs.container }} \
      bash /tmp/redteam/runner.sh --output-format junit --output-dir /tmp/results

- name: Copy results from container
  if: always()
  run: |
    docker cp ${{ steps.sandbox.outputs.container }}:/tmp/results/redteam-junit.xml . || true

- name: Upload test results
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: redteam-results
    path: redteam-junit.xml
```

## Module contract

Every module file must:
- Define a single `run_tests` function (no top-level side effects beyond comments)
- Use only `test_pass`, `test_fail`, `test_warn`, `info`, `header` from harness
- Not modify global state beyond the harness counters
- Be independently runnable via `runner.sh --module <name>`
- Have a comment header with module name and one-line description

## What NOT to change

- **Test logic** — no assertion changes, no new tests, no removed tests
- **Test ordering** — modules run in numbered order, same as today
- **Exit behavior** — `FAIL > 0` exits 1, same as today
- **Language** — bash only
- **Backward compat** — `redteam-sandbox.sh` still works (delegates to runner)

## Verification

After each phase, run the full suite and confirm:
- Same number of PASS/FAIL/WARN results
- Same exit code
- No test logic changes (diff the extracted module against the original section)

## Effort estimate

- Phase 1 (harness): ~1 session
- Phase 2 (runner): ~1 session
- Phase 3 (extract 17 modules): ~2 sessions (mechanical but tedious)
- Phase 4 (wrapper): trivial
- Phase 5 (CI update): trivial

Total: ~4-5 sessions, low risk (no logic changes until phase 3 is verified).
