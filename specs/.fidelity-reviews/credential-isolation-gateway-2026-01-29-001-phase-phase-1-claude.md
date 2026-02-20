# Fidelity Review: credential-isolation-gateway

**Spec ID:** credential-isolation-gateway-2026-01-29-001
**Scope:** phase (phase: phase-1)
**Verdict:** pass
**Date:** 2026-02-19T19:01:01.965978
**Provider:** claude

## Summary

Phase 1 (Dangerous Path Blocklist) is fully implemented and aligns with all spec requirements. All 5 tasks are complete: DANGEROUS_PATHS array with all 13 specified paths, validate_mount_path() with symlink resolution via realpath -m, --allow-dangerous-mount override flag in argument parsing and help text, mount validation integrated into new.sh creation flow, and comprehensive unit tests covering direct paths, subdirectories, symlinks, safe paths, and argument parsing. The implementation is clean, well-documented, and handles edge cases gracefully.

## Requirement Alignment
**Status:** yes

All 5 tasks map directly to implementation: (1) DANGEROUS_PATHS array in lib/validate.sh contains all 13 paths specified in the plan (~/.ssh, ~/.aws, ~/.config/gcloud, ~/.config/gh, ~/.azure, ~/.netrc, ~/.kube, ~/.gnupg, ~/.docker, ~/.npmrc, ~/.pypirc, /var/run/docker.sock, /run/docker.sock). (2) validate_mount_path() implemented with is_dangerous_mount_path() helper using realpath -m for symlink resolution. (3) --allow-dangerous-mount flag added to lib/args.sh (default: false, parsed correctly). (4) Mount validation integrated at the correct point in commands/new.sh (lines 244-254) — checks each mount's host path unless override flag is set, with warning when bypassed. (5) Unit tests in tests/test_validate.sh cover 19 test cases across 5 categories.

## Success Criteria
**Status:** yes

All Phase 1 verification criteria are satisfied: (1) 'sandbox new --mount ~/.ssh:/ssh' would be blocked — validate_mount_path() calls die() with clear error message including the matched dangerous path and override instructions. (2) 'sandbox new --mount ~/.ssh:/ssh --allow-dangerous-mount' would succeed — when flag is true, validation is skipped and a warning is emitted via warn(). (3) Symlinks to ~/.ssh are also blocked — is_dangerous_mount_path() uses realpath -m to resolve symlinks before matching. The fidelity review criteria (all dangerous paths blocked, override flag works, symlinks resolved correctly, error messages clear and actionable) are all met.

## Deviations

- **[LOW]** The implementation splits path checking into two functions (is_dangerous_mount_path as a boolean check + validate_mount_path as a die-on-failure wrapper) rather than a single validate_mount_path function.
  - Justification: This is a positive deviation — the separation allows the test suite to use the boolean helper (is_dangerous_mount_path) for assertions without triggering die/exit, while validate_mount_path provides the blocking behavior for production use. Good software design practice.
- **[LOW]** MATCHED_DANGEROUS_PATH is set as a global variable rather than being returned via a mechanism like stdout capture.
  - Justification: Acceptable in bash context — bash functions can't return strings, so a global variable is the standard pattern. The variable name is descriptive and scoped to the validation logic. Used in both the error message and could be useful for future logging.

## Test Coverage
**Status:** sufficient

19 test cases across 5 categories provide comprehensive coverage: (1) Direct dangerous path tests — 4 tests covering ~/.ssh, ~/.aws, /var/run/docker.sock, /run/docker.sock. (2) Subdirectory tests — 5 tests covering subpaths of ~/.ssh, ~/.aws, ~/.config/gcloud, ~/.azure, ~/.kube. (3) Symlink tests — 2 tests with graceful skip when symlinks can't be created, plus proper cleanup via rm -rf of temp dir. (4) Safe path tests — 5 negative tests confirming /tmp, $HOME/projects, /workspace, $HOME/Documents, /opt/myapp are allowed. (5) Argument parsing tests — 3 tests verifying flag parsing: present, absent (default false), and with other args. Minor gap: no test for validate_mount_path() itself (the die-on-failure wrapper) or the MATCHED_DANGEROUS_PATH content, but the underlying is_dangerous_mount_path function is thoroughly tested.

## Code Quality

Code is clean, well-commented, and follows existing codebase patterns. The realpath -m fallback handles environments where realpath is unavailable. Path extraction from mount spec uses correct ${mount%%:*} parameter expansion. The is_dangerous_mount_path function correctly checks both exact matches and subdirectory matches against both the original and resolved paths. Test file properly sources all required libraries and includes cleanup of temporary test directories.


## Documentation
**Status:** adequate

Implementation is well-documented: (1) DANGEROUS_PATHS array has a clear comment explaining its purpose. (2) is_dangerous_mount_path() has inline docs explaining return values and the MATCHED_DANGEROUS_PATH side-effect. (3) validate_mount_path() has a brief doc comment. (4) --allow-dangerous-mount flag is documented in the help text with description 'Allow mounting credential directories (unsafe)'. (5) The error message in validate_mount_path includes the matched path and instructions to use the override flag. (6) Test file has a header comment describing its scope.

## Recommendations

- Consider adding a test case for validate_mount_path() directly to verify the die message format (could use a subshell to capture the exit).
- Consider testing a path like $HOME/.sshkeys to verify it is NOT flagged (prefix-but-not-subdirectory false positive check).
- When moving to Phase 2+, consider whether the DANGEROUS_PATHS array should be configurable via a config file for user customization.

---
*Generated by Foundry MCP Fidelity Review*