# sbx Compatibility

foundry-sandbox depends on Docker's `sbx` CLI for microVM lifecycle, network policy, secret storage, and credential injection. This document tracks which `sbx` versions are tested and supported.

## Supported Version Range

| Constant | Value | Description |
|----------|-------|-------------|
| `SBX_MIN_VERSION` | 0.26.0 | Minimum supported version |
| `SBX_MAX_VERSION` | 0.29.0 | Exclusive upper bound |

Defined in `foundry_sandbox/sbx.py`. Every `cast` command that calls `sbx_check_available()` enforces this range.

**Out-of-range behavior:** `cast` prints a clear error to stderr with the detected version, supported range, and remediation steps, then exits with code 1.

## Tested-Against Matrix

| sbx Version | OS | Hypervisor | Date Tested | Result |
|-------------|-----|-----------|-------------|--------|
| 0.26.1 | Fedora 43 (Linux 6.17.8) | KVM | 2026-04-20 | Pass — Phase 0 validation, all features working |

## Rationale

- **0.26.0 minimum**: The version where Linux KVM microVM support was confirmed working. Earlier versions may work but have not been tested.
- **0.29.0 max**: Upper bound set conservatively. When a new `sbx` version is released, the weekly CI drift job (`sbx-drift.yml`) will open an issue prompting manual testing and range expansion.

## Pinning a Specific Version

To pin a specific `sbx` version (recommended for production use):

1. Download the binary from [GitHub releases](https://github.com/docker/sbx-releases):
   ```bash
   curl -fsSL https://github.com/docker/sbx-releases/releases/download/v0.26.1/sbx-linux-amd64 -o /usr/local/bin/sbx
   chmod +x /usr/local/bin/sbx
   ```
2. Verify: `sbx --version`
3. Prevent accidental upgrades by excluding from package manager updates.

## Expanding the Supported Range

1. Install the new `sbx` version
2. Run `./scripts/ci-local.sh` — all tests must pass
3. Run the chaos test modules against a live sandbox: `./tests/chaos/runner.sh`
4. Run the benchmark script: `./scripts/bench-git-safety.py --sandbox <name>`
5. Update `SBX_MIN_VERSION` or `SBX_MAX_VERSION` in `foundry_sandbox/sbx.py`
6. Add an entry to the tested-against matrix above
7. Commit and push

## Weekly Drift Detection

A GitHub Actions workflow (`.github/workflows/sbx-drift.yml`) runs weekly:
- Downloads the latest `sbx` release
- Compares against the supported range
- Opens a GitHub issue labeled `sbx-drift` if the version is outside range
- Deduplicates: comments on an existing open issue rather than creating duplicates

Can also be triggered manually via the GitHub Actions "Run workflow" button.
