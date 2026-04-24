# sbx Compatibility

Foundry Sandbox depends on Docker's standalone `sbx` CLI for microVM
lifecycle, network policy, secret storage, credential injection, and sandbox
templates. This page tracks which `sbx` versions are supported by the current
Foundry codebase.

For the product-level responsibility split, see
[Foundry and sbx](foundry-and-sbx.md).

## Supported Version Range

| Constant | Value | Description |
|----------|-------|-------------|
| `SBX_MIN_VERSION` | `0.26.0` | Minimum supported version |
| `SBX_MAX_VERSION` | `0.29.0` | Exclusive upper bound |

These constants are defined in `foundry_sandbox/sbx.py`. Every `cast` command
that checks `sbx` availability enforces this range before creating, starting, or
attaching to a sandbox.

When the installed version is outside the supported range, `cast` exits with a
clear error that includes the detected version, the supported range, and the
recommended remediation.

## Tested-Against Matrix

| sbx Version | OS | Hypervisor | Date Tested | Result |
|-------------|----|------------|-------------|--------|
| `0.26.1` | Fedora 43, Linux 6.17.8 | KVM | 2026-04-20 | Pass: Phase 0 validation and sbx migration baseline |

The supported range is intentionally wider than the tested-against matrix. The
matrix records versions that have been manually validated with live `sbx`
sandboxes and Foundry's git-safety workflow.

## Compatibility Rationale

The `0.26.0` minimum reflects the earliest supported line where Foundry's sbx
migration assumptions were validated: standalone CLI behavior, Linux KVM
microVMs, host-side credential injection, `sbx exec`, policy commands, and
template support.

The `< 0.29.0` upper bound is conservative. Docker Sandboxes is still documented
as experimental, so Foundry treats new `sbx` release lines as requiring manual
validation before the supported range is expanded.

Foundry requires the standalone `sbx` CLI. It rejects Docker Desktop's
`docker sandbox` plugin shim because the plugin has a smaller command surface
and different lifecycle behavior.

## Commands Foundry Relies On

Foundry's `sbx` wrapper currently depends on these command surfaces:

```bash
sbx version
sbx create
sbx run
sbx stop
sbx rm
sbx ls --json
sbx exec
sbx secret set
sbx template save
sbx template rm
sbx diagnose
```

When reviewing a new `sbx` release, check these commands first. Pay special
attention to output format changes in `sbx version`, `sbx ls --json`, and
diagnostic commands.

## Expanding the Supported Range

Before updating `SBX_MIN_VERSION` or `SBX_MAX_VERSION`:

1. Install the new standalone `sbx` release.
2. Confirm `sbx version` reports the expected version.
3. Run the unit suite.
4. Run live smoke tests against a real `sbx` sandbox.
5. Run chaos and red-team suites that exercise wrapper injection, wrapper
   repair, credential isolation, branch isolation, and blocked git operations.
6. Update the constants in `foundry_sandbox/sbx.py`.
7. Add a row to the tested-against matrix above.

Useful commands:

```bash
pytest tests/unit
pytest tests/smoke -m requires_sbx
./tests/chaos/runner.sh
./tests/redteam/runner.sh
```

## Weekly Drift Detection

`.github/workflows/sbx-drift.yml` runs weekly and can also be triggered
manually. It downloads the latest `sbx` release, compares that version against
the supported range in `foundry_sandbox/sbx.py`, and opens or updates an
`sbx-drift` issue when the latest release is outside the supported range.

When closing a drift issue, update this document along with the version
constants.

## Primary sbx References

- [Docker Sandboxes overview](https://docs.docker.com/ai/sandboxes/)
- [Docker Sandboxes get started](https://docs.docker.com/ai/sandboxes/get-started/)
- [`sbx` CLI reference](https://docs.docker.com/reference/cli/sbx/)
- [`sbx template` reference](https://docs.docker.com/reference/cli/sbx/template/)
- [`sbx version` reference](https://docs.docker.com/reference/cli/sbx/version/)
