# Wrapper Integrity Enforcement

## Purpose

The git wrapper script (`/usr/local/bin/git` inside each sandbox) mediates all git operations through the foundry-git-safety server. An agent with sudo access inside the sandbox can remove or replace this wrapper to regain unrestricted git access. Wrapper integrity enforcement detects and remediates such tampering.

## Threat Model

**Attacker:** An AI agent running inside a sandbox with sudo privileges.

**Attack:** `sudo rm /usr/local/bin/git` or `sudo mv /usr/bin/git /usr/local/bin/git` to bypass the safety proxy.

**Defenses in depth:**

1. **Template bake** — The wrapper is baked into the `foundry-git-wrapper:latest` sbx template, so it survives `sbx reset`.
2. **Checksum verification** — `cast start` computes SHA-256 of the installed wrapper and compares against the expected digest stored in sandbox metadata.
3. **Watchdog polling** — An optional background thread periodically verifies all running sandboxes and re-injects the wrapper on drift.

## How It Works

### At Sandbox Creation (`cast new`)

1. The wrapper is injected into the sandbox via `sbx exec`.
2. The SHA-256 checksum of the local `stubs/git-wrapper-sbx.sh` is computed and stored in the sandbox's metadata file as `wrapper_checksum`.

### At Sandbox Start (`cast start`)

1. `verify_wrapper_integrity()` reads `sha256sum /usr/local/bin/git` from inside the sandbox.
2. The result is compared against the stored `wrapper_checksum`.
3. On mismatch or absence, the wrapper is re-injected and the metadata is updated.
4. The `wrapper_last_verified` timestamp is always updated.

### Continuous Monitoring (`cast watchdog`)

A daemon thread polls all running sandboxes at a configurable interval (default 30s):

1. Computes the expected checksum once per cycle.
2. For each running sandbox with `git_safety_enabled`, verifies the installed wrapper.
3. Re-injects on mismatch and logs a warning.
4. Updates `wrapper_last_verified` on match.

```bash
# Start standalone watchdog
cast watchdog

# Start watchdog alongside a sandbox
cast start my-sandbox --watchdog

# Custom poll interval
cast watchdog --interval 60
```

## CLI Surface

- **`cast status <name>`** — Shows `Wrapper checksum: <first 16 hex chars>...` and `Wrapper last verified: <ISO timestamp>` when available.
- **`cast list`** — Running sandboxes without a stored checksum show a `!` drift marker.

## Residual Risk

The watchdog closes the window between tampering and detection, but does not eliminate it:

- **Race window:** Up to one poll interval (default 30s) may pass before re-injection.
- **`sbx exec` access:** A sophisticated agent could also interfere with `sbx exec` calls from the host. This is documented as an accepted risk in the security model.
- **Root inside VM:** Full root access inside the microVM cannot be restricted by foundry — this is a property of the `sbx` runtime. The wrapper is a best-effort mediation layer, not a mandatory access control.

For environments requiring stronger guarantees, consider disabling `sbx exec -u root` for non-foundry callers (requires sbx-side policy support).
