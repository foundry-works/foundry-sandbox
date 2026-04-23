# Operations Runbook

This runbook focuses on the current supported operating model: sandbox lifecycle, host-side paths, diagnostics, wrapper repair, and common failure cases.

## Host Paths

Current defaults:

```text
~/.sandboxes/
  sandboxes/<name>/metadata.json
  presets/
  .last-cast-new.json
  .last-attach.json

<repo>/.sbx/<sandbox>-worktrees/<branch>/

~/.foundry/
  secrets/sandbox-hmac/<sandbox>
  data/git-safety/sandboxes/<sandbox>.json
  logs/decisions.jsonl
```

## Routine Operations

### Inspect Local State

```bash
cast config
cast list
cast status repo-feature-login
cast diagnose
```

### Start and Stop

```bash
cast stop repo-feature-login
cast start repo-feature-login
cast start repo-feature-login --watchdog
```

### Attach and Reattach

```bash
cast attach repo-feature-login
cast attach --last
```

### Destroy

```bash
cast destroy repo-feature-login --yes
cast destroy-all
```

`cast destroy-all` requires the literal confirmation string `destroy all` unless `SANDBOX_NONINTERACTIVE=1` is set.

## Git Safety Server

`cast new` and `cast start` automatically ensure `foundry-git-safety` is running. Manual checks are still useful during troubleshooting:

```bash
foundry-git-safety status
foundry-git-safety start --foreground
foundry-git-safety stop
```

Useful local endpoints:

```bash
curl http://127.0.0.1:8083/health
curl http://127.0.0.1:8083/ready
curl http://127.0.0.1:8083/metrics
```

## Wrapper Repair

The supported repair paths are:

```bash
cast start repo-feature-login
cast watchdog
```

`cast start` verifies the installed wrapper and re-injects it when needed. `cast watchdog` keeps doing that for all running sandboxes on a polling loop.

Manual wrapper reinjection is intentionally not the primary runbook anymore; the authoritative wrapper asset is packaged as `foundry_sandbox/assets/git-wrapper.sh`.

If repair fails during `cast start`, the sandbox can still come up with git
safety disabled. Treat that as degraded operation only.

## Credentials

Refresh host credentials into running sandboxes:

```bash
cast refresh-creds repo-feature-login
cast refresh-creds --last
cast refresh-creds --all
```

## Troubleshooting

### `sbx` Not Available or Wrong Binary

Symptoms:

- `cast` exits before doing any work
- error mentions the Docker Desktop plugin shim

Checks:

```bash
sbx version
cast config
```

Foundry requires the standalone `sbx` CLI and will reject the Docker Desktop plugin shim.

### Metadata Exists but the Sandbox Does Not

Symptoms:

- `cast start <name>` reports metadata exists but no `sbx` sandbox exists

Resolution:

```bash
cast destroy <name>
cast new <repo> <branch>
```

This usually indicates partial cleanup or pre-current-layout state.

### Git Commands Fail Inside the Sandbox

Checks:

```bash
foundry-git-safety status
cast diagnose
cast status repo-feature-login
cast start repo-feature-login
```

`cast start` is the supported repair path for missing or stale wrapper state.

### Git Safety Disabled After Start

Symptoms:

- `cast start` reports the sandbox started without git safety enforcement
- `cast status <name>` shows `Git safety: False`

Checks:

```bash
cast status repo-feature-login
foundry-git-safety status
cast diagnose
sbx exec repo-feature-login -- which git
```

Resolution:

```bash
cast start repo-feature-login
cast status repo-feature-login
cast destroy repo-feature-login --yes
cast new <repo> <branch> <from-branch>
```

Do not trust sandbox git enforcement until `cast status` reports `Git safety`
as true and the wrapper resolves to `/usr/local/bin/git`.

### Credentials Not Taking Effect

Checks:

```bash
cast refresh-creds --all
sbx secret list
```

Verify the corresponding host environment variables are set before refreshing.

### Deep Policy Changes Not Reflected

If you changed deep-policy rules in `foundry-git-safety`, restart the server and recreate or restart the sandbox:

```bash
foundry-git-safety stop
foundry-git-safety start --deep-policy
cast start repo-feature-login
```
