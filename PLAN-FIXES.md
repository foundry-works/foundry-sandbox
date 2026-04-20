# Plan Fixes

1. Fix stdin-backed `sbx` execution in `foundry_sandbox/sbx.py`.
   - Make `_run_sbx()` use text mode when passing string input.
   - Verify `sbx_secret_set()`, wrapper injection, and `--copy` all work with real subprocess calls.
   - Add tests that fail on the current `TypeError` path.

2. Fix git wrapper workspace detection and fail closed when git safety is not active.
   - Stop hard-coding `WORKSPACE_DIR=/workspace`.
   - Pass the real sandbox workspace path into wrapper setup.
   - Ensure git commands inside the synced repo do not fall through to `/usr/bin/git` when git safety should be enforced.

3. Restore a real interactive attach flow.
   - Update `sbx_exec_streaming()` to use `sbx exec -it` for interactive sessions.
   - Start a login shell or otherwise guarantee `/etc/profile.d/foundry-git-safety.sh` is sourced.
   - Add an attach-path test that covers shell startup assumptions.

4. Remove or replace the stale installer build step.
   - `install.sh` still calls `cast build`, but the CLI no longer exposes `build`.
   - Either restore a supported build command or remove the installer step and update the user-facing messaging.
   - Add a CLI/install test so the installer cannot reference deleted commands again.

5. Preserve `agent` in `cast new --last` and preset replay state.
   - Save `agent=agent` in `save_last_cast_new()` and `save_cast_preset()` call sites.
   - Add tests for `--agent codex --last` and preset replay to confirm the selected agent survives round-trips.
