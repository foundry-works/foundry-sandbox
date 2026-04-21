"""Host-side watchdog for git wrapper integrity enforcement.

Periodically polls running sandboxes and re-injects the git wrapper
when a checksum mismatch is detected. Runs as a daemon thread.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from foundry_sandbox.utils import log_debug, log_warn

_reinjection_count: int = 0


class WrapperWatchdog:
    """Background thread that monitors sandbox wrapper integrity."""

    def __init__(
        self,
        *,
        poll_interval: float = 10.0,
    ) -> None:
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the watchdog daemon thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="wrapper-watchdog",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the watchdog to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def is_running(self) -> bool:
        """Check if the watchdog thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def _run_loop(self) -> None:
        """Main poll loop (runs in daemon thread)."""
        while not self._stop_event.is_set():
            try:
                self._poll_all_sandboxes()
            except Exception as exc:
                log_debug(f"Watchdog poll error: {exc}")
            self._stop_event.wait(timeout=self._poll_interval)

    def _poll_all_sandboxes(self) -> None:
        from foundry_sandbox.git_safety import (
            compute_wrapper_checksum,
            verify_wrapper_integrity,
        )
        from foundry_sandbox.sbx import sbx_is_running, sbx_ls
        from foundry_sandbox.state import load_sandbox_metadata, patch_sandbox_metadata

        try:
            expected_checksum = compute_wrapper_checksum()
        except FileNotFoundError:
            return

        for sb in sbx_ls():
            if self._stop_event.is_set():
                return
            name = sb.get("name", "")
            if not name or not sbx_is_running(name):
                continue
            metadata = load_sandbox_metadata(name)
            if not metadata or not metadata.get("git_safety_enabled", True):
                continue

            try:
                is_ok, actual_sha = verify_wrapper_integrity(
                    name, expected_checksum=expected_checksum,
                )
            except Exception:
                continue

            if not is_ok:
                self._reinject_wrapper(
                    name, metadata, expected_checksum, actual_sha,
                )
            else:
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    patch_sandbox_metadata(name, wrapper_last_verified=now)
                except Exception:
                    pass

    def _reinject_wrapper(
        self,
        name: str,
        metadata: dict[str, object],
        expected_checksum: str,
        actual_checksum: str,
    ) -> None:
        from foundry_sandbox.git_safety import (
            emit_wrapper_tamper_event,
            generate_hmac_secret,
            inject_git_wrapper,
            write_hmac_secret_for_server,
            write_hmac_secret_to_sandbox,
        )
        from foundry_sandbox.state import patch_sandbox_metadata

        global _reinjection_count

        sandbox_id = str(metadata.get("sbx_name", name))
        workspace_dir = str(metadata.get("workspace_dir", "/workspace"))

        # Rotate HMAC before re-injection so any captured old secret is dead.
        try:
            new_secret = generate_hmac_secret()
            write_hmac_secret_to_sandbox(name, new_secret)
            write_hmac_secret_for_server(sandbox_id, new_secret)
        except Exception as exc:
            log_warn(
                f"Watchdog: HMAC rotation failed for '{name}', "
                f"skipping re-injection: {exc}"
            )
            emit_wrapper_tamper_event(
                sandbox=name,
                expected_sha256=expected_checksum,
                actual_sha256=actual_checksum,
                action="reinject_failed",
            )
            return

        try:
            inject_git_wrapper(
                name, sandbox_id=sandbox_id, workspace_dir=workspace_dir,
            )
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            patch_sandbox_metadata(
                name,
                wrapper_checksum=expected_checksum,
                wrapper_last_verified=now,
            )
            _reinjection_count += 1
            log_warn(
                f"Watchdog: re-injected git wrapper in '{name}' "
                f"(checksum={expected_checksum[:12]}...)"
            )
            emit_wrapper_tamper_event(
                sandbox=name,
                expected_sha256=expected_checksum,
                actual_sha256=actual_checksum,
                action="reinjected",
            )
        except Exception as exc:
            log_debug(f"Watchdog: re-injection failed for '{name}': {exc}")
            emit_wrapper_tamper_event(
                sandbox=name,
                expected_sha256=expected_checksum,
                actual_sha256=actual_checksum,
                action="reinject_failed",
            )


def get_reinjection_count() -> int:
    """Return total number of re-injections performed by the watchdog."""
    return _reinjection_count


_singleton: WrapperWatchdog | None = None


def start_watchdog(*, poll_interval: float = 10.0) -> WrapperWatchdog:
    """Start the global watchdog singleton."""
    global _singleton
    if _singleton is None:
        _singleton = WrapperWatchdog(poll_interval=poll_interval)
    _singleton.start()
    return _singleton


def stop_watchdog() -> None:
    """Stop the global watchdog singleton."""
    global _singleton
    if _singleton is not None:
        _singleton.stop()
