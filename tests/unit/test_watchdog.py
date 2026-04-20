"""Tests for foundry_sandbox.watchdog module."""

from __future__ import annotations

from unittest.mock import patch

from foundry_sandbox.watchdog import (
    WrapperWatchdog,
    get_reinjection_count,
    start_watchdog,
)


class TestWrapperWatchdogStartStop:
    def test_start_creates_daemon_thread(self):
        wd = WrapperWatchdog(poll_interval=999)
        with patch.object(wd, "_poll_all_sandboxes"):
            wd.start()
        try:
            assert wd.is_running()
            t = wd._thread
            assert t is not None
            assert t.daemon is True
        finally:
            wd.stop()

    def test_stop_joins_thread(self):
        wd = WrapperWatchdog(poll_interval=999)
        with patch.object(wd, "_poll_all_sandboxes"):
            wd.start()
        wd.stop()
        assert not wd.is_running()
        assert wd._thread is None

    def test_start_idempotent(self):
        wd = WrapperWatchdog(poll_interval=999)
        with patch.object(wd, "_poll_all_sandboxes"):
            wd.start()
            wd.start()
        assert wd.is_running()
        wd.stop()


class TestWrapperWatchdogPoll:
    """Tests where _poll_all_sandboxes detects a mismatch and calls _reinject_wrapper."""

    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="s1")
    @patch("foundry_sandbox.paths.path_worktree", return_value="/tmp/wt")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "def456"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_reinjects_on_mismatch(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_worktree, mock_gen_hmac,
        mock_write_wt, mock_write_srv, mock_inject, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1",
            "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()

        mock_inject.assert_called_once_with(
            "sb1", sandbox_id="sb1", workspace_dir="/workspace",
        )
        mock_patch.assert_called_once()
        call_kwargs = mock_patch.call_args[1]
        assert call_kwargs["wrapper_checksum"] == "abc123"

    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(True, "abc123"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_skips_on_match(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_patch,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1",
            "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()

        mock_patch.assert_called_once()
        call_kwargs = mock_patch.call_args[1]
        assert "wrapper_last_verified" in call_kwargs

    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity")
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_skips_non_git_safety_sandboxes(
        self, mock_ls, mock_running, mock_meta, mock_checksum, mock_verify,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1",
            "git_safety_enabled": False,
        }
        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()
        mock_verify.assert_not_called()


class TestWrapperWatchdogReinjectionCount:
    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="s1")
    @patch("foundry_sandbox.paths.path_worktree", return_value="/tmp/wt")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_counter_increments(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_worktree, mock_gen_hmac,
        mock_write_wt, mock_write_srv, mock_inject, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [
            {"name": "sb1", "status": "running"},
            {"name": "sb2", "status": "running"},
        ]

        def meta_side_effect(name):
            return {
                "sbx_name": name,
                "workspace_dir": "/workspace",
                "git_safety_enabled": True,
            }

        mock_meta.side_effect = meta_side_effect

        before = get_reinjection_count()
        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()
        assert get_reinjection_count() == before + 2


class TestWrapperWatchdogComputeError:
    @patch(
        "foundry_sandbox.git_safety.compute_wrapper_checksum",
        side_effect=FileNotFoundError,
    )
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_returns_early_on_missing_wrapper(self, mock_ls, mock_checksum):
        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()
        mock_ls.assert_not_called()


# ============================================================================
# H1: Default poll interval is 10.0
# ============================================================================


class TestDefaultInterval:
    def test_default_poll_interval_is_10(self):
        wd = WrapperWatchdog()
        assert wd._poll_interval == 10.0

    def test_start_watchdog_default_interval_is_10(self):
        with patch("foundry_sandbox.watchdog.WrapperWatchdog.start"):
            with patch("foundry_sandbox.watchdog._singleton", None):
                wd = start_watchdog()
                assert wd._poll_interval == 10.0


# ============================================================================
# H2: HMAC rotation on re-injection
# ============================================================================


class TestHmacRotationOnReinjection:
    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="new_secret_1")
    @patch("foundry_sandbox.paths.path_worktree", return_value="/tmp/worktrees/sb1")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_hmac_writers_called_before_inject(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_worktree, mock_gen_hmac,
        mock_write_wt, mock_write_srv, mock_inject, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1", "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        # Track call order
        call_order = []
        mock_write_wt.side_effect = lambda *a, **kw: call_order.append("write_wt")
        mock_write_srv.side_effect = lambda *a, **kw: call_order.append("write_srv")
        mock_inject.side_effect = lambda *a, **kw: call_order.append("inject")

        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()

        assert call_order == ["write_wt", "write_srv", "inject"]

    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.paths.path_worktree", return_value="/tmp/wt")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_consecutive_tamper_events_produce_different_secrets(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_worktree,
        mock_write_wt, mock_write_srv,
        mock_inject, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1", "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        counter = {"n": 0}

        def gen_secret():
            n = counter["n"]
            counter["n"] += 1
            return f"secret_{n}"

        with patch(
            "foundry_sandbox.git_safety.generate_hmac_secret",
            side_effect=gen_secret,
        ):
            wd = WrapperWatchdog(poll_interval=999)
            wd._poll_all_sandboxes()
            wd._poll_all_sandboxes()

        # Two polls → two distinct HMAC values
        assert counter["n"] == 2

    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", side_effect=OSError("disk full"))
    @patch("foundry_sandbox.paths.path_worktree", return_value="/tmp/wt")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_hmac_failure_skips_reinjection(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_worktree, mock_gen_hmac,
        mock_write_wt, mock_write_srv, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1", "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()

        mock_emit.assert_called_once_with(
            sandbox="sb1",
            expected_sha256="abc123",
            actual_sha256="wrong",
            action="reinject_failed",
        )


# ============================================================================
# H3: Tamper event observability
# ============================================================================


class TestTamperEventEmission:
    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_for_server")
    @patch("foundry_sandbox.git_safety.write_hmac_secret_to_worktree")
    @patch("foundry_sandbox.git_safety.generate_hmac_secret", return_value="s1")
    @patch("foundry_sandbox.paths.path_worktree", return_value="/tmp/wt")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_event_emitted_once_per_mismatch(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_worktree, mock_gen_hmac,
        mock_write_wt, mock_write_srv, mock_inject, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1", "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()

        mock_emit.assert_called_once_with(
            sandbox="sb1",
            expected_sha256="abc123",
            actual_sha256="wrong",
            action="reinjected",
        )

    @patch("foundry_sandbox.git_safety.emit_wrapper_tamper_event")
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(True, "abc123"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_no_event_on_matching_checksum(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_patch, mock_emit,
    ):
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_meta.return_value = {
            "sbx_name": "sb1", "workspace_dir": "/workspace",
            "git_safety_enabled": True,
        }

        wd = WrapperWatchdog(poll_interval=999)
        wd._poll_all_sandboxes()

        mock_emit.assert_not_called()
