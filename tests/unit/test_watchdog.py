"""Tests for foundry_sandbox.watchdog module."""

from __future__ import annotations

from unittest.mock import patch

from foundry_sandbox.watchdog import (
    WrapperWatchdog,
    get_reinjection_count,
)


def _poll_context(
    *,
    ls_return=None,
    running=True,
    meta=None,
    checksum="abc123",
    verify_return=(True, "abc123"),
):
    """Build a decorator stack that mocks all _poll_all_sandboxes dependencies."""
    import functools

    def decorator(func):
        @functools.wraps(func)
        @patch("foundry_sandbox.state.patch_sandbox_metadata")
        @patch("foundry_sandbox.git_safety.inject_git_wrapper")
        @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=verify_return)
        @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value=checksum)
        @patch("foundry_sandbox.state.load_sandbox_metadata", return_value=meta)
        @patch("foundry_sandbox.sbx.sbx_is_running", return_value=running)
        @patch("foundry_sandbox.sbx.sbx_ls", return_value=ls_return or [])
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator


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
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "def456"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_reinjects_on_mismatch(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_inject, mock_patch,
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
    @patch("foundry_sandbox.state.patch_sandbox_metadata")
    @patch("foundry_sandbox.git_safety.inject_git_wrapper")
    @patch("foundry_sandbox.git_safety.verify_wrapper_integrity", return_value=(False, "wrong"))
    @patch("foundry_sandbox.git_safety.compute_wrapper_checksum", return_value="abc123")
    @patch("foundry_sandbox.state.load_sandbox_metadata")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_counter_increments(
        self, mock_ls, mock_running, mock_meta, mock_checksum,
        mock_verify, mock_inject, mock_patch,
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
