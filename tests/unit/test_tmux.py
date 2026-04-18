"""Unit tests for foundry_sandbox.tmux.

Tests session existence checks, session creation command construction,
scrollback/mouse configuration, and the attach dispatch logic.

All subprocess and os.execvp calls are mocked.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.tmux import (
    attach,
    attach_existing,
    create_and_attach,
    session_exists,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(returncode=0):
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# TestSessionExists
# ---------------------------------------------------------------------------


class TestSessionExists:
    """session_exists checks tmux has-session."""

    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_true_when_session_found(self, mock_run):
        assert session_exists("my-session") is True
        cmd = mock_run.call_args[0][0]
        assert cmd == ["tmux", "has-session", "-t", "my-session"]

    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(1))
    def test_false_when_no_session(self, mock_run):
        assert session_exists("missing") is False

    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_uses_check_false(self, mock_run):
        """Must not raise on exit code 1."""
        session_exists("test")
        _, kwargs = mock_run.call_args
        assert kwargs["check"] is False


# ---------------------------------------------------------------------------
# TestCreateAndAttach
# ---------------------------------------------------------------------------


class TestCreateAndAttach:
    """create_and_attach creates session and configures scrollback/mouse."""

    @patch("foundry_sandbox.tmux.os.execvp")
    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_creates_session_with_container(self, mock_run, mock_execvp, monkeypatch):
        monkeypatch.delenv("CONTAINER_USER", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_SCROLLBACK", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_MOUSE", raising=False)

        create_and_attach("sess", "/worktree", "container-1")

        # First call: new-session
        new_session_call = mock_run.call_args_list[0]
        cmd = new_session_call[0][0]
        assert cmd[:4] == ["tmux", "new-session", "-d", "-s"]
        assert cmd[4] == "sess"

        # Should exec into tmux attach
        mock_execvp.assert_called_once_with(
            "tmux", ["tmux", "attach-session", "-t", "sess"]
        )

    @patch("foundry_sandbox.tmux.os.execvp")
    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_configures_scrollback(self, mock_run, mock_execvp, monkeypatch):
        monkeypatch.delenv("CONTAINER_USER", raising=False)
        monkeypatch.setenv("SANDBOX_TMUX_SCROLLBACK", "50000")
        monkeypatch.delenv("SANDBOX_TMUX_MOUSE", raising=False)

        create_and_attach("sess", "/worktree", "c1")

        # Find scrollback configuration call
        scrollback_calls = [
            c for c in mock_run.call_args_list
            if "history-limit" in (c[0][0] if c[0] else [])
        ]
        assert len(scrollback_calls) == 1
        cmd = scrollback_calls[0][0][0]
        assert "50000" in cmd

    @patch("foundry_sandbox.tmux.os.execvp")
    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_mouse_on_by_default(self, mock_run, mock_execvp, monkeypatch):
        monkeypatch.delenv("CONTAINER_USER", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_SCROLLBACK", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_MOUSE", raising=False)

        create_and_attach("sess", "/worktree", "c1")

        mouse_calls = [
            c for c in mock_run.call_args_list
            if "mouse" in (c[0][0] if c[0] else [])
        ]
        assert len(mouse_calls) == 1
        cmd = mouse_calls[0][0][0]
        assert "on" in cmd

    @patch("foundry_sandbox.tmux.os.execvp")
    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_mouse_off_when_disabled(self, mock_run, mock_execvp, monkeypatch):
        monkeypatch.delenv("CONTAINER_USER", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_SCROLLBACK", raising=False)
        monkeypatch.setenv("SANDBOX_TMUX_MOUSE", "0")

        create_and_attach("sess", "/worktree", "c1")

        mouse_calls = [
            c for c in mock_run.call_args_list
            if "mouse" in (c[0][0] if c[0] else [])
        ]
        assert len(mouse_calls) == 1
        cmd = mouse_calls[0][0][0]
        assert "off" in cmd

    @patch("foundry_sandbox.tmux.os.execvp")
    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_working_dir_in_exec_cmd(self, mock_run, mock_execvp, monkeypatch):
        monkeypatch.delenv("CONTAINER_USER", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_SCROLLBACK", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_MOUSE", raising=False)

        create_and_attach("sess", "/worktree", "c1", working_dir="apps/api")

        new_session_call = mock_run.call_args_list[0]
        cmd = new_session_call[0][0]
        # The docker command should contain the working dir
        docker_cmd_str = cmd[-1]  # Last arg is the shell command
        assert "apps/api" in docker_cmd_str

    @patch("foundry_sandbox.tmux.os.execvp")
    @patch("foundry_sandbox.tmux.subprocess.run", return_value=_completed(0))
    def test_custom_container_user(self, mock_run, mock_execvp, monkeypatch):
        monkeypatch.setenv("CONTAINER_USER", "custom-user")
        monkeypatch.delenv("SANDBOX_TMUX_SCROLLBACK", raising=False)
        monkeypatch.delenv("SANDBOX_TMUX_MOUSE", raising=False)

        create_and_attach("sess", "/worktree", "c1")

        new_session_call = mock_run.call_args_list[0]
        cmd = new_session_call[0][0]
        docker_cmd_str = cmd[-1]
        assert "custom-user" in docker_cmd_str


# ---------------------------------------------------------------------------
# TestAttachExisting
# ---------------------------------------------------------------------------


class TestAttachExisting:
    """attach_existing replaces process with tmux attach."""

    @patch("foundry_sandbox.tmux.os.execvp")
    def test_execs_tmux_attach(self, mock_execvp):
        attach_existing("my-session")
        mock_execvp.assert_called_once_with(
            "tmux", ["tmux", "attach-session", "-t", "my-session"]
        )


# ---------------------------------------------------------------------------
# TestAttach
# ---------------------------------------------------------------------------


class TestAttach:
    """attach dispatches to create_and_attach or attach_existing."""

    @patch("foundry_sandbox.tmux.create_and_attach")
    @patch("foundry_sandbox.tmux.session_exists", return_value=False)
    def test_creates_when_no_session(self, mock_exists, mock_create):
        attach("my-sandbox", "c1", "/worktree", "apps/api")
        mock_create.assert_called_once_with("my-sandbox", "/worktree", "c1", "apps/api")

    @patch("foundry_sandbox.tmux.attach_existing")
    @patch("foundry_sandbox.tmux.session_exists", return_value=True)
    def test_attaches_when_session_exists(self, mock_exists, mock_attach):
        attach("my-sandbox", "c1", "/worktree")
        mock_attach.assert_called_once_with("my-sandbox")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
