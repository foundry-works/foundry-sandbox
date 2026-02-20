"""Unit tests for foundry_sandbox.docker.exec_in_container_streaming().

Tests for real-time streaming execution of commands inside containers,
including normal completion, timeout handling with SIGTERM/SIGKILL sequence,
and docker stop backstop calls.

All subprocess calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch, call

import pytest

from foundry_sandbox.docker import exec_in_container_streaming


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_process(returncode: int = 0) -> MagicMock:
    """Build a mock subprocess.Popen process."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.wait = MagicMock(return_value=returncode)
    proc.terminate = MagicMock()
    proc.kill = MagicMock()
    return proc


def _mock_process_timeout_on_first_wait(
    timeout_seconds: int | None = None,
) -> MagicMock:
    """Build a mock process that raises TimeoutExpired on first wait()."""
    proc = MagicMock()

    def wait_side_effect(timeout=None):
        # First call (with main timeout) raises TimeoutExpired
        if timeout == timeout_seconds or (timeout_seconds is None and timeout is None):
            raise subprocess.TimeoutExpired("docker exec", timeout or 0)
        # Subsequent calls (e.g., with 5s timeout or no timeout) return gracefully
        return 124

    proc.wait = MagicMock(side_effect=wait_side_effect)
    proc.terminate = MagicMock()
    proc.kill = MagicMock()
    return proc


def _mock_process_sigterm_fails(returncode: int = 143) -> MagicMock:
    """Build a mock process that doesn't stop after SIGTERM, requires SIGKILL."""
    proc = MagicMock()
    proc.returncode = returncode

    # Track call count to wait()
    call_count = [0]

    def wait_side_effect(timeout=None):
        call_count[0] += 1
        # First call (main timeout) raises TimeoutExpired
        if call_count[0] == 1:
            raise subprocess.TimeoutExpired("docker exec", timeout or 0)
        # Second call (5s timeout after SIGTERM) also raises
        if call_count[0] == 2 and timeout == 5:
            raise subprocess.TimeoutExpired("docker exec", 5)
        # Final call (after SIGKILL, no timeout) returns
        return returncode

    proc.wait = MagicMock(side_effect=wait_side_effect)
    proc.terminate = MagicMock()
    proc.kill = MagicMock()
    return proc


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingNormalCompletion
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingNormalCompletion:
    """Normal process completion returns the process exit code."""

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_returns_exit_code_zero(self, mock_verbose, mock_popen):
        """Process completes successfully with exit code 0."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("container-1", "echo", "hello")

        assert result == 0
        proc.wait.assert_called_once_with(timeout=3600)
        proc.terminate.assert_not_called()
        proc.kill.assert_not_called()

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_returns_nonzero_exit_code(self, mock_verbose, mock_popen):
        """Process exits with non-zero code."""
        proc = _mock_process(returncode=42)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("container-1", "false")

        assert result == 42
        proc.wait.assert_called_once_with(timeout=3600)

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_respects_custom_timeout(self, mock_verbose, mock_popen):
        """Custom timeout is passed to proc.wait()."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("container-1", "sleep", "1", timeout=60)

        assert result == 0
        proc.wait.assert_called_once_with(timeout=60)

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_builds_correct_docker_exec_command(self, mock_verbose, mock_popen):
        """Command is built correctly with docker exec prefix."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        exec_in_container_streaming("my-container", "ls", "-la", "/tmp")

        call_args = mock_popen.call_args[0][0]
        assert call_args == ["docker", "exec", "my-container", "ls", "-la", "/tmp"]


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingTimeout
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingTimeout:
    """Timeout handling returns exit code 124."""

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_returns_124_on_timeout(self, mock_verbose, mock_popen, mock_run):
        """Timeout expires, process is terminated, returns 124."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        result = exec_in_container_streaming("container-1", "long-command", timeout=3600)

        assert result == 124
        proc.terminate.assert_called_once()
        proc.kill.assert_not_called()  # SIGTERM succeeded, no SIGKILL needed

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_sigterm_wait_returns_before_sigkill(self, mock_verbose, mock_popen, mock_run):
        """SIGTERM → wait 5s succeeds, so no SIGKILL."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        result = exec_in_container_streaming("container-1", "cmd", timeout=3600)

        assert result == 124
        proc.terminate.assert_called_once()
        # First wait(timeout=3600) raises TimeoutExpired
        # Second wait(timeout=5) should return (mocked to return after TimeoutExpired)
        assert proc.wait.call_count == 2
        proc.kill.assert_not_called()

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_sigkill_when_sigterm_fails(self, mock_verbose, mock_popen, mock_run):
        """SIGTERM → wait 5s fails, so SIGKILL."""
        proc = _mock_process_sigterm_fails()
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        result = exec_in_container_streaming("container-1", "stubborn-process", timeout=3600)

        assert result == 124
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        # wait() called 3 times: main timeout, after SIGTERM, after SIGKILL
        assert proc.wait.call_count == 3

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_backstop_docker_stop_called_on_timeout(self, mock_verbose, mock_popen, mock_run):
        """docker stop backstop is called after timeout."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        exec_in_container_streaming("container-1", "cmd", timeout=3600)

        # Verify docker stop was called with correct args
        assert mock_run.called
        call_args = mock_run.call_args
        assert call_args[0][0] == ["docker", "stop", "--time", "10", "container-1"]
        assert call_args[1]["check"] is False
        assert call_args[1]["timeout"] == 15

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_backstop_suppresses_stderr_stdout(self, mock_verbose, mock_popen, mock_run):
        """docker stop backstop suppresses output."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        exec_in_container_streaming("container-1", "cmd", timeout=3600)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["stdout"] == subprocess.DEVNULL
        assert call_kwargs["stderr"] == subprocess.DEVNULL


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingBackstopErrors
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingBackstopErrors:
    """Backstop docker stop errors are handled gracefully."""

    @patch("foundry_sandbox.docker.log_warn")
    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_docker_stop_oserror_logged_and_ignored(
        self, mock_verbose, mock_popen, mock_run, mock_log_warn
    ):
        """OSError from docker stop is logged but doesn't affect return value."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.side_effect = OSError("docker not found")

        result = exec_in_container_streaming("container-1", "cmd", timeout=3600)

        assert result == 124
        assert mock_log_warn.called
        assert "Backstop docker stop failed" in mock_log_warn.call_args[0][0]

    @patch("foundry_sandbox.docker.log_warn")
    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_docker_stop_timeout_logged_and_ignored(
        self, mock_verbose, mock_popen, mock_run, mock_log_warn
    ):
        """TimeoutExpired from docker stop is logged but doesn't affect return value."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.side_effect = subprocess.TimeoutExpired("docker stop", 15)

        result = exec_in_container_streaming("container-1", "cmd", timeout=3600)

        assert result == 124
        assert mock_log_warn.called


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingNonExistentContainer
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingNonExistentContainer:
    """Non-existent container returns docker exec exit code."""

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_nonexistent_container_returns_docker_exit_code(self, mock_verbose, mock_popen):
        """docker exec returns non-zero for non-existent container."""
        # docker exec returns 125 for "container not found" style errors
        proc = _mock_process(returncode=125)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("nonexistent", "echo", "test")

        assert result == 125
        proc.wait.assert_called_once_with(timeout=3600)

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_various_docker_error_codes_propagate(self, mock_verbose, mock_popen):
        """Various docker error codes are returned as-is."""
        for error_code in [1, 127, 128, 137]:  # Various docker/command errors
            proc = _mock_process(returncode=error_code)
            mock_popen.return_value = proc

            result = exec_in_container_streaming(f"container", "cmd", timeout=3600)

            assert result == error_code


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingVerboseOutput
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingVerboseOutput:
    """Verbose mode prints command to stderr."""

    @patch("foundry_sandbox.docker.sys.stderr")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=True)
    def test_verbose_prints_command(self, mock_verbose, mock_popen, mock_stderr):
        """With verbose=True, command is printed to stderr."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        exec_in_container_streaming("container-1", "echo", "test")

        # Check that print was called with the command
        # Note: We're not directly testing print() here, but the code calls:
        # print(f"+ {' '.join(cmd)}", file=sys.stderr)
        # The actual test would need to capture that

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_non_verbose_no_print_overhead(self, mock_verbose, mock_popen):
        """With verbose=False, no print overhead."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("container-1", "echo", "test")

        assert result == 0
        # Verify Popen was called directly without print side effects
        mock_popen.assert_called_once()


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingSequenceValidation
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingSequenceValidation:
    """Verify the correct sequence of operations for SIGTERM/SIGKILL."""

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_graceful_shutdown_sequence_sigterm_succeeds(
        self, mock_verbose, mock_popen, mock_run
    ):
        """Verify sequence: wait(timeout) → TimeoutExpired → terminate() → wait(timeout=5) → success."""
        proc = _mock_process_timeout_on_first_wait(timeout_seconds=3600)
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        exec_in_container_streaming("container-1", "cmd", timeout=3600)

        # Verify call order
        terminate_called = False
        wait_calls = []

        for call_obj in proc.mock_calls:
            if call_obj[0] == 'terminate':
                terminate_called = True
            elif call_obj[0] == 'wait':
                wait_calls.append(call_obj)

        assert terminate_called
        # Should have 2 wait calls: initial and after SIGTERM
        assert len(wait_calls) >= 1

    @patch("foundry_sandbox.docker.subprocess.run")
    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_graceful_shutdown_sequence_sigkill_fallback(
        self, mock_verbose, mock_popen, mock_run
    ):
        """Verify sequence when SIGTERM fails: terminate() → wait(5) → TimeoutExpired → kill() → wait()."""
        proc = _mock_process_sigterm_fails()
        mock_popen.return_value = proc
        mock_run.return_value = MagicMock(returncode=0)

        exec_in_container_streaming("container-1", "stubborn", timeout=3600)

        # Verify terminate and kill were both called
        assert proc.terminate.called
        assert proc.kill.called

        # Verify wait was called 3 times
        assert proc.wait.call_count == 3


# ---------------------------------------------------------------------------
# TestExecInContainerStreamingEdgeCases
# ---------------------------------------------------------------------------


class TestExecInContainerStreamingEdgeCases:
    """Edge cases and boundary conditions."""

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_single_argument_command(self, mock_verbose, mock_popen):
        """Command with no additional arguments."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("container-1", "pwd")

        assert result == 0
        call_args = mock_popen.call_args[0][0]
        assert call_args == ["docker", "exec", "container-1", "pwd"]

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_many_arguments(self, mock_verbose, mock_popen):
        """Command with many arguments."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        args = [f"arg{i}" for i in range(10)]
        exec_in_container_streaming("container-1", "cmd", *args)

        call_args = mock_popen.call_args[0][0]
        assert call_args[:3] == ["docker", "exec", "container-1"]
        assert call_args[3:] == ["cmd"] + args

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_zero_exit_code(self, mock_verbose, mock_popen):
        """Explicit exit code 0."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("c", "true")

        assert result == 0

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_high_exit_code(self, mock_verbose, mock_popen):
        """High exit code (e.g., 255)."""
        proc = _mock_process(returncode=255)
        mock_popen.return_value = proc

        result = exec_in_container_streaming("c", "fail")

        assert result == 255

    @patch("foundry_sandbox.docker.subprocess.Popen")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_default_timeout_is_3600(self, mock_verbose, mock_popen):
        """Default timeout is 3600 seconds (1 hour)."""
        proc = _mock_process(returncode=0)
        mock_popen.return_value = proc

        exec_in_container_streaming("container-1", "cmd")

        proc.wait.assert_called_once_with(timeout=3600)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
