"""Tests for kernel-separation assertion in cast diagnose (H7).

Verifies that _collect_isolation reports correct status when host and
sandbox kernels differ or match, and that per-sandbox failures don't
abort the whole run.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from foundry_sandbox.commands.diagnose import _collect_isolation, diagnose


def _mock_completed(stdout: str = "", returncode: int = 0) -> MagicMock:
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.stdout = stdout
    mock.stderr = ""
    mock.returncode = returncode
    return mock


class TestCollectIsolationDifferentKernels:
    """Different kernels → status 'ok'."""

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    @patch("foundry_sandbox.commands.diagnose.subprocess.run")
    def test_different_kernel_status_ok(
        self, mock_run, mock_ls, mock_running, mock_exec,
    ):
        mock_run.return_value = _mock_completed(stdout="6.1.0-host\n")
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_exec.return_value = _mock_completed(stdout="6.1.0-sandbox\n")

        result = _collect_isolation()

        assert result["host_kernel"] == "6.1.0-host"
        assert len(result["sandboxes"]) == 1
        assert result["sandboxes"][0]["name"] == "sb1"
        assert result["sandboxes"][0]["kernel"] == "6.1.0-sandbox"
        assert result["sandboxes"][0]["status"] == "ok"


class TestCollectIsolationEqualKernels:
    """Equal kernels → status 'warn' in JSON and text output."""

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    @patch("foundry_sandbox.commands.diagnose.subprocess.run")
    def test_equal_kernel_status_warn(
        self, mock_run, mock_ls, mock_running, mock_exec,
    ):
        mock_run.return_value = _mock_completed(stdout="6.1.0-same\n")
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_exec.return_value = _mock_completed(stdout="6.1.0-same\n")

        result = _collect_isolation()

        assert result["sandboxes"][0]["status"] == "warn"

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    @patch("foundry_sandbox.commands.diagnose.subprocess.run")
    def test_warn_surfaces_in_json_output(
        self, mock_run, mock_ls, mock_running, mock_exec,
    ):
        from click.testing import CliRunner

        mock_run.return_value = _mock_completed(stdout="6.1.0-same\n")
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_exec.return_value = _mock_completed(stdout="6.1.0-same\n")

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose",
                    return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health",
                    return_value={"reachable": False}):
            result = runner.invoke(diagnose, ["--json"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        sb = data["isolation"]["sandboxes"][0]
        assert sb["status"] == "warn"

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    @patch("foundry_sandbox.commands.diagnose.subprocess.run")
    def test_warn_surfaces_in_text_output(
        self, mock_run, mock_ls, mock_running, mock_exec,
    ):
        from click.testing import CliRunner

        mock_run.return_value = _mock_completed(stdout="6.1.0-same\n")
        mock_ls.return_value = [{"name": "sb1", "status": "running"}]
        mock_exec.return_value = _mock_completed(stdout="6.1.0-same\n")

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose",
                    return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health",
                    return_value={"reachable": False}):
            result = runner.invoke(diagnose, [])

        assert result.exit_code == 0
        assert "WARN" in result.output
        assert "sb1" in result.output


class TestCollectIsolationExecFailure:
    """sbx_exec failure per sandbox does not abort the whole diagnose run."""

    @patch("foundry_sandbox.sbx.sbx_exec")
    @patch("foundry_sandbox.sbx.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.sbx.sbx_ls")
    @patch("foundry_sandbox.commands.diagnose.subprocess.run")
    def test_exec_failure_does_not_abort(
        self, mock_run, mock_ls, mock_running, mock_exec,
    ):
        mock_run.return_value = _mock_completed(stdout="6.1.0-host\n")
        mock_ls.return_value = [
            {"name": "sb1", "status": "running"},
            {"name": "sb2", "status": "running"},
        ]

        def exec_side_effect(name, cmd, **kwargs):
            if name == "sb1":
                raise RuntimeError("sandbox unreachable")
            return _mock_completed(stdout="6.1.0-sandbox\n")

        mock_exec.side_effect = exec_side_effect

        result = _collect_isolation()

        # Both sandboxes present; sb1 has empty kernel → warn
        assert len(result["sandboxes"]) == 2
        sb1 = next(s for s in result["sandboxes"] if s["name"] == "sb1")
        sb2 = next(s for s in result["sandboxes"] if s["name"] == "sb2")
        assert sb1["status"] == "warn"
        assert sb1["kernel"] == ""
        assert sb2["status"] == "ok"
