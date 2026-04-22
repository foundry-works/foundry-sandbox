"""Tests for foundry_sandbox.sbx module."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.sbx import (
    TIMEOUT_SBX_EXEC,
    TIMEOUT_SBX_LIFECYCLE,
    TIMEOUT_SBX_QUERY,
    TIMEOUT_SBX_SECRET,
    VALID_NETWORK_PROFILES,
    _is_docker_plugin_path,
    _resolve_sbx_binary,
    _run_standalone_probe,
    check_sbx_version,
    find_sbx_binary,
    get_sbx_version,
    sbx_check_available,
    sbx_create,
    sbx_diagnose,
    sbx_exec,
    sbx_exec_streaming,
    sbx_is_installed,
    sbx_is_running,
    sbx_ls,
    sbx_policy_allow,
    sbx_policy_deny,
    sbx_policy_set_default,
    sbx_ports_publish,
    sbx_ports_unpublish,
    sbx_rm,
    sbx_run,
    sbx_sandbox_exists,
    sbx_secret_set,
    sbx_stop,
    sbx_template_load,
    sbx_template_rm,
    sbx_template_save,
)


def _mock_completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.stdout = stdout
    mock.stderr = stderr
    mock.returncode = returncode
    return mock


# ============================================================================
# find_sbx_binary / sbx_is_installed
# ============================================================================


class TestFindSbxBinary:
    def test_found(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            assert find_sbx_binary() == "/usr/local/bin/sbx"

    def test_not_found(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value=None):
            assert find_sbx_binary() is None


class TestSbxIsInstalled:
    def test_installed(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            assert sbx_is_installed() is True

    def test_not_installed(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value=None):
            assert sbx_is_installed() is False


class TestSbxCheckAvailable:
    def test_available(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.os.path.realpath", return_value="/usr/local/bin/sbx"):
                with patch("foundry_sandbox.sbx.check_sbx_version"):
                    with patch("foundry_sandbox.sbx._run_standalone_probe", return_value=True):
                        sbx_check_available()  # should not raise

    def test_not_available(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value=None):
            with pytest.raises(SystemExit):
                sbx_check_available()


# ============================================================================
# get_sbx_version / check_sbx_version
# ============================================================================


class TestGetSbxVersion:
    def test_success(self):
        mock_result = MagicMock()
        mock_result.stdout = "sbx 0.26.1\n"
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.subprocess.run", return_value=mock_result):
                assert get_sbx_version() == "0.26.1"

    def test_bare_version(self):
        mock_result = MagicMock()
        mock_result.stdout = "0.27.0\n"
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.subprocess.run", return_value=mock_result):
                assert get_sbx_version() == "0.27.0"

    def test_no_binary(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value=None):
            assert get_sbx_version() is None

    def test_timeout(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.subprocess.run", side_effect=subprocess.TimeoutExpired("sbx", 5)):
                assert get_sbx_version() is None

    def test_os_error(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.subprocess.run", side_effect=OSError("not found")):
                assert get_sbx_version() is None


class TestCheckSbxVersion:
    def test_version_in_range(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1"):
            check_sbx_version()  # should not raise

    def test_version_at_min(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.0"):
            check_sbx_version()  # boundary — should pass

    def test_version_below_min(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.25.0"):
            with pytest.raises(SystemExit):
                check_sbx_version()

    def test_version_at_max(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.29.0"):
            with pytest.raises(SystemExit):
                check_sbx_version()

    def test_version_above_max(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.30.0"):
            with pytest.raises(SystemExit):
                check_sbx_version()

    def test_version_none(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value=None):
            check_sbx_version()  # no sbx — skip silently

    def test_version_parse_garbage(self):
        with patch("foundry_sandbox.sbx.get_sbx_version", return_value="unknown"):
            with patch("foundry_sandbox.sbx.log_warn") as mock_warn:
                check_sbx_version()  # warn but don't block
                mock_warn.assert_called_once()


# ============================================================================
# sbx_create
# ============================================================================


class TestSbxCreate:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_basic(self, mock_run):
        mock_run.return_value = _mock_completed("Created sandbox test-sbx")
        sbx_create("test-sbx", "claude", "/tmp/workspace")
        mock_run.assert_called_once_with(
            ["create", "--name", "test-sbx", "claude", "/tmp/workspace"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_with_branch(self, mock_run):
        mock_run.return_value = _mock_completed("Created sandbox test-sbx")
        sbx_create("test-sbx", "claude", "/tmp/workspace", branch="feature-x")
        mock_run.assert_called_once_with(
            ["create", "--name", "test-sbx", "--branch", "feature-x", "claude", "/tmp/workspace"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_path_object(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_create("test", "codex", Path("/tmp/repo"))
        mock_run.assert_called_once_with(
            ["create", "--name", "test", "codex", "/tmp/repo"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_with_cpus(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_create("test", "claude", "/tmp/ws", cpus="2")
        mock_run.assert_called_once_with(
            ["create", "--name", "test", "--cpus", "2", "claude", "/tmp/ws"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_with_memory(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_create("test", "claude", "/tmp/ws", memory="4g")
        mock_run.assert_called_once_with(
            ["create", "--name", "test", "--memory", "4g", "claude", "/tmp/ws"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_with_cpus_and_memory(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_create("test", "claude", "/tmp/ws", cpus="0.5", memory="512m")
        mock_run.assert_called_once_with(
            ["create", "--name", "test", "--cpus", "0.5", "--memory", "512m",
             "claude", "/tmp/ws"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_cpus_memory_none_omits_flags(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_create("test", "claude", "/tmp/ws", cpus=None, memory=None)
        mock_run.assert_called_once_with(
            ["create", "--name", "test", "claude", "/tmp/ws"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )


# ============================================================================
# sbx_run / sbx_stop / sbx_rm
# ============================================================================


class TestSbxRun:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_basic(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_run("my-sandbox")
        mock_run.assert_called_once_with(["run", "my-sandbox"], timeout=TIMEOUT_SBX_LIFECYCLE)


class TestSbxStop:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_basic(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_stop("my-sandbox")
        mock_run.assert_called_once_with(["stop", "my-sandbox"], timeout=TIMEOUT_SBX_LIFECYCLE)


class TestSbxRm:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_basic(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_rm("my-sandbox")
        mock_run.assert_called_once_with(["rm", "my-sandbox"], timeout=TIMEOUT_SBX_LIFECYCLE)


# ============================================================================
# sbx_ls / sbx_is_running / sbx_sandbox_exists
# ============================================================================


class TestSbxLs:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_parse_json(self, mock_run):
        data = [
            {"name": "sbx-1", "status": "running", "agent": "claude", "branch": "main"},
            {"name": "sbx-2", "status": "stopped", "agent": "codex", "branch": "dev"},
        ]
        mock_run.return_value = _mock_completed(stdout=json.dumps(data))
        result = sbx_ls()
        assert len(result) == 2
        assert result[0]["name"] == "sbx-1"
        assert result[1]["status"] == "stopped"

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_empty(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="[]")
        assert sbx_ls() == []

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_nonzero_exit(self, mock_run):
        mock_run.return_value = _mock_completed(returncode=1, stderr="error")
        assert sbx_ls() == []

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_invalid_json(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="not json")
        assert sbx_ls() == []

    @patch("foundry_sandbox.sbx._run_sbx", side_effect=subprocess.TimeoutExpired("sbx", 30))
    def test_timeout(self, mock_run):
        assert sbx_ls() == []


class TestSbxIsRunning:
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_running(self, mock_ls):
        mock_ls.return_value = [
            {"name": "test", "status": "running"},
        ]
        assert sbx_is_running("test") is True

    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_stopped(self, mock_ls):
        mock_ls.return_value = [
            {"name": "test", "status": "stopped"},
        ]
        assert sbx_is_running("test") is False

    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_not_found(self, mock_ls):
        mock_ls.return_value = [
            {"name": "other", "status": "running"},
        ]
        assert sbx_is_running("test") is False

    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_empty_list(self, mock_ls):
        mock_ls.return_value = []
        assert sbx_is_running("test") is False


class TestSbxSandboxExists:
    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_exists(self, mock_ls):
        mock_ls.return_value = [
            {"name": "test", "status": "stopped"},
        ]
        assert sbx_sandbox_exists("test") is True

    @patch("foundry_sandbox.sbx.sbx_ls")
    def test_not_exists(self, mock_ls):
        mock_ls.return_value = []
        assert sbx_sandbox_exists("test") is False


# ============================================================================
# sbx_exec
# ============================================================================


class TestSbxExec:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_basic(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="output")
        sbx_exec("test", ["git", "status"])
        mock_run.assert_called_once_with(
            ["exec", "test", "--", "git", "status"],
            timeout=TIMEOUT_SBX_EXEC,
            quiet=False,
            input=None,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_as_root(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_exec("test", ["cp", "a", "b"], user="root")
        mock_run.assert_called_once_with(
            ["exec", "-u", "root", "test", "--", "cp", "a", "b"],
            timeout=TIMEOUT_SBX_EXEC,
            quiet=False,
            input=None,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_with_env(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_exec("test", ["echo", "hi"], env={"FOO": "bar"})
        mock_run.assert_called_once_with(
            ["exec", "-e", "FOO=bar", "test", "--", "echo", "hi"],
            timeout=TIMEOUT_SBX_EXEC,
            quiet=False,
            input=None,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_quiet(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_exec("test", ["ls"], quiet=True)
        mock_run.assert_called_once_with(
            ["exec", "test", "--", "ls"],
            timeout=TIMEOUT_SBX_EXEC,
            quiet=True,
            input=None,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_with_input(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_exec("test", ["tee", "/tmp/f"], input="hello")
        mock_run.assert_called_once_with(
            ["exec", "test", "--", "tee", "/tmp/f"],
            timeout=TIMEOUT_SBX_EXEC,
            quiet=False,
            input="hello",
        )


class TestSbxExecStreaming:
    @patch("foundry_sandbox.sbx.subprocess.Popen")
    def test_basic(self, mock_popen):
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc
        result = sbx_exec_streaming("test", ["bash"])
        mock_popen.assert_called_once()
        cmd = mock_popen.call_args[0][0]
        assert cmd == ["sbx", "exec", "test", "--", "bash"]
        assert result is mock_proc

    @patch("foundry_sandbox.sbx.subprocess.Popen")
    def test_as_root(self, mock_popen):
        mock_popen.return_value = MagicMock()
        sbx_exec_streaming("test", ["bash"], user="root")
        cmd = mock_popen.call_args[0][0]
        assert cmd == ["sbx", "exec", "-u", "root", "test", "--", "bash"]

    @patch("foundry_sandbox.sbx.subprocess.Popen")
    def test_interactive(self, mock_popen):
        mock_popen.return_value = MagicMock()
        sbx_exec_streaming("test", ["bash", "-l"], interactive=True)
        cmd = mock_popen.call_args[0][0]
        assert cmd == ["sbx", "exec", "-it", "test", "--", "bash", "-l"]

    @patch("foundry_sandbox.sbx.subprocess.Popen")
    def test_interactive_with_user(self, mock_popen):
        mock_popen.return_value = MagicMock()
        sbx_exec_streaming("test", ["bash"], interactive=True, user="root")
        cmd = mock_popen.call_args[0][0]
        assert "-it" in cmd
        assert "-u" in cmd


# ============================================================================
# sbx_secret_set
# ============================================================================


class TestSbxSecretSet:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_per_sandbox(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_secret_set("anthropic", "sk-test-123")
        mock_run.assert_called_once_with(
            ["secret", "set", "anthropic"],
            input="sk-test-123",
            timeout=TIMEOUT_SBX_SECRET,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_global(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_secret_set("github", "ghp_test", global_scope=True)
        mock_run.assert_called_once_with(
            ["secret", "set", "-g", "github"],
            input="ghp_test",
            timeout=TIMEOUT_SBX_SECRET,
        )


# ============================================================================
# sbx_policy_*
# ============================================================================


class TestSbxPolicy:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_set_default(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_policy_set_default("balanced")
        mock_run.assert_called_once_with(
            ["policy", "set-default", "balanced"],
            timeout=TIMEOUT_SBX_QUERY,
        )

    def test_set_default_invalid(self):
        with pytest.raises(ValueError, match="Invalid network profile"):
            sbx_policy_set_default("invalid")

    def test_valid_profiles(self):
        assert VALID_NETWORK_PROFILES == {"balanced", "allow-all", "deny-all"}

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_allow(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_policy_allow("api.github.com")
        mock_run.assert_called_once_with(
            ["policy", "allow", "network", "api.github.com"],
            timeout=TIMEOUT_SBX_QUERY,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_deny(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_policy_deny("evil.com")
        mock_run.assert_called_once_with(
            ["policy", "deny", "network", "evil.com"],
            timeout=TIMEOUT_SBX_QUERY,
        )


# ============================================================================
# sbx_template_*
# ============================================================================


class TestSbxTemplate:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_save(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_template_save("my-sandbox", "my-template")
        mock_run.assert_called_once_with(
            ["template", "save", "my-sandbox", "my-template"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_load(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_template_load("my-template")
        mock_run.assert_called_once_with(
            ["template", "load", "my-template"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_rm(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_template_rm("my-template")
        mock_run.assert_called_once_with(
            ["template", "rm", "my-template"],
            timeout=TIMEOUT_SBX_LIFECYCLE,
        )


# ============================================================================
# sbx_ports_*
# ============================================================================


class TestSbxPorts:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_publish(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_ports_publish("my-sandbox", "8080:80")
        mock_run.assert_called_once_with(
            ["ports", "publish", "my-sandbox", "8080:80"],
            timeout=TIMEOUT_SBX_QUERY,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_unpublish(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_ports_unpublish("my-sandbox", "8080:80")
        mock_run.assert_called_once_with(
            ["ports", "unpublish", "my-sandbox", "8080:80"],
            timeout=TIMEOUT_SBX_QUERY,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_publish_tcp_spec(self, mock_run):
        mock_run.return_value = _mock_completed()
        sbx_ports_publish("my-sandbox", "tcp://0.0.0.0:9090:9090")
        mock_run.assert_called_once_with(
            ["ports", "publish", "my-sandbox", "tcp://0.0.0.0:9090:9090"],
            timeout=TIMEOUT_SBX_QUERY,
        )


# ============================================================================
# sbx_diagnose
# ============================================================================


class TestRunSbxInternal:
    """Test _run_sbx passes correct kwargs to subprocess.run."""

    @patch("foundry_sandbox.sbx.subprocess.run")
    def test_text_mode_enabled(self, mock_run):
        mock_run.return_value = _mock_completed()
        from foundry_sandbox.sbx import _run_sbx
        _run_sbx(["ls"])
        _, kwargs = mock_run.call_args
        assert kwargs["text"] is True

    @patch("foundry_sandbox.sbx.subprocess.run")
    def test_string_input_works(self, mock_run):
        mock_run.return_value = _mock_completed()
        from foundry_sandbox.sbx import _run_sbx
        _run_sbx(["secret", "set", "anthropic"], input="sk-test-key")
        _, kwargs = mock_run.call_args
        assert kwargs["text"] is True
        assert kwargs["input"] == "sk-test-key"

    @patch("foundry_sandbox.sbx.subprocess.run")
    def test_no_input_still_text(self, mock_run):
        mock_run.return_value = _mock_completed()
        from foundry_sandbox.sbx import _run_sbx
        _run_sbx(["ls"])
        _, kwargs = mock_run.call_args
        assert kwargs["text"] is True
        assert "input" not in kwargs


class TestSbxDiagnose:
    @patch("foundry_sandbox.sbx._run_sbx")
    def test_basic(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="All checks passed")
        result = sbx_diagnose()
        assert result.stdout == "All checks passed"
        mock_run.assert_called_once_with(["diagnose"], timeout=TIMEOUT_SBX_QUERY)

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_parse_json_success(self, mock_run):
        data = {"status": "ok", "version": "0.26.1", "daemon": "running"}
        mock_run.return_value = _mock_completed(stdout=json.dumps(data))
        result = sbx_diagnose(parse=True)
        assert isinstance(result, dict)
        assert result["status"] == "ok"
        assert result["daemon"] == "running"
        mock_run.assert_called_once_with(
            ["diagnose", "--json"], timeout=TIMEOUT_SBX_QUERY, check=False,
        )

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_parse_nonzero_exit(self, mock_run):
        mock_run.return_value = _mock_completed(
            returncode=1, stderr="sbx daemon not running",
        )
        result = sbx_diagnose(parse=True)
        assert isinstance(result, dict)
        assert "error" in result
        assert result["error"] == "sbx daemon not running"

    @patch("foundry_sandbox.sbx._run_sbx")
    def test_parse_invalid_json(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="not json at all")
        result = sbx_diagnose(parse=True)
        assert isinstance(result, dict)
        assert "error" in result
        assert "raw" in result


# ============================================================================
# sbx identity probe (H5)
# ============================================================================


class TestIsDockerPluginPath:
    def test_docker_cli_plugins_rejected(self):
        assert _is_docker_plugin_path(
            os.path.expanduser("~/.docker/cli-plugins/sbx")
        )

    def test_macos_app_bundle_rejected(self):
        assert _is_docker_plugin_path(
            "/Applications/Docker.app/Contents/Resources/cli-plugins/sbx"
        )

    def test_windows_path_rejected(self):
        assert _is_docker_plugin_path(
            "C:\\Program Files\\Docker\\Docker\\resources\\cli-plugins\\sbx"
        )

    def test_standalone_path_accepted(self):
        assert not _is_docker_plugin_path("/usr/local/bin/sbx")

    def test_homebrew_path_accepted(self):
        assert not _is_docker_plugin_path("/opt/homebrew/bin/sbx")


class TestResolveSbxBinary:
    def test_resolves_realpath(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.os.path.realpath", return_value="/opt/sbx/bin/sbx"):
                assert _resolve_sbx_binary() == "/opt/sbx/bin/sbx"

    def test_none_when_not_found(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value=None):
            assert _resolve_sbx_binary() is None


class TestRunStandaloneProbe:
    def test_success(self):
        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0)
            assert _run_standalone_probe() is True

    def test_failure(self):
        with patch("foundry_sandbox.sbx.subprocess.run") as mock_run:
            mock_run.return_value = _mock_completed(returncode=1)
            assert _run_standalone_probe() is False

    def test_timeout(self):
        with patch("foundry_sandbox.sbx.subprocess.run", side_effect=subprocess.TimeoutExpired("sbx", 5)):
            assert _run_standalone_probe() is False

    def test_os_error(self):
        with patch("foundry_sandbox.sbx.subprocess.run", side_effect=OSError("not found")):
            assert _run_standalone_probe() is False


class TestSbxCheckAvailableIdentity:
    """Test the identity probe integration in sbx_check_available."""

    def test_plugin_path_rejected(self):
        plugin_path = os.path.expanduser("~/.docker/cli-plugins/sbx")
        with patch("foundry_sandbox.sbx.shutil.which", return_value=plugin_path):
            with patch("foundry_sandbox.sbx.os.path.realpath", return_value=plugin_path):
                with patch("foundry_sandbox.sbx.check_sbx_version"):
                    with pytest.raises(SystemExit):
                        sbx_check_available()

    def test_standalone_accepted_when_probe_passes(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"):
            with patch("foundry_sandbox.sbx.os.path.realpath", return_value="/usr/local/bin/sbx"):
                with patch("foundry_sandbox.sbx.check_sbx_version"):
                    with patch("foundry_sandbox.sbx._run_standalone_probe", return_value=True):
                        sbx_check_available()  # should not raise

    def test_unknown_path_rejected_when_probe_fails(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/opt/custom/bin/sbx"):
            with patch("foundry_sandbox.sbx.os.path.realpath", return_value="/opt/custom/bin/sbx"):
                with patch("foundry_sandbox.sbx.check_sbx_version"):
                    with patch("foundry_sandbox.sbx._run_standalone_probe", return_value=False):
                        with pytest.raises(SystemExit):
                            sbx_check_available()
