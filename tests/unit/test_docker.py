"""Unit tests for foundry_sandbox.docker.

Tests credential placeholder generation, subnet generation and collision
detection, compose command building, container status queries, volume
management, and HMAC secret provisioning.

All subprocess calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import hashlib
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.docker import (
    _run_cmd,
    container_is_running,
    copy_to_container,
    exec_in_container,
    generate_sandbox_subnet,
    get_compose_command,
    get_unified_proxy_host_port,
    hmac_secret_file_count,
    setup_credential_placeholders,
    setup_unified_proxy_url,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(stdout="", stderr="", returncode=0):
    """Build a mock subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# TestRunCmd
# ---------------------------------------------------------------------------


class TestRunCmd:
    """_run_cmd wraps subprocess.run correctly."""

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_passes_timeout(self, mock_run):
        _run_cmd(["echo", "hi"], timeout=42)
        _, kwargs = mock_run.call_args
        assert kwargs["timeout"] == 42

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_quiet_mode_suppresses_output(self, mock_run):
        _run_cmd(["echo", "hi"], quiet=True)
        _, kwargs = mock_run.call_args
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_non_quiet_captures_output(self, mock_run):
        _run_cmd(["echo", "hi"], quiet=False)
        _, kwargs = mock_run.call_args
        assert kwargs["stdout"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.PIPE


# ---------------------------------------------------------------------------
# TestSetupCredentialPlaceholders
# ---------------------------------------------------------------------------


class TestSetupCredentialPlaceholders:
    """setup_credential_placeholders detects auth config correctly."""

    def test_oauth_token_sets_oauth_placeholder(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "some-token")
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch("pathlib.Path.is_file", return_value=False):
            creds = setup_credential_placeholders()
            env = creds.to_env_dict()

        assert env["SANDBOX_ANTHROPIC_API_KEY"] == ""
        assert env["SANDBOX_CLAUDE_OAUTH"].startswith("CRED_PROXY_")

    def test_no_oauth_sets_api_key_placeholder(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch("pathlib.Path.is_file", return_value=False):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_ANTHROPIC_API_KEY"].startswith("CRED_PROXY_")
        assert env["SANDBOX_CLAUDE_OAUTH"] == ""

    def test_opencode_enabled_sets_zhipu_placeholder(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "1")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch("pathlib.Path.is_file", return_value=False):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_ZHIPU_API_KEY"].startswith("CRED_PROXY_")

    def test_opencode_disabled_clears_zhipu(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch("pathlib.Path.is_file", return_value=False):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_ZHIPU_API_KEY"] == ""

    def test_tavily_api_key_sets_enable_flag(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.setenv("TAVILY_API_KEY", "tvly-xxx")

        with patch("pathlib.Path.is_file", return_value=False):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_ENABLE_TAVILY"] == "1"

    def test_no_tavily_clears_enable_flag(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch("pathlib.Path.is_file", return_value=False):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_ENABLE_TAVILY"] == "0"

    def test_placeholders_are_unique_per_call(self, monkeypatch):
        """Each call generates unique random nonces."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch("pathlib.Path.is_file", return_value=False):
            env1 = setup_credential_placeholders().to_env_dict()
            env2 = setup_credential_placeholders().to_env_dict()

        assert env1["SANDBOX_ANTHROPIC_API_KEY"] != env2["SANDBOX_ANTHROPIC_API_KEY"]

    def test_gemini_oauth_detection(self, monkeypatch, tmp_path):
        """Detects Gemini OAuth from settings.json selectedType."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        settings = tmp_path / ".gemini" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text('{"selectedType": "oauth-personal"}')

        with patch("pathlib.Path.home", return_value=tmp_path):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_GEMINI_API_KEY"] == ""

    def test_gemini_non_oauth_sets_placeholder(self, monkeypatch, tmp_path):
        """Non-OAuth Gemini gets a placeholder."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        settings = tmp_path / ".gemini" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text('{"selectedType": "api-key"}')

        with patch("pathlib.Path.home", return_value=tmp_path):
            env = setup_credential_placeholders().to_env_dict()

        assert env["SANDBOX_GEMINI_API_KEY"].startswith("CRED_PROXY_")

    def test_toctou_no_is_file_guard(self, monkeypatch, tmp_path):
        """Gemini settings read does not use .is_file() guard (TOCTOU fix)."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        # No .gemini directory — should still work via OSError catch
        with patch("pathlib.Path.home", return_value=tmp_path):
            creds = setup_credential_placeholders()
            env = creds.to_env_dict()

        # Should get a placeholder (not fail) when file doesn't exist
        assert env["SANDBOX_GEMINI_API_KEY"].startswith("CRED_PROXY_")


# ---------------------------------------------------------------------------
# TestGenerateSandboxSubnet
# ---------------------------------------------------------------------------


class TestGenerateSandboxSubnet:
    """generate_sandbox_subnet derives subnets from project name."""

    @patch("foundry_sandbox.docker._get_existing_docker_subnets", return_value=set())
    def test_generates_valid_subnet(self, _mock):
        subnet, proxy_ip = generate_sandbox_subnet("test-project")
        # Must be in 10.x.x.0/24 format
        parts = subnet.split(".")
        assert parts[0] == "10"
        assert subnet.endswith(".0/24")
        # proxy_ip must match subnet with .2
        assert proxy_ip == subnet.replace(".0/24", ".2")

    @patch("foundry_sandbox.docker._get_existing_docker_subnets", return_value=set())
    def test_deterministic_for_same_name(self, _mock):
        s1, _ = generate_sandbox_subnet("my-sandbox")
        s2, _ = generate_sandbox_subnet("my-sandbox")
        assert s1 == s2

    @patch("foundry_sandbox.docker._get_existing_docker_subnets", return_value=set())
    def test_different_names_different_subnets(self, _mock):
        s1, _ = generate_sandbox_subnet("sandbox-a")
        s2, _ = generate_sandbox_subnet("sandbox-b")
        assert s1 != s2

    def test_collision_avoidance(self):
        """When first subnet collides, retries with salt."""
        # Compute what the first attempt would produce
        digest = hashlib.sha256("collide-project".encode()).digest()
        b1 = max(1, min(254, digest[0]))
        b2 = max(1, min(254, digest[1]))
        colliding = f"10.{b1}.{b2}.0/24"

        with patch("foundry_sandbox.docker._get_existing_docker_subnets",
                    return_value={colliding}):
            subnet, _ = generate_sandbox_subnet("collide-project")

        # Should get a different subnet (from salt=1)
        assert subnet != colliding
        assert subnet.startswith("10.")
        assert subnet.endswith(".0/24")

    def test_exhaustion_raises(self):
        """When all 16 salts collide, RuntimeError is raised."""
        # Make all possible subnets "existing"
        all_subnets = set()
        for salt in range(16):
            seed = "exhaust-project" if salt == 0 else f"exhaust-project\x00{salt}"
            digest = hashlib.sha256(seed.encode()).digest()
            b1 = max(1, min(254, digest[0]))
            b2 = max(1, min(254, digest[1]))
            all_subnets.add(f"10.{b1}.{b2}.0/24")

        with patch("foundry_sandbox.docker._get_existing_docker_subnets",
                    return_value=all_subnets):
            with pytest.raises(RuntimeError, match="Could not find an unused"):
                generate_sandbox_subnet("exhaust-project")

    @patch("foundry_sandbox.docker._get_existing_docker_subnets", return_value=set())
    def test_bytes_clamped_to_valid_range(self, _mock):
        """Subnet bytes must be in 1-254 range."""
        subnet, _ = generate_sandbox_subnet("any-name")
        parts = subnet.replace("/24", "").split(".")
        byte1, byte2 = int(parts[1]), int(parts[2])
        assert 1 <= byte1 <= 254
        assert 1 <= byte2 <= 254


# ---------------------------------------------------------------------------
# TestGetComposeCommand
# ---------------------------------------------------------------------------


class TestGetComposeCommand:
    """get_compose_command builds correct docker compose args."""

    def test_basic_compose_command(self):
        cmd = get_compose_command()
        assert cmd[:2] == ["docker", "compose"]
        assert any("docker-compose.yml" in arg for arg in cmd)

    def test_credential_isolation_adds_file(self):
        cmd = get_compose_command(isolate_credentials=True)
        assert any("credential-isolation" in arg for arg in cmd)

    def test_no_isolation_omits_file(self):
        cmd = get_compose_command(isolate_credentials=False)
        assert not any("credential-isolation" in arg for arg in cmd)

    def test_override_file_included_when_exists(self, tmp_path):
        override = tmp_path / "override.yml"
        override.write_text("version: '3'")
        cmd = get_compose_command(override_file=str(override))
        assert str(override) in cmd

    def test_override_file_ignored_when_missing(self):
        cmd = get_compose_command(override_file="/nonexistent/override.yml")
        assert "/nonexistent/override.yml" not in cmd


# ---------------------------------------------------------------------------
# TestContainerIsRunning
# ---------------------------------------------------------------------------


class TestContainerIsRunning:
    """container_is_running queries docker ps."""

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_true_when_container_found(self, mock_run):
        mock_run.return_value = _completed(stdout="my-sandbox-dev-1\n")
        assert container_is_running("my-sandbox") is True

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_false_when_no_container(self, mock_run):
        mock_run.return_value = _completed(stdout="")
        assert container_is_running("my-sandbox") is False

    @patch("foundry_sandbox.docker.subprocess.run", side_effect=OSError("no docker"))
    def test_false_on_oserror(self, mock_run):
        assert container_is_running("my-sandbox") is False


# ---------------------------------------------------------------------------
# TestGetUnifiedProxyHostPort
# ---------------------------------------------------------------------------


class TestGetUnifiedProxyHostPort:
    """get_unified_proxy_host_port extracts port from docker port output."""

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_extracts_port(self, mock_run):
        mock_run.return_value = _completed(stdout="0.0.0.0:54321\n")
        assert get_unified_proxy_host_port("my-sandbox") == "54321"

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_handles_ipv6_format(self, mock_run):
        mock_run.return_value = _completed(stdout=":::54321\n")
        assert get_unified_proxy_host_port("my-sandbox") == "54321"

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_empty_on_failure(self, mock_run):
        mock_run.return_value = _completed(stdout="", returncode=1)
        assert get_unified_proxy_host_port("my-sandbox") == ""

    @patch("foundry_sandbox.docker.subprocess.run", side_effect=OSError)
    def test_empty_on_oserror(self, mock_run):
        assert get_unified_proxy_host_port("my-sandbox") == ""


# ---------------------------------------------------------------------------
# TestSetupUnifiedProxyUrl
# ---------------------------------------------------------------------------


class TestSetupUnifiedProxyUrl:
    """setup_unified_proxy_url builds URL from port."""

    @patch("foundry_sandbox.docker.get_unified_proxy_host_port", return_value="12345")
    def test_builds_url(self, _mock):
        assert setup_unified_proxy_url("my-sandbox") == "http://127.0.0.1:12345"

    @patch("foundry_sandbox.docker.get_unified_proxy_host_port", return_value="")
    def test_empty_on_no_port(self, _mock):
        assert setup_unified_proxy_url("my-sandbox") == ""


# ---------------------------------------------------------------------------
# TestExecInContainer
# ---------------------------------------------------------------------------


class TestExecInContainer:
    """exec_in_container delegates to _run_cmd."""

    @patch("foundry_sandbox.docker._run_cmd", return_value=_completed(stdout="output"))
    def test_builds_docker_exec_command(self, mock_run):
        exec_in_container("c1", "echo", "hello")
        args = mock_run.call_args[0][0]
        assert args[:3] == ["docker", "exec", "c1"]
        assert args[3:] == ["echo", "hello"]


# ---------------------------------------------------------------------------
# TestCopyToContainer
# ---------------------------------------------------------------------------


class TestCopyToContainer:
    """copy_to_container delegates to _run_cmd with docker cp."""

    @patch("foundry_sandbox.docker._run_cmd", return_value=_completed())
    def test_builds_docker_cp_command(self, mock_run):
        copy_to_container("/host/file", "c1", "/container/file")
        args = mock_run.call_args[0][0]
        assert args == ["docker", "cp", "/host/file", "c1:/container/file"]


# ---------------------------------------------------------------------------
# TestHmacSecretFileCount
# ---------------------------------------------------------------------------


class TestHmacSecretFileCount:
    """hmac_secret_file_count counts files in HMAC volume."""

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_returns_count(self, mock_run):
        mock_run.return_value = _completed(stdout="3\n")
        assert hmac_secret_file_count("my-sandbox") == 3

    @patch("foundry_sandbox.docker.subprocess.run")
    def test_returns_zero_on_empty(self, mock_run):
        mock_run.return_value = _completed(stdout="0\n")
        assert hmac_secret_file_count("my-sandbox") == 0

    @patch("foundry_sandbox.docker.subprocess.run", side_effect=OSError("no docker"))
    def test_returns_zero_on_error(self, mock_run):
        assert hmac_secret_file_count("my-sandbox") == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
