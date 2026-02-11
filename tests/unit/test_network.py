"""Unit tests for foundry_sandbox/network.py and foundry_sandbox/proxy.py.

Tests cover:
- foundry_sandbox.network: network mode validation, docker-compose override
  file manipulation (generate, strip, append, header management), timezone detection
- foundry_sandbox.proxy: proxy container naming, HTTP transport (URL/socket/exec),
  registration lifecycle, health checks, container IP resolution
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from foundry_sandbox import network, proxy


# ============================================================================
# network.py Tests
# ============================================================================


class TestValidateNetworkMode:
    """Tests for validate_network_mode()."""

    def test_valid_modes_accepted(self):
        """Valid network modes should not raise."""
        for mode in ["limited", "host-only", "none"]:
            network.validate_network_mode(mode)  # Should not raise

    def test_full_mode_rejected(self):
        """'full' mode should raise ValueError with security message."""
        with pytest.raises(ValueError, match="removed for security"):
            network.validate_network_mode("full")

    def test_invalid_mode_rejected(self):
        """Invalid mode should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid network mode"):
            network.validate_network_mode("unrestricted")


class TestGenerateNetworkConfig:
    """Tests for generate_network_config()."""

    def test_none_mode(self, tmp_path):
        """'none' mode should write network_mode: none."""
        f = tmp_path / "override.yml"
        f.write_text("")

        network.generate_network_config("none", str(f))

        content = f.read_text()
        assert 'network_mode: "none"' in content

    def test_limited_mode(self, tmp_path):
        """'limited' mode should add cap_add and environment."""
        f = tmp_path / "override.yml"
        f.write_text("")

        network.generate_network_config("limited", str(f))

        content = f.read_text()
        assert "cap_add:" in content
        assert "NET_ADMIN" in content
        assert "SYS_ADMIN" not in content
        assert "SANDBOX_NETWORK_MODE=limited" in content

    def test_host_only_mode(self, tmp_path):
        """'host-only' mode should add cap_add and environment."""
        f = tmp_path / "override.yml"
        f.write_text("")

        network.generate_network_config("host-only", str(f))

        content = f.read_text()
        assert "SANDBOX_NETWORK_MODE=host-only" in content


class TestEnsureOverrideHeader:
    """Tests for ensure_override_header()."""

    def test_creates_new_file(self, tmp_path):
        """Non-existent file should be created with header."""
        f = tmp_path / "override.yml"

        network.ensure_override_header(str(f))

        content = f.read_text()
        assert content.startswith("services:\n  dev:\n")

    def test_preserves_existing_with_header(self, tmp_path):
        """File with existing header should be preserved."""
        f = tmp_path / "override.yml"
        f.write_text("services:\n  dev:\n    image: test\n")

        network.ensure_override_header(str(f))

        content = f.read_text()
        assert content == "services:\n  dev:\n    image: test\n"

    def test_prepends_header_to_headerless_file(self, tmp_path):
        """File without header should get header prepended."""
        f = tmp_path / "override.yml"
        f.write_text("    image: test\n")

        network.ensure_override_header(str(f))

        content = f.read_text()
        assert content.startswith("services:\n  dev:\n")
        assert "image: test" in content


class TestStripNetworkConfig:
    """Tests for strip_network_config()."""

    def test_nonexistent_file_noop(self, tmp_path):
        """Non-existent file should not raise."""
        network.strip_network_config(str(tmp_path / "missing.yml"))

    def test_strips_network_capabilities(self, tmp_path):
        """Should strip NET_ADMIN, NET_RAW, SYS_ADMIN from cap_add."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "      - SYS_ADMIN\n"
            "    environment:\n"
            "      - SANDBOX_NETWORK_MODE=limited\n"
        )

        network.strip_network_config(str(f))

        content = f.read_text()
        assert "NET_ADMIN" not in content
        assert "SYS_ADMIN" not in content
        assert "SANDBOX_NETWORK_MODE" not in content

    def test_preserves_non_network_items(self, tmp_path):
        """Should preserve non-network cap_add and environment entries."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "      - MKNOD\n"
            "    environment:\n"
            "      - SANDBOX_NETWORK_MODE=limited\n"
            "      - MY_VAR=value\n"
        )

        network.strip_network_config(str(f))

        content = f.read_text()
        assert "MKNOD" in content
        assert "MY_VAR=value" in content
        assert "NET_ADMIN" not in content
        assert "SANDBOX_NETWORK_MODE" not in content


class TestStripYamlBlocksEdgeCases:
    """Edge-case tests for _strip_yaml_blocks (the YAML block parser).

    Exercises corner cases in the manual YAML list-item parser that
    strip_network_config, strip_ssh_agent_config, etc. delegate to.
    """

    def test_empty_file(self, tmp_path):
        """Empty file should remain empty."""
        f = tmp_path / "override.yml"
        f.write_text("")

        network._strip_yaml_blocks(str(f), {
            "volumes": lambda line: True,
        })

        assert f.read_text() == ""

    def test_header_only_no_items(self, tmp_path):
        """Block header with no items should be dropped entirely."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    volumes:\n"
            "    image: test\n"
        )

        network._strip_yaml_blocks(str(f), {
            "volumes": lambda line: True,
        })

        content = f.read_text()
        assert "volumes:" not in content
        assert "image: test" in content

    def test_all_items_removed_drops_header(self, tmp_path):
        """Block whose items are all filtered should lose its header too."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "      - NET_RAW\n"
            "    image: test\n"
        )

        network._strip_yaml_blocks(str(f), {
            "cap_add": lambda line: True,  # remove all
        })

        content = f.read_text()
        assert "cap_add:" not in content
        assert "NET_ADMIN" not in content
        assert "NET_RAW" not in content
        assert "image: test" in content

    def test_some_items_kept(self, tmp_path):
        """Block with mixed kept/removed items preserves header and kept items."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "      - MKNOD\n"
            "      - SYS_ADMIN\n"
        )

        network._strip_yaml_blocks(str(f), {
            "cap_add": lambda line: "NET_ADMIN" in line or "SYS_ADMIN" in line,
        })

        content = f.read_text()
        assert "cap_add:" in content
        assert "MKNOD" in content
        assert "NET_ADMIN" not in content
        assert "SYS_ADMIN" not in content

    def test_block_at_end_of_file(self, tmp_path):
        """Block at the very end of file (no trailing content) should work."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    environment:\n"
            "      - KEEP=yes\n"
            "      - DROP=yes\n"
        )

        network._strip_yaml_blocks(str(f), {
            "environment": lambda line: "DROP" in line,
        })

        content = f.read_text()
        assert "KEEP=yes" in content
        assert "DROP" not in content

    def test_multiple_tracked_blocks(self, tmp_path):
        """Multiple tracked blocks should each be filtered independently."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "      - MKNOD\n"
            "    volumes:\n"
            '      - "/data:/data"\n'
            '      - "/ssh:/ssh-agent"\n'
            "    environment:\n"
            "      - SANDBOX_NETWORK_MODE=limited\n"
            "      - MY_VAR=value\n"
        )

        network._strip_yaml_blocks(str(f), {
            "cap_add": lambda line: "NET_ADMIN" in line,
            "volumes": lambda line: "/ssh-agent" in line,
            "environment": lambda line: "SANDBOX_NETWORK_MODE" in line,
        })

        content = f.read_text()
        assert "MKNOD" in content
        assert "NET_ADMIN" not in content
        assert "/data:/data" in content
        assert "/ssh-agent" not in content
        assert "MY_VAR=value" in content
        assert "SANDBOX_NETWORK_MODE" not in content

    def test_untracked_blocks_preserved(self, tmp_path):
        """Blocks not in the filter dict should be left untouched."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    ports:\n"
            '      - "8080:80"\n'
            "    cap_add:\n"
            "      - NET_ADMIN\n"
        )

        network._strip_yaml_blocks(str(f), {
            "cap_add": lambda line: True,
        })

        content = f.read_text()
        assert "ports:" in content
        assert "8080:80" in content
        assert "cap_add:" not in content

    def test_adjacent_tracked_blocks(self, tmp_path):
        """Two tracked blocks directly adjacent (no gap) should both filter."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "    environment:\n"
            "      - DROP_ME=yes\n"
        )

        network._strip_yaml_blocks(str(f), {
            "cap_add": lambda line: True,
            "environment": lambda line: True,
        })

        content = f.read_text()
        assert "cap_add:" not in content
        assert "environment:" not in content
        assert "NET_ADMIN" not in content
        assert "DROP_ME" not in content

    def test_predicate_receives_rstripped_line(self, tmp_path):
        """Predicate should receive right-stripped line content."""
        received = []
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    environment:\n"
            "      - FOO=bar\n"
        )

        def capture(line):
            received.append(line)
            return False

        network._strip_yaml_blocks(str(f), {"environment": capture})

        assert len(received) == 1
        assert received[0] == "      - FOO=bar"

    def test_nonexistent_file_noop(self, tmp_path):
        """Non-existent file should not raise."""
        network._strip_yaml_blocks(
            str(tmp_path / "missing.yml"),
            {"volumes": lambda line: True},
        )

    def test_idempotent_strip(self, tmp_path):
        """Running the same strip twice should produce identical output."""
        f = tmp_path / "override.yml"
        original = (
            "services:\n"
            "  dev:\n"
            "    cap_add:\n"
            "      - NET_ADMIN\n"
            "      - MKNOD\n"
            "    environment:\n"
            "      - SANDBOX_NETWORK_MODE=limited\n"
            "      - MY_VAR=value\n"
        )
        f.write_text(original)
        filters = {
            "cap_add": lambda line: "NET_ADMIN" in line,
            "environment": lambda line: "SANDBOX_NETWORK_MODE" in line,
        }

        network._strip_yaml_blocks(str(f), filters)
        first = f.read_text()

        network._strip_yaml_blocks(str(f), filters)
        second = f.read_text()

        assert first == second


class TestStripSshAgentConfig:
    """Tests for strip_ssh_agent_config()."""

    def test_strips_ssh_volumes_and_env(self, tmp_path):
        """Should strip SSH agent socket volume and SSH_AUTH_SOCK env."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    volumes:\n"
            f'      - "/tmp/ssh-agent:/ssh-agent"\n'
            '      - "/data:/data"\n'
            "    environment:\n"
            "      - SSH_AUTH_SOCK=/ssh-agent\n"
            "      - OTHER=val\n"
        )

        network.strip_ssh_agent_config(str(f))

        content = f.read_text()
        assert "/ssh-agent" not in content
        assert "SSH_AUTH_SOCK" not in content
        assert "/data:/data" in content
        assert "OTHER=val" in content


class TestStripClaudeHomeConfig:
    """Tests for strip_claude_home_config()."""

    def test_strips_claude_volume(self, tmp_path):
        """Should strip volume mount to /home/ubuntu/.claude."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    volumes:\n"
            '      - "/host/.claude:/home/ubuntu/.claude"\n'
            '      - "/data:/data"\n'
        )

        network.strip_claude_home_config(str(f))

        content = f.read_text()
        assert "/home/ubuntu/.claude" not in content
        assert "/data:/data" in content


class TestStripTimezoneConfig:
    """Tests for strip_timezone_config()."""

    def test_strips_timezone_volumes_and_env(self, tmp_path):
        """Should strip /etc/localtime, /etc/timezone volumes and TZ env."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    volumes:\n"
            '      - "/etc/localtime:/etc/localtime:ro"\n'
            '      - "/etc/timezone:/etc/timezone:ro"\n'
            '      - "/data:/data"\n'
            "    environment:\n"
            "      - TZ=America/New_York\n"
            "      - OTHER=val\n"
        )

        network.strip_timezone_config(str(f))

        content = f.read_text()
        assert "/etc/localtime" not in content
        assert "/etc/timezone" not in content
        assert "TZ=" not in content
        assert "/data:/data" in content
        assert "OTHER=val" in content


class TestAppendOverrideListItem:
    """Tests for append_override_list_item()."""

    def test_appends_to_existing_list(self, tmp_path):
        """Should append item to existing YAML list."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    volumes:\n"
            '      - "/data:/data"\n'
        )

        network.append_override_list_item(str(f), "volumes", '"/new:/new"')

        content = f.read_text()
        assert '"/new:/new"' in content
        assert '"/data:/data"' in content

    def test_creates_new_list(self, tmp_path):
        """Should create list key if not present."""
        f = tmp_path / "override.yml"
        f.write_text("services:\n  dev:\n")

        network.append_override_list_item(str(f), "volumes", '"/data:/data"')

        content = f.read_text()
        assert "volumes:" in content
        assert '"/data:/data"' in content


class TestAddClaudeHomeToOverride:
    """Tests for add_claude_home_to_override()."""

    def test_adds_volume_mount(self, tmp_path):
        """Should add Claude home volume mount."""
        f = tmp_path / "override.yml"

        network.add_claude_home_to_override(str(f), "/host/.claude")

        content = f.read_text()
        assert "/host/.claude:/home/ubuntu/.claude" in content

    def test_empty_home_strips_only(self, tmp_path):
        """Empty claude_home should only strip existing config."""
        f = tmp_path / "override.yml"
        f.write_text(
            "services:\n"
            "  dev:\n"
            "    volumes:\n"
            '      - "/old/.claude:/home/ubuntu/.claude"\n'
        )

        network.add_claude_home_to_override(str(f), "")

        content = f.read_text()
        assert "/home/ubuntu/.claude" not in content


class TestAddSshAgentToOverride:
    """Tests for add_ssh_agent_to_override()."""

    def test_adds_socket_and_env(self, tmp_path):
        """Should add SSH agent socket volume and SSH_AUTH_SOCK env."""
        f = tmp_path / "override.yml"

        network.add_ssh_agent_to_override(str(f), "/tmp/ssh-xxx")

        content = f.read_text()
        assert "/tmp/ssh-xxx:/ssh-agent" in content
        assert "SSH_AUTH_SOCK=/ssh-agent" in content

    def test_empty_sock_strips_only(self, tmp_path):
        """Empty agent_sock should only strip existing config."""
        f = tmp_path / "override.yml"

        network.add_ssh_agent_to_override(str(f), "")

        content = f.read_text()
        assert "SSH_AUTH_SOCK" not in content


class TestAddNetworkToOverride:
    """Tests for add_network_to_override()."""

    def test_idempotent_application(self, tmp_path):
        """Applying twice should produce same result."""
        f = tmp_path / "override.yml"

        network.add_network_to_override("limited", str(f))
        first = f.read_text()

        network.add_network_to_override("limited", str(f))
        second = f.read_text()

        assert first == second

    def test_mode_switch(self, tmp_path):
        """Switching modes should strip old config and apply new."""
        f = tmp_path / "override.yml"

        network.add_network_to_override("limited", str(f))
        assert "SANDBOX_NETWORK_MODE=limited" in f.read_text()

        network.add_network_to_override("none", str(f))
        content = f.read_text()
        assert "SANDBOX_NETWORK_MODE" not in content
        assert 'network_mode: "none"' in content


class TestDetectHostTimezone:
    """Tests for detect_host_timezone()."""

    def test_from_etc_timezone(self, tmp_path):
        """Should read timezone from /etc/timezone if available."""
        tz_file = tmp_path / "timezone"
        tz_file.write_text("America/New_York\n")

        with patch("foundry_sandbox.network.Path") as mock_path_cls:
            # /etc/timezone exists and readable
            mock_tz_path = MagicMock()
            mock_tz_path.exists.return_value = True
            mock_tz_path.read_text.return_value = "America/New_York\n"

            mock_lt_path = MagicMock()
            mock_lt_path.exists.return_value = False

            def path_side_effect(arg):
                if arg == "/etc/timezone":
                    return mock_tz_path
                if arg == "/etc/localtime":
                    return mock_lt_path
                return MagicMock()

            mock_path_cls.side_effect = path_side_effect

            result = network.detect_host_timezone()
            assert result == "America/New_York"

    def test_from_tz_env(self, monkeypatch):
        """Should fall back to $TZ env var."""
        monkeypatch.setenv("TZ", "UTC")

        with patch("foundry_sandbox.network.Path") as mock_path_cls:
            mock_path = MagicMock()
            mock_path.exists.return_value = False
            mock_path_cls.return_value = mock_path
            mock_path_cls.side_effect = lambda _: mock_path

            result = network.detect_host_timezone()
            assert result == "UTC"

    def test_no_timezone_detected(self, monkeypatch):
        """Should return None if no timezone source available."""
        monkeypatch.delenv("TZ", raising=False)

        with patch("foundry_sandbox.network.Path") as mock_path_cls:
            mock_path = MagicMock()
            mock_path.exists.return_value = False
            mock_path_cls.return_value = mock_path
            mock_path_cls.side_effect = lambda _: mock_path

            result = network.detect_host_timezone()
            assert result is None


# ============================================================================
# proxy.py Tests
# ============================================================================


class TestProxyContainerName:
    """Tests for proxy_container_name()."""

    def test_explicit_name(self, monkeypatch):
        """PROXY_CONTAINER_NAME should be used directly."""
        monkeypatch.setenv("PROXY_CONTAINER_NAME", "my-proxy")
        monkeypatch.delenv("CONTAINER_NAME", raising=False)

        assert proxy.proxy_container_name() == "my-proxy"

    def test_derived_from_container_name(self, monkeypatch):
        """Should derive proxy name from CONTAINER_NAME."""
        monkeypatch.delenv("PROXY_CONTAINER_NAME", raising=False)
        monkeypatch.setenv("CONTAINER_NAME", "sandbox-123")

        assert proxy.proxy_container_name() == "sandbox-123-unified-proxy-1"

    def test_no_name_returns_empty(self, monkeypatch):
        """No environment variables should return empty string."""
        monkeypatch.delenv("PROXY_CONTAINER_NAME", raising=False)
        monkeypatch.delenv("CONTAINER_NAME", raising=False)

        assert proxy.proxy_container_name() == ""


class TestProxyCurl:
    """Tests for proxy_curl() HTTP transport."""

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_http_mode(self, mock_run, monkeypatch):
        """PROXY_URL should use direct HTTP."""
        monkeypatch.setenv("PROXY_URL", "http://localhost:8080")
        monkeypatch.delenv("PROXY_SOCKET_PATH", raising=False)

        mock_run.return_value = Mock(
            returncode=0, stdout='{"status":"ok"}', stderr=""
        )

        result = proxy.proxy_curl("GET", "/internal/health")

        assert result == {"status": "ok"}
        cmd = mock_run.call_args[0][0]
        assert "http://localhost:8080/internal/health" in cmd

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_unix_socket_mode(self, mock_run, monkeypatch):
        """PROXY_SOCKET_PATH should use Unix socket."""
        monkeypatch.delenv("PROXY_URL", raising=False)
        monkeypatch.setenv("PROXY_SOCKET_PATH", "/var/run/proxy.sock")

        mock_run.return_value = Mock(
            returncode=0, stdout='{"status":"ok"}', stderr=""
        )

        result = proxy.proxy_curl("GET", "/internal/health")

        assert result == {"status": "ok"}
        cmd = mock_run.call_args[0][0]
        assert "--unix-socket" in cmd
        assert "/var/run/proxy.sock" in cmd

    @patch("foundry_sandbox.proxy.proxy_container_name")
    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_docker_exec_mode(self, mock_run, mock_name, monkeypatch):
        """Fallback should use docker exec."""
        monkeypatch.delenv("PROXY_URL", raising=False)
        monkeypatch.delenv("PROXY_SOCKET_PATH", raising=False)
        mock_name.return_value = "sandbox-proxy-1"

        mock_run.return_value = Mock(
            returncode=0, stdout='{"status":"ok"}', stderr=""
        )

        result = proxy.proxy_curl("GET", "/internal/health")

        assert result == {"status": "ok"}
        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd
        assert "exec" in cmd
        assert "sandbox-proxy-1" in cmd

    @patch("foundry_sandbox.proxy.proxy_container_name")
    def test_no_transport_raises(self, mock_name, monkeypatch):
        """No proxy transport available should raise RuntimeError."""
        monkeypatch.delenv("PROXY_URL", raising=False)
        monkeypatch.delenv("PROXY_SOCKET_PATH", raising=False)
        mock_name.return_value = ""

        with pytest.raises(RuntimeError, match="PROXY_CONTAINER_NAME or CONTAINER_NAME required"):
            proxy.proxy_curl("GET", "/internal/health")

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_curl_failure_raises(self, mock_run, monkeypatch):
        """Curl failure should raise RuntimeError."""
        monkeypatch.setenv("PROXY_URL", "http://localhost:8080")

        mock_run.return_value = Mock(
            returncode=7, stdout="", stderr="Connection refused"
        )

        with pytest.raises(RuntimeError, match="curl failed"):
            proxy.proxy_curl("GET", "/internal/health")

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_include_status_code(self, mock_run, monkeypatch):
        """include_status_code=True should return body and http_code."""
        monkeypatch.setenv("PROXY_URL", "http://localhost:8080")

        mock_run.return_value = Mock(
            returncode=0, stdout='{"status":"ok"}\n200', stderr=""
        )

        result = proxy.proxy_curl("GET", "/internal/health", include_status_code=True)

        assert result["http_code"] == 200
        assert result["body"]["status"] == "ok"

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_post_with_data(self, mock_run, monkeypatch):
        """POST with data should include JSON body."""
        monkeypatch.setenv("PROXY_URL", "http://localhost:8080")

        mock_run.return_value = Mock(
            returncode=0, stdout='{"status":"registered"}', stderr=""
        )

        data = {"container_id": "abc", "ip_address": "10.0.0.1"}
        proxy.proxy_curl("POST", "/internal/containers", data)

        cmd = mock_run.call_args[0][0]
        assert "-d" in cmd
        # Find the JSON data argument
        d_idx = cmd.index("-d")
        json_body = json.loads(cmd[d_idx + 1])
        assert json_body["container_id"] == "abc"


class TestProxyRegister:
    """Tests for proxy_register()."""

    def test_empty_args_raises(self):
        """Empty container_id or ip_address should raise."""
        with pytest.raises(RuntimeError, match="required"):
            proxy.proxy_register("", "10.0.0.1")

        with pytest.raises(RuntimeError, match="required"):
            proxy.proxy_register("abc123", "")

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_successful_registration(self, mock_curl):
        """Successful registration should return JSON string."""
        mock_curl.return_value = {"status": "registered", "container_id": "abc"}

        result = proxy.proxy_register("abc", "10.0.0.1")

        assert "registered" in result
        mock_curl.assert_called_once()
        call_data = mock_curl.call_args[0][2]
        assert call_data["container_id"] == "abc"
        assert call_data["ip_address"] == "10.0.0.1"
        assert call_data["ttl_seconds"] == 86400

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_registration_with_metadata(self, mock_curl):
        """Registration with metadata should pass it through."""
        mock_curl.return_value = {"status": "registered"}

        proxy.proxy_register("abc", "10.0.0.1", metadata={"env": "test"})

        call_data = mock_curl.call_args[0][2]
        assert call_data["metadata"] == {"env": "test"}

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_registration_failure_raises(self, mock_curl):
        """Failed registration should raise RuntimeError."""
        mock_curl.return_value = {"status": "error", "message": "IP conflict"}

        with pytest.raises(RuntimeError, match="IP conflict"):
            proxy.proxy_register("abc", "10.0.0.1")


class TestProxyUnregister:
    """Tests for proxy_unregister()."""

    def test_empty_id_returns_zero(self):
        """Empty container_id should return 0."""
        assert proxy.proxy_unregister("") == 0

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_successful_unregister(self, mock_curl):
        """Successful unregister should return 0."""
        mock_curl.return_value = {"body": {}, "http_code": 200}

        assert proxy.proxy_unregister("abc123") == 0

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_not_found_returns_zero(self, mock_curl):
        """404 (already unregistered) should return 0."""
        mock_curl.return_value = {"body": {}, "http_code": 404}

        assert proxy.proxy_unregister("abc123") == 0

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_curl_error_returns_zero(self, mock_curl):
        """Curl error should return 0 (never block destroy)."""
        mock_curl.side_effect = RuntimeError("connection refused")

        assert proxy.proxy_unregister("abc123") == 0


class TestProxyWaitReady:
    """Tests for proxy_wait_ready()."""

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_immediately_ready(self, mock_curl):
        """Proxy already healthy should return True immediately."""
        mock_curl.return_value = {
            "body": {"status": "healthy"},
            "http_code": 200,
        }

        result = proxy.proxy_wait_ready(timeout=10, _sleep=lambda d: None)

        assert result is True

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_ready_after_retries(self, mock_curl):
        """Proxy becoming healthy after retries should return True."""
        mock_curl.side_effect = [
            RuntimeError("connection refused"),
            RuntimeError("connection refused"),
            {"body": {"status": "healthy"}, "http_code": 200},
        ]
        sleep_calls = []

        result = proxy.proxy_wait_ready(
            timeout=30, _sleep=lambda d: sleep_calls.append(d)
        )

        assert result is True
        assert len(sleep_calls) >= 2

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_timeout_returns_false(self, mock_curl):
        """Timeout should return False."""
        mock_curl.side_effect = RuntimeError("connection refused")
        total_slept = [0]

        def fake_sleep(d):
            total_slept[0] += d

        result = proxy.proxy_wait_ready(timeout=3, _sleep=fake_sleep)

        assert result is False
        assert total_slept[0] >= 3


class TestProxyGetContainerIp:
    """Tests for proxy_get_container_ip()."""

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_found_ip(self, mock_run):
        """Valid IP should be returned."""
        mock_run.return_value = Mock(
            returncode=0, stdout="10.0.0.5\n", stderr=""
        )

        result = proxy.proxy_get_container_ip("abc123")

        assert result == "10.0.0.5"

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_no_value_returns_empty(self, mock_run):
        """Docker '<no value>' should return empty string."""
        mock_run.return_value = Mock(
            returncode=0, stdout="<no value>\n", stderr=""
        )

        result = proxy.proxy_get_container_ip("abc123")

        assert result == ""

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_failure_returns_empty(self, mock_run):
        """Docker inspect failure should return empty string."""
        mock_run.return_value = Mock(returncode=1, stdout="", stderr="error")

        result = proxy.proxy_get_container_ip("abc123")

        assert result == ""

    @patch("foundry_sandbox.proxy.subprocess.run")
    def test_custom_network(self, mock_run):
        """Custom network name should be passed to docker inspect."""
        mock_run.return_value = Mock(
            returncode=0, stdout="10.0.0.5\n", stderr=""
        )

        proxy.proxy_get_container_ip("abc123", "my-network")

        cmd = mock_run.call_args[0][0]
        assert "my-network" in str(cmd)


class TestSetupProxyRegistration:
    """Tests for setup_proxy_registration()."""

    @patch("foundry_sandbox.proxy.proxy_register")
    @patch("foundry_sandbox.proxy.proxy_get_container_ip")
    @patch("foundry_sandbox.proxy.proxy_wait_ready")
    def test_successful_setup(self, mock_wait, mock_ip, mock_register):
        """Full registration lifecycle should succeed."""
        mock_wait.return_value = True
        mock_ip.return_value = "10.0.0.5"
        mock_register.return_value = '{"status":"registered"}'

        proxy.setup_proxy_registration("abc123")

        mock_wait.assert_called_once_with(30)
        mock_register.assert_called_once()

    @patch("foundry_sandbox.proxy.proxy_wait_ready")
    def test_proxy_not_ready_raises(self, mock_wait):
        """Proxy not ready should raise RuntimeError."""
        mock_wait.return_value = False

        with pytest.raises(RuntimeError, match="not ready"):
            proxy.setup_proxy_registration("abc123")

    @patch("foundry_sandbox.proxy.proxy_get_container_ip")
    @patch("foundry_sandbox.proxy.proxy_wait_ready")
    def test_no_ip_raises(self, mock_wait, mock_ip):
        """No container IP found should raise RuntimeError."""
        mock_wait.return_value = True
        mock_ip.return_value = ""

        with pytest.raises(RuntimeError, match="Could not determine container IP"):
            proxy.setup_proxy_registration("abc123")

    @patch("foundry_sandbox.proxy.proxy_register")
    @patch("foundry_sandbox.proxy.proxy_get_container_ip")
    @patch("foundry_sandbox.proxy.proxy_wait_ready")
    def test_fallback_network_lookup(self, mock_wait, mock_ip, mock_register):
        """Should try project-prefix network if default fails."""
        mock_wait.return_value = True
        # First call (default network) returns empty, second (prefixed) returns IP
        mock_ip.side_effect = ["", "10.0.0.5"]
        mock_register.return_value = '{"status":"registered"}'

        proxy.setup_proxy_registration("myproject-dev-1")

        assert mock_ip.call_count == 2


class TestCleanupProxyRegistration:
    """Tests for cleanup_proxy_registration()."""

    def test_empty_id_returns_zero(self):
        """Empty container_id should return 0."""
        assert proxy.cleanup_proxy_registration("") == 0

    @patch("foundry_sandbox.proxy.proxy_unregister")
    def test_cleanup_calls_unregister(self, mock_unreg):
        """Should call proxy_unregister."""
        mock_unreg.return_value = 0

        result = proxy.cleanup_proxy_registration("abc123")

        assert result == 0
        mock_unreg.assert_called_once_with("abc123")


class TestProxyIsRegistered:
    """Tests for proxy_is_registered()."""

    def test_empty_id_returns_false(self):
        """Empty container_id should return False."""
        assert proxy.proxy_is_registered("") is False

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_registered(self, mock_curl):
        """200 response should return True."""
        mock_curl.return_value = {"body": {}, "http_code": 200}

        assert proxy.proxy_is_registered("abc123") is True

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_not_registered(self, mock_curl):
        """404 response should return False."""
        mock_curl.return_value = {"body": {}, "http_code": 404}

        assert proxy.proxy_is_registered("abc123") is False

    @patch("foundry_sandbox.proxy.proxy_curl")
    def test_error_returns_false(self, mock_curl):
        """Error should return False."""
        mock_curl.side_effect = RuntimeError("connection error")

        assert proxy.proxy_is_registered("abc123") is False
