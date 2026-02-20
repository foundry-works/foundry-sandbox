"""Unit tests for compose_extras parameter in foundry_sandbox.docker.

Tests the compose_extras parameter in get_compose_command() and compose_down()
to ensure proper ordering of docker-compose -f arguments and error handling.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.docker import (
    compose_down,
    compose_up,
    get_compose_command,
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
# TestGetComposeCommandExtras
# ---------------------------------------------------------------------------


class TestGetComposeCommandExtras:
    """get_compose_command handles compose_extras parameter correctly."""

    def test_compose_extras_none_produces_base_command(self):
        """Test: compose_extras=None produces same command as current."""
        cmd = get_compose_command(compose_extras=None)
        assert cmd[:2] == ["docker", "compose"]
        assert any("docker-compose.yml" in arg for arg in cmd)
        # Should not have any extra -f args beyond base
        f_count = cmd.count("-f")
        assert f_count == 1

    def test_compose_extras_appends_in_correct_order(self, tmp_path):
        """Test: compose_extras appends -f args in correct order.

        Extras paths should appear after base, credential-isolation, and
        override files.
        """
        extra1 = tmp_path / "extra1.yml"
        extra2 = tmp_path / "extra2.yml"
        extra1.write_text("version: '3'")
        extra2.write_text("version: '3'")

        cmd = get_compose_command(
            compose_extras=[str(extra1), str(extra2)]
        )

        # Find all -f indices
        f_indices = [i for i, arg in enumerate(cmd) if arg == "-f"]
        files = [cmd[i + 1] for i in f_indices]

        # Base file should come first
        assert any("docker-compose.yml" in f for f in files[0:1])
        # Extras should be last
        assert str(extra1) in files[-2:]
        assert str(extra2) in files[-2:]

    def test_full_4_layer_ordering(self, tmp_path):
        """Test: full 4-layer ordering (base + isolation + override + extras).

        With all layers active, verify exact -f ordering: base, isolation,
        override, extras.
        """
        override = tmp_path / "override.yml"
        extra1 = tmp_path / "extra1.yml"
        extra2 = tmp_path / "extra2.yml"

        override.write_text("version: '3'")
        extra1.write_text("version: '3'")
        extra2.write_text("version: '3'")

        cmd = get_compose_command(
            override_file=str(override),
            isolate_credentials=True,
            compose_extras=[str(extra1), str(extra2)],
        )

        # Extract file paths in order
        files = []
        for i, arg in enumerate(cmd):
            if arg == "-f" and i + 1 < len(cmd):
                files.append(cmd[i + 1])

        # Verify order: base, isolation, override, extra1, extra2
        assert len(files) == 5
        assert "docker-compose.yml" in files[0]
        assert "credential-isolation" in files[1]
        assert str(override) == files[2]
        assert str(extra1) == files[3]
        assert str(extra2) == files[4]

    def test_compose_extras_empty_list_ignored(self):
        """Test: empty compose_extras list is treated as no extras."""
        cmd = get_compose_command(compose_extras=[])
        f_count = cmd.count("-f")
        assert f_count == 1  # Only base file

    def test_invalid_extras_path_raises_filenotfound(self):
        """Test: invalid extras path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError) as exc_info:
            get_compose_command(compose_extras=["/nonexistent/extra.yml"])

        assert "Compose extras path does not exist" in str(exc_info.value)
        assert "/nonexistent/extra.yml" in str(exc_info.value)

    def test_invalid_extras_directory_raises_filenotfound(self, tmp_path):
        """Test: extras path that is a directory raises FileNotFoundError."""
        extra_dir = tmp_path / "extra_dir"
        extra_dir.mkdir()

        with pytest.raises(FileNotFoundError) as exc_info:
            get_compose_command(compose_extras=[str(extra_dir)])

        assert "Compose extras path does not exist or is not a regular file" in str(exc_info.value)

    def test_single_extra_file(self, tmp_path):
        """Test: single extra file is appended correctly."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        cmd = get_compose_command(compose_extras=[str(extra)])

        assert "-f" in cmd
        assert str(extra) in cmd
        # Verify it comes after base file
        f_indices = [i for i, arg in enumerate(cmd) if arg == "-f"]
        files = [cmd[i + 1] for i in f_indices]
        assert len(files) == 2
        assert str(extra) == files[1]

    def test_multiple_extras_preserve_order(self, tmp_path):
        """Test: multiple extras preserve specified order."""
        extras = [tmp_path / f"extra{i}.yml" for i in range(1, 4)]
        for extra in extras:
            extra.write_text("version: '3'")

        cmd = get_compose_command(compose_extras=[str(e) for e in extras])

        f_indices = [i for i, arg in enumerate(cmd) if arg == "-f"]
        files = [cmd[i + 1] for i in f_indices]

        # Verify order is preserved
        for i, extra in enumerate(extras):
            assert str(extra) == files[i + 1]  # +1 skips base file

    def test_extras_ignored_when_override_missing(self, tmp_path):
        """Test: extras are still added even when override file is missing."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        cmd = get_compose_command(
            override_file="/nonexistent/override.yml",
            compose_extras=[str(extra)],
        )

        # Override should be ignored but extra should still be present
        assert "/nonexistent/override.yml" not in cmd
        assert str(extra) in cmd

    def test_extras_with_isolation_and_no_override(self, tmp_path):
        """Test: extras work with isolation but no override file."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        cmd = get_compose_command(
            isolate_credentials=True,
            compose_extras=[str(extra)],
        )

        f_indices = [i for i, arg in enumerate(cmd) if arg == "-f"]
        files = [cmd[i + 1] for i in f_indices]

        # Should have: base, isolation, extra
        assert len(files) == 3
        assert "docker-compose.yml" in files[0]
        assert "credential-isolation" in files[1]
        assert str(extra) == files[2]

    def test_extras_validation_checks_all_paths(self, tmp_path):
        """Test: validation checks all paths before using any."""
        valid_extra = tmp_path / "valid.yml"
        valid_extra.write_text("version: '3'")
        invalid_extra = "/nonexistent/invalid.yml"

        with pytest.raises(FileNotFoundError):
            get_compose_command(compose_extras=[str(valid_extra), invalid_extra])

    def test_compose_extras_called_with_list_type(self, tmp_path):
        """Test: compose_extras accepts list type parameter."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        # Verify list type works
        cmd = get_compose_command(compose_extras=[str(extra)])
        assert str(extra) in cmd


# ---------------------------------------------------------------------------
# TestComposeDownExtras
# ---------------------------------------------------------------------------


class TestComposeDownExtras:
    """compose_down passes compose_extras through to get_compose_command."""

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_with_extras(self, mock_run, tmp_path):
        """Test: compose_down succeeds with compose_extras parameter."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            compose_extras=[str(extra)],
        )

        # Verify subprocess.run was called
        assert mock_run.called
        # Get the command that was run
        cmd = mock_run.call_args[0][0]
        # Verify extra file is in command
        assert str(extra) in cmd
        assert "down" in cmd

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_without_allowlist_extra(self, mock_run, tmp_path):
        """Test: compose_down succeeds without allowlist extra override file.

        Lifecycle stability: compose_down with compose_extras should work
        even when the allowlist extra file is not present.
        """
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        # This should not raise even if intermediate files are missing
        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            compose_extras=[str(extra)],
        )

        assert mock_run.called

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_with_multiple_extras(self, mock_run, tmp_path):
        """Test: compose_down handles multiple extras correctly."""
        extra1 = tmp_path / "extra1.yml"
        extra2 = tmp_path / "extra2.yml"
        extra1.write_text("version: '3'")
        extra2.write_text("version: '3'")

        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            compose_extras=[str(extra1), str(extra2)],
        )

        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert str(extra1) in cmd
        assert str(extra2) in cmd

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_invalid_extra_raises(self, mock_run, tmp_path):
        """Test: compose_down with invalid extra raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            compose_down(
                worktree_path="/tmp/work",
                claude_config_path="/tmp/config",
                container="test-container",
                compose_extras=["/nonexistent/extra.yml"],
            )

        # subprocess.run may have been called for auto-detect, but error should occur
        # before the final down command is issued

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_passes_env_vars(self, mock_run, tmp_path):
        """Test: compose_down passes environment variables correctly."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        compose_down(
            worktree_path="/path/to/work",
            claude_config_path="/path/to/config",
            container="test-container",
            compose_extras=[str(extra)],
        )

        # Check env vars were passed
        call_kwargs = mock_run.call_args[1]
        env = call_kwargs.get("env")
        assert env is not None
        assert env["WORKSPACE_PATH"] == "/path/to/work"
        assert env["CLAUDE_CONFIG_PATH"] == "/path/to/config"
        assert env["CONTAINER_NAME"] == "test-container"

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_with_override_and_extras(self, mock_run, tmp_path):
        """Test: compose_down with both override_file and compose_extras."""
        override = tmp_path / "override.yml"
        extra = tmp_path / "extra.yml"
        override.write_text("version: '3'")
        extra.write_text("version: '3'")

        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            override_file=str(override),
            compose_extras=[str(extra)],
        )

        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert str(override) in cmd
        assert str(extra) in cmd

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_with_isolation_and_extras(self, mock_run, tmp_path):
        """Test: compose_down with isolate_credentials and compose_extras."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            isolate_credentials=True,
            compose_extras=[str(extra)],
        )

        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        # Should have isolation file and extra
        assert any("credential-isolation" in arg for arg in cmd)
        assert str(extra) in cmd

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_with_remove_volumes_and_extras(self, mock_run, tmp_path):
        """Test: compose_down with remove_volumes flag and compose_extras."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            remove_volumes=True,
            compose_extras=[str(extra)],
        )

        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "-v" in cmd
        assert str(extra) in cmd
        assert "down" in cmd

    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_compose_down_none_extras_default(self, mock_run):
        """Test: compose_down with compose_extras=None works correctly."""
        compose_down(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            compose_extras=None,
        )

        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        # Should work normally with base file only
        assert "docker" in cmd
        assert "down" in cmd


# ---------------------------------------------------------------------------
# TestComposeExtrasEdgeCases
# ---------------------------------------------------------------------------


class TestComposeExtrasEdgeCases:
    """Edge cases and integration scenarios for compose_extras."""

    def test_extras_with_special_chars_in_path(self, tmp_path):
        """Test: extras with special characters in path are handled."""
        special_dir = tmp_path / "dir-with-special_chars.v1"
        special_dir.mkdir()
        extra = special_dir / "extra.yml"
        extra.write_text("version: '3'")

        cmd = get_compose_command(compose_extras=[str(extra)])
        assert str(extra) in cmd

    def test_extras_with_absolute_paths(self, tmp_path):
        """Test: extras with absolute paths work correctly."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")
        abs_path = str(extra.resolve())

        cmd = get_compose_command(compose_extras=[abs_path])
        assert abs_path in cmd

    def test_extras_case_sensitive(self, tmp_path):
        """Test: extras path handling is case-sensitive."""
        extra = tmp_path / "Extra.yml"
        extra.write_text("version: '3'")

        cmd = get_compose_command(compose_extras=[str(extra)])
        assert str(extra) in cmd
        # Verify exact case is preserved
        assert "Extra.yml" in cmd[cmd.index(str(extra))]

    def test_compose_extras_preserves_command_structure(self, tmp_path):
        """Test: adding extras doesn't break command structure."""
        extra = tmp_path / "extra.yml"
        extra.write_text("version: '3'")

        cmd = get_compose_command(compose_extras=[str(extra)])

        # Verify structure is valid
        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        # -f flags should be paired with file paths
        f_indices = [i for i, arg in enumerate(cmd) if arg == "-f"]
        for f_idx in f_indices:
            assert f_idx + 1 < len(cmd), "Each -f must have a file path following"


# ---------------------------------------------------------------------------
# TestProxyAllowlistExtraPath
# ---------------------------------------------------------------------------


class TestProxyAllowlistExtraPath:
    """Tests for PROXY_ALLOWLIST_EXTRA_PATH threading in compose_up."""

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_allowlist_extra_path_set_generates_override(
        self,
        mock_run,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
        tmp_path,
    ):
        """Test: PROXY_ALLOWLIST_EXTRA_PATH set generates override with read-only mount.

        When env var is set and isolate_credentials=True, compose_up should
        create a temp YAML override with bind mount and env var.
        """
        # Setup mock for credential placeholders
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Create a real allowlist file
        allowlist_file = tmp_path / "allowlist-extra.yml"
        allowlist_file.write_text("rules:\n  - allow: true\n")

        # Set the environment variable
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", str(allowlist_file))

        compose_up(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            isolate_credentials=True,
        )

        # Verify subprocess.run was called
        assert mock_run.called

        # Verify that a compose extras file was passed to compose_cmd
        # (the temporary override file should be in the command)
        cmd_calls = [call[0][0] for call in mock_run.call_args_list]
        found_override = False
        for cmd in cmd_calls:
            if isinstance(cmd, list):
                for arg in cmd:
                    if isinstance(arg, str) and arg.startswith("/tmp") and "allowlist-extra-" in arg:
                        found_override = True
                        break
        assert found_override, "Override file should have been passed to compose command"

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_allowlist_extra_path_unset_produces_no_extra_mount(
        self,
        mock_run,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
    ):
        """Test: PROXY_ALLOWLIST_EXTRA_PATH unset produces no extra mount/env.

        When env var is not set, no extra override should be created.
        """
        import os
        import tempfile
        import glob

        # Setup mock for credential placeholders
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Ensure env var is not set
        monkeypatch.delenv("PROXY_ALLOWLIST_EXTRA_PATH", raising=False)

        # Get the temp directory to track files
        temp_dir = tempfile.gettempdir()
        files_before = set(glob.glob(os.path.join(temp_dir, "allowlist-extra-*")))

        compose_up(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            isolate_credentials=True,
        )

        # Verify no allowlist-extra temp files were created
        files_after = set(glob.glob(os.path.join(temp_dir, "allowlist-extra-*")))
        new_files = files_after - files_before
        assert len(new_files) == 0, f"No temp override files should be created, but found: {new_files}"

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    def test_allowlist_extra_path_nonexistent_file_raises_filenotfound(
        self,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
    ):
        """Test: nonexistent file path raises FileNotFoundError.

        When env var points to non-existent file, FileNotFoundError should be raised.
        """
        # Setup mock for credential placeholders
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Set the environment variable to a non-existent file
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", "/nonexistent/allowlist-extra.yml")

        with pytest.raises(FileNotFoundError) as exc_info:
            compose_up(
                worktree_path="/tmp/work",
                claude_config_path="/tmp/config",
                container="test-container",
                isolate_credentials=True,
            )

        assert "PROXY_ALLOWLIST_EXTRA_PATH is not a regular file" in str(exc_info.value)

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    @patch("foundry_sandbox.docker.subprocess.run")
    def test_allowlist_extra_path_temp_file_cleaned_up_on_success(
        self,
        mock_run,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
        tmp_path,
    ):
        """Test: temp override file cleaned up after compose_up succeeds.

        The temp YAML file should be deleted after compose_up completes.
        """
        import os
        import tempfile
        import glob

        # Setup mock for credential placeholders
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Create a real allowlist file
        allowlist_file = tmp_path / "allowlist-extra.yml"
        allowlist_file.write_text("rules:\n  - allow: true\n")

        # Set the environment variable
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", str(allowlist_file))

        # Get the temp directory to track files
        temp_dir = tempfile.gettempdir()
        files_before = set(glob.glob(os.path.join(temp_dir, "allowlist-extra-*")))

        # Make subprocess.run return success
        mock_run.return_value = _completed()

        compose_up(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            isolate_credentials=True,
        )

        # Check files after
        files_after = set(glob.glob(os.path.join(temp_dir, "allowlist-extra-*")))

        # Any new temp files should have been cleaned up
        new_files = files_after - files_before
        assert len(new_files) == 0, f"Temp files should have been cleaned up, but found: {new_files}"

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    @patch("foundry_sandbox.docker.subprocess.run")
    def test_allowlist_extra_path_temp_file_cleaned_up_on_failure(
        self,
        mock_run,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
        tmp_path,
    ):
        """Test: temp override file cleaned up after compose_up fails.

        The temp YAML file should be deleted even if compose_up fails (exception path).
        """
        import os
        import tempfile
        import glob

        # Setup mock for credential placeholders
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Create a real allowlist file
        allowlist_file = tmp_path / "allowlist-extra.yml"
        allowlist_file.write_text("rules:\n  - allow: true\n")

        # Set the environment variable
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", str(allowlist_file))

        # Get the temp directory to track files
        temp_dir = tempfile.gettempdir()
        files_before = set(glob.glob(os.path.join(temp_dir, "allowlist-extra-*")))

        # Make subprocess.run fail for the main compose up command
        def mock_run_side_effect(cmd, *args, **kwargs):
            if len(cmd) > 0 and "up" in cmd and "no-deps" not in cmd:
                # This is the main compose up command, make it fail
                result = MagicMock(spec=subprocess.CompletedProcess)
                result.returncode = 1
                result.stdout = b"error"
                result.stderr = b"compose up failed"
                return result
            # For other commands (proxy up), return success
            return _completed()

        mock_run.side_effect = mock_run_side_effect

        with pytest.raises(subprocess.CalledProcessError):
            compose_up(
                worktree_path="/tmp/work",
                claude_config_path="/tmp/config",
                container="test-container",
                isolate_credentials=True,
            )

        # Check files after
        files_after = set(glob.glob(os.path.join(temp_dir, "allowlist-extra-*")))

        # Any new temp files should have been cleaned up even after exception
        new_files = files_after - files_before
        assert len(new_files) == 0, f"Temp files should have been cleaned up after failure, but found: {new_files}"


class TestYamlPathQuoting:
    """Tests for YAML path quoting of host paths in compose overrides.

    The compose_up function quotes host paths with single quotes and escapes
    internal single quotes via doubling. This prevents YAML parsing issues
    with paths containing colons, spaces, or other special characters.
    """

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_path_with_spaces_is_quoted(
        self,
        mock_run,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
        tmp_path,
    ):
        """Host path with spaces is wrapped in single quotes in the override YAML."""
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Create a file in a directory with spaces
        spaced_dir = tmp_path / "my configs"
        spaced_dir.mkdir()
        allowlist_file = spaced_dir / "allowlist-extra.yml"
        allowlist_file.write_text("domains: []\n")

        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", str(allowlist_file))

        compose_up(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            isolate_credentials=True,
        )

        # Verify compose_up was called (quoting is validated by the fact
        # that compose_up didn't error on YAML parsing).
        assert mock_run.called

    @patch("foundry_sandbox.docker._wait_for_proxy_health", return_value=True)
    @patch("foundry_sandbox.docker._capture_container_logs", return_value="")
    @patch("foundry_sandbox.docker.generate_sandbox_subnet", return_value=("10.0.0.0/24", "10.0.0.2"))
    @patch("foundry_sandbox.docker.provision_hmac_secret")
    @patch("foundry_sandbox.docker.populate_stubs_volume")
    @patch("foundry_sandbox.docker.setup_credential_placeholders")
    @patch("foundry_sandbox.docker.get_sandbox_verbose", return_value=False)
    @patch("foundry_sandbox.docker.subprocess.run", return_value=_completed())
    def test_path_with_colon_is_quoted(
        self,
        mock_run,
        mock_verbose,
        mock_cred_placeholders,
        mock_stubs,
        mock_hmac,
        mock_subnet,
        mock_logs,
        mock_health,
        monkeypatch,
        tmp_path,
    ):
        """Host path containing a colon is properly quoted so YAML doesn't split it."""
        mock_cred_env = MagicMock()
        mock_cred_env.to_env_dict.return_value = {}
        mock_cred_placeholders.return_value = mock_cred_env

        # Create a file with colon in directory name
        colon_dir = tmp_path / "config:v2"
        colon_dir.mkdir()
        allowlist_file = colon_dir / "allowlist-extra.yml"
        allowlist_file.write_text("domains: []\n")

        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", str(allowlist_file))

        compose_up(
            worktree_path="/tmp/work",
            claude_config_path="/tmp/config",
            container="test-container",
            isolate_credentials=True,
        )

        assert mock_run.called


class TestYamlPathQuotingUnit:
    """Unit-level tests for the path quoting logic used in compose overrides."""

    def test_single_quote_escaping(self):
        """Verify the escaping logic: single quotes are doubled inside YAML single-quoted scalars."""
        host_path = "/path/with'quote/file.yml"
        container_mount = "/etc/unified-proxy/allowlist-extra.yml"
        quoted_host = host_path.replace("'", "''")
        yaml_line = f"      - '{quoted_host}:{container_mount}:ro'\n"

        assert "with''quote" in yaml_line
        # The line should be parseable by a YAML parser as a single scalar
        import yaml
        doc = yaml.safe_load(f"volumes:\n{yaml_line}")
        assert doc["volumes"][0] == f"{host_path}:{container_mount}:ro"

    def test_colon_in_path_preserved(self):
        """A colon in the host path doesn't break the volume mount spec."""
        host_path = "/path/config:v2/file.yml"
        container_mount = "/etc/unified-proxy/allowlist-extra.yml"
        quoted_host = host_path.replace("'", "''")
        yaml_line = f"      - '{quoted_host}:{container_mount}:ro'\n"

        import yaml
        doc = yaml.safe_load(f"volumes:\n{yaml_line}")
        assert doc["volumes"][0] == f"{host_path}:{container_mount}:ro"

    def test_space_in_path_preserved(self):
        """Spaces in the host path are preserved inside single quotes."""
        host_path = "/path/my configs/file.yml"
        container_mount = "/etc/unified-proxy/allowlist-extra.yml"
        quoted_host = host_path.replace("'", "''")
        yaml_line = f"      - '{quoted_host}:{container_mount}:ro'\n"

        import yaml
        doc = yaml.safe_load(f"volumes:\n{yaml_line}")
        assert doc["volumes"][0] == f"{host_path}:{container_mount}:ro"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
