"""Unit tests for foundry_sandbox.permissions permission merging logic."""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.permissions import (
    FOUNDRY_ALLOW,
    FOUNDRY_DENY,
    _INSTALL_SCRIPT,
    install_workspace_permissions,
)


class TestPermissionLists:
    """Test FOUNDRY_ALLOW and FOUNDRY_DENY lists."""

    def test_allow_list_non_empty(self) -> None:
        assert len(FOUNDRY_ALLOW) > 0

    def test_deny_list_non_empty(self) -> None:
        assert len(FOUNDRY_DENY) > 0

    def test_allow_contains_foundry_skill(self) -> None:
        assert "Skill(foundry:*)" in FOUNDRY_ALLOW

    def test_allow_contains_mcp_tools(self) -> None:
        assert any(e.startswith("mcp__plugin_foundry") for e in FOUNDRY_ALLOW)

    def test_deny_contains_spec_read_block(self) -> None:
        assert "Read(/workspace/**/specs/**/*.json)" in FOUNDRY_DENY

    def test_deny_contains_gh_api_block(self) -> None:
        assert "Bash(gh api:*)" in FOUNDRY_DENY

    def test_no_duplicates_in_allow(self) -> None:
        assert len(FOUNDRY_ALLOW) == len(set(FOUNDRY_ALLOW))

    def test_no_duplicates_in_deny(self) -> None:
        assert len(FOUNDRY_DENY) == len(set(FOUNDRY_DENY))


class TestInstallScriptRendering:
    """Test _INSTALL_SCRIPT template rendering."""

    def test_renders_with_json_dumps(self) -> None:
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps(FOUNDRY_ALLOW),
            deny_json=json.dumps(FOUNDRY_DENY),
        )
        assert "FOUNDRY_ALLOW" in script
        assert "FOUNDRY_DENY" in script
        assert "Skill(foundry:*)" in script

    def test_rendered_script_is_valid_python(self) -> None:
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps(FOUNDRY_ALLOW),
            deny_json=json.dumps(FOUNDRY_DENY),
        )
        # Should compile without SyntaxError
        compile(script, "<install_script>", "exec")


class TestMergePermissionsLogic:
    """Test the merge_permissions logic embedded in _INSTALL_SCRIPT."""

    def test_set_union_and_sorted(self) -> None:
        # Execute the merge_permissions function from the rendered script
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps(["a", "c"]),
            deny_json=json.dumps(["x"]),
        )
        namespace: dict = {}
        exec(script, namespace)  # noqa: S102
        merge_fn = namespace["merge_permissions"]

        result = merge_fn(["b", "a"], ["c", "a"])
        assert result == ["a", "b", "c"]

    def test_deduplication(self) -> None:
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps([]),
            deny_json=json.dumps([]),
        )
        namespace: dict = {}
        exec(script, namespace)  # noqa: S102
        merge_fn = namespace["merge_permissions"]

        result = merge_fn(["x", "x", "y"], ["y", "z"])
        assert result == ["x", "y", "z"]

    def test_empty_inputs(self) -> None:
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps([]),
            deny_json=json.dumps([]),
        )
        namespace: dict = {}
        exec(script, namespace)  # noqa: S102
        merge_fn = namespace["merge_permissions"]

        result = merge_fn([], [])
        assert result == []


class TestInstallScriptExecution:
    """Test the full _INSTALL_SCRIPT by executing it in a temp directory."""

    def test_creates_settings_json(self) -> None:
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps(["Bash(git:*)"]),
            deny_json=json.dumps(["Bash(rm:*)"]),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            # Override home directory to temp dir
            patched_script = script.replace(
                'os.path.expanduser("~/.claude")',
                f'"{os.path.join(tmpdir, ".claude")}"',
            )
            exec(patched_script, {"__name__": "__main__"})  # noqa: S102

            settings_file = os.path.join(tmpdir, ".claude", "settings.json")
            assert os.path.exists(settings_file)
            with open(settings_file) as f:
                settings = json.load(f)
            assert "Bash(git:*)" in settings["permissions"]["allow"]
            assert "Bash(rm:*)" in settings["permissions"]["deny"]

    def test_merges_with_existing_settings(self) -> None:
        script = _INSTALL_SCRIPT.format(
            allow_json=json.dumps(["new_perm"]),
            deny_json=json.dumps(["new_deny"]),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            claude_dir = os.path.join(tmpdir, ".claude")
            os.makedirs(claude_dir)
            settings_file = os.path.join(claude_dir, "settings.json")
            with open(settings_file, "w") as f:
                json.dump(
                    {"permissions": {"allow": ["existing_perm"], "deny": ["existing_deny"]}, "other": "value"},
                    f,
                )

            patched_script = script.replace(
                'os.path.expanduser("~/.claude")',
                f'"{claude_dir}"',
            )
            exec(patched_script, {"__name__": "__main__"})  # noqa: S102

            with open(settings_file) as f:
                settings = json.load(f)
            assert "existing_perm" in settings["permissions"]["allow"]
            assert "new_perm" in settings["permissions"]["allow"]
            assert "existing_deny" in settings["permissions"]["deny"]
            assert "new_deny" in settings["permissions"]["deny"]
            assert settings["other"] == "value"


class TestInstallWorkspacePermissions:
    """Test install_workspace_permissions() docker exec calls."""

    def test_correct_command_structure(self) -> None:
        mock_result = MagicMock(returncode=0, stderr="", stdout="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            install_workspace_permissions("test-container-123")

        mock_run.assert_called_once()
        args = mock_run.call_args
        cmd = args[0][0]
        assert cmd[0] == "docker"
        assert cmd[1] == "exec"
        assert "-u" in cmd
        assert "ubuntu" in cmd
        assert "-i" in cmd
        assert "test-container-123" in cmd
        assert "python3" in cmd

    def test_script_passed_as_input(self) -> None:
        mock_result = MagicMock(returncode=0, stderr="", stdout="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            install_workspace_permissions("ctr-1")

        kwargs = mock_run.call_args[1]
        assert "input" in kwargs
        assert "FOUNDRY_ALLOW" in kwargs["input"]
        assert "FOUNDRY_DENY" in kwargs["input"]

    def test_nonzero_exit_raises_runtime_error(self) -> None:
        mock_result = MagicMock(returncode=1, stderr="permission denied", stdout="")
        with patch("subprocess.run", return_value=mock_result), \
             pytest.raises(RuntimeError, match="Permission installation failed"):
            install_workspace_permissions("ctr-fail")
