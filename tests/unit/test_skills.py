"""Unit tests for foundry_sandbox.skills.

Tests skill configuration loading, environment resolution, mount generation,
permission merging, and container installation.

All subprocess calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.skills import (
    SkillConfig,
    _append_stub_to_workspace,
    _register_mcp_servers,
    get_skill_env,
    get_skill_mounts,
    get_skill_permissions,
    install_skills_to_container,
    load_skills_config,
    resolve_skill_env,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _completed(stdout="", stderr="", returncode=0):
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


def _default_skill(**overrides: object) -> SkillConfig:
    """Build a SkillConfig with sensible defaults, overriding specific fields."""
    kwargs: dict[str, object] = dict(
        name="test-skill",
        path="/host/skill",
        mount_target="/skills/test-skill",
        mcp_server={"command": "python", "args": ["/skills/test-skill/server.py"]},
        permissions_allow=["Bash(my-tool:*)"],
        permissions_deny=["Bash(danger:*)"],
        stubs=["GUIDE.md"],
        env={"API_KEY": "$HOST_API_KEY"},
    )
    kwargs.update(overrides)
    return SkillConfig(**kwargs)  # type: ignore[arg-type]


def _make_config(**overrides: object) -> dict[str, SkillConfig]:
    """Build a skills_config dict with sensible defaults."""
    skill = _default_skill(**overrides)
    return {skill.name: skill}


# ---------------------------------------------------------------------------
# TestLoadSkillsConfig
# ---------------------------------------------------------------------------


class TestLoadSkillsConfig:
    """Tests for load_skills_config()."""

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_returns_empty_when_file_missing(self, mock_path, tmp_path):
        mock_path.return_value = tmp_path / "nonexistent.toml"
        assert load_skills_config() == {}

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_returns_empty_on_invalid_toml(self, mock_path, tmp_path):
        toml_file = tmp_path / "skills.toml"
        toml_file.write_text("this is not valid [[ toml")
        mock_path.return_value = toml_file
        assert load_skills_config() == {}

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_returns_empty_when_skills_section_not_dict(self, mock_path, tmp_path):
        toml_file = tmp_path / "skills.toml"
        toml_file.write_text('skills = "not a table"\n')
        mock_path.return_value = toml_file
        assert load_skills_config() == {}

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_parses_valid_config(self, mock_path, tmp_path):
        toml_file = tmp_path / "skills.toml"
        toml_file.write_text("""\
[skills.my-tool]
path = "~/GitHub/my-tool"
mount_target = "/skills/my-tool"
permissions_allow = ["Bash(my-tool:*)"]
permissions_deny = []
stubs = ["README.md"]

[skills.my-tool.mcp_server]
command = "python"
args = ["/skills/my-tool/server.py"]

[skills.my-tool.env]
KEY = "$HOST_KEY"
STATIC = "value"
""")
        mock_path.return_value = toml_file

        result = load_skills_config()
        assert "my-tool" in result
        skill = result["my-tool"]
        assert skill.name == "my-tool"
        assert skill.path == "~/GitHub/my-tool"
        assert skill.mount_target == "/skills/my-tool"
        assert skill.mcp_server == {"command": "python", "args": ["/skills/my-tool/server.py"]}
        assert skill.permissions_allow == ["Bash(my-tool:*)"]
        assert skill.permissions_deny == []
        assert skill.stubs == ["README.md"]
        assert skill.env == {"KEY": "$HOST_KEY", "STATIC": "value"}

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_skips_non_dict_entries(self, mock_path, tmp_path):
        toml_file = tmp_path / "skills.toml"
        toml_file.write_text("""\
[skills]
bad_entry = "not a table"

[skills.good]
path = "/some/path"
""")
        mock_path.return_value = toml_file

        result = load_skills_config()
        assert "bad_entry" not in result
        assert "good" in result

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_defaults_for_missing_fields(self, mock_path, tmp_path):
        toml_file = tmp_path / "skills.toml"
        toml_file.write_text("""\
[skills.minimal]
""")
        mock_path.return_value = toml_file

        result = load_skills_config()
        skill = result["minimal"]
        assert skill.path == ""
        assert skill.mount_target == ""
        assert skill.mcp_server is None
        assert skill.permissions_allow == []
        assert skill.permissions_deny == []
        assert skill.stubs == []
        assert skill.env == {}

    @patch("foundry_sandbox.skills._skills_toml_path")
    def test_multiple_skills(self, mock_path, tmp_path):
        toml_file = tmp_path / "skills.toml"
        toml_file.write_text("""\
[skills.alpha]
path = "/alpha"

[skills.beta]
path = "/beta"
""")
        mock_path.return_value = toml_file

        result = load_skills_config()
        assert len(result) == 2
        assert "alpha" in result
        assert "beta" in result


# ---------------------------------------------------------------------------
# TestResolveSkillEnv
# ---------------------------------------------------------------------------


class TestResolveSkillEnv:
    """Tests for resolve_skill_env()."""

    def test_resolves_host_var(self):
        with patch.dict(os.environ, {"MY_KEY": "secret123"}):
            result = resolve_skill_env({"API_KEY": "$MY_KEY"})
        assert result == {"API_KEY": "secret123"}

    def test_missing_host_var_returns_empty_and_warns(self):
        env = {"MISSING": "$NONEXISTENT_VAR_XYZ"}
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NONEXISTENT_VAR_XYZ", None)
            with patch("foundry_sandbox.skills.log_warn") as mock_warn:
                result = resolve_skill_env(env)
        assert result == {"MISSING": ""}
        mock_warn.assert_called_once()

    def test_static_values_pass_through(self):
        result = resolve_skill_env({"FOO": "bar", "NUM": "42"})
        assert result == {"FOO": "bar", "NUM": "42"}

    def test_mixed_static_and_resolved(self):
        with patch.dict(os.environ, {"REAL": "value"}):
            result = resolve_skill_env({"A": "$REAL", "B": "static"})
        assert result == {"A": "value", "B": "static"}

    def test_empty_dict(self):
        assert resolve_skill_env({}) == {}


# ---------------------------------------------------------------------------
# TestGetSkillMounts
# ---------------------------------------------------------------------------


class TestGetSkillMounts:
    """Tests for get_skill_mounts()."""

    def test_returns_mount_string(self):
        config = _make_config(path="/host/tool", mount_target="/skills/tool")
        mounts = get_skill_mounts(["test-skill"], config)
        assert mounts == ["/host/tool:/skills/tool:ro"]

    def test_default_mount_target(self):
        config = _make_config(path="/host/tool", mount_target="")
        mounts = get_skill_mounts(["test-skill"], config)
        assert mounts == ["/host/tool:/skills/test-skill:ro"]

    def test_expands_user_path(self):
        config = _make_config(path="~/my-tool", mount_target="/skills/tool")
        mounts = get_skill_mounts(["test-skill"], config)
        expected_host = os.path.expanduser("~/my-tool")
        assert mounts == [f"{expected_host}:/skills/tool:ro"]

    def test_skips_unknown_skill(self):
        config = _make_config()
        mounts = get_skill_mounts(["nonexistent"], config)
        assert mounts == []

    def test_skips_skill_without_path(self):
        config = _make_config(path="")
        mounts = get_skill_mounts(["test-skill"], config)
        assert mounts == []

    def test_multiple_skills(self):
        config = {
            "a": SkillConfig(name="a", path="/host/a"),
            "b": SkillConfig(name="b", path="/host/b", mount_target="/custom/b"),
        }
        mounts = get_skill_mounts(["a", "b"], config)
        assert len(mounts) == 2
        assert "/host/a:/skills/a:ro" in mounts
        assert "/host/b:/custom/b:ro" in mounts


# ---------------------------------------------------------------------------
# TestGetSkillEnv
# ---------------------------------------------------------------------------


class TestGetSkillEnv:
    """Tests for get_skill_env()."""

    def test_merges_env_from_multiple_skills(self):
        config = {
            "a": SkillConfig(name="a", env={"X": "1"}),
            "b": SkillConfig(name="b", env={"Y": "2"}),
        }
        with patch.dict(os.environ, {}):
            result = get_skill_env(["a", "b"], config)
        assert result == {"X": "1", "Y": "2"}

    def test_later_skill_overrides_earlier(self):
        config = {
            "a": SkillConfig(name="a", env={"X": "first"}),
            "b": SkillConfig(name="b", env={"X": "second"}),
        }
        result = get_skill_env(["a", "b"], config)
        assert result["X"] == "second"

    def test_skips_unknown_skill(self):
        config = {"a": SkillConfig(name="a", env={"X": "1"})}
        result = get_skill_env(["missing"], config)
        assert result == {}

    def test_empty_skill_names(self):
        config = _make_config()
        result = get_skill_env([], config)
        assert result == {}


# ---------------------------------------------------------------------------
# TestGetSkillPermissions
# ---------------------------------------------------------------------------


class TestGetSkillPermissions:
    """Tests for get_skill_permissions()."""

    def test_merges_permissions(self):
        config = {
            "a": SkillConfig(name="a", permissions_allow=["p1"], permissions_deny=["d1"]),
            "b": SkillConfig(name="b", permissions_allow=["p2"], permissions_deny=["d2"]),
        }
        allow, deny = get_skill_permissions(["a", "b"], config)
        assert allow == ["p1", "p2"]
        assert deny == ["d1", "d2"]

    def test_empty_skill_names(self):
        config = _make_config()
        allow, deny = get_skill_permissions([], config)
        assert allow == []
        assert deny == []

    def test_skips_unknown_skill(self):
        config = _make_config()
        allow, deny = get_skill_permissions(["missing"], config)
        assert allow == []
        assert deny == []


# ---------------------------------------------------------------------------
# TestRegisterMcpServers
# ---------------------------------------------------------------------------


class TestRegisterMcpServers:
    """Tests for _register_mcp_servers()."""

    @patch("foundry_sandbox.skills.subprocess.run", return_value=_completed())
    def test_calls_docker_exec(self, mock_run):
        servers = {"my-tool": {"command": "python", "args": ["/tool/server.py"]}}
        _register_mcp_servers("container1", servers)

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "docker"
        assert "container1" in cmd

    @patch("foundry_sandbox.skills.subprocess.run", return_value=_completed(returncode=1, stderr="error"))
    def test_warns_on_failure(self, mock_run):
        with patch("foundry_sandbox.skills.log_warn") as mock_warn:
            _register_mcp_servers("c1", {"tool": {"command": "x"}})
        mock_warn.assert_called_once()


# ---------------------------------------------------------------------------
# TestAppendStubToWorkspace
# ---------------------------------------------------------------------------


class TestAppendStubToWorkspace:
    """Tests for _append_stub_to_workspace()."""

    @patch("foundry_sandbox.skills.subprocess.run")
    def test_touches_then_appends(self, mock_run, tmp_path):
        stub = tmp_path / "GUIDE.md"
        stub.write_text("# Guide content")

        # grep returns 1 (marker not found), then touch/append succeed
        mock_run.side_effect = [
            _completed(returncode=1),  # grep -qF (marker not found)
            _completed(),              # touch
            _completed(),              # cat >>
        ]

        _append_stub_to_workspace("c1", stub, "GUIDE.md")

        assert mock_run.call_count == 3
        # First call: grep (idempotency check)
        grep_cmd = mock_run.call_args_list[0][0][0]
        assert "grep" in grep_cmd
        # Second call: touch
        touch_cmd = mock_run.call_args_list[1][0][0]
        assert "touch" in touch_cmd
        # Third call: cat >>
        append_cmd = mock_run.call_args_list[2][0][0]
        assert "cat >>" in " ".join(append_cmd)

    @patch("foundry_sandbox.skills.subprocess.run", return_value=_completed(returncode=0))
    def test_skips_already_installed_stub(self, mock_run, tmp_path):
        stub = tmp_path / "GUIDE.md"
        stub.write_text("# Guide content")

        _append_stub_to_workspace("c1", stub, "GUIDE.md")

        # Only the grep check, no touch or append
        assert mock_run.call_count == 1


# ---------------------------------------------------------------------------
# TestInstallSkillsToContainer
# ---------------------------------------------------------------------------


class TestInstallSkillsToContainer:
    """Tests for install_skills_to_container()."""

    def test_noop_when_no_skills(self):
        with patch("foundry_sandbox.skills.subprocess.run") as mock_run:
            install_skills_to_container("c1", [], {})
        mock_run.assert_not_called()

    @patch("foundry_sandbox.skills.subprocess.run")
    def test_registers_mcp_and_appends_stubs(self, mock_run, tmp_path):
        stub = tmp_path / "GUIDE.md"
        stub.write_text("# content")
        config = {
            "tool": SkillConfig(
                name="tool",
                path=str(tmp_path),
                mcp_server={"command": "python", "args": ["/s/server.py"]},
                stubs=["GUIDE.md"],
            ),
        }

        # MCP registration succeeds, grep returns 1 (not found), touch/append succeed
        mock_run.side_effect = [
            _completed(),              # MCP registration
            _completed(returncode=1),  # grep -qF (marker not found)
            _completed(),              # touch
            _completed(),              # cat >>
        ]

        install_skills_to_container("c1", ["tool"], config)

        # MCP registration (1) + grep (1) + touch (1) + cat (1) = 4
        assert mock_run.call_count == 4

    @patch("foundry_sandbox.skills.subprocess.run", return_value=_completed())
    def test_skips_missing_stub_file(self, mock_run, tmp_path):
        config = {
            "tool": SkillConfig(
                name="tool",
                path=str(tmp_path),
                stubs=["NONEXISTENT.md"],
            ),
        }

        install_skills_to_container("c1", ["tool"], config)
        # No MCP server, stub file doesn't exist → no calls
        mock_run.assert_not_called()

    @patch("foundry_sandbox.skills.subprocess.run", return_value=_completed())
    def test_skips_skill_without_mcp(self, mock_run):
        config = {
            "tool": SkillConfig(name="tool", path="/x"),
        }
        install_skills_to_container("c1", ["tool"], config)
        mock_run.assert_not_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
