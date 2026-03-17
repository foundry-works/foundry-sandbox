"""Unit tests for foundry_sandbox.commands.skills_cmd.

Tests the CLI commands: skills list, skills show, skills init.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from foundry_sandbox.commands.skills_cmd import skills
from foundry_sandbox.skills import SkillConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

runner = CliRunner()


def _sample_config() -> dict[str, SkillConfig]:
    return {
        "research": SkillConfig(
            name="research",
            path="~/GitHub/research-tool",
            mcp_server={"command": "python", "args": ["/skills/research/server.py"]},
            permissions_allow=["Bash(research:*)"],
            permissions_deny=["Bash(danger:*)"],
            stubs=["GUIDE.md"],
            env={"KEY": "$HOST_KEY"},
        ),
        "lint": SkillConfig(
            name="lint",
            path="/opt/lint",
        ),
    }


# ---------------------------------------------------------------------------
# TestSkillsList
# ---------------------------------------------------------------------------


class TestSkillsList:
    """Tests for 'cast skills list'."""

    @patch("foundry_sandbox.commands.skills_cmd.load_skills_config", return_value={})
    def test_no_skills_configured(self, mock_load):
        result = runner.invoke(skills, ["list"])
        assert result.exit_code == 0
        assert "No skills configured" in result.output
        assert "cast skills init" in result.output

    @patch("foundry_sandbox.commands.skills_cmd.load_skills_config")
    def test_lists_skills(self, mock_load):
        mock_load.return_value = _sample_config()
        result = runner.invoke(skills, ["list"])
        assert result.exit_code == 0
        assert "research" in result.output
        assert "lint" in result.output
        assert "yes" in result.output  # research has MCP
        assert "no" in result.output   # lint has no MCP


# ---------------------------------------------------------------------------
# TestSkillsShow
# ---------------------------------------------------------------------------


class TestSkillsShow:
    """Tests for 'cast skills show <name>'."""

    @patch("foundry_sandbox.commands.skills_cmd.load_skills_config")
    def test_shows_skill_details(self, mock_load):
        mock_load.return_value = _sample_config()
        result = runner.invoke(skills, ["show", "research"])
        assert result.exit_code == 0
        assert "research" in result.output
        assert "~/GitHub/research-tool" in result.output
        assert "GUIDE.md" in result.output

    @patch("foundry_sandbox.commands.skills_cmd.load_skills_config")
    def test_skill_not_found(self, mock_load):
        mock_load.return_value = _sample_config()
        result = runner.invoke(skills, ["show", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output
        assert "research" in result.output  # suggests available


# ---------------------------------------------------------------------------
# TestSkillsInit
# ---------------------------------------------------------------------------


class TestSkillsInit:
    """Tests for 'cast skills init'."""

    @patch("foundry_sandbox.commands.skills_cmd._skills_toml_path")
    def test_creates_example_config(self, mock_path, tmp_path):
        toml_path = tmp_path / "skills.toml"
        mock_path.return_value = toml_path

        result = runner.invoke(skills, ["init"])
        assert result.exit_code == 0
        assert "Created example" in result.output
        assert toml_path.is_file()
        content = toml_path.read_text()
        assert "[skills]" in content

    @patch("foundry_sandbox.commands.skills_cmd._skills_toml_path")
    def test_skips_if_already_exists(self, mock_path, tmp_path):
        toml_path = tmp_path / "skills.toml"
        toml_path.write_text("[skills]\n")
        mock_path.return_value = toml_path

        result = runner.invoke(skills, ["init"])
        assert result.exit_code == 0
        assert "already exists" in result.output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
