"""Tests for cast template CLI commands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.template_cmd import template
from foundry_sandbox.template_cache import TemplateCacheEntry


def _entry(name: str = "work", key: str = "abc123") -> TemplateCacheEntry:
    return TemplateCacheEntry(
        profile_name=name,
        cache_key=key,
        template_tag=f"profile-{name}-{key}:latest",
        base_template="foundry-git-wrapper:latest",
        built_at="2026-04-23T14:30:00+00:00",
        sbx_version="0.26.1",
        cast_version="1.5.0",
        bakeable_inputs={"packages": {"pip": ["ruff"]}, "tooling": ["github"]},
    )


class TestTemplateList:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("foundry_sandbox.template_cache.list_cached_templates")
    def test_empty(self, mock_list):
        mock_list.return_value = []
        result = self.runner.invoke(template, ["list"])
        assert result.exit_code == 0
        assert "No cached profile templates" in result.output

    @patch("foundry_sandbox.template_cache.list_cached_templates")
    def test_with_entries(self, mock_list):
        mock_list.return_value = [_entry("work", "abc123"), _entry("python", "def456")]
        result = self.runner.invoke(template, ["list"])
        assert result.exit_code == 0
        assert "work" in result.output
        assert "python" in result.output

    @patch("foundry_sandbox.template_cache.list_cached_templates")
    def test_default_invocation_lists(self, mock_list):
        """Running `cast template` with no subcommand should list."""
        mock_list.return_value = []
        result = self.runner.invoke(template, [])
        assert result.exit_code == 0
        assert "No cached profile templates" in result.output


class TestTemplateShow:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("foundry_sandbox.template_cache._read_cache_entry")
    def test_show_existing(self, mock_read):
        mock_read.return_value = _entry()
        result = self.runner.invoke(template, ["show", "work"])
        assert result.exit_code == 0
        assert "profile-work-abc123:latest" in result.output
        assert "foundry-git-wrapper:latest" in result.output

    @patch("foundry_sandbox.template_cache._read_cache_entry")
    def test_show_missing(self, mock_read):
        mock_read.return_value = None
        result = self.runner.invoke(template, ["show", "missing"])
        assert result.exit_code == 1
        assert "No cached template" in result.output


class TestTemplateRm:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("foundry_sandbox.template_cache.invalidate_cached_template")
    def test_rm_existing(self, mock_inv):
        mock_inv.return_value = True
        result = self.runner.invoke(template, ["rm", "work"])
        assert result.exit_code == 0
        assert "Removed" in result.output

    @patch("foundry_sandbox.template_cache.invalidate_cached_template")
    def test_rm_missing(self, mock_inv):
        mock_inv.return_value = False
        result = self.runner.invoke(template, ["rm", "work"])
        assert result.exit_code == 0
        assert "No cached template found" in result.output


class TestTemplateRebuild:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("foundry_sandbox.template_cache.build_profile_template")
    @patch("foundry_sandbox.template_cache.invalidate_cached_template")
    @patch("foundry_sandbox.foundry_config.resolve_profile")
    @patch("foundry_sandbox.foundry_config.resolve_foundry_config")
    @patch("foundry_sandbox.sbx.sbx_check_available")
    def test_rebuild(
        self, mock_sbx, mock_config, mock_profile, mock_inv, mock_build,
    ):
        prof = MagicMock()
        prof.template = None
        mock_profile.return_value = prof
        mock_config.return_value = MagicMock()
        mock_build.return_value = "profile-work-abc123:latest"

        result = self.runner.invoke(template, ["rebuild", "work"])
        assert result.exit_code == 0
        mock_inv.assert_called_once_with("work")
        mock_build.assert_called_once()
        assert "Built: profile-work-abc123:latest" in result.output

    @patch("foundry_sandbox.foundry_config.resolve_profile")
    @patch("foundry_sandbox.foundry_config.resolve_foundry_config")
    @patch("foundry_sandbox.sbx.sbx_check_available")
    def test_rebuild_unknown_profile(self, mock_sbx, mock_config, mock_profile):
        mock_profile.side_effect = ValueError("Unknown profile 'missing'")
        mock_config.return_value = MagicMock()

        result = self.runner.invoke(template, ["rebuild", "missing"])
        assert result.exit_code == 1
