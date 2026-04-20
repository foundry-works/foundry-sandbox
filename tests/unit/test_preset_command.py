"""Tests for cast preset save and managed-template cleanup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from foundry_sandbox.commands.preset import (
    _managed_tag_for_preset,
    preset,
)


# ============================================================================
# _managed_tag_for_preset
# ============================================================================


class TestManagedTagForPreset:
    def test_simple_name(self):
        assert _managed_tag_for_preset("mysetup") == "preset-mysetup:latest"

    def test_name_with_spaces(self):
        assert _managed_tag_for_preset("my setup") == "preset-my-setup:latest"

    def test_name_with_special_chars(self):
        tag = _managed_tag_for_preset("hello@world#123")
        assert tag == "preset-hello-world-123:latest"

    def test_name_with_dots(self):
        tag = _managed_tag_for_preset("v2.0")
        assert tag == "preset-v2.0:latest"

    def test_invalid_name_raises(self):
        with pytest.raises(ValueError, match="Cannot derive"):
            _managed_tag_for_preset("!!!")


# ============================================================================
# cast preset save
# ============================================================================


class TestPresetSave:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("foundry_sandbox.commands.preset.sbx_template_save")
    @patch("foundry_sandbox.commands.preset.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.preset.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.preset.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.preset.save_cast_preset")
    def test_save_with_explicit_sandbox(
        self, mock_save, mock_meta, mock_exists, mock_running, mock_tpl_save,
    ):
        mock_meta.return_value = {
            "repo_url": "https://github.com/org/repo",
            "agent": "claude",
            "branch": "main",
            "from_branch": "",
            "working_dir": "",
            "pip_requirements": "",
            "allow_pr": False,
            "network_profile": "balanced",
            "enable_opencode": False,
            "enable_zai": False,
            "copies": [],
        }
        mock_tpl_save.return_value = MagicMock(returncode=0)

        result = self.runner.invoke(preset, ["save", "mysetup", "--sandbox", "test-sandbox"])
        assert result.exit_code == 0
        assert "Saved preset 'mysetup'" in result.output
        mock_tpl_save.assert_called_once_with("test-sandbox", "preset-mysetup:latest")
        mock_save.assert_called_once()
        call_kwargs = mock_save.call_args
        assert call_kwargs[1]["template"] == "preset-mysetup:latest"
        assert call_kwargs[1]["template_managed"] is True

    @patch("foundry_sandbox.commands.preset.sbx_template_save")
    @patch("foundry_sandbox.commands._helpers.auto_detect_sandbox", return_value="auto-sandbox")
    @patch("foundry_sandbox.commands.preset.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.preset.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.preset.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.preset.save_cast_preset")
    def test_save_auto_detects_sandbox(
        self, mock_save, mock_meta, mock_exists, mock_running, mock_detect, mock_tpl_save,
    ):
        mock_meta.return_value = {
            "repo_url": "https://github.com/org/repo",
            "agent": "claude",
            "branch": "main",
        }
        mock_tpl_save.return_value = MagicMock(returncode=0)

        result = self.runner.invoke(preset, ["save", "mysetup"])
        assert result.exit_code == 0
        mock_detect.assert_called_once()

    @patch("foundry_sandbox.commands.preset.sbx_sandbox_exists", return_value=False)
    def test_save_fails_when_sandbox_missing(self, mock_exists):
        result = self.runner.invoke(preset, ["save", "mysetup", "--sandbox", "missing"])
        assert result.exit_code != 0
        assert "not found" in result.output

    @patch("foundry_sandbox.commands.preset.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.preset.sbx_is_running", return_value=False)
    def test_save_fails_when_sandbox_stopped(self, mock_running, mock_exists):
        result = self.runner.invoke(preset, ["save", "mysetup", "--sandbox", "stopped"])
        assert result.exit_code != 0
        assert "not running" in result.output

    @patch("foundry_sandbox.commands.preset.sbx_template_save")
    @patch("foundry_sandbox.commands.preset.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.preset.sbx_sandbox_exists", return_value=True)
    @patch("foundry_sandbox.commands.preset.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.preset.save_cast_preset")
    def test_save_fails_when_template_snapshot_fails(
        self, mock_save, mock_meta, mock_exists, mock_running, mock_tpl_save,
    ):
        mock_meta.return_value = {"repo_url": "u", "agent": "claude", "branch": "b"}
        mock_tpl_save.return_value = MagicMock(returncode=1, stderr="template save error")

        result = self.runner.invoke(preset, ["save", "mysetup", "--sandbox", "test"])
        assert result.exit_code != 0
        assert "Failed to save template" in result.output
        mock_save.assert_not_called()


# ============================================================================
# Managed template cleanup on delete
# ============================================================================


class TestPresetDeleteCleanup:
    def setup_method(self):
        self.runner = CliRunner()

    @patch("foundry_sandbox.commands.preset.sbx_template_rm")
    @patch("foundry_sandbox.commands.preset.load_cast_preset")
    @patch("foundry_sandbox.commands.preset.list_cast_presets", return_value=[])
    @patch("foundry_sandbox.commands.preset.delete_cast_preset", return_value=True)
    def test_delete_cleans_managed_template(
        self, mock_del, mock_list, mock_load, mock_rm,
    ):
        mock_load.return_value = {
            "template": "preset-mysetup:latest",
            "template_managed": True,
        }
        mock_rm.return_value = MagicMock(returncode=0)

        result = self.runner.invoke(preset, ["delete", "mysetup"])
        assert result.exit_code == 0
        assert "Deleted preset: mysetup" in result.output
        mock_rm.assert_called_once_with("preset-mysetup:latest")

    @patch("foundry_sandbox.commands.preset.sbx_template_rm")
    @patch("foundry_sandbox.commands.preset.load_cast_preset")
    @patch("foundry_sandbox.commands.preset.list_cast_presets", return_value=[])
    @patch("foundry_sandbox.commands.preset.delete_cast_preset", return_value=True)
    def test_delete_does_not_remove_non_managed_templates(
        self, mock_del, mock_list, mock_load, mock_rm,
    ):
        mock_load.return_value = {
            "template": "foundry-git-wrapper:latest",
            "template_managed": False,
        }

        result = self.runner.invoke(preset, ["delete", "mysetup"])
        assert result.exit_code == 0
        mock_rm.assert_not_called()

    @patch("foundry_sandbox.commands.preset.sbx_template_rm")
    @patch("foundry_sandbox.commands.preset.load_cast_preset")
    @patch("foundry_sandbox.commands.preset.list_cast_presets", return_value=["other-preset"])
    @patch("foundry_sandbox.commands.preset.delete_cast_preset", return_value=True)
    def test_delete_keeps_template_if_other_preset_references_it(
        self, mock_del, mock_list, mock_load, mock_rm,
    ):
        mock_load.side_effect = [
            {"template": "preset-shared:latest", "template_managed": True},
            {"template": "preset-shared:latest", "template_managed": True},
        ]

        result = self.runner.invoke(preset, ["delete", "mysetup"])
        assert result.exit_code == 0
        mock_rm.assert_not_called()

    @patch("foundry_sandbox.commands.preset.sbx_template_rm")
    @patch("foundry_sandbox.commands.preset.load_cast_preset")
    @patch("foundry_sandbox.commands.preset.list_cast_presets", return_value=[])
    @patch("foundry_sandbox.commands.preset.delete_cast_preset", return_value=True)
    def test_delete_warns_but_succeeds_on_template_rm_failure(
        self, mock_del, mock_list, mock_load, mock_rm,
    ):
        mock_load.return_value = {
            "template": "preset-mysetup:latest",
            "template_managed": True,
        }
        mock_rm.return_value = MagicMock(returncode=1, stderr="rm failed")

        result = self.runner.invoke(preset, ["delete", "mysetup"])
        assert result.exit_code == 0
        assert "Deleted preset: mysetup" in result.output


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
