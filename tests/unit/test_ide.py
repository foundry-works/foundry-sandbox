"""Tests for IDE config, resolver, and launcher."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from foundry_sandbox.foundry_config import (
    IdeConfig,
    FoundryConfig,
    _merge,
    load_user_ide_config,
)
from foundry_sandbox.ide import IdeSpec, resolve_ide, launch_ide


# ---------------------------------------------------------------------------
# IdeConfig model
# ---------------------------------------------------------------------------


class TestIdeConfig:
    def test_defaults(self):
        cfg = IdeConfig()
        assert cfg.preferred == ""
        assert cfg.args == []
        assert cfg.auto_open_on_attach is False

    def test_valid_config(self):
        cfg = IdeConfig(preferred="cursor", args=["--reuse-window"], auto_open_on_attach=True)
        assert cfg.preferred == "cursor"
        assert cfg.args == ["--reuse-window"]
        assert cfg.auto_open_on_attach is True

    def test_rejects_unknown_keys(self):
        with pytest.raises(Exception, match="Extra inputs are not permitted"):
            IdeConfig(preferred="cursor", unknown=True)

    def test_foundry_config_accepts_ide(self):
        cfg = FoundryConfig(version="1", ide=IdeConfig(preferred="zed"))
        assert cfg.ide is not None
        assert cfg.ide.preferred == "zed"

    def test_foundry_config_ide_defaults_to_none(self):
        cfg = FoundryConfig(version="1")
        assert cfg.ide is None


# ---------------------------------------------------------------------------
# Repo ide: ignored with warning
# ---------------------------------------------------------------------------


class TestRepoIdeIgnored:
    def test_repo_ide_stripped_on_resolve(self, tmp_path, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            repo_file = tmp_path / "foundry.yaml"
            repo_file.write_text(
                'version: "1"\nide:\n  preferred: cursor\n'
            )
            from foundry_sandbox.foundry_config import resolve_foundry_config
            config = resolve_foundry_config(tmp_path)
        assert config.ide is None
        assert "user-only" in caplog.text.lower() or "ide" in caplog.text.lower()

    def test_merge_takes_user_ide_not_repo(self):
        user = FoundryConfig(version="1", ide=IdeConfig(preferred="cursor"))
        repo = FoundryConfig(version="1", ide=IdeConfig(preferred="zed"))
        # Normally repo.ide is stripped before merge, but verify merge logic
        merged = _merge([user, repo])
        assert merged.ide is not None
        assert merged.ide.preferred == "zed"  # last non-None wins

    def test_merge_user_ide_preserved_without_repo(self):
        user = FoundryConfig(version="1", ide=IdeConfig(preferred="cursor"))
        merged = _merge([FoundryConfig(version="1"), user])
        assert merged.ide is not None
        assert merged.ide.preferred == "cursor"


# ---------------------------------------------------------------------------
# load_user_ide_config
# ---------------------------------------------------------------------------


class TestLoadUserIdeConfig:
    def test_returns_none_when_no_file(self, tmp_path):
        with patch("foundry_sandbox.foundry_config._USER_CONFIG_PATH", tmp_path / "foundry.yaml"):
            assert load_user_ide_config() is None

    def test_returns_config_when_present(self, tmp_path):
        config_file = tmp_path / "foundry.yaml"
        config_file.write_text('version: "1"\nide:\n  preferred: code\n  args: ["--new-window"]\n')
        with patch("foundry_sandbox.foundry_config._USER_CONFIG_PATH", config_file):
            result = load_user_ide_config()
        assert result is not None
        assert result.preferred == "code"
        assert result.args == ["--new-window"]

    def test_returns_none_when_no_ide_section(self, tmp_path):
        config_file = tmp_path / "foundry.yaml"
        config_file.write_text('version: "1"\n')
        with patch("foundry_sandbox.foundry_config._USER_CONFIG_PATH", config_file):
            assert load_user_ide_config() is None


# ---------------------------------------------------------------------------
# resolve_ide
# ---------------------------------------------------------------------------


class TestResolveIde:
    def test_empty_returns_none(self):
        assert resolve_ide("") is None

    @patch("shutil.which", return_value="/usr/bin/code")
    def test_alias_resolves(self, mock_which):
        spec = resolve_ide("code")
        assert spec is not None
        assert spec.kind == "alias"
        assert spec.name == "code"
        assert spec.display == "VS Code"
        assert spec.executable == "/usr/bin/code"

    @patch("shutil.which", return_value=None)
    def test_alias_without_executable_still_resolves(self, mock_which):
        spec = resolve_ide("cursor")
        assert spec is not None
        assert spec.kind == "alias"
        assert spec.name == "cursor"
        assert spec.executable == "cursor"  # falls back to bare name

    @patch("shutil.which", return_value="/usr/local/bin/my-editor")
    def test_bare_command_resolves(self, mock_which):
        spec = resolve_ide("my-editor")
        assert spec is not None
        assert spec.kind == "command"
        assert spec.name == "my-editor"
        assert spec.executable == "/usr/local/bin/my-editor"

    @patch("shutil.which", return_value=None)
    def test_unknown_command_returns_none(self, mock_which):
        assert resolve_ide("nonexistent-editor-xyz") is None

    def test_explicit_path_resolves(self, tmp_path):
        exe = tmp_path / "my-ide"
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
        spec = resolve_ide(str(exe))
        assert spec is not None
        assert spec.kind == "path"
        assert spec.name == "my-ide"

    def test_non_executable_path_returns_none(self, tmp_path):
        exe = tmp_path / "my-ide"
        exe.write_text("not executable")
        exe.chmod(0o644)
        assert resolve_ide(str(exe)) is None

    def test_nonexistent_path_returns_none(self, tmp_path):
        assert resolve_ide(str(tmp_path / "nope")) is None


# ---------------------------------------------------------------------------
# launch_ide
# ---------------------------------------------------------------------------


class TestLaunchIde:
    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    def test_launch_with_extra_args(self, mock_cli):
        spec = IdeSpec(kind="command", name="code", display="VS Code", executable="/usr/bin/code")
        result = launch_ide(spec, "/some/path", ["--reuse-window"])
        assert result is True
        call_args = mock_cli.call_args[0]
        assert "--reuse-window" in call_args[2]  # extra_args parameter

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=False)
    @patch("foundry_sandbox.ide._try_macos_open", return_value=False)
    def test_launch_failure_returns_false(self, mock_macos, mock_cli):
        spec = IdeSpec(kind="command", name="code", display="VS Code", executable="/usr/bin/code")
        result = launch_ide(spec, "/some/path")
        assert result is False

    @patch("foundry_sandbox.ide._launch_via_cli", return_value=True)
    def test_launch_no_args(self, mock_cli):
        spec = IdeSpec(kind="command", name="code", display="VS Code", executable="/usr/bin/code")
        result = launch_ide(spec, "/some/path")
        assert result is True
        call_args = mock_cli.call_args[0]
        assert call_args[2] == []  # extra_args is empty list
