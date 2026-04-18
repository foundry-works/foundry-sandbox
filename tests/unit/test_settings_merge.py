"""Unit tests for foundry_sandbox.settings_merge.

Tests merge success/failure, host-side merge logic,
credential key stripping, and temp file cleanup.
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.settings_merge import (
    merge_claude_settings_in_container,
    merge_claude_settings_safe,
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


# ---------------------------------------------------------------------------
# TestMergeInContainer
# ---------------------------------------------------------------------------


class TestMergeInContainer:
    """merge_claude_settings_in_container reads, merges on host, writes back."""

    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    @patch("foundry_sandbox.settings_merge.subprocess.run")
    def test_returns_true_on_success(self, mock_run, mock_cpf, tmp_path):
        # Create a host settings file
        host = tmp_path / "host.json"
        host.write_text(json.dumps({"theme": "dark"}))

        # docker exec cat returns container settings
        mock_run.return_value = _completed(stdout='{"model": "opus"}')

        assert merge_claude_settings_in_container("c1", str(host)) is True
        # copy_file_to_container called to write merged result back
        assert mock_cpf.call_count == 1

    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    @patch("foundry_sandbox.settings_merge.subprocess.run")
    def test_returns_true_when_container_settings_missing(self, mock_run, mock_cpf, tmp_path):
        host = tmp_path / "host.json"
        host.write_text(json.dumps({"theme": "dark"}))

        # cat fails (file doesn't exist in container) — merge starts from {}
        mock_run.return_value = _completed(returncode=1)

        assert merge_claude_settings_in_container("c1", str(host)) is True
        assert mock_cpf.call_count == 1

    @patch("foundry_sandbox.settings_merge.copy_file_to_container",
           side_effect=OSError("copy failed"))
    @patch("foundry_sandbox.settings_merge.subprocess.run")
    def test_returns_false_on_copy_back_failure(self, mock_run, mock_cpf, tmp_path):
        host = tmp_path / "host.json"
        host.write_text(json.dumps({"theme": "dark"}))

        mock_run.return_value = _completed(stdout='{}')

        assert merge_claude_settings_in_container("c1", str(host)) is False

    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    @patch("foundry_sandbox.settings_merge.subprocess.run")
    def test_temp_file_cleaned_up(self, mock_run, mock_cpf, tmp_path):
        host = tmp_path / "host.json"
        host.write_text(json.dumps({"theme": "dark"}))

        mock_run.return_value = _completed(stdout='{}')
        merge_claude_settings_in_container("c1", str(host))

        # No stale temp files
        temps = list(tmp_path.glob("container-settings-*"))
        assert len(temps) == 0

    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    @patch("foundry_sandbox.settings_merge.subprocess.run")
    def test_preserves_container_model_and_hooks(self, mock_run, mock_cpf, tmp_path):
        host = tmp_path / "host.json"
        host.write_text(json.dumps({"theme": "dark", "model": "haiku"}))

        container_settings = {"model": "opus", "hooks": {"pre": "echo hi"}}
        mock_run.return_value = _completed(stdout=json.dumps(container_settings))

        captured = {}

        def capture_copy(cid, src, dst):
            with open(src) as f:
                captured.update(json.load(f))

        mock_cpf.side_effect = capture_copy

        merge_claude_settings_in_container("c1", str(host))

        # Container's model and hooks should be preserved over host values
        assert captured["model"] == "opus"
        assert captured["hooks"] == {"pre": "echo hi"}
        assert captured["theme"] == "dark"


# ---------------------------------------------------------------------------
# TestMergeSafe
# ---------------------------------------------------------------------------


class TestMergeSafe:
    """merge_claude_settings_safe strips credentials and delegates."""

    def test_strips_credential_keys(self, tmp_path):
        settings = tmp_path / "settings.json"
        settings.write_text(json.dumps({
            "theme": "dark",
            "env": {"ANTHROPIC_API_KEY": "sk-secret"},
            "mcpServers": {"s1": {}},
            "oauthTokens": {"t": "abc"},
            "apiKey": "sk-123",
        }))

        captured = {}

        def capture_merge(container_id, path):
            with open(path) as f:
                captured.update(json.load(f))
            return True

        with patch("foundry_sandbox.settings_merge.merge_claude_settings_in_container",
                    side_effect=capture_merge):
            result = merge_claude_settings_safe("c1", str(settings))

        assert result is True
        assert "env" not in captured
        assert "mcpServers" not in captured
        assert "oauthTokens" not in captured
        assert "apiKey" not in captured
        assert captured["theme"] == "dark"

    def test_returns_false_on_missing_file(self):
        result = merge_claude_settings_safe("c1", "/nonexistent/settings.json")
        assert result is False

    def test_returns_false_on_invalid_json(self, tmp_path):
        settings = tmp_path / "settings.json"
        settings.write_text("not json {{{")
        result = merge_claude_settings_safe("c1", str(settings))
        assert result is False

    def test_temp_file_cleanup_on_success(self, tmp_path):
        settings = tmp_path / "settings.json"
        settings.write_text(json.dumps({"theme": "dark"}))

        with patch("foundry_sandbox.settings_merge.merge_claude_settings_in_container",
                    return_value=True):
            merge_claude_settings_safe("c1", str(settings))

        # No stale temp files
        temps = list(tmp_path.glob("settings-safe-*"))
        assert len(temps) == 0

    def test_temp_file_cleanup_on_failure(self, tmp_path):
        settings = tmp_path / "settings.json"
        settings.write_text(json.dumps({"theme": "dark"}))

        with patch("foundry_sandbox.settings_merge.merge_claude_settings_in_container",
                    side_effect=RuntimeError("fail")):
            with pytest.raises(RuntimeError):
                merge_claude_settings_safe("c1", str(settings))

        temps = list(tmp_path.glob("settings-safe-*"))
        assert len(temps) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
