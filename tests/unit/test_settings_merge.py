"""Unit tests for foundry_sandbox.settings_merge.

Tests merge success/failure, subprocess return code handling,
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
    """merge_claude_settings_in_container delegates to docker exec."""

    @patch("foundry_sandbox.settings_merge.subprocess.run")
    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    def test_returns_true_on_success(self, mock_cpf, mock_run):
        mock_run.return_value = _completed(returncode=0)
        assert merge_claude_settings_in_container("c1", "/host/s.json") is True

    @patch("foundry_sandbox.settings_merge.subprocess.run")
    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    def test_returns_false_on_nonzero_exit(self, mock_cpf, mock_run):
        mock_run.side_effect = [
            _completed(returncode=1),  # merge fails
            _completed(),  # cleanup
        ]
        assert merge_claude_settings_in_container("c1", "/host/s.json") is False

    @patch("foundry_sandbox.settings_merge.copy_file_to_container",
           side_effect=OSError("copy failed"))
    def test_returns_false_on_copy_failure(self, mock_cpf):
        assert merge_claude_settings_in_container("c1", "/host/s.json") is False

    @patch("foundry_sandbox.settings_merge.subprocess.run")
    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    def test_cleanup_called_on_success(self, mock_cpf, mock_run):
        mock_run.return_value = _completed(returncode=0)
        merge_claude_settings_in_container("c1", "/host/s.json")
        # Should have 2 subprocess.run calls: merge + cleanup
        assert mock_run.call_count == 2

    @patch("foundry_sandbox.settings_merge.subprocess.run")
    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    def test_cleanup_called_on_failure(self, mock_cpf, mock_run):
        mock_run.side_effect = [
            _completed(returncode=1),  # merge fails
            _completed(),  # cleanup
        ]
        merge_claude_settings_in_container("c1", "/host/s.json")
        # Should still cleanup on failure
        assert mock_run.call_count == 2


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
