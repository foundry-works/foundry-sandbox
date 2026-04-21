"""Unit tests for the diagnose command."""

import json
from unittest.mock import patch

from foundry_sandbox.commands.diagnose import _redact_secrets


class TestSecretRedaction:
    def test_redact_hmac_secret(self):
        secret_hex = "a" * 64
        text = f'hmac_secret="{secret_hex}"'
        result = _redact_secrets(text)
        assert secret_hex not in result
        assert "[REDACTED]" in result

    def test_redact_api_key(self):
        text = 'api_key="sk-abcdefghijklmnopqrstuvwxyz123456"'
        result = _redact_secrets(text)
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in result
        assert "[REDACTED]" in result

    def test_redact_github_token(self):
        text = 'token="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"'
        result = _redact_secrets(text)
        assert "ghp_" not in result
        assert "[REDACTED]" in result

    def test_no_redaction_on_normal_text(self):
        text = "Everything is fine"
        assert _redact_secrets(text) == text


class TestDiagnoseCommand:
    def test_diagnose_json_output(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose") as mock_sbx, \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health") as mock_health, \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}):
            mock_sbx.return_value = {"output": "sbx ok"}
            mock_health.return_value = {"reachable": False, "error": "not running"}

            result = runner.invoke(diagnose, ["--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "versions" in data
            assert "sbx_diagnose" in data
            assert "git_safety" in data

    def test_diagnose_text_output(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose") as mock_sbx, \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health") as mock_health, \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness") as mock_ready, \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}):
            mock_sbx.return_value = {"output": "sbx ok"}
            mock_health.return_value = {"status": "ok", "config_valid": True, "uptime_seconds": 42}
            mock_ready.return_value = {"ready": True, "checks": {"workspace": {"ok": True, "detail": "ok"}}}

            result = runner.invoke(diagnose, [])
            assert result.exit_code == 0
            assert "Versions" in result.output
            assert "Git Safety Server" in result.output

    def test_diagnose_server_down(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose") as mock_sbx, \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health") as mock_health, \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness") as mock_ready, \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}):
            mock_sbx.return_value = {"error": "sbx not found"}
            mock_health.return_value = {"reachable": False, "error": "Connection refused"}
            mock_ready.return_value = {"ready": False, "error": "Connection refused"}

            result = runner.invoke(diagnose, [])
            assert result.exit_code == 0
            assert "unreachable" in result.output


class TestTamperCounterDisplay:
    """Tests for the tamper counter in diagnose output."""

    def test_shows_server_counter_in_text_output(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose", return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health", return_value={"status": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness", return_value={"ready": True, "checks": {}}), \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_counter", return_value={"total": 5, "reachable": True}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_events", return_value=[]):
            result = runner.invoke(diagnose, [])
            assert result.exit_code == 0
            assert "Server counter: 5 total" in result.output

    def test_shows_unreachable_when_server_down(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose", return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health", return_value={"status": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness", return_value={"ready": True, "checks": {}}), \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_counter", return_value={"total": 0, "reachable": False}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_events", return_value=[]):
            result = runner.invoke(diagnose, [])
            assert result.exit_code == 0
            assert "Server counter: unreachable" in result.output

    def test_warns_on_degraded_log(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose", return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health", return_value={"status": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness", return_value={"ready": True, "checks": {}}), \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_counter", return_value={"total": 5, "reachable": True}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_events", return_value=[
                 {"timestamp": "2026-01-01", "sandbox": "sbx-1", "outcome": "reinjected"},
                 {"timestamp": "2026-01-02", "sandbox": "sbx-2", "outcome": "reinjected"},
             ]):
            result = runner.invoke(diagnose, [])
            assert result.exit_code == 0
            assert "WARNING" in result.output
            assert "3 event(s) not in decision log" in result.output

    def test_no_warning_when_counter_matches_log(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose", return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health", return_value={"status": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness", return_value={"ready": True, "checks": {}}), \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_counter", return_value={"total": 2, "reachable": True}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_events", return_value=[
                 {"timestamp": "2026-01-01", "sandbox": "sbx-1", "outcome": "reinjected"},
                 {"timestamp": "2026-01-02", "sandbox": "sbx-2", "outcome": "reinjected"},
             ]):
            result = runner.invoke(diagnose, [])
            assert result.exit_code == 0
            assert "WARNING" not in result.output

    def test_tamper_counter_in_json_output(self):
        from click.testing import CliRunner
        from foundry_sandbox.commands.diagnose import diagnose

        runner = CliRunner()
        with patch("foundry_sandbox.commands.diagnose._collect_sbx_diagnose", return_value={"output": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_health", return_value={"status": "ok"}), \
             patch("foundry_sandbox.commands.diagnose._collect_git_safety_readiness", return_value={"ready": True, "checks": {}}), \
             patch("foundry_sandbox.commands.diagnose._collect_isolation", return_value={"host_kernel": "", "sandboxes": []}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_counter", return_value={"total": 3, "reachable": True}), \
             patch("foundry_sandbox.commands.diagnose._collect_tamper_events", return_value=[]):
            result = runner.invoke(diagnose, ["--json"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["tamper_counter"]["total"] == 3
            assert data["tamper_counter"]["reachable"] is True
