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
