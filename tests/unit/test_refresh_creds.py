"""Tests for the ``cast refresh-creds`` command."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from foundry_sandbox.commands.refresh_creds import refresh_creds, _refresh_one


class TestRefreshOne:
    @patch("foundry_sandbox.commands.refresh_creds.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.refresh_creds.sbx_secret_set")
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_success(self, mock_validate, mock_set, mock_running):
        mock_validate.return_value = (True, "")
        mock_set.return_value = None
        result = _refresh_one("my-sandbox")
        assert result is True

    @patch("foundry_sandbox.commands.refresh_creds.sbx_is_running", return_value=False)
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_not_running(self, mock_validate, mock_running):
        mock_validate.return_value = (True, "")
        result = _refresh_one("my-sandbox")
        assert result is False

    @patch("foundry_sandbox.foundry_config.collect_secret_refs")
    @patch("foundry_sandbox.foundry_config.resolve_foundry_config")
    @patch("foundry_sandbox.commands.refresh_creds.load_sandbox_metadata")
    @patch("foundry_sandbox.commands.refresh_creds.sbx_is_running", return_value=True)
    @patch("foundry_sandbox.commands.refresh_creds.sbx_secret_set")
    @patch("foundry_sandbox.commands.refresh_creds.validate_existing_sandbox_name")
    def test_pushes_foundry_config_secret_refs(
        self,
        mock_validate,
        mock_set,
        mock_running,
        mock_metadata,
        mock_resolve,
        mock_collect,
    ):
        mock_validate.return_value = (True, "")
        mock_set.return_value = None
        mock_metadata.return_value = {"host_worktree_path": "/tmp/worktree"}
        mock_resolve.return_value = object()
        mock_collect.return_value = [
            ("tavily", "TAVILY_API_KEY"),
            ("internal-api", "INTERNAL_API_KEY"),
        ]

        with patch.dict(
            "os.environ",
            {
                "TAVILY_API_KEY": "tvly-secret",
                "INTERNAL_API_KEY": "svc-secret",
            },
            clear=True,
        ):
            result = _refresh_one("my-sandbox")

        assert result is True
        mock_resolve.assert_called_once()
        mock_collect.assert_called_once()
        mock_set.assert_any_call("tavily", "tvly-secret", global_scope=True)
        mock_set.assert_any_call("internal-api", "svc-secret", global_scope=True)


class TestRefreshCredsCommand:
    @patch("foundry_sandbox.commands.refresh_creds.sbx_check_available")
    @patch("foundry_sandbox.commands.refresh_creds._refresh_one", return_value=True)
    def test_explicit_name(self, mock_refresh, mock_check):
        runner = CliRunner()
        result = runner.invoke(refresh_creds, ["my-sandbox"])
        assert result.exit_code == 0
        mock_refresh.assert_called_once_with("my-sandbox")

    @patch("foundry_sandbox.commands.refresh_creds.sbx_check_available")
    @patch("foundry_sandbox.state.load_last_attach", return_value="last-sandbox")
    @patch("foundry_sandbox.commands._helpers.validate_existing_sandbox_name", return_value=(True, ""))
    @patch("foundry_sandbox.commands.refresh_creds._refresh_one", return_value=True)
    def test_last_flag(self, mock_refresh, mock_validate, mock_last, mock_check):
        runner = CliRunner()
        result = runner.invoke(refresh_creds, ["--last"])
        assert result.exit_code == 0
        mock_refresh.assert_called_once_with("last-sandbox")

    @patch("foundry_sandbox.commands.refresh_creds.sbx_check_available")
    @patch("foundry_sandbox.commands.refresh_creds._refresh_one", return_value=False)
    def test_failure_exits(self, mock_refresh, mock_check):
        runner = CliRunner()
        result = runner.invoke(refresh_creds, ["my-sandbox"])
        assert result.exit_code == 1
