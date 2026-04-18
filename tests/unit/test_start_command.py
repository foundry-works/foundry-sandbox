"""Unit tests for metadata flag parsing in `foundry_sandbox.commands.start`."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.start import _export_feature_flags, _flag_enabled, start


def test_flag_enabled_accepts_common_true_values() -> None:
    assert _flag_enabled(True) is True
    assert _flag_enabled(1) is True
    assert _flag_enabled("1") is True
    assert _flag_enabled("true") is True
    assert _flag_enabled(" yes ") is True


def test_flag_enabled_rejects_common_false_values() -> None:
    assert _flag_enabled(False) is False
    assert _flag_enabled(0) is False
    assert _flag_enabled("0") is False
    assert _flag_enabled("false") is False
    assert _flag_enabled("") is False
    assert _flag_enabled(None) is False


def test_export_feature_flags_normalizes_env_values(monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
    monkeypatch.delenv("SANDBOX_ENABLE_ZAI", raising=False)

    env: dict[str, str] = {}
    enable_opencode, enable_zai = _export_feature_flags(
        {"enable_opencode": True, "enable_zai": 0}, env
    )

    assert enable_opencode is True
    assert enable_zai is False
    assert env["SANDBOX_ENABLE_OPENCODE"] == "1"
    assert env["SANDBOX_ENABLE_ZAI"] == "0"


@patch("foundry_sandbox.commands.start.ensure_bare_repo")
@patch("foundry_sandbox.commands.start.repo_url_to_bare_path", return_value="/fake/bare/path")
@patch("foundry_sandbox.commands.start._finalize_container")
@patch("foundry_sandbox.commands.start.setup_proxy_registration")
@patch("foundry_sandbox.commands.start.compose_up")
@patch("foundry_sandbox.commands.start.add_timezone_to_override")
@patch("foundry_sandbox.commands.start.add_claude_home_to_override")
@patch("foundry_sandbox.commands.start.prepopulate_foundry_global")
@patch("foundry_sandbox.commands.start.ensure_override_from_metadata")
@patch("foundry_sandbox.commands.start._setup_ssh_forwarding", return_value=False)
@patch("foundry_sandbox.commands.start.api_keys")
@patch("foundry_sandbox.commands.start._uses_credential_isolation", return_value=False)
@patch("foundry_sandbox.commands.start.load_sandbox_metadata")
@patch("foundry_sandbox.commands.start.check_image_freshness", return_value=False)
@patch("foundry_sandbox.commands.start.derive_sandbox_paths")
@patch("foundry_sandbox.commands.start.validate_existing_sandbox_name", return_value=(True, ""))
def test_start_refreshes_bare_repo(
    _mock_validate,
    mock_paths,
    _mock_freshness,
    mock_load_meta,
    _mock_isolation,
    mock_api_keys,
    _mock_ssh,
    _mock_override,
    _mock_foundry,
    _mock_claude_home,
    _mock_tz,
    _mock_compose,
    _mock_proxy,
    _mock_finalize,
    mock_bare_path,
    mock_ensure_bare,
    tmp_path,
) -> None:
    """ensure_bare_repo is called during start when repo_url is set."""
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    paths_obj = MagicMock()
    paths_obj.worktree_path = worktree
    paths_obj.container_name = "test-container"
    paths_obj.claude_config_path = tmp_path / "claude"
    paths_obj.override_file = tmp_path / "override.yml"
    mock_paths.return_value = paths_obj

    mock_load_meta.return_value = {"repo_url": "https://github.com/org/repo.git"}
    mock_api_keys.export_gh_token.return_value = ""

    runner = CliRunner()
    result = runner.invoke(start, ["my-sandbox"], catch_exceptions=False)

    assert result.exit_code == 0
    mock_bare_path.assert_called_once_with("https://github.com/org/repo.git")
    mock_ensure_bare.assert_called_once_with("https://github.com/org/repo.git", "/fake/bare/path")


@patch("foundry_sandbox.commands.start.ensure_bare_repo")
@patch("foundry_sandbox.commands.start._finalize_container")
@patch("foundry_sandbox.commands.start.compose_up")
@patch("foundry_sandbox.commands.start.add_timezone_to_override")
@patch("foundry_sandbox.commands.start.add_claude_home_to_override")
@patch("foundry_sandbox.commands.start.prepopulate_foundry_global")
@patch("foundry_sandbox.commands.start.ensure_override_from_metadata")
@patch("foundry_sandbox.commands.start._setup_ssh_forwarding", return_value=False)
@patch("foundry_sandbox.commands.start.api_keys")
@patch("foundry_sandbox.commands.start._uses_credential_isolation", return_value=False)
@patch("foundry_sandbox.commands.start.load_sandbox_metadata")
@patch("foundry_sandbox.commands.start.check_image_freshness", return_value=False)
@patch("foundry_sandbox.commands.start.derive_sandbox_paths")
@patch("foundry_sandbox.commands.start.validate_existing_sandbox_name", return_value=(True, ""))
def test_start_skips_bare_repo_refresh_when_no_repo_url(
    _mock_validate,
    mock_paths,
    _mock_freshness,
    mock_load_meta,
    _mock_isolation,
    mock_api_keys,
    _mock_ssh,
    _mock_override,
    _mock_foundry,
    _mock_claude_home,
    _mock_tz,
    _mock_compose,
    _mock_finalize,
    mock_ensure_bare,
    tmp_path,
) -> None:
    """ensure_bare_repo is NOT called when repo_url is empty."""
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    paths_obj = MagicMock()
    paths_obj.worktree_path = worktree
    paths_obj.container_name = "test-container"
    paths_obj.claude_config_path = tmp_path / "claude"
    paths_obj.override_file = tmp_path / "override.yml"
    mock_paths.return_value = paths_obj

    mock_load_meta.return_value = {"repo_url": ""}
    mock_api_keys.export_gh_token.return_value = ""

    runner = CliRunner()
    result = runner.invoke(start, ["my-sandbox"], catch_exceptions=False)

    assert result.exit_code == 0
    mock_ensure_bare.assert_not_called()
