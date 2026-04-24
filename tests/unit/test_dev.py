"""Tests for the cast dev command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foundry_sandbox.commands.dev import dev


# Common mocks for the full create+attach path (bottom-up decorator order).
# All patches target the module that *uses* the import (dev.py).
_CREATE_MOCKS = [
    patch("foundry_sandbox.commands.attach.sbx_exec_streaming"),
    patch("foundry_sandbox.commands.dev.sbx_is_running", return_value=True),
    patch("foundry_sandbox.commands.dev.sbx_check_available"),
    patch("foundry_sandbox.ide._launch_via_cli", return_value=True),
    patch("foundry_sandbox.ide._try_macos_open", return_value=False),
    patch("foundry_sandbox.commands.dev.resolve_host_worktree_path"),
    patch("foundry_sandbox.foundry_config.load_user_ide_config"),
    patch("foundry_sandbox.commands.dev.resolve_foundry_config"),
    patch("foundry_sandbox.commands.dev.resolve_profile"),
    patch("foundry_sandbox.commands.dev.new_sbx_setup"),
    patch("foundry_sandbox.commands.dev._validate_preconditions"),
    patch("foundry_sandbox.commands.dev._generate_branch_name", return_value="user/repo-20260423-1200"),
    patch("foundry_sandbox.commands.dev._detect_remote_default_branch", return_value="main"),
    patch("foundry_sandbox.commands.dev._branch_exists_on_remote", return_value=True),
    patch("foundry_sandbox.commands.dev._resolve_repo_input"),
    patch("foundry_sandbox.commands.dev.find_sandbox_by_profile", return_value=None),
    patch("foundry_sandbox.commands.dev.validate_sandbox_name", return_value=(True, "")),
    patch("foundry_sandbox.commands.dev.repo_name_from_url", return_value="repo"),
    patch("foundry_sandbox.commands.dev._helpers_sandbox_name", return_value="test-sbx"),
    patch("foundry_sandbox.commands.dev.os.makedirs"),
    patch("foundry_sandbox.state.patch_sandbox_metadata"),
    patch("foundry_sandbox.commands.dev.save_last_cast_new"),
    patch("foundry_sandbox.commands.dev.save_last_attach"),
    patch("shutil.which", return_value="/usr/bin/code"),
    patch("foundry_sandbox.state.load_last_ide", return_value=None),
]


def _apply_mocks(func):
    """Apply common mocks to a test method."""
    for mock in reversed(_CREATE_MOCKS):
        func = mock(func)
    return func


def _setup_repo_and_worktree(mock_resolve, mock_worktree, mock_setup):
    """Set up standard repo resolution and sandbox creation mocks."""
    mock_resolve.return_value = (
        "https://github.com/org/repo",
        "/fake/repo",
        "https://github.com/org/repo",
        "main",
    )
    mock_workspace = MagicMock()
    mock_workspace.is_dir.return_value = True
    mock_workspace.__str__ = lambda self: "/fake/worktree"
    mock_worktree.return_value = mock_workspace
    mock_setup.return_value = "/fake/worktree"


def _setup_profile_mocks(mock_resolve_config, mock_resolve_profile):
    """Set up profile resolution mocks with an empty default profile."""
    from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
    mock_resolve_config.return_value = FoundryConfig(version="1")
    mock_resolve_profile.return_value = DevProfile()


class TestDevCreatePath:
    """Tests for the create path (no existing sandbox)."""

    @_apply_mocks
    def test_create_basic(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)

        runner = CliRunner()
        result = runner.invoke(dev, ["."])
        assert result.exit_code == 0
        mock_setup.assert_called_once()
        mock_save_attach.assert_called()
        assert "Created sandbox" in result.output

    @_apply_mocks
    def test_profile_persisted(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--profile", "my-profile"])
        assert result.exit_code == 0
        mock_patch.assert_called_once()
        call_kwargs = mock_patch.call_args
        assert call_kwargs[1]["profile"] == "my-profile"

    @_apply_mocks
    def test_no_ide(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--no-ide"])
        assert result.exit_code == 0
        mock_cli.assert_not_called()

    @_apply_mocks
    def test_invalid_agent(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--agent", "invalid"])
        assert result.exit_code != 0

    @patch("foundry_sandbox.commands.dev.sbx_check_available")
    @patch("foundry_sandbox.commands.dev._resolve_repo_input")
    def test_not_a_git_repo(self, mock_resolve_repo, mock_check):
        mock_resolve_repo.return_value = ("", "", "", "")

        runner = CliRunner()
        result = runner.invoke(dev, ["/nonexistent"])
        assert result.exit_code != 0


class TestDevReusePath:
    """Tests for the reuse path (existing sandbox found)."""

    @_apply_mocks
    def test_reuse_found(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import IdeConfig
        mock_ide_config.return_value = IdeConfig(preferred="code")
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)
        mock_find.return_value = "existing-sandbox"

        runner = CliRunner()
        result = runner.invoke(dev, ["."])
        assert result.exit_code == 0
        assert "Reusing sandbox: existing-sandbox" in result.output
        mock_setup.assert_not_called()

    @_apply_mocks
    def test_fresh_skips_reuse(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)
        mock_find.return_value = "existing-sandbox"

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--fresh"])
        assert result.exit_code == 0
        assert "Creating new sandbox" in result.output
        mock_setup.assert_called_once()

    @_apply_mocks
    def test_reuse_no_match_creates(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        _setup_profile_mocks(mock_resolve_config, mock_resolve_profile)
        mock_find.return_value = None

        runner = CliRunner()
        result = runner.invoke(dev, ["."])
        assert result.exit_code == 0
        assert "Creating new sandbox" in result.output
        mock_setup.assert_called_once()


class TestDevDryRun:
    """Tests for --plan dry-run mode."""

    @patch("foundry_sandbox.commands.dev.sbx_check_available")
    @patch("foundry_sandbox.commands.dev._resolve_repo_input")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("foundry_sandbox.commands.dev.resolve_foundry_config")
    @patch("foundry_sandbox.commands.dev.resolve_profile")
    @patch("foundry_sandbox.foundry_config.render_plan_text", return_value="PLAN OUTPUT")
    def test_plan_mode(
        self, mock_render, mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_resolve_repo, mock_check,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
        mock_ide_config.return_value = None
        mock_resolve_repo.return_value = (
            "https://github.com/org/repo",
            "/fake/repo",
            "https://github.com/org/repo",
            "main",
        )
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.return_value = DevProfile()

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--plan"])
        assert result.exit_code == 0
        assert "PLAN OUTPUT" in result.output
        assert "Effective settings" in result.output


class TestDevProfileResolution:
    """Tests for profile resolution in cast dev."""

    @_apply_mocks
    def test_profile_provides_agent_default(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.return_value = DevProfile(agent="codex")

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--profile", "work"])
        assert result.exit_code == 0
        call_kwargs = mock_setup.call_args
        assert call_kwargs[1]["agent"] == "codex"

    @_apply_mocks
    def test_cli_flag_overrides_profile(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.return_value = DevProfile(agent="codex")

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--profile", "work", "--agent", "gemini"])
        assert result.exit_code == 0
        call_kwargs = mock_setup.call_args
        assert call_kwargs[1]["agent"] == "gemini"

    @patch("foundry_sandbox.commands.dev.sbx_check_available")
    @patch("foundry_sandbox.commands.dev._resolve_repo_input")
    @patch("foundry_sandbox.foundry_config.load_user_ide_config")
    @patch("foundry_sandbox.commands.dev.resolve_foundry_config")
    @patch("foundry_sandbox.commands.dev.resolve_profile")
    def test_unknown_profile_exits_with_error(
        self, mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_resolve_repo, mock_check,
    ):
        from foundry_sandbox.foundry_config import FoundryConfig
        mock_ide_config.return_value = None
        mock_resolve_repo.return_value = (
            "https://github.com/org/repo",
            "/fake/repo",
            "https://github.com/org/repo",
            "main",
        )
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.side_effect = ValueError("Unknown profile 'nonexistent'")

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--profile", "nonexistent"])
        assert result.exit_code != 0

    @_apply_mocks
    def test_default_profile_succeeds_with_no_config(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.return_value = DevProfile()

        runner = CliRunner()
        result = runner.invoke(dev, ["."])
        assert result.exit_code == 0
        assert "Created sandbox" in result.output
        # Agent should be the hardcoded default "claude"
        call_kwargs = mock_setup.call_args
        assert call_kwargs[1]["agent"] == "claude"

    @_apply_mocks
    def test_profile_packages_flow_to_setup(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig, PackageBootstrap
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(
            version="1",
            allow_system_packages=True,
        )
        mock_resolve_profile.return_value = DevProfile(
            packages=PackageBootstrap(pip="requirements.txt", apt=["jq"]),
        )

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--profile", "work"])
        assert result.exit_code == 0
        call_kwargs = mock_setup.call_args
        assert call_kwargs[1]["packages"] is not None
        assert call_kwargs[1]["packages"]["pip"] == "requirements.txt"
        assert call_kwargs[1]["packages"]["apt"] == ["jq"]

    @_apply_mocks
    def test_pip_requirements_cli_bridge(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.return_value = DevProfile()

        runner = CliRunner()
        result = runner.invoke(dev, [".", "--pip-requirements", "dev-requirements.txt"])
        assert result.exit_code == 0
        call_kwargs = mock_setup.call_args
        assert call_kwargs[1]["packages"] is not None
        assert call_kwargs[1]["packages"]["pip"] == "dev-requirements.txt"


class TestDevTemplateCache:
    """Tests for template cache integration in cast dev."""

    @_apply_mocks
    def test_cache_hit_uses_cached_template(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig, PackageBootstrap
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(
            version="1",
            allow_system_packages=True,
        )
        mock_resolve_profile.return_value = DevProfile(
            packages=PackageBootstrap(pip=["ruff"]),
        )

        with patch("foundry_sandbox.template_cache.lookup_cached_template") as mock_lookup, \
             patch("foundry_sandbox.template_cache.build_profile_template") as mock_build:
            mock_lookup.return_value = "profile-work-abc123:latest"
            runner = CliRunner()
            result = runner.invoke(dev, [".", "--profile", "work"])
            assert result.exit_code == 0
            mock_build.assert_not_called()
            call_kwargs = mock_setup.call_args
            assert call_kwargs[1]["template"] == "profile-work-abc123:latest"
            assert call_kwargs[1]["skip_package_bootstrap"] is True

    @_apply_mocks
    def test_cache_miss_builds_template(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig, PackageBootstrap
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(
            version="1",
            allow_system_packages=True,
        )
        mock_resolve_profile.return_value = DevProfile(
            packages=PackageBootstrap(pip=["ruff"]),
        )

        with patch("foundry_sandbox.template_cache.lookup_cached_template") as mock_lookup, \
             patch("foundry_sandbox.template_cache.build_profile_template") as mock_build:
            mock_lookup.return_value = None
            mock_build.return_value = "profile-work-abc123:latest"
            runner = CliRunner()
            result = runner.invoke(dev, [".", "--profile", "work"])
            assert result.exit_code == 0
            mock_build.assert_called_once()
            call_kwargs = mock_setup.call_args
            assert call_kwargs[1]["skip_package_bootstrap"] is True

    @_apply_mocks
    def test_build_failure_falls_back(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig, PackageBootstrap
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(
            version="1",
            allow_system_packages=True,
        )
        mock_resolve_profile.return_value = DevProfile(
            packages=PackageBootstrap(pip=["ruff"]),
        )

        with patch("foundry_sandbox.template_cache.lookup_cached_template") as mock_lookup, \
             patch("foundry_sandbox.template_cache.build_profile_template") as mock_build:
            mock_lookup.return_value = None
            mock_build.side_effect = RuntimeError("build failed")
            runner = CliRunner()
            result = runner.invoke(dev, [".", "--profile", "work"])
            assert result.exit_code == 0
            call_kwargs = mock_setup.call_args
            assert call_kwargs[1]["skip_package_bootstrap"] is False

    @_apply_mocks
    def test_default_profile_skips_cache(
        self, mock_last_ide, mock_which, mock_save_attach, mock_save_new,
        mock_patch, mock_makedirs, mock_sandbox_name, mock_repo_name,
        mock_validate_name, mock_find, mock_resolve_repo, mock_branch_exists,
        mock_detect_branch, mock_gen_branch, mock_validate, mock_setup,
        mock_resolve_profile, mock_resolve_config,
        mock_ide_config, mock_worktree, mock_macos, mock_cli,
        mock_check, mock_running, mock_exec,
    ):
        from foundry_sandbox.foundry_config import DevProfile, FoundryConfig
        mock_ide_config.return_value = None
        _setup_repo_and_worktree(mock_resolve_repo, mock_worktree, mock_setup)
        mock_resolve_config.return_value = FoundryConfig(version="1")
        mock_resolve_profile.return_value = DevProfile()

        with patch("foundry_sandbox.template_cache.lookup_cached_template") as mock_lookup:
            runner = CliRunner()
            result = runner.invoke(dev, ["."])
            assert result.exit_code == 0
            mock_lookup.assert_not_called()
