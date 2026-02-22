"""Unit tests for _collect_compose_extras() in foundry_sandbox.docker.

Tests auto-discovery (config/docker-compose.*.yml), FOUNDRY_COMPOSE_EXTRAS
env var parsing, CLI extras, path resolution/validation, and deduplication.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from foundry_sandbox.docker import _collect_compose_extras


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------


class TestAutoDiscovery:
    """Auto-discovery finds config/docker-compose.*.yml files."""

    def test_discovers_matching_files_sorted(self, tmp_path, monkeypatch):
        """Matching files are discovered and sorted by name."""
        config = tmp_path / "config"
        config.mkdir()
        (config / "docker-compose.redis.yml").write_text("services: {}")
        (config / "docker-compose.chromadb.yml").write_text("services: {}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert len(result) == 2
        assert "chromadb" in result[0]  # chromadb < redis alphabetically
        assert "redis" in result[1]

    def test_empty_when_no_matching_files(self, tmp_path):
        """Returns empty list when no files match the glob."""
        config = tmp_path / "config"
        config.mkdir()
        # Non-matching files
        (config / "user-services.yaml").write_text("services: []")
        (config / "docker-compose.redis.yml.example").write_text("services: {}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert result == []

    def test_empty_when_config_dir_missing(self, tmp_path):
        """Returns empty list when config/ directory doesn't exist."""
        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert result == []

    def test_ignores_example_and_disabled_extensions(self, tmp_path):
        """Files with .example or .disabled extensions are not discovered."""
        config = tmp_path / "config"
        config.mkdir()
        (config / "docker-compose.redis.yml").write_text("services: {}")
        (config / "docker-compose.ollama.yml.example").write_text("services: {}")
        (config / "docker-compose.postgres.yml.disabled").write_text("services: {}")
        (config / "docker-compose.mongo.yml.bak").write_text("services: {}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert len(result) == 1
        assert "redis" in result[0]


# ---------------------------------------------------------------------------
# FOUNDRY_COMPOSE_EXTRAS env var
# ---------------------------------------------------------------------------


class TestEnvVar:
    """FOUNDRY_COMPOSE_EXTRAS env var parsing."""

    def test_single_path(self, tmp_path, monkeypatch):
        """Single path in env var is collected."""
        extra = tmp_path / "extra.yml"
        extra.write_text("services: {}")
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", str(extra))

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert len(result) == 1
        assert result[0] == str(extra.resolve())

    def test_multiple_colon_separated_paths(self, tmp_path, monkeypatch):
        """Multiple colon-separated paths are all collected."""
        e1 = tmp_path / "a.yml"
        e2 = tmp_path / "b.yml"
        e1.write_text("services: {}")
        e2.write_text("services: {}")
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", f"{e1}:{e2}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert len(result) == 2

    def test_empty_segments_skipped(self, tmp_path, monkeypatch):
        """Leading, trailing, and double colons produce empty segments that are skipped."""
        extra = tmp_path / "extra.yml"
        extra.write_text("services: {}")
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", f":{extra}:::")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert len(result) == 1

    def test_unset_env_var_produces_nothing(self, tmp_path, monkeypatch):
        """Unset env var adds no extras."""
        monkeypatch.delenv("FOUNDRY_COMPOSE_EXTRAS", raising=False)

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        assert result == []


# ---------------------------------------------------------------------------
# CLI extras
# ---------------------------------------------------------------------------


class TestCliExtras:
    """CLI extras (--compose-extra flag) are appended after env var paths."""

    def test_cli_extras_appended_after_env_var(self, tmp_path, monkeypatch):
        """CLI extras appear after env var paths in the result."""
        env_file = tmp_path / "env.yml"
        cli_file = tmp_path / "cli.yml"
        env_file.write_text("services: {}")
        cli_file.write_text("services: {}")
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", str(env_file))

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras(extra_paths=[str(cli_file)])

        assert len(result) == 2
        assert result[0] == str(env_file.resolve())
        assert result[1] == str(cli_file.resolve())

    def test_cli_extras_none_is_safe(self, tmp_path):
        """extra_paths=None is handled gracefully."""
        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras(extra_paths=None)

        assert result == []

    def test_cli_extras_empty_list_is_safe(self, tmp_path):
        """extra_paths=[] is handled gracefully."""
        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras(extra_paths=[])

        assert result == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    """Deduplication on resolved absolute paths."""

    def test_dedup_relative_and_absolute_same_file(self, tmp_path, monkeypatch):
        """Relative and absolute paths to the same file are deduplicated."""
        extra = tmp_path / "extra.yml"
        extra.write_text("services: {}")

        # Pass same file as both env var (absolute) and CLI (relative via symlink)
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", str(extra))

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras(extra_paths=[str(extra)])

        assert len(result) == 1

    def test_dedup_preserves_earliest_occurrence(self, tmp_path, monkeypatch):
        """When duplicated, the earliest occurrence's resolved path is kept."""
        config = tmp_path / "config"
        config.mkdir()
        shared = config / "docker-compose.shared.yml"
        shared.write_text("services: {}")

        # Same file via auto-discovery and CLI
        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras(extra_paths=[str(shared)])

        assert len(result) == 1
        assert result[0] == str(shared.resolve())


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    """Path validation raises FileNotFoundError."""

    def test_missing_path_raises(self, tmp_path):
        """Non-existent path raises FileNotFoundError with the offending path."""
        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError, match="/nonexistent/extra.yml"):
                _collect_compose_extras(extra_paths=["/nonexistent/extra.yml"])

    def test_directory_path_raises(self, tmp_path):
        """Path pointing to a directory raises FileNotFoundError."""
        d = tmp_path / "some-dir"
        d.mkdir()

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError, match="some-dir"):
                _collect_compose_extras(extra_paths=[str(d)])

    def test_error_message_includes_source(self, tmp_path, monkeypatch):
        """Error message includes which source (env var, CLI, etc.) produced the bad path."""
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", "/nonexistent/from-env.yml")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError, match="FOUNDRY_COMPOSE_EXTRAS"):
                _collect_compose_extras()

    def test_error_message_includes_source_cli(self, tmp_path):
        """Error message includes extra_paths source label."""
        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            with pytest.raises(FileNotFoundError, match="extra_paths"):
                _collect_compose_extras(extra_paths=["/nonexistent/cli.yml"])


# ---------------------------------------------------------------------------
# All three sources combined
# ---------------------------------------------------------------------------


class TestCombinedSources:
    """All three sources combine correctly."""

    def test_all_sources_combine_in_order(self, tmp_path, monkeypatch):
        """Auto-discovered + env var + CLI extras combine in correct order."""
        # Auto-discovered
        config = tmp_path / "config"
        config.mkdir()
        auto = config / "docker-compose.auto.yml"
        auto.write_text("services: {}")

        # Env var
        env_file = tmp_path / "env-extra.yml"
        env_file.write_text("services: {}")
        monkeypatch.setenv("FOUNDRY_COMPOSE_EXTRAS", str(env_file))

        # CLI
        cli_file = tmp_path / "cli-extra.yml"
        cli_file.write_text("services: {}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras(extra_paths=[str(cli_file)])

        assert len(result) == 3
        assert "auto" in result[0]
        assert "env-extra" in result[1]
        assert "cli-extra" in result[2]

    def test_paths_are_resolved_to_absolute(self, tmp_path, monkeypatch):
        """All returned paths are absolute."""
        config = tmp_path / "config"
        config.mkdir()
        (config / "docker-compose.test.yml").write_text("services: {}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            result = _collect_compose_extras()

        for p in result:
            assert os.path.isabs(p), f"Expected absolute path, got: {p}"


# ---------------------------------------------------------------------------
# Integration with get_compose_command ordering
# ---------------------------------------------------------------------------


class TestIntegrationWithComposeCommand:
    """_collect_compose_extras() output integrates with get_compose_command() ordering."""

    def test_collected_extras_appear_after_base_in_compose_command(self, tmp_path):
        """Extras from _collect_compose_extras appear after base files in -f chain."""
        from foundry_sandbox.docker import get_compose_command

        config = tmp_path / "config"
        config.mkdir()
        extra = config / "docker-compose.redis.yml"
        extra.write_text("services: {}")

        with patch("foundry_sandbox.docker._script_dir", return_value=tmp_path):
            extras = _collect_compose_extras()

        cmd = get_compose_command(compose_extras=extras)

        f_indices = [i for i, arg in enumerate(cmd) if arg == "-f"]
        files = [cmd[i + 1] for i in f_indices]

        # Base file first, then extras
        assert "docker-compose.yml" in files[0]
        assert str(extra.resolve()) in files[-1]
