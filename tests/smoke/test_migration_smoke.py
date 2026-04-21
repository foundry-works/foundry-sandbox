"""Migration smoke test — verifies installed-wheel migration path.

Runs against a built wheel (not editable install) to prove the real
cast migrate-to-sbx CLI works with package resources resolved correctly.
Does not require sbx binary (metadata-only migration contract).
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from foundry_sandbox.commands.migrate import migrate_to_sbx


def _write_old_json_metadata(config_dir: Path, data: dict) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "metadata.json").write_text(json.dumps(data) + "\n")


def _make_config_dir(sandbox_home: Path, name: str) -> Path:
    d = sandbox_home / "claude-config" / name
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.mark.slow
class TestMigrationSmoke:
    """End-to-end migration smoke test against installed wheel."""

    def test_full_migration_metadata_only(self, tmp_path, monkeypatch):
        """Migrate old-format sandbox metadata and verify correct conversion."""
        monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
        config_dir = _make_config_dir(tmp_path, "smoke-test-sandbox")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/example/project",
            "branch": "main",
            "network_mode": "limited",
        })

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])

        assert result.exit_code == 0, f"CLI failed: {result.output}"
        assert "Migration complete" in result.output

        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["backend"] == "sbx"
        assert data["network_profile"] == "balanced"
        assert data["sbx_name"] == "smoke-test-sandbox"
        assert data["git_safety_enabled"] is False

    def test_legacy_env_migration(self, tmp_path, monkeypatch):
        """Migrate legacy env-file metadata to sbx format."""
        monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
        config_dir = _make_config_dir(tmp_path, "legacy-sandbox")
        env_path = config_dir / "metadata.env"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text("\n".join([
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_BRANCH=feature",
            "SANDBOX_NETWORK_MODE=host-only",
        ]) + "\n")

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])

        assert result.exit_code == 0
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["backend"] == "sbx"
        assert data["branch"] == "feature"
        assert not env_path.exists()
        assert (config_dir / "metadata.env.pre-sbx-migration").exists()

    def test_migration_with_existing_worktree(self, tmp_path, monkeypatch):
        """Migration of sandbox with existing worktree directory."""
        monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
        config_dir = _make_config_dir(tmp_path, "wt-sandbox")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/org/repo",
            "branch": "develop",
        })

        # Create an existing worktree directory (simulating 0.20.x layout)
        worktree_dir = tmp_path / "worktrees" / "wt-sandbox"
        worktree_dir.mkdir(parents=True)
        (worktree_dir / ".git").mkdir()

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])

        assert result.exit_code == 0
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["backend"] == "sbx"
        assert data["git_safety_enabled"] is False

    def test_idempotent_migration(self, tmp_path, monkeypatch):
        """Running migration twice produces the same result."""
        monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
        config_dir = _make_config_dir(tmp_path, "idempotent-test")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/org/repo",
            "branch": "main",
        })

        runner = CliRunner()
        result1 = runner.invoke(migrate_to_sbx, ["--force"])
        assert result1.exit_code == 0

        result2 = runner.invoke(migrate_to_sbx, ["--force"])
        assert result2.exit_code == 0

        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["backend"] == "sbx"
        assert data["git_safety_enabled"] is False

    def test_wheel_import_succeeds(self):
        """Verify all migration imports resolve from installed wheel."""
        from foundry_sandbox.migration import convert_old_metadata_to_sbx
        from foundry_sandbox.commands.migrate import migrate_to_sbx

        assert callable(convert_old_metadata_to_sbx)
        assert callable(migrate_to_sbx)
