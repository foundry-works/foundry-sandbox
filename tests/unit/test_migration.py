"""Unit tests for foundry_sandbox/migration.py and commands/migrate.py.

Tests legacy metadata parsing, field mapping, snapshot/restore,
credential push, and CLI integration with Click CliRunner.
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from foundry_sandbox.migration import (
    NETWORK_MODE_MAP,
    classify_sandbox_dirs,
    convert_old_metadata_to_sbx,
    convert_old_preset_to_new,
    find_latest_snapshot,
    get_migration_lock,
    parse_legacy_env_metadata,
    push_credentials,
    restore_from_snapshot,
    snapshot_sandbox_home,
)
from foundry_sandbox.commands.migrate import migrate_from_sbx, migrate_to_sbx


@pytest.fixture
def sandbox_home(tmp_path, monkeypatch):
    """Set up isolated SANDBOX_HOME for each test."""
    monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
    return tmp_path


def _write_env_file(path: Path, lines: list[str]) -> None:
    """Write a metadata.env file with the given lines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def _write_old_json_metadata(config_dir: Path, data: dict) -> None:
    """Write an old-format metadata.json (no backend field)."""
    config_dir.mkdir(parents=True, exist_ok=True)
    meta_path = config_dir / "metadata.json"
    meta_path.write_text(json.dumps(data) + "\n")


def _make_config_dir(sandbox_home: Path, name: str) -> Path:
    """Create a claude-config/<name> directory and return it."""
    d = sandbox_home / "claude-config" / name
    d.mkdir(parents=True, exist_ok=True)
    return d


class TestParseLegacyEnvMetadata:
    """Tests for parse_legacy_env_metadata()."""

    def test_empty_file(self, tmp_path):
        path = tmp_path / "metadata.env"
        path.write_text("")
        assert parse_legacy_env_metadata(path) == {}

    def test_comments_and_blanks(self, tmp_path):
        path = tmp_path / "metadata.env"
        path.write_text("# comment\n\n  \n# another\n")
        assert parse_legacy_env_metadata(path) == {}

    def test_nonexistent_file(self, tmp_path):
        assert parse_legacy_env_metadata(tmp_path / "missing.env") == {}

    def test_minimal_fields(self, tmp_path):
        path = tmp_path / "metadata.env"
        _write_env_file(path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_BRANCH=main",
        ])
        result = parse_legacy_env_metadata(path)
        assert result["repo_url"] == "https://github.com/org/repo"
        assert result["branch"] == "main"

    def test_full_fields(self, tmp_path):
        path = tmp_path / "metadata.env"
        _write_env_file(path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_BRANCH=feature-branch",
            "SANDBOX_FROM_BRANCH=dev",
            "SANDBOX_NETWORK_MODE=limited",
            "SANDBOX_WORKING_DIR=src/app",
            "SANDBOX_PIP_REQUIREMENTS=requirements.txt",
            "SANDBOX_ALLOW_PR=1",
            "SANDBOX_ENABLE_OPENCODE=true",
            "SANDBOX_ENABLE_ZAI=0",
            "SANDBOX_SYNC_SSH=1",
            "SANDBOX_SSH_MODE=always",
            "SANDBOX_AGENT=codex",
        ])
        result = parse_legacy_env_metadata(path)
        assert result["repo_url"] == "https://github.com/org/repo"
        assert result["branch"] == "feature-branch"
        assert result["from_branch"] == "dev"
        assert result["network_mode"] == "limited"
        assert result["working_dir"] == "src/app"
        assert result["pip_requirements"] == "requirements.txt"
        assert result["allow_pr"] is True
        assert result["enable_opencode"] is True
        assert result["enable_zai"] is False
        assert result["sync_ssh"] is True
        assert result["ssh_mode"] == "always"
        assert result["agent"] == "codex"

    def test_array_syntax_copies(self, tmp_path):
        path = tmp_path / "metadata.env"
        _write_env_file(path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_BRANCH=main",
            'SANDBOX_COPIES=(file.txt:/dest/file.txt other.txt:/dest/other.txt)',
        ])
        result = parse_legacy_env_metadata(path)
        assert result["copies"] == ["file.txt:/dest/file.txt", "other.txt:/dest/other.txt"]

    def test_empty_array(self, tmp_path):
        path = tmp_path / "metadata.env"
        _write_env_file(path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_COPIES=()",
        ])
        result = parse_legacy_env_metadata(path)
        assert result["copies"] == []

    def test_quoted_values(self, tmp_path):
        path = tmp_path / "metadata.env"
        _write_env_file(path, [
            'SANDBOX_REPO_URL="https://github.com/org/repo"',
            "SANDBOX_BRANCH='main'",
        ])
        result = parse_legacy_env_metadata(path)
        assert result["repo_url"] == "https://github.com/org/repo"
        assert result["branch"] == "main"

    def test_unknown_keys_ignored(self, tmp_path):
        path = tmp_path / "metadata.env"
        _write_env_file(path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "UNKNOWN_KEY=value",
            "ANOTHER_UNKNOWN=123",
        ])
        result = parse_legacy_env_metadata(path)
        assert "repo_url" in result
        assert "UNKNOWN_KEY" not in result
        assert "ANOTHER_UNKNOWN" not in result


class TestConvertOldMetadataToSbx:
    """Tests for convert_old_metadata_to_sbx()."""

    def test_minimal_old_metadata_defaults(self):
        old = {"repo_url": "https://github.com/org/repo", "branch": "main"}
        new_data, warnings = convert_old_metadata_to_sbx(old, "my-sandbox")

        assert new_data["backend"] == "sbx"
        assert new_data["sbx_name"] == "my-sandbox"
        assert new_data["agent"] == "claude"
        assert new_data["git_safety_enabled"] is False
        assert new_data["workspace_dir"] == "/workspace"
        assert new_data["network_profile"] == "balanced"
        assert new_data["template"] == ""
        assert new_data["copies"] == []

    def test_network_mode_mapping(self):
        for old_val, new_val in NETWORK_MODE_MAP.items():
            old = {"repo_url": "https://github.com/org/repo", "branch": "main", "network_mode": old_val}
            new_data, _ = convert_old_metadata_to_sbx(old, "test")
            assert new_data["network_profile"] == new_val

    def test_unknown_network_mode_defaults_balanced(self):
        old = {"repo_url": "", "branch": "", "network_mode": "full"}
        new_data, warnings = convert_old_metadata_to_sbx(old, "test")
        assert new_data["network_profile"] == "balanced"
        assert any("Unknown network_mode" in w for w in warnings)

    def test_dropped_fields_generate_warnings(self):
        old = {
            "repo_url": "",
            "branch": "",
            "mounts": ["/host:/container"],
            "compose_extras": "extra.yml",
            "sparse_checkout": True,
            "sync_ssh": True,
            "ssh_mode": "always",
            "pre_foundry": True,
            "pre_foundry_version": "1.0.0",
        }
        _, warnings = convert_old_metadata_to_sbx(old, "test")
        # network_mode is mapped, not truly dropped
        for field in ("mounts", "compose_extras", "sparse_checkout", "sync_ssh",
                      "ssh_mode", "pre_foundry", "pre_foundry_version"):
            assert any(f"Dropped field '{field}'" in w for w in warnings), \
                f"Expected warning for dropped field '{field}'"

    def test_sbxs_name_set_to_sandbox_name(self):
        old = {"repo_url": "", "branch": ""}
        new_data, _ = convert_old_metadata_to_sbx(old, "my-special-sandbox")
        assert new_data["sbx_name"] == "my-special-sandbox"

    def test_full_metadata_round_trip(self):
        old = {
            "repo_url": "https://github.com/org/repo",
            "branch": "feature-branch",
            "from_branch": "dev",
            "working_dir": "src",
            "pip_requirements": "requirements.txt",
            "allow_pr": True,
            "enable_opencode": True,
            "enable_zai": False,
            "copies": ["file.txt:/dest/file.txt"],
            "agent": "codex",
            "network_mode": "limited",
        }
        new_data, warnings = convert_old_metadata_to_sbx(old, "test")
        assert new_data["repo_url"] == "https://github.com/org/repo"
        assert new_data["branch"] == "feature-branch"
        assert new_data["from_branch"] == "dev"
        assert new_data["working_dir"] == "src"
        assert new_data["pip_requirements"] == "requirements.txt"
        assert new_data["allow_pr"] is True
        assert new_data["enable_opencode"] is True
        assert new_data["enable_zai"] is False
        assert new_data["copies"] == ["file.txt:/dest/file.txt"]
        assert new_data["agent"] == "codex"
        assert new_data["network_profile"] == "balanced"

    def test_boolean_string_parsing(self):
        old = {
            "repo_url": "",
            "branch": "",
            "allow_pr": "1",
            "enable_opencode": "true",
            "enable_zai": "0",
        }
        new_data, _ = convert_old_metadata_to_sbx(old, "test")
        assert new_data["allow_pr"] is True
        assert new_data["enable_opencode"] is True
        assert new_data["enable_zai"] is False


class TestConvertOldPresetToNew:
    """Tests for convert_old_preset_to_new()."""

    def test_minimal_preset_gets_defaults(self):
        new_args, warnings = convert_old_preset_to_new({"repo": "org/repo"})
        assert new_args["repo"] == "org/repo"
        assert new_args["agent"] == "claude"
        assert new_args["network_profile"] == "balanced"
        assert len(warnings) == 0

    def test_network_mode_mapped(self):
        for old_val, new_val in NETWORK_MODE_MAP.items():
            new_args, _ = convert_old_preset_to_new({
                "repo": "org/repo", "network_mode": old_val,
            })
            assert new_args["network_profile"] == new_val

    def test_dropped_fields_generate_warnings(self):
        old = {
            "repo": "org/repo",
            "sparse": True,
            "pre_foundry": True,
            "sync_ssh": True,
            "mounts": ["/host:/container"],
            "compose_extras": "extra.yml",
        }
        _, warnings = convert_old_preset_to_new(old)
        for field in ("sparse", "pre_foundry", "sync_ssh", "mounts", "compose_extras"):
            assert any(f"Dropped preset field '{field}'" in w for w in warnings)

    def test_agent_default_added(self):
        new_args, _ = convert_old_preset_to_new({"repo": "org/repo"})
        assert "agent" in new_args
        assert new_args["agent"] == "claude"

    def test_existing_agent_preserved(self):
        new_args, _ = convert_old_preset_to_new({"repo": "org/repo", "agent": "codex"})
        assert new_args["agent"] == "codex"

    def test_unknown_fields_removed_with_warning(self):
        old = {"repo": "org/repo", "unknown_field": "value", "another": 123}
        _, warnings = convert_old_preset_to_new(old)
        assert any("unknown_field" in w for w in warnings)
        assert any("another" in w for w in warnings)

    def test_full_preset_converts(self):
        old = {
            "repo": "org/repo",
            "agent": "gemini",
            "branch": "feature",
            "from_branch": "dev",
            "working_dir": "src",
            "pip_requirements": "requirements.txt",
            "allow_pr": True,
            "network_mode": "host-only",
            "enable_opencode": True,
            "enable_zai": False,
            "copies": ["a.txt:/b.txt"],
        }
        new_args, _ = convert_old_preset_to_new(old)
        assert new_args["repo"] == "org/repo"
        assert new_args["agent"] == "gemini"
        assert new_args["branch"] == "feature"
        assert new_args["network_profile"] == "allow-all"
        assert new_args["copies"] == ["a.txt:/b.txt"]


class TestClassifySandboxDirs:
    """Tests for classify_sandbox_dirs()."""

    def test_empty_config_dir(self, sandbox_home):
        assert classify_sandbox_dirs(sandbox_home) == []

    def test_no_config_dir(self, sandbox_home):
        # claude-config doesn't exist
        assert classify_sandbox_dirs(sandbox_home) == []

    def test_sbx_format_detected(self, sandbox_home):
        config_dir = _make_config_dir(sandbox_home, "my-sbx")
        _write_old_json_metadata(config_dir, {
            "backend": "sbx", "sbx_name": "my-sbx", "agent": "claude",
            "repo_url": "", "branch": "",
        })
        result = classify_sandbox_dirs(sandbox_home)
        assert len(result) == 1
        assert result[0]["name"] == "my-sbx"
        assert result[0]["format"] == "sbx"

    def test_old_json_format_detected(self, sandbox_home):
        config_dir = _make_config_dir(sandbox_home, "old-sandbox")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/org/repo",
            "branch": "main",
        })
        result = classify_sandbox_dirs(sandbox_home)
        assert len(result) == 1
        assert result[0]["format"] == "old_json"

    def test_legacy_env_format_detected(self, sandbox_home):
        config_dir = _make_config_dir(sandbox_home, "legacy-sandbox")
        env_path = config_dir / "metadata.env"
        _write_env_file(env_path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_BRANCH=main",
        ])
        result = classify_sandbox_dirs(sandbox_home)
        assert len(result) == 1
        assert result[0]["format"] == "legacy_env"

    def test_empty_format_detected(self, sandbox_home):
        _make_config_dir(sandbox_home, "empty-sandbox")
        result = classify_sandbox_dirs(sandbox_home)
        assert len(result) == 1
        assert result[0]["format"] == "empty"

    def test_mixed_formats(self, sandbox_home):
        # SBX
        d1 = _make_config_dir(sandbox_home, "sbx-sandbox")
        _write_old_json_metadata(d1, {"backend": "sbx", "sbx_name": "sbx-sandbox",
                                       "agent": "claude", "repo_url": "", "branch": ""})
        # Old JSON
        d2 = _make_config_dir(sandbox_home, "old-sandbox")
        _write_old_json_metadata(d2, {"repo_url": "https://github.com/org/repo", "branch": "main"})
        # Legacy ENV
        d3 = _make_config_dir(sandbox_home, "legacy-sandbox")
        _write_env_file(d3 / "metadata.env", ["SANDBOX_REPO_URL=https://github.com/org/repo"])
        # Empty
        _make_config_dir(sandbox_home, "empty-sandbox")

        result = classify_sandbox_dirs(sandbox_home)
        assert len(result) == 4
        formats = {r["name"]: r["format"] for r in result}
        assert formats["sbx-sandbox"] == "sbx"
        assert formats["old-sandbox"] == "old_json"
        assert formats["legacy-sandbox"] == "legacy_env"
        assert formats["empty-sandbox"] == "empty"


class TestSnapshotSandboxHome:
    """Tests for snapshot_sandbox_home()."""

    def test_creates_snapshot_dir(self, sandbox_home):
        snap = snapshot_sandbox_home(sandbox_home)
        assert snap.exists()
        assert snap.parent.name == ".migration-snapshots"

    def test_manifest_written(self, sandbox_home):
        snap = snapshot_sandbox_home(sandbox_home)
        manifest_path = snap / "snapshot-manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["source_version"] == "0.20.x"
        assert "timestamp" in manifest

    def test_copies_claude_config(self, sandbox_home):
        config_dir = _make_config_dir(sandbox_home, "test-sandbox")
        _write_old_json_metadata(config_dir, {"repo_url": "", "branch": ""})

        snap = snapshot_sandbox_home(sandbox_home)
        assert (snap / "claude-config" / "test-sandbox" / "metadata.json").exists()

    def test_copies_presets(self, sandbox_home):
        presets_dir = sandbox_home / "presets"
        presets_dir.mkdir()
        (presets_dir / "test.json").write_text(json.dumps({"args": {"repo": "org/repo"}}))

        snap = snapshot_sandbox_home(sandbox_home)
        assert (snap / "presets" / "test.json").exists()

    def test_copies_dot_files(self, sandbox_home):
        (sandbox_home / ".last-cast-new.json").write_text("{}")
        (sandbox_home / ".last-attach.json").write_text("{}")

        snap = snapshot_sandbox_home(sandbox_home)
        assert (snap / ".last-cast-new.json").exists()
        assert (snap / ".last-attach.json").exists()

    def test_migration_lock_written(self, sandbox_home):
        snapshot_sandbox_home(sandbox_home)
        lock_path = sandbox_home / ".migration-in-progress"
        assert lock_path.exists()
        lock = json.loads(lock_path.read_text())
        assert "snapshot_dir" in lock

    def test_does_not_copy_repos_or_worktrees(self, sandbox_home):
        (sandbox_home / "repos" / "org" / "repo.git").mkdir(parents=True)
        (sandbox_home / "worktrees" / "test").mkdir(parents=True)

        snap = snapshot_sandbox_home(sandbox_home)
        assert not (snap / "repos").exists()
        assert not (snap / "worktrees").exists()

    def test_custom_snapshot_dir(self, sandbox_home, tmp_path):
        custom_dir = tmp_path / "custom-snap"
        snap = snapshot_sandbox_home(sandbox_home, custom_dir)
        assert snap == custom_dir
        assert snap.exists()


class TestRestoreFromSnapshot:
    """Tests for restore_from_snapshot()."""

    def test_restores_claude_config(self, sandbox_home):
        # Create original state
        config_dir = _make_config_dir(sandbox_home, "test-sandbox")
        _write_old_json_metadata(config_dir, {"repo_url": "original", "branch": "main"})

        # Snapshot
        snap = snapshot_sandbox_home(sandbox_home)

        # Modify current state
        _write_old_json_metadata(config_dir, {"repo_url": "modified", "branch": "changed"})

        # Restore
        restore_from_snapshot(snap, sandbox_home)

        # Verify original restored
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["repo_url"] == "original"

    def test_removes_migration_lock(self, sandbox_home):
        snapshot_sandbox_home(sandbox_home)
        assert (sandbox_home / ".migration-in-progress").exists()

        snap = find_latest_snapshot(sandbox_home)
        assert snap is not None
        restore_from_snapshot(snap, sandbox_home)
        assert not (sandbox_home / ".migration-in-progress").exists()


class TestFindLatestSnapshot:
    """Tests for find_latest_snapshot()."""

    def test_no_snapshots(self, sandbox_home):
        assert find_latest_snapshot(sandbox_home) is None

    def test_finds_latest(self, sandbox_home):
        snapshot_sandbox_home(sandbox_home)
        snap2 = snapshot_sandbox_home(sandbox_home)
        latest = find_latest_snapshot(sandbox_home)
        assert latest == snap2


class TestGetMigrationLock:
    """Tests for get_migration_lock()."""

    def test_no_lock(self, sandbox_home):
        assert get_migration_lock(sandbox_home) is None

    def test_lock_exists(self, sandbox_home):
        snapshot_sandbox_home(sandbox_home)
        lock = get_migration_lock(sandbox_home)
        assert lock is not None
        assert "snapshot_dir" in lock


class TestPushCredentials:
    """Tests for push_credentials()."""

    def test_missing_credentials_reported(self, sandbox_home, monkeypatch):
        # Clear all credential env vars
        for key in ("ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY"):
            monkeypatch.delenv(key, raising=False)

        pushed, missing = push_credentials(dry_run=True)
        assert len(pushed) == 0
        assert len(missing) == 3  # anthropic, github, openai

    def test_credentials_detected_in_dry_run(self, sandbox_home, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp-test-token")
        # Explicitly clear to prevent leak from real environment
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)

        pushed, missing = push_credentials(dry_run=True)
        assert "anthropic" in pushed
        assert "github" in pushed
        assert "openai" in missing


class TestMigrateToSbxCommand:
    """CLI integration tests for migrate-to-sbx."""

    def test_no_sandbox_home_exits_error(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", str(tmp_path / "nonexistent"))
        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx)
        assert result.exit_code != 0

    def test_nothing_to_migrate(self, sandbox_home):
        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])
        assert "No sandboxes or presets found" in result.output

    def test_plan_mode_no_changes(self, sandbox_home):
        # Create old-format sandbox
        config_dir = _make_config_dir(sandbox_home, "test-sandbox")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/org/repo",
            "branch": "main",
        })

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--plan"])
        assert result.exit_code == 0
        assert "Dry run" in result.output
        # Original metadata unchanged
        data = json.loads((config_dir / "metadata.json").read_text())
        assert "backend" not in data

    def test_full_migration(self, sandbox_home):
        # Create old-format sandbox
        config_dir = _make_config_dir(sandbox_home, "test-sandbox")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/org/repo",
            "branch": "main",
            "network_mode": "limited",
        })

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])
        assert result.exit_code == 0
        assert "Migration complete" in result.output

        # Verify converted metadata
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["backend"] == "sbx"
        assert data["network_profile"] == "balanced"
        assert data["sbx_name"] == "test-sandbox"
        assert data["git_safety_enabled"] is False

    def test_legacy_env_migration(self, sandbox_home):
        config_dir = _make_config_dir(sandbox_home, "legacy-sandbox")
        env_path = config_dir / "metadata.env"
        _write_env_file(env_path, [
            "SANDBOX_REPO_URL=https://github.com/org/repo",
            "SANDBOX_BRANCH=feature",
            "SANDBOX_NETWORK_MODE=host-only",
        ])

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])
        assert result.exit_code == 0

        # Verify converted
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["backend"] == "sbx"
        assert data["branch"] == "feature"
        assert data["network_profile"] == "allow-all"

        # Verify env file renamed
        assert not env_path.exists()
        assert (config_dir / "metadata.env.pre-sbx-migration").exists()

    def test_idempotent_re_run(self, sandbox_home):
        config_dir = _make_config_dir(sandbox_home, "test-sandbox")
        _write_old_json_metadata(config_dir, {
            "repo_url": "https://github.com/org/repo",
            "branch": "main",
        })

        runner = CliRunner()
        # First migration
        result1 = runner.invoke(migrate_to_sbx, ["--force"])
        assert result1.exit_code == 0

        # Second migration should be idempotent
        result2 = runner.invoke(migrate_to_sbx, ["--force"])
        assert result2.exit_code == 0
        assert "already" in result2.output.lower() or "skip" in result2.output.lower()

    def test_preset_migration(self, sandbox_home):
        # Create preset
        presets_dir = sandbox_home / "presets"
        presets_dir.mkdir()
        (presets_dir / "test-preset.json").write_text(json.dumps({
            "args": {
                "repo": "org/repo",
                "network_mode": "limited",
                "sparse": True,
            },
        }))

        runner = CliRunner()
        result = runner.invoke(migrate_to_sbx, ["--force"])
        assert result.exit_code == 0

        # Verify preset converted
        preset_data = json.loads((presets_dir / "test-preset.json").read_text())
        assert preset_data["args"]["network_profile"] == "balanced"
        assert "network_mode" not in preset_data["args"]
        assert "sparse" not in preset_data["args"]


class TestMigrateFromSbxCommand:
    """CLI integration tests for migrate-from-sbx."""

    def test_no_snapshot_exits_error(self, sandbox_home):
        runner = CliRunner()
        result = runner.invoke(migrate_from_sbx)
        assert result.exit_code != 0
        assert "No migration snapshot found" in result.output

    def test_rollback_restores_state(self, sandbox_home):
        # Create original state
        config_dir = _make_config_dir(sandbox_home, "test-sandbox")
        _write_old_json_metadata(config_dir, {"repo_url": "original", "branch": "main"})

        # Snapshot
        snapshot_sandbox_home(sandbox_home)

        # Migrate
        runner = CliRunner()
        runner.invoke(migrate_to_sbx, ["--force"])

        # Verify migration happened
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data.get("backend") == "sbx"

        # Rollback
        result = runner.invoke(migrate_from_sbx, ["--force"])
        assert result.exit_code == 0
        assert "Rollback complete" in result.output

        # Verify original state restored
        data = json.loads((config_dir / "metadata.json").read_text())
        assert data["repo_url"] == "original"
        assert "backend" not in data

    def test_custom_snapshot_dir(self, sandbox_home, tmp_path):
        snap = snapshot_sandbox_home(sandbox_home, tmp_path / "custom")

        runner = CliRunner()
        result = runner.invoke(migrate_from_sbx, [
            "--snapshot-dir", str(snap), "--force",
        ])
        assert result.exit_code == 0
