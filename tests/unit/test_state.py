"""Unit tests for foundry_sandbox/state.py module.

Tests sandbox metadata persistence, security validation, cast-new presets,
and last-attach state tracking.
"""

import json
import os
import stat
import pytest
from pathlib import Path

from foundry_sandbox.state import (
    metadata_is_secure,
    write_sandbox_metadata,
    load_sandbox_metadata,
    list_sandboxes,
    inspect_sandbox,
    save_last_cast_new,
    load_last_cast_new,
    save_cast_preset,
    load_cast_preset,
    list_cast_presets,
    show_cast_preset,
    delete_cast_preset,
    save_last_attach,
    load_last_attach,
    _parse_legacy_metadata,
)


@pytest.fixture
def sandbox_home(tmp_path, monkeypatch):
    """Set up isolated SANDBOX_HOME for each test."""
    monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
    return tmp_path


class TestMetadataIsSecure:
    """Tests for metadata_is_secure() security validation."""

    def test_nonexistent_file_returns_false(self, tmp_path):
        """Missing file should return False."""
        result = metadata_is_secure(tmp_path / "missing.json")
        assert result is False

    def test_secure_file_returns_true(self, tmp_path):
        """File owned by current user with 600 permissions should return True."""
        secure_file = tmp_path / "secure.json"
        secure_file.write_text("{}")
        secure_file.chmod(0o600)

        result = metadata_is_secure(secure_file)
        assert result is True

    def test_group_writable_returns_false(self, tmp_path):
        """File with group-writable bit should return False."""
        insecure_file = tmp_path / "group_writable.json"
        insecure_file.write_text("{}")
        insecure_file.chmod(0o620)

        result = metadata_is_secure(insecure_file)
        assert result is False

    def test_world_writable_returns_false(self, tmp_path):
        """File with world-writable bit should return False."""
        insecure_file = tmp_path / "world_writable.json"
        insecure_file.write_text("{}")
        insecure_file.chmod(0o602)

        result = metadata_is_secure(insecure_file)
        assert result is False

    def test_group_and_world_writable_returns_false(self, tmp_path):
        """File with both group and world writable bits should return False."""
        insecure_file = tmp_path / "both_writable.json"
        insecure_file.write_text("{}")
        insecure_file.chmod(0o622)

        result = metadata_is_secure(insecure_file)
        assert result is False

    def test_readable_by_others_returns_true(self, tmp_path):
        """File readable by group/world is acceptable."""
        readable_file = tmp_path / "readable.json"
        readable_file.write_text("{}")
        readable_file.chmod(0o644)

        result = metadata_is_secure(readable_file)
        assert result is True


class TestMetadataWriteRead:
    """Tests for write_sandbox_metadata() and load_sandbox_metadata() round-trip."""

    def test_write_then_read_produces_identical_data(self, sandbox_home):
        """Write metadata then read it back produces identical data."""
        write_sandbox_metadata(
            "test-sandbox",
            repo_url="https://github.com/user/repo.git",
            branch="main",
            from_branch="dev",
            network_mode="limited",
            sync_ssh=1,
            ssh_mode="always",
            working_dir="/workspace",
            sparse_checkout=True,
            pip_requirements="requirements.txt",
            allow_pr=True,
            enable_opencode=True,
            enable_zai=False,
            mounts=["host:/container"],
            copies=["file.txt:/dest/file.txt"],
        )

        metadata = load_sandbox_metadata("test-sandbox")

        assert metadata is not None
        assert metadata["repo_url"] == "https://github.com/user/repo.git"
        assert metadata["branch"] == "main"
        assert metadata["from_branch"] == "dev"
        assert metadata["network_mode"] == "limited"
        assert metadata["sync_ssh"] == 1
        assert metadata["ssh_mode"] == "always"
        assert metadata["working_dir"] == "/workspace"
        assert metadata["sparse_checkout"] is True
        assert metadata["pip_requirements"] == "requirements.txt"
        assert metadata["allow_pr"] is True
        assert metadata["enable_opencode"] is True
        assert metadata["enable_zai"] is False
        assert metadata["mounts"] == ["host:/container"]
        assert metadata["copies"] == ["file.txt:/dest/file.txt"]

    def test_write_minimal_metadata(self, sandbox_home):
        """Write and read minimal metadata with defaults."""
        write_sandbox_metadata(
            "minimal",
            repo_url="https://github.com/test/repo.git",
            branch="main",
        )

        metadata = load_sandbox_metadata("minimal")

        assert metadata is not None
        assert metadata["repo_url"] == "https://github.com/test/repo.git"
        assert metadata["branch"] == "main"
        assert metadata["from_branch"] == ""
        assert metadata["network_mode"] == ""
        assert metadata["sync_ssh"] == 0
        # ssh_mode is auto-derived as "disabled" when sync_ssh=0 and ssh_mode=""
        assert metadata["ssh_mode"] == "disabled"
        assert metadata["working_dir"] == ""
        assert metadata["sparse_checkout"] is False
        assert metadata["pip_requirements"] == ""
        assert metadata["allow_pr"] is False
        assert metadata["enable_opencode"] is False
        assert metadata["enable_zai"] is False
        assert metadata["mounts"] == []
        assert metadata["copies"] == []

    def test_write_creates_secure_file(self, sandbox_home):
        """Write creates file with 600 permissions."""
        write_sandbox_metadata(
            "secure-test",
            repo_url="https://github.com/test/repo.git",
            branch="main",
        )

        metadata_path = sandbox_home / "claude-config" / "secure-test" / "metadata.json"
        assert metadata_path.exists()

        # Check permissions are 0o600
        file_mode = metadata_path.stat().st_mode
        assert stat.S_IMODE(file_mode) == 0o600

    def test_auto_derives_ssh_mode_when_missing(self, sandbox_home):
        """Load auto-derives ssh_mode from sync_ssh if missing."""
        # Write metadata with sync_ssh=1 but no ssh_mode
        metadata_path = sandbox_home / "claude-config" / "test" / "metadata.json"
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_text(json.dumps({
            "repo_url": "https://github.com/test/repo.git",
            "branch": "main",
            "sync_ssh": 1,
            "ssh_mode": "",
            "from_branch": "",
            "network_mode": "",
            "working_dir": "",
            "sparse_checkout": False,
            "pip_requirements": "",
            "allow_pr": False,
            "enable_opencode": False,
            "enable_zai": False,
            "mounts": [],
            "copies": [],
        }))
        metadata_path.chmod(0o600)

        metadata = load_sandbox_metadata("test")
        assert metadata is not None
        assert metadata["ssh_mode"] == "always"

    def test_auto_derives_ssh_mode_disabled(self, sandbox_home):
        """Load auto-derives ssh_mode as disabled when sync_ssh=0."""
        metadata_path = sandbox_home / "claude-config" / "test" / "metadata.json"
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_text(json.dumps({
            "repo_url": "https://github.com/test/repo.git",
            "branch": "main",
            "sync_ssh": 0,
            "ssh_mode": "",
            "from_branch": "",
            "network_mode": "",
            "working_dir": "",
            "sparse_checkout": False,
            "pip_requirements": "",
            "allow_pr": False,
            "enable_opencode": False,
            "enable_zai": False,
            "mounts": [],
            "copies": [],
        }))
        metadata_path.chmod(0o600)

        metadata = load_sandbox_metadata("test")
        assert metadata is not None
        assert metadata["ssh_mode"] == "disabled"


class TestMetadataMissingAndCorrupt:
    """Tests for handling missing and corrupt metadata files."""

    def test_missing_metadata_returns_none(self, sandbox_home):
        """Load returns None for non-existent sandbox."""
        metadata = load_sandbox_metadata("nonexistent")
        assert metadata is None

    def test_corrupt_json_returns_none(self, sandbox_home):
        """Load returns None for corrupt JSON."""
        metadata_path = sandbox_home / "claude-config" / "corrupt" / "metadata.json"
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_text("not valid json {{{")
        metadata_path.chmod(0o600)

        metadata = load_sandbox_metadata("corrupt")
        assert metadata is None

    def test_insecure_metadata_returns_none(self, sandbox_home):
        """Load returns None if file fails security check."""
        metadata_path = sandbox_home / "claude-config" / "insecure" / "metadata.json"
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_text(json.dumps({
            "repo_url": "https://github.com/test/repo.git",
            "branch": "main",
        }))
        # Make it world-writable
        metadata_path.chmod(0o666)

        metadata = load_sandbox_metadata("insecure")
        assert metadata is None

    def test_empty_json_returns_none(self, sandbox_home):
        """Load returns None for empty JSON file."""
        metadata_path = sandbox_home / "claude-config" / "empty" / "metadata.json"
        metadata_path.parent.mkdir(parents=True)
        metadata_path.write_text("")
        metadata_path.chmod(0o600)

        metadata = load_sandbox_metadata("empty")
        assert metadata is None


class TestLegacyMetadataMigration:
    """Tests for legacy ENV format metadata migration."""

    def test_parse_legacy_basic_fields(self, tmp_path):
        """Parse legacy ENV format with basic fields."""
        legacy_file = tmp_path / "metadata.env"
        legacy_file.write_text("""
SANDBOX_REPO_URL="https://github.com/user/repo.git"
SANDBOX_BRANCH="main"
SANDBOX_FROM_BRANCH="dev"
SANDBOX_NETWORK_MODE="limited"
SANDBOX_SYNC_SSH="1"
""")

        data = _parse_legacy_metadata(legacy_file)

        assert data["repo_url"] == "https://github.com/user/repo.git"
        assert data["branch"] == "main"
        assert data["from_branch"] == "dev"
        assert data["network_mode"] == "limited"
        assert data["sync_ssh"] == "1"

    def test_parse_legacy_with_arrays(self, tmp_path):
        """Parse legacy ENV format with array syntax."""
        legacy_file = tmp_path / "metadata.env"
        legacy_file.write_text("""
SANDBOX_REPO_URL="https://github.com/user/repo.git"
SANDBOX_BRANCH="main"
SANDBOX_MOUNTS=(host:/container "path with spaces:/dest")
SANDBOX_COPIES=(file1.txt:/dest1 file2.txt:/dest2)
""")

        data = _parse_legacy_metadata(legacy_file)

        assert data["mounts"] == ["host:/container", "path with spaces:/dest"]
        assert data["copies"] == ["file1.txt:/dest1", "file2.txt:/dest2"]

    def test_parse_legacy_ignores_comments(self, tmp_path):
        """Parse legacy ENV format ignoring comments and blank lines."""
        legacy_file = tmp_path / "metadata.env"
        legacy_file.write_text("""
# This is a comment
SANDBOX_REPO_URL="https://github.com/user/repo.git"

# Another comment
SANDBOX_BRANCH="main"
""")

        data = _parse_legacy_metadata(legacy_file)

        assert data["repo_url"] == "https://github.com/user/repo.git"
        assert data["branch"] == "main"

    def test_load_migrates_legacy_to_json(self, sandbox_home):
        """Load auto-migrates legacy ENV format to JSON."""
        # Create legacy file
        legacy_path = sandbox_home / "claude-config" / "legacy" / "metadata.env"
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_text("""
SANDBOX_REPO_URL="https://github.com/user/repo.git"
SANDBOX_BRANCH="main"
SANDBOX_SYNC_SSH="1"
SANDBOX_MOUNTS=(host:/container)
""")
        legacy_path.chmod(0o600)

        # Load should migrate
        metadata = load_sandbox_metadata("legacy")

        # Check data was loaded correctly
        assert metadata is not None
        assert metadata["repo_url"] == "https://github.com/user/repo.git"
        assert metadata["branch"] == "main"
        # sync_ssh is parsed as string "1" from legacy, kept as string in returned data
        # but converted to int when written to JSON
        assert metadata["ssh_mode"] == "always"  # Auto-derived
        assert metadata["mounts"] == ["host:/container"]

        # Check JSON file was created
        json_path = sandbox_home / "claude-config" / "legacy" / "metadata.json"
        assert json_path.exists()
        assert metadata_is_secure(json_path)

        # Verify the JSON file has integer sync_ssh
        with open(json_path) as f:
            json_data = json.load(f)
            assert json_data["sync_ssh"] == 1  # Should be int in JSON

        # Check legacy file was removed
        assert not legacy_path.exists()

    def test_load_prefers_json_over_legacy(self, sandbox_home):
        """Load prefers JSON metadata when both formats exist."""
        base_path = sandbox_home / "claude-config" / "both"
        base_path.mkdir(parents=True)

        # Create both formats
        json_path = base_path / "metadata.json"
        json_path.write_text(json.dumps({
            "repo_url": "https://github.com/json/repo.git",
            "branch": "json-branch",
            "from_branch": "",
            "network_mode": "",
            "sync_ssh": 0,
            "ssh_mode": "disabled",
            "working_dir": "",
            "sparse_checkout": False,
            "pip_requirements": "",
            "allow_pr": False,
            "enable_opencode": False,
            "enable_zai": False,
            "mounts": [],
            "copies": [],
        }))
        json_path.chmod(0o600)

        legacy_path = base_path / "metadata.env"
        legacy_path.write_text("""
SANDBOX_REPO_URL="https://github.com/legacy/repo.git"
SANDBOX_BRANCH="legacy-branch"
""")
        legacy_path.chmod(0o600)

        # Load should use JSON
        metadata = load_sandbox_metadata("both")
        assert metadata["repo_url"] == "https://github.com/json/repo.git"
        assert metadata["branch"] == "json-branch"

    def test_legacy_insecure_returns_none(self, sandbox_home):
        """Load returns None if legacy file fails security check."""
        legacy_path = sandbox_home / "claude-config" / "insecure-legacy" / "metadata.env"
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_text("""
SANDBOX_REPO_URL="https://github.com/user/repo.git"
SANDBOX_BRANCH="main"
""")
        legacy_path.chmod(0o666)  # World-writable

        metadata = load_sandbox_metadata("insecure-legacy")
        assert metadata is None


class TestListSandboxes:
    """Tests for list_sandboxes() directory scanning."""

    def test_list_empty_returns_empty_list(self, sandbox_home):
        """List returns empty list when no sandboxes exist."""
        result = list_sandboxes()
        assert result == []

    def test_list_returns_correct_sandbox_set(self, sandbox_home):
        """List returns all valid sandboxes with metadata."""
        # Create three sandboxes
        write_sandbox_metadata("sandbox1", repo_url="https://github.com/test/repo1.git", branch="main")
        write_sandbox_metadata("sandbox2", repo_url="https://github.com/test/repo2.git", branch="dev")
        write_sandbox_metadata("sandbox3", repo_url="https://github.com/test/repo3.git", branch="feature")

        result = list_sandboxes()

        assert len(result) == 3
        names = {sb["name"] for sb in result}
        assert names == {"sandbox1", "sandbox2", "sandbox3"}

        # Check one sandbox has complete data
        sb1 = next(sb for sb in result if sb["name"] == "sandbox1")
        assert sb1["repo_url"] == "https://github.com/test/repo1.git"
        assert sb1["branch"] == "main"

    def test_list_skips_directories_without_metadata(self, sandbox_home):
        """List skips directories that don't have metadata."""
        # Create sandbox with metadata
        write_sandbox_metadata("valid", repo_url="https://github.com/test/repo.git", branch="main")

        # Create directory without metadata
        empty_dir = sandbox_home / "claude-config" / "empty"
        empty_dir.mkdir(parents=True)

        result = list_sandboxes()

        assert len(result) == 1
        assert result[0]["name"] == "valid"

    def test_list_skips_insecure_metadata(self, sandbox_home):
        """List skips sandboxes with insecure metadata."""
        # Create valid sandbox
        write_sandbox_metadata("valid", repo_url="https://github.com/test/repo.git", branch="main")

        # Create sandbox with insecure metadata
        insecure_path = sandbox_home / "claude-config" / "insecure" / "metadata.json"
        insecure_path.parent.mkdir(parents=True)
        insecure_path.write_text(json.dumps({
            "repo_url": "https://github.com/test/insecure.git",
            "branch": "main",
        }))
        insecure_path.chmod(0o666)

        result = list_sandboxes()

        assert len(result) == 1
        assert result[0]["name"] == "valid"

    def test_list_returns_sorted_results(self, sandbox_home):
        """List returns sandboxes in sorted order by name."""
        write_sandbox_metadata("zebra", repo_url="https://github.com/test/z.git", branch="main")
        write_sandbox_metadata("alpha", repo_url="https://github.com/test/a.git", branch="main")
        write_sandbox_metadata("beta", repo_url="https://github.com/test/b.git", branch="main")

        result = list_sandboxes()
        names = [sb["name"] for sb in result]

        assert names == ["alpha", "beta", "zebra"]


class TestInspectSandbox:
    """Tests for inspect_sandbox() single sandbox query."""

    def test_inspect_existing_sandbox(self, sandbox_home):
        """Inspect returns full metadata with name field."""
        write_sandbox_metadata(
            "test-inspect",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            from_branch="dev",
        )

        result = inspect_sandbox("test-inspect")

        assert result is not None
        assert result["name"] == "test-inspect"
        assert result["repo_url"] == "https://github.com/test/repo.git"
        assert result["branch"] == "main"
        assert result["from_branch"] == "dev"

    def test_inspect_nonexistent_returns_none(self, sandbox_home):
        """Inspect returns None for non-existent sandbox."""
        result = inspect_sandbox("nonexistent")
        assert result is None

    def test_inspect_insecure_returns_none(self, sandbox_home):
        """Inspect returns None if metadata is insecure."""
        insecure_path = sandbox_home / "claude-config" / "insecure" / "metadata.json"
        insecure_path.parent.mkdir(parents=True)
        insecure_path.write_text(json.dumps({
            "repo_url": "https://github.com/test/repo.git",
            "branch": "main",
        }))
        insecure_path.chmod(0o666)

        result = inspect_sandbox("insecure")
        assert result is None


class TestCastNewPresets:
    """Tests for cast-new preset persistence."""

    def test_save_and_load_preset(self, sandbox_home):
        """Save and load a cast-new preset."""
        save_cast_preset(
            "my-preset",
            repo="https://github.com/test/repo.git",
            branch="main",
            from_branch="dev",
            working_dir="/workspace",
            sparse=True,
            pip_requirements="requirements.txt",
            allow_pr=True,
            network_mode="limited",
            sync_ssh=True,
            enable_opencode=True,
            enable_zai=False,
            mounts=["host:/container"],
            copies=["file.txt:/dest"],
        )

        preset = load_cast_preset("my-preset")

        assert preset is not None
        assert preset["repo"] == "https://github.com/test/repo.git"
        assert preset["branch"] == "main"
        assert preset["from_branch"] == "dev"
        assert preset["working_dir"] == "/workspace"
        assert preset["sparse"] is True
        assert preset["pip_requirements"] == "requirements.txt"
        assert preset["allow_pr"] is True
        assert preset["network_mode"] == "limited"
        assert preset["sync_ssh"] is True
        assert preset["enable_opencode"] is True
        assert preset["enable_zai"] is False
        assert preset["mounts"] == ["host:/container"]
        assert preset["copies"] == ["file.txt:/dest"]

    def test_load_nonexistent_preset_returns_none(self, sandbox_home):
        """Load returns None for non-existent preset."""
        result = load_cast_preset("nonexistent")
        assert result is None

    def test_list_cast_presets(self, sandbox_home):
        """List returns all preset names."""
        save_cast_preset("preset1", repo="https://github.com/test/repo1.git")
        save_cast_preset("preset2", repo="https://github.com/test/repo2.git")
        save_cast_preset("preset3", repo="https://github.com/test/repo3.git")

        presets = list_cast_presets()

        assert presets == ["preset1", "preset2", "preset3"]

    def test_list_presets_empty(self, sandbox_home):
        """List returns empty list when no presets exist."""
        result = list_cast_presets()
        assert result == []

    def test_show_cast_preset(self, sandbox_home):
        """Show returns pretty-printed JSON for preset."""
        save_cast_preset(
            "show-test",
            repo="https://github.com/test/repo.git",
            branch="main",
        )

        result = show_cast_preset("show-test")

        assert result is not None
        data = json.loads(result)
        assert "args" in data
        assert data["args"]["repo"] == "https://github.com/test/repo.git"

    def test_show_nonexistent_preset_returns_none(self, sandbox_home):
        """Show returns None for non-existent preset."""
        result = show_cast_preset("nonexistent")
        assert result is None

    def test_delete_cast_preset(self, sandbox_home):
        """Delete removes a preset and returns True."""
        save_cast_preset("delete-test", repo="https://github.com/test/repo.git")

        result = delete_cast_preset("delete-test")

        assert result is True
        assert load_cast_preset("delete-test") is None

    def test_delete_nonexistent_returns_false(self, sandbox_home):
        """Delete returns False for non-existent preset."""
        result = delete_cast_preset("nonexistent")
        assert result is False

    def test_preset_has_command_line(self, sandbox_home):
        """Preset includes command_line field for display."""
        save_cast_preset(
            "cmd-test",
            repo="https://github.com/test/repo.git",
            branch="main",
            sparse=True,
        )

        preset = load_cast_preset("cmd-test")

        assert preset is not None
        assert "command_line" in preset
        assert "cast new" in preset["command_line"]
        assert "https://github.com/test/repo.git" in preset["command_line"]
        assert "--sparse" in preset["command_line"]

    def test_load_preset_coerces_string_booleans(self, sandbox_home):
        """String booleans in preset args are normalized safely."""
        preset_path = sandbox_home / "presets" / "string-bool.json"
        preset_path.parent.mkdir(parents=True, exist_ok=True)
        preset_path.write_text(json.dumps({
            "command_line": "cast new demo/repo",
            "args": {
                "repo": "demo/repo",
                "sparse": "0",
                "allow_pr": "false",
                "sync_ssh": "0",
                "enable_opencode": "true",
                "enable_zai": "1",
            },
        }))

        preset = load_cast_preset("string-bool")

        assert preset is not None
        assert preset["sparse"] is False
        assert preset["allow_pr"] is False
        assert preset["sync_ssh"] is False
        assert preset["enable_opencode"] is True
        assert preset["enable_zai"] is True


class TestLastCastNew:
    """Tests for last cast-new command persistence."""

    def test_save_and_load_last_cast_new(self, sandbox_home):
        """Save and load last cast-new command."""
        command_line = save_last_cast_new(
            repo="https://github.com/test/repo.git",
            branch="main",
            working_dir="/workspace",
            sparse=True,
            allow_pr=True,
        )

        assert "cast new" in command_line

        last = load_last_cast_new()

        assert last is not None
        assert last["repo"] == "https://github.com/test/repo.git"
        assert last["branch"] == "main"
        assert last["working_dir"] == "/workspace"
        assert last["sparse"] is True
        assert last["allow_pr"] is True

    def test_load_nonexistent_returns_none(self, sandbox_home):
        """Load returns None when no last cast-new exists."""
        result = load_last_cast_new()
        assert result is None

    def test_save_overwrites_previous(self, sandbox_home):
        """Save overwrites previous last cast-new command."""
        save_last_cast_new(repo="https://github.com/test/first.git", branch="main")
        save_last_cast_new(repo="https://github.com/test/second.git", branch="dev")

        last = load_last_cast_new()

        assert last["repo"] == "https://github.com/test/second.git"
        assert last["branch"] == "dev"

    def test_load_last_cast_new_coerces_string_booleans(self, sandbox_home):
        """.last-cast-new JSON with string booleans is normalized safely."""
        last_path = sandbox_home / ".last-cast-new.json"
        last_path.write_text(json.dumps({
            "command_line": "cast new demo/repo",
            "args": {
                "repo": "demo/repo",
                "sparse": "0",
                "allow_pr": "false",
                "sync_ssh": "0",
                "enable_opencode": "1",
                "enable_zai": "yes",
            },
        }))

        last = load_last_cast_new()

        assert last is not None
        assert last["sparse"] is False
        assert last["allow_pr"] is False
        assert last["sync_ssh"] is False
        assert last["enable_opencode"] is True
        assert last["enable_zai"] is True


class TestLastAttach:
    """Tests for last-attach state persistence."""

    def test_save_and_load_last_attach(self, sandbox_home):
        """Save and load last attached sandbox name."""
        save_last_attach("my-sandbox")

        result = load_last_attach()

        assert result == "my-sandbox"

    def test_load_nonexistent_returns_none(self, sandbox_home):
        """Load returns None when no last attach exists."""
        result = load_last_attach()
        assert result is None

    def test_save_overwrites_previous(self, sandbox_home):
        """Save overwrites previous last attach."""
        save_last_attach("first-sandbox")
        save_last_attach("second-sandbox")

        result = load_last_attach()

        assert result == "second-sandbox"

    def test_load_empty_sandbox_name_returns_none(self, sandbox_home):
        """Load returns None if sandbox_name is empty."""
        # Manually create file with empty name
        last_attach_path = sandbox_home / ".last-attach.json"
        last_attach_path.write_text(json.dumps({
            "timestamp": "2024-01-01T00:00:00Z",
            "sandbox_name": "",
        }))

        result = load_last_attach()
        assert result is None


class TestSecureWrite:
    """Tests for _secure_write() helper."""

    def test_creates_parent_directories(self, sandbox_home):
        """Secure write creates parent directories as needed."""
        write_sandbox_metadata(
            "nested-path-sandbox",
            repo_url="https://github.com/test/repo.git",
            branch="main",
        )

        metadata_path = sandbox_home / "claude-config" / "nested-path-sandbox" / "metadata.json"
        assert metadata_path.exists()

    def test_rejects_path_traversal_in_name(self, sandbox_home):
        """Sandbox names with path separators are rejected."""
        import pytest as _pytest
        with _pytest.raises(ValueError):
            write_sandbox_metadata(
                "nested/path/sandbox",
                repo_url="https://github.com/test/repo.git",
                branch="main",
            )

    def test_sets_600_permissions(self, sandbox_home):
        """Secure write sets 600 permissions on file."""
        write_sandbox_metadata(
            "perms-test",
            repo_url="https://github.com/test/repo.git",
            branch="main",
        )

        metadata_path = sandbox_home / "claude-config" / "perms-test" / "metadata.json"
        file_mode = metadata_path.stat().st_mode

        assert stat.S_IMODE(file_mode) == 0o600


class TestEdgeCases:
    """Tests for edge cases and unusual inputs."""

    def test_empty_lists_preserved(self, sandbox_home):
        """Empty mounts and copies lists are preserved."""
        write_sandbox_metadata(
            "empty-lists",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            mounts=[],
            copies=[],
        )

        metadata = load_sandbox_metadata("empty-lists")

        assert metadata["mounts"] == []
        assert metadata["copies"] == []

    def test_none_lists_become_empty(self, sandbox_home):
        """None values for lists become empty lists."""
        write_sandbox_metadata(
            "none-lists",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            mounts=None,
            copies=None,
        )

        metadata = load_sandbox_metadata("none-lists")

        assert metadata["mounts"] == []
        assert metadata["copies"] == []

    def test_special_characters_in_fields(self, sandbox_home):
        """Special characters in fields are preserved."""
        write_sandbox_metadata(
            "special-chars",
            repo_url="https://github.com/user/repo-with-dashes_and_underscores.git",
            branch="feature/my-feature",
            from_branch="release/v1.0",
            working_dir="/path/with spaces/and-dashes",
        )

        metadata = load_sandbox_metadata("special-chars")

        assert metadata["repo_url"] == "https://github.com/user/repo-with-dashes_and_underscores.git"
        assert metadata["branch"] == "feature/my-feature"
        assert metadata["from_branch"] == "release/v1.0"
        assert metadata["working_dir"] == "/path/with spaces/and-dashes"

    def test_unicode_in_fields(self, sandbox_home):
        """Unicode characters in fields are preserved."""
        write_sandbox_metadata(
            "unicode-test",
            repo_url="https://github.com/test/repo.git",
            branch="main",
            working_dir="/workspace/日本語/文字",
        )

        metadata = load_sandbox_metadata("unicode-test")

        assert metadata["working_dir"] == "/workspace/日本語/文字"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
