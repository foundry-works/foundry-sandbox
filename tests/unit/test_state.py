"""Unit tests for foundry_sandbox/state.py module.

Tests sandbox metadata persistence, security validation, cast-new presets,
and last-attach state tracking with the sbx backend.
"""

import json
import pytest

from foundry_sandbox.state import (
    metadata_is_secure,
    patch_sandbox_metadata,
    write_sandbox_metadata,
    load_sandbox_metadata,
    list_sandboxes,
    save_last_cast_new,
    load_last_cast_new,
    save_cast_preset,
    load_cast_preset,
    list_cast_presets,
    show_cast_preset,
    delete_cast_preset,
    save_last_attach,
    load_last_attach,
)
from foundry_sandbox.models import SbxSandboxMetadata


@pytest.fixture
def sandbox_home(tmp_path, monkeypatch):
    """Set up isolated SANDBOX_HOME for each test."""
    monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))
    return tmp_path


class TestMetadataIsSecure:
    """Tests for metadata_is_secure() security validation."""

    def test_nonexistent_file_returns_false(self, tmp_path):
        result = metadata_is_secure(tmp_path / "missing.json")
        assert result is False

    def test_secure_file_returns_true(self, tmp_path):
        secure_file = tmp_path / "secure.json"
        secure_file.write_text("{}")
        secure_file.chmod(0o600)
        assert metadata_is_secure(secure_file) is True

    def test_group_writable_returns_false(self, tmp_path):
        insecure_file = tmp_path / "group_writable.json"
        insecure_file.write_text("{}")
        insecure_file.chmod(0o620)
        assert metadata_is_secure(insecure_file) is False

    def test_world_writable_returns_false(self, tmp_path):
        insecure_file = tmp_path / "world_writable.json"
        insecure_file.write_text("{}")
        insecure_file.chmod(0o602)
        assert metadata_is_secure(insecure_file) is False

    def test_readable_by_others_returns_true(self, tmp_path):
        readable_file = tmp_path / "readable.json"
        readable_file.write_text("{}")
        readable_file.chmod(0o644)
        assert metadata_is_secure(readable_file) is True


class TestMetadataWriteRead:
    """Tests for write_sandbox_metadata() and load_sandbox_metadata() round-trip."""

    def test_write_then_read_full(self, sandbox_home):
        write_sandbox_metadata(
            "test-sandbox",
            SbxSandboxMetadata(
                sbx_name="test-sandbox",
                agent="claude",
                repo_url="https://github.com/user/repo.git",
                branch="main",
                from_branch="dev",
                git_safety_enabled=True,
                working_dir="src",
                pip_requirements="requirements.txt",
                allow_pr=True,
                enable_opencode=True,
                enable_zai=False,
                copies=["file.txt:/dest/file.txt"],
            ),
        )

        metadata = load_sandbox_metadata("test-sandbox")

        assert metadata is not None
        assert metadata["sbx_name"] == "test-sandbox"
        assert metadata["agent"] == "claude"
        assert metadata["repo_url"] == "https://github.com/user/repo.git"
        assert metadata["branch"] == "main"
        assert metadata["from_branch"] == "dev"
        assert metadata["git_safety_enabled"] is True
        assert metadata["working_dir"] == "src"
        assert metadata["pip_requirements"] == "requirements.txt"
        assert metadata["allow_pr"] is True
        assert metadata["enable_opencode"] is True
        assert metadata["enable_zai"] is False
        assert metadata["copies"] == ["file.txt:/dest/file.txt"]

    def test_write_minimal_metadata(self, sandbox_home):
        write_sandbox_metadata(
            "minimal",
            SbxSandboxMetadata(
                sbx_name="minimal",
                agent="codex",
                repo_url="https://github.com/test/repo.git",
                branch="main",
            ),
        )

        metadata = load_sandbox_metadata("minimal")

        assert metadata is not None
        assert metadata["sbx_name"] == "minimal"
        assert metadata["agent"] == "codex"
        assert metadata["repo_url"] == "https://github.com/test/repo.git"
        assert metadata["branch"] == "main"
        assert metadata["from_branch"] == ""
        assert metadata["git_safety_enabled"] is True
        assert metadata["working_dir"] == ""
        assert metadata["pip_requirements"] == ""
        assert metadata["allow_pr"] is False
        assert metadata["enable_opencode"] is False
        assert metadata["enable_zai"] is False
        assert metadata["copies"] == []

    def test_load_nonexistent_returns_none(self, sandbox_home):
        assert load_sandbox_metadata("nonexistent") is None

    def test_load_empty_metadata_file(self, sandbox_home):
        config_dir = sandbox_home / "sandboxes" / "empty-sandbox"
        config_dir.mkdir(parents=True)
        meta_file = config_dir / "metadata.json"
        meta_file.write_text("")

        assert load_sandbox_metadata("empty-sandbox") is None

    def test_write_creates_config_directory(self, sandbox_home):
        config_dir = sandbox_home / "sandboxes" / "new-sandbox"
        assert not config_dir.exists()

        write_sandbox_metadata(
            "new-sandbox",
            SbxSandboxMetadata(
                sbx_name="new-sandbox",
                agent="claude",
                repo_url="https://github.com/org/repo",
                branch="main",
            ),
        )

        assert config_dir.exists()
        assert (config_dir / "metadata.json").exists()

    def test_metadata_json_is_valid(self, sandbox_home):
        write_sandbox_metadata(
            "json-check",
            SbxSandboxMetadata(
                sbx_name="json-check",
                agent="claude",
                repo_url="https://github.com/org/repo",
                branch="main",
            ),
        )

        config_dir = sandbox_home / "sandboxes" / "json-check"
        meta_file = config_dir / "metadata.json"
        data = json.loads(meta_file.read_text())
        assert data["sbx_name"] == "json-check"


class TestPatchMetadata:
    """Tests for patch_sandbox_metadata()."""

    def test_patch_single_field(self, sandbox_home):
        write_sandbox_metadata(
            "patch-test",
            SbxSandboxMetadata(
                sbx_name="patch-test",
                agent="claude",
                repo_url="https://github.com/org/repo",
                branch="main",
            ),
        )

        patch_sandbox_metadata("patch-test", branch="develop")

        metadata = load_sandbox_metadata("patch-test")
        assert metadata["branch"] == "develop"
        assert metadata["repo_url"] == "https://github.com/org/repo"

    def test_patch_multiple_fields(self, sandbox_home):
        write_sandbox_metadata(
            "patch-multi",
            SbxSandboxMetadata(
                sbx_name="patch-multi",
                agent="claude",
                repo_url="https://github.com/org/repo",
                branch="main",
            ),
        )

        patch_sandbox_metadata(
            "patch-multi",
            branch="feature-x",
            allow_pr=True,
        )

        metadata = load_sandbox_metadata("patch-multi")
        assert metadata["branch"] == "feature-x"
        assert metadata["allow_pr"] is True

    def test_patch_unknown_field_raises(self, sandbox_home):
        write_sandbox_metadata(
            "patch-bad",
            SbxSandboxMetadata(
                sbx_name="patch-bad",
                agent="claude",
                repo_url="u",
                branch="b",
            ),
        )

        with pytest.raises(ValueError, match="Unknown"):
            patch_sandbox_metadata("patch-bad", nonexistent_field="value")

    def test_patch_nonexistent_raises(self, sandbox_home):
        with pytest.raises(FileNotFoundError):
            patch_sandbox_metadata("no-such-sandbox", branch="x")


class TestListSandboxes:
    """Tests for list_sandboxes()."""

    def test_empty_home(self, sandbox_home):
        assert list_sandboxes() == []

    def test_lists_existing_sandboxes(self, sandbox_home):
        write_sandbox_metadata(
            "sbx-1",
            SbxSandboxMetadata(
                sbx_name="sbx-1",
                agent="claude",
                repo_url="https://github.com/org/repo",
                branch="main",
            ),
        )
        write_sandbox_metadata(
            "sbx-2",
            SbxSandboxMetadata(
                sbx_name="sbx-2",
                agent="codex",
                repo_url="https://github.com/org/other",
                branch="dev",
            ),
        )

        result = list_sandboxes()
        names = [s["name"] for s in result]
        assert "sbx-1" in names
        assert "sbx-2" in names
        assert len(result) == 2

    def test_skips_empty_config_dirs(self, sandbox_home):
        config_dir = sandbox_home / "sandboxes" / "empty"
        config_dir.mkdir(parents=True)

        assert list_sandboxes() == []


# ============================================================================
# Cast New Presets & History
# ============================================================================


class TestCastNewHistory:
    """Tests for save_last_cast_new() and load_last_cast_new()."""

    def test_save_and_load(self, sandbox_home):
        save_last_cast_new(
            repo="https://github.com/org/repo",
            agent="claude",
            branch="main",
        )

        result = load_last_cast_new()
        assert result is not None
        assert result["repo"] == "https://github.com/org/repo"
        assert result["agent"] == "claude"
        assert result["branch"] == "main"

    def test_load_nonexistent(self, sandbox_home):
        assert load_last_cast_new() is None

    def test_overwrites_previous(self, sandbox_home):
        save_last_cast_new(repo="first/repo", branch="main")
        save_last_cast_new(repo="second/repo", branch="dev")

        result = load_last_cast_new()
        assert result["repo"] == "second/repo"
        assert result["branch"] == "dev"

    def test_command_line_included(self, sandbox_home):
        save_last_cast_new(
            repo="org/repo",
            agent="codex",
            branch="feature-x",
            allow_pr=True,
        )

        result = load_last_cast_new()
        assert "command_line" in result
        assert "org/repo" in result["command_line"]

    def test_agent_roundtrip(self, sandbox_home):
        """Agent selection survives save/load cycle."""
        save_last_cast_new(
            repo="org/repo",
            agent="codex",
            branch="main",
        )
        result = load_last_cast_new()
        assert result["agent"] == "codex"

    def test_agent_default_is_claude(self, sandbox_home):
        save_last_cast_new(repo="org/repo")
        result = load_last_cast_new()
        assert result["agent"] == "claude"

    def test_template_roundtrip(self, sandbox_home):
        """Template and template_managed survive last-cast-new save/load."""
        save_last_cast_new(
            repo="org/repo",
            branch="main",
            template="preset-mysetup:latest",
            template_managed=True,
        )
        result = load_last_cast_new()
        assert result is not None
        assert result["template"] == "preset-mysetup:latest"
        assert result["template_managed"] is True

    def test_template_defaults_when_absent(self, sandbox_home):
        """Missing template fields default to empty string / False on load."""
        save_last_cast_new(repo="org/repo", branch="main")
        result = load_last_cast_new()
        assert result is not None
        assert result["template"] == ""
        assert result["template_managed"] is False


class TestCastPresets:
    """Tests for preset CRUD operations."""

    def test_save_and_load(self, sandbox_home):
        save_cast_preset(
            "my-preset",
            repo="org/repo",
            agent="claude",
            branch="main",
        )

        result = load_cast_preset("my-preset")
        assert result is not None
        assert result["repo"] == "org/repo"
        assert result["agent"] == "claude"

    def test_list_presets(self, sandbox_home):
        save_cast_preset("preset-a", repo="a/repo")
        save_cast_preset("preset-b", repo="b/repo")

        names = list_cast_presets()
        assert names == ["preset-a", "preset-b"]

    def test_show_preset(self, sandbox_home):
        save_cast_preset("show-me", repo="org/repo")

        output = show_cast_preset("show-me")
        assert output is not None
        data = json.loads(output)
        assert "args" in data

    def test_delete_preset(self, sandbox_home):
        save_cast_preset("delete-me", repo="org/repo")
        assert delete_cast_preset("delete-me") is True
        assert load_cast_preset("delete-me") is None

    def test_delete_nonexistent(self, sandbox_home):
        assert delete_cast_preset("nope") is False

    def test_load_nonexistent(self, sandbox_home):
        assert load_cast_preset("nope") is None

    def test_show_nonexistent(self, sandbox_home):
        assert show_cast_preset("nope") is None

    def test_agent_roundtrip(self, sandbox_home):
        """Agent selection survives preset save/load cycle."""
        save_cast_preset(
            "agent-test",
            repo="org/repo",
            agent="codex",
            branch="main",
        )
        result = load_cast_preset("agent-test")
        assert result is not None
        assert result["agent"] == "codex"

    def test_agent_roundtrip_non_claude(self, sandbox_home):
        """Non-default agents (gemini, kiro, etc.) are preserved."""
        for agent in ("codex", "gemini", "kiro", "copilot"):
            save_cast_preset(
                f"agent-{agent}",
                repo="org/repo",
                agent=agent,
            )
            result = load_cast_preset(f"agent-{agent}")
            assert result["agent"] == agent

    def test_template_roundtrip(self, sandbox_home):
        """Template and template_managed survive preset save/load."""
        save_cast_preset(
            "with-template",
            repo="org/repo",
            template="preset-with-template:latest",
            template_managed=True,
        )
        result = load_cast_preset("with-template")
        assert result is not None
        assert result["template"] == "preset-with-template:latest"
        assert result["template_managed"] is True

    def test_template_defaults_when_absent(self, sandbox_home):
        """Missing template fields default to empty string / False on load."""
        save_cast_preset("no-template", repo="org/repo")
        result = load_cast_preset("no-template")
        assert result is not None
        assert result["template"] == ""
        assert result["template_managed"] is False

    def test_unmanaged_template_preserved(self, sandbox_home):
        """A user-supplied non-managed template tag is saved with template_managed=False."""
        save_cast_preset(
            "custom-tag",
            repo="org/repo",
            template="user-custom:v1",
            template_managed=False,
        )
        result = load_cast_preset("custom-tag")
        assert result is not None
        assert result["template"] == "user-custom:v1"
        assert result["template_managed"] is False


# ============================================================================
# Last Attach State
# ============================================================================


class TestLastAttach:
    """Tests for save_last_attach() and load_last_attach()."""

    def test_save_and_load(self, sandbox_home):
        save_last_attach("my-sandbox")
        assert load_last_attach() == "my-sandbox"

    def test_load_nonexistent(self, sandbox_home):
        assert load_last_attach() is None

    def test_overwrites_previous(self, sandbox_home):
        save_last_attach("first")
        save_last_attach("second")
        assert load_last_attach() == "second"
