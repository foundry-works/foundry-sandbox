"""Unit tests for foundation modules.

Covers:
  - foundry_sandbox.constants: directory getters and runtime flag defaults
  - foundry_sandbox.models: Pydantic model construction and serialization round-trips
  - foundry_sandbox.config: JSON load/write/merge operations
  - foundry_sandbox.paths: path derivation and filesystem helpers
"""

import json
import os
from pathlib import Path

import pytest

from foundry_sandbox.constants import (
    get_sandbox_home,
    get_repos_dir,
    get_claude_configs_dir,
    get_sandbox_debug,
    get_sandbox_verbose,
    get_sandbox_assume_yes,
)
from foundry_sandbox.config import (
    load_json,
    write_json,
    deep_merge,
    deep_merge_no_overwrite,
    json_escape,
    json_array_from_lines,
)
from foundry_sandbox.models import SbxSandboxMetadata
from foundry_sandbox.paths import (
    SandboxPaths,
    path_claude_config,
    path_claude_home,
    path_metadata_file,
    path_last_cast_new,
    path_last_attach,
    path_presets_dir,
    path_preset_file,
    derive_sandbox_paths,
    ensure_dir,
    safe_remove,
    resolve_host_worktree_path,
    find_next_sandbox_name,
)


# ============================================================================
# Constants Tests
# ============================================================================


class TestConstantsDirectoryGetters:
    """Tests for directory path getters with env var overrides."""

    def test_sandbox_home_default(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_HOME", raising=False)
        result = get_sandbox_home()
        assert result.name == ".sandboxes"
        assert result.parent.name == os.path.basename(os.path.expanduser("~"))

    def test_sandbox_home_override(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/test-sandboxes")
        result = get_sandbox_home()
        assert str(result) == "/tmp/test-sandboxes"

    def test_repos_dir(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/sb")
        assert str(get_repos_dir()) == "/tmp/sb/repos"

    def test_claude_configs_dir(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/sb")
        assert str(get_claude_configs_dir()) == "/tmp/sb/claude-config"


class TestConstantsRuntimeFlags:
    """Tests for runtime flag getters with env var defaults and overrides."""

    @pytest.mark.parametrize("getter,env_var,default", [
        (get_sandbox_debug, "SANDBOX_DEBUG", 0),
        (get_sandbox_verbose, "SANDBOX_VERBOSE", 0),
        (get_sandbox_assume_yes, "SANDBOX_ASSUME_YES", 0),
    ])
    def test_int_flag_default(self, monkeypatch, getter, env_var, default):
        monkeypatch.delenv(env_var, raising=False)
        assert getter() == default

    @pytest.mark.parametrize("getter,env_var", [
        (get_sandbox_debug, "SANDBOX_DEBUG"),
        (get_sandbox_verbose, "SANDBOX_VERBOSE"),
        (get_sandbox_assume_yes, "SANDBOX_ASSUME_YES"),
    ])
    def test_int_flag_override(self, monkeypatch, getter, env_var):
        monkeypatch.setenv(env_var, "1")
        assert getter() == 1


# ============================================================================
# Paths Tests
# ============================================================================


class TestPathDerivation:
    """Tests for individual path resolution functions with known inputs/outputs."""

    @pytest.fixture(autouse=True)
    def set_sandbox_home(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/sb")

    def test_path_claude_config(self):
        assert str(path_claude_config("my-sandbox")) == "/tmp/sb/claude-config/my-sandbox"

    def test_path_claude_home(self):
        assert str(path_claude_home("my-sandbox")) == "/tmp/sb/claude-config/my-sandbox/claude"

    def test_path_metadata_file(self):
        assert str(path_metadata_file("my-sandbox")) == "/tmp/sb/claude-config/my-sandbox/metadata.json"

    def test_path_last_cast_new(self):
        assert str(path_last_cast_new()) == "/tmp/sb/.last-cast-new.json"

    def test_path_last_attach(self):
        assert str(path_last_attach()) == "/tmp/sb/.last-attach.json"

    def test_path_presets_dir(self):
        assert str(path_presets_dir()) == "/tmp/sb/presets"

    def test_path_preset_file(self):
        assert str(path_preset_file("default")) == "/tmp/sb/presets/default.json"


class TestDeriveSandboxPaths:
    """Tests for derive_sandbox_paths composite function."""

    @pytest.fixture(autouse=True)
    def set_sandbox_home(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/sb")

    def test_returns_sandbox_paths_tuple(self):
        from unittest.mock import patch
        with patch("foundry_sandbox.paths.resolve_host_worktree_path", return_value=Path("/repo/.sbx/test-box-worktrees/br")):
            result = derive_sandbox_paths("test-box")
        assert isinstance(result, SandboxPaths)

    def test_worktree_path_from_metadata(self):
        from unittest.mock import patch
        with patch("foundry_sandbox.paths.resolve_host_worktree_path", return_value=Path("/repo/.sbx/test-box-worktrees/br")):
            result = derive_sandbox_paths("test-box")
        assert str(result.worktree_path) == "/repo/.sbx/test-box-worktrees/br"

    def test_claude_config_path(self):
        from unittest.mock import patch
        with patch("foundry_sandbox.paths.resolve_host_worktree_path", return_value=Path("/repo/.sbx/test-box-worktrees/br")):
            result = derive_sandbox_paths("test-box")
        assert str(result.claude_config_path) == "/tmp/sb/claude-config/test-box"

    def test_claude_home_path(self):
        from unittest.mock import patch
        with patch("foundry_sandbox.paths.resolve_host_worktree_path", return_value=Path("/repo/.sbx/test-box-worktrees/br")):
            result = derive_sandbox_paths("test-box")
        assert str(result.claude_home_path) == "/tmp/sb/claude-config/test-box/claude"


class TestPathSafetyAssertions:
    """Tests for path traversal prevention via _assert_safe_path_component."""

    @pytest.fixture(autouse=True)
    def set_sandbox_home(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/sb")

    @pytest.mark.parametrize("bad_name", [
        "../evil",
        "../../etc/passwd",
        "foo/bar",
        "foo\\bar",
        "..",
        ".",
        "",
    ])
    def test_path_claude_config_rejects_traversal(self, bad_name):
        with pytest.raises(ValueError):
            path_claude_config(bad_name)

    @pytest.mark.parametrize("bad_name", [
        "../evil",
        "../../etc/passwd",
    ])
    def test_path_preset_file_rejects_traversal(self, bad_name):
        with pytest.raises(ValueError):
            path_preset_file(bad_name)

    @pytest.mark.parametrize("bad_name", ["../x", "a/b", ".", "..", ""])
    def test_derive_sandbox_paths_rejects_traversal(self, bad_name):
        with pytest.raises(ValueError):
            derive_sandbox_paths(bad_name)

    def test_valid_names_pass(self):
        from unittest.mock import patch
        path_claude_config("my-sandbox")
        path_preset_file("default")
        with patch("foundry_sandbox.paths.resolve_host_worktree_path", return_value=Path("/repo/.sbx/test-box-worktrees/br")):
            derive_sandbox_paths("test-box")


class TestFilesystemHelpers:
    """Tests for ensure_dir and safe_remove."""

    def test_ensure_dir_creates_directory(self, tmp_path):
        target = tmp_path / "a" / "b" / "c"
        result = ensure_dir(target)
        assert target.is_dir()
        assert result == target

    def test_ensure_dir_existing(self, tmp_path):
        result = ensure_dir(tmp_path)
        assert result == tmp_path

    def test_ensure_dir_from_string(self, tmp_path):
        target = str(tmp_path / "from_str")
        result = ensure_dir(target)
        assert result.is_dir()

    def test_safe_remove_file(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("data")
        safe_remove(f)
        assert not f.exists()

    def test_safe_remove_directory(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        (d / "file.txt").write_text("data")
        safe_remove(d)
        assert not d.exists()

    def test_safe_remove_nonexistent(self, tmp_path):
        safe_remove(tmp_path / "nope")


# ============================================================================
# Models Tests
# ============================================================================


class TestSbxSandboxMetadata:
    """Tests for Pydantic SbxSandboxMetadata model."""

    def test_required_fields_only(self):
        m = SbxSandboxMetadata(
            sbx_name="test-sandbox",
            repo_url="https://github.com/user/repo",
            branch="main",
            agent="claude",
        )
        assert m.repo_url == "https://github.com/user/repo"
        assert m.branch == "main"
        assert m.agent == "claude"
        assert m.sbx_name == "test-sandbox"

    def test_defaults(self):
        m = SbxSandboxMetadata(sbx_name="test", repo_url="url", branch="br", agent="claude")
        assert m.from_branch == ""
        assert m.working_dir == ""
        assert m.pip_requirements == ""
        assert m.allow_pr is False
        assert m.copies == []

    def test_serialization_round_trip(self):
        original = SbxSandboxMetadata(
            sbx_name="test",
            repo_url="https://github.com/user/repo",
            branch="main",
            agent="codex",
            copies=["/a:/b"],
            allow_pr=True,
        )
        json_str = original.model_dump_json()
        restored = SbxSandboxMetadata.model_validate_json(json_str)
        assert restored == original

    def test_dict_round_trip(self):
        original = SbxSandboxMetadata(
            sbx_name="test",
            repo_url="url",
            branch="br",
            agent="claude",
            copies=["a:b"],
        )
        d = original.model_dump()
        assert isinstance(d, dict)
        restored = SbxSandboxMetadata(**d)
        assert restored == original

    def test_missing_required_field_raises(self):
        with pytest.raises(Exception):
            SbxSandboxMetadata(sbx_name="test", repo_url="url", branch="br")  # missing agent


# ============================================================================
# Config Tests
# ============================================================================


class TestLoadJson:
    """Tests for load_json."""

    def test_valid_json(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text('{"key": "value", "num": 42}')
        assert load_json(str(f)) == {"key": "value", "num": 42}

    def test_missing_file(self, tmp_path):
        assert load_json(str(tmp_path / "missing.json")) == {}

    def test_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not valid json {{{")
        assert load_json(str(f)) == {}

    def test_non_dict_json(self, tmp_path):
        f = tmp_path / "array.json"
        f.write_text("[1, 2, 3]")
        assert load_json(str(f)) == {}

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.json"
        f.write_text("")
        assert load_json(str(f)) == {}


class TestWriteJson:
    """Tests for write_json."""

    def test_writes_valid_json(self, tmp_path):
        f = tmp_path / "out.json"
        write_json(str(f), {"a": 1, "b": [2, 3]})
        assert json.loads(f.read_text()) == {"a": 1, "b": [2, 3]}

    def test_creates_parent_dirs(self, tmp_path):
        f = tmp_path / "deep" / "nested" / "out.json"
        write_json(str(f), {"nested": True})
        assert f.exists()
        assert json.loads(f.read_text()) == {"nested": True}

    def test_trailing_newline(self, tmp_path):
        f = tmp_path / "out.json"
        write_json(str(f), {})
        assert f.read_text().endswith("\n")


class TestDeepMerge:
    """Tests for deep_merge."""

    def test_flat_merge(self):
        assert deep_merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_overlay_wins(self):
        assert deep_merge({"a": 1}, {"a": 2}) == {"a": 2}

    def test_nested_merge(self):
        base = {"x": {"a": 1, "b": 2}}
        overlay = {"x": {"b": 3, "c": 4}}
        assert deep_merge(base, overlay) == {"x": {"a": 1, "b": 3, "c": 4}}

    def test_deep_nested(self):
        base = {"a": {"b": {"c": 1}}}
        overlay = {"a": {"b": {"d": 2}}}
        assert deep_merge(base, overlay) == {"a": {"b": {"c": 1, "d": 2}}}

    def test_overlay_replaces_non_dict(self):
        assert deep_merge({"a": "string"}, {"a": {"nested": True}}) == {"a": {"nested": True}}

    def test_empty_base(self):
        assert deep_merge({}, {"a": 1}) == {"a": 1}

    def test_empty_overlay(self):
        assert deep_merge({"a": 1}, {}) == {"a": 1}


class TestDeepMergeNoOverwrite:
    """Tests for deep_merge_no_overwrite."""

    def test_base_wins(self):
        assert deep_merge_no_overwrite({"a": 1}, {"a": 99}) == {"a": 1}

    def test_fills_missing(self):
        assert deep_merge_no_overwrite({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_nested_base_wins(self):
        base = {"x": {"a": 1}}
        overlay = {"x": {"a": 99, "b": 2}}
        assert deep_merge_no_overwrite(base, overlay) == {"x": {"a": 1, "b": 2}}

    def test_empty_base(self):
        assert deep_merge_no_overwrite({}, {"a": 1}) == {"a": 1}


class TestJsonEscape:
    """Tests for json_escape."""

    def test_no_special_chars(self):
        assert json_escape("hello") == "hello"

    def test_backslash(self):
        assert json_escape("a\\b") == "a\\\\b"

    def test_quotes(self):
        assert json_escape('say "hi"') == 'say \\"hi\\"'

    def test_newline(self):
        assert json_escape("line1\nline2") == "line1\\nline2"

    def test_tab(self):
        assert json_escape("col1\tcol2") == "col1\\tcol2"

    def test_carriage_return(self):
        assert json_escape("a\rb") == "a\\rb"

    def test_combined(self):
        assert json_escape('a\\b\n"c"') == 'a\\\\b\\n\\"c\\"'


class TestJsonArrayFromLines:
    """Tests for json_array_from_lines."""

    def test_empty_input(self):
        assert json_array_from_lines("") == "[]"

    def test_single_line(self):
        result = json_array_from_lines('"hello"')
        assert '"hello"' in result
        assert result.startswith("[")
        assert result.endswith("]")

    def test_multiple_lines(self):
        result = json_array_from_lines('"a"\n"b"\n"c"')
        assert '"a"' in result
        assert '"b"' in result
        assert '"c"' in result

    def test_skips_blank_lines(self):
        result = json_array_from_lines('"a"\n\n"b"\n')
        assert '"a"' in result
        assert '"b"' in result
        lines = [line.strip() for line in result.splitlines() if line.strip() and line.strip() not in ("[", "]")]
        assert len(lines) == 2


# ============================================================================
# EnvironmentScope Tests
# ============================================================================


class TestEnvironmentScope:
    """Tests for environment_scope context manager."""

    def test_restores_on_normal_exit(self, monkeypatch):
        from foundry_sandbox.utils import environment_scope

        monkeypatch.setenv("ES_TEST_KEY", "original")
        with environment_scope({"ES_TEST_KEY": "modified"}):
            assert os.environ["ES_TEST_KEY"] == "modified"
        assert os.environ["ES_TEST_KEY"] == "original"

    def test_restores_on_exception(self, monkeypatch):
        from foundry_sandbox.utils import environment_scope

        monkeypatch.setenv("ES_TEST_KEY", "original")
        with pytest.raises(ValueError):
            with environment_scope({"ES_TEST_KEY": "modified"}):
                raise ValueError("boom")
        assert os.environ["ES_TEST_KEY"] == "original"

    def test_removes_vars_added_inside_scope(self, monkeypatch):
        from foundry_sandbox.utils import environment_scope

        monkeypatch.delenv("ES_NEW_VAR", raising=False)
        with environment_scope():
            os.environ["ES_NEW_VAR"] = "injected"
            assert os.environ["ES_NEW_VAR"] == "injected"
        assert "ES_NEW_VAR" not in os.environ

    def test_no_updates(self, monkeypatch):
        from foundry_sandbox.utils import environment_scope

        monkeypatch.setenv("ES_TEST_KEY", "original")
        with environment_scope():
            assert os.environ["ES_TEST_KEY"] == "original"
        assert os.environ["ES_TEST_KEY"] == "original"

    def test_multiple_updates(self, monkeypatch):
        from foundry_sandbox.utils import environment_scope

        monkeypatch.delenv("ES_A", raising=False)
        monkeypatch.delenv("ES_B", raising=False)
        with environment_scope({"ES_A": "1", "ES_B": "2"}):
            assert os.environ["ES_A"] == "1"
            assert os.environ["ES_B"] == "2"
        assert "ES_A" not in os.environ
        assert "ES_B" not in os.environ


# ============================================================================
# Phase 2 Path Tests
# ============================================================================


class TestResolveHostWorktreePath:
    """Tests for resolve_host_worktree_path."""

    @pytest.fixture(autouse=True)
    def set_sandbox_home(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_HOME", "/tmp/sb")

    def test_returns_metadata_host_worktree_path(self, tmp_path, monkeypatch):
        meta_dir = tmp_path / "claude-config" / "my-sandbox"
        meta_dir.mkdir(parents=True)
        metadata_file = meta_dir / "metadata.json"
        metadata_file.write_text(
            '{"sbx_name":"my-sandbox","repo_url":"url","branch":"br","agent":"claude",'
            '"host_worktree_path":"/repo/.sbx/my-sandbox-worktrees/br"}\n'
        )

        monkeypatch.setattr(
            "foundry_sandbox.paths.path_claude_config",
            lambda name: meta_dir,
        )
        monkeypatch.setattr(
            "foundry_sandbox.paths.path_metadata_file",
            lambda name: metadata_file,
        )

        result = resolve_host_worktree_path("my-sandbox")
        assert str(result) == "/repo/.sbx/my-sandbox-worktrees/br"

    def test_raises_when_no_host_worktree_path(self, monkeypatch):
        from unittest.mock import patch as mock_patch

        with mock_patch("foundry_sandbox.state.load_sandbox_metadata", return_value=None):
            with pytest.raises(ValueError, match="no host_worktree_path"):
                resolve_host_worktree_path("my-sandbox")

    def test_raises_when_empty_host_worktree_path(self, monkeypatch):
        from unittest.mock import patch as mock_patch

        with mock_patch(
            "foundry_sandbox.state.load_sandbox_metadata",
            return_value={"host_worktree_path": ""},
        ):
            with pytest.raises(ValueError, match="no host_worktree_path"):
                resolve_host_worktree_path("my-sandbox")


class TestFindNextSandboxName:
    """Tests for find_next_sandbox_name — only checks claude-config/."""

    @pytest.fixture(autouse=True)
    def set_sandbox_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SANDBOX_HOME", str(tmp_path))

    def test_returns_base_when_available(self, tmp_path):
        configs = tmp_path / "claude-config"
        configs.mkdir()
        result = find_next_sandbox_name("my-sandbox")
        assert result == "my-sandbox"

    def test_appends_suffix_on_collision(self, tmp_path):
        configs = tmp_path / "claude-config"
        configs.mkdir()
        (configs / "my-sandbox").mkdir()
        result = find_next_sandbox_name("my-sandbox")
        assert result == "my-sandbox-2"

    def test_only_checks_configs_not_worktrees(self, tmp_path):
        configs = tmp_path / "claude-config"
        configs.mkdir()
        worktrees = tmp_path / "worktrees"
        worktrees.mkdir()
        (worktrees / "my-sandbox").mkdir()
        # Worktree exists but config doesn't — name is available
        result = find_next_sandbox_name("my-sandbox")
        assert result == "my-sandbox"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
