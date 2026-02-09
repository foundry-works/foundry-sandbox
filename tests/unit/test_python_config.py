"""Unit tests for extracted Python configuration modules.

Tests lib/python/ modules that were extracted from container_config.sh
inline Python scripts for testability.
"""

import json
import os
import sys

import pytest

# Add lib/python to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../lib/python"))

from json_config import load_json, write_json, deep_merge, deep_merge_no_overwrite
from merge_claude_settings import merge_claude_settings
from ensure_claude_foundry_mcp import (
    ensure_claude_foundry_mcp,
    FOUNDRY_ALLOW,
    FOUNDRY_DENY,
)
from sync_opencode_foundry import (
    is_local_plugin,
    plugin_spec,
    plugin_name,
    map_plugin_to_local,
    command_looks_like_foundry,
)


class TestJsonConfig:
    """Tests for json_config.py shared utilities."""

    def test_load_json_valid(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text('{"key": "value"}')
        assert load_json(str(f)) == {"key": "value"}

    def test_load_json_missing(self, tmp_path):
        assert load_json(str(tmp_path / "missing.json")) == {}

    def test_load_json_invalid(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        assert load_json(str(f)) == {}

    def test_write_json(self, tmp_path):
        f = tmp_path / "out.json"
        write_json(str(f), {"a": 1})
        assert json.loads(f.read_text()) == {"a": 1}

    def test_write_json_creates_dirs(self, tmp_path):
        f = tmp_path / "sub" / "dir" / "out.json"
        write_json(str(f), {"nested": True})
        assert f.exists()

    def test_deep_merge_basic(self):
        base = {"a": 1, "b": 2}
        overlay = {"b": 3, "c": 4}
        assert deep_merge(base, overlay) == {"a": 1, "b": 3, "c": 4}

    def test_deep_merge_nested(self):
        base = {"x": {"a": 1, "b": 2}}
        overlay = {"x": {"b": 3, "c": 4}}
        assert deep_merge(base, overlay) == {"x": {"a": 1, "b": 3, "c": 4}}

    def test_deep_merge_no_overwrite(self):
        base = {"a": 1, "b": 2}
        overlay = {"b": 99, "c": 3}
        result = deep_merge_no_overwrite(base, overlay)
        assert result == {"a": 1, "b": 2, "c": 3}

    def test_deep_merge_no_overwrite_nested(self):
        base = {"x": {"a": 1}}
        overlay = {"x": {"a": 99, "b": 2}}
        result = deep_merge_no_overwrite(base, overlay)
        assert result == {"x": {"a": 1, "b": 2}}


class TestMergeClaudeSettings:
    """Tests for merge_claude_settings.py."""

    def test_preserves_model_and_hooks(self, tmp_path):
        container = tmp_path / "container.json"
        host = tmp_path / "host.json"

        container.write_text(json.dumps({
            "model": "opus",
            "subagentModel": "haiku",
            "hooks": {"PreToolUse": []},
            "theme": "dark",
        }))
        host.write_text(json.dumps({
            "model": "sonnet",
            "theme": "light",
            "extra": "setting",
        }))

        merge_claude_settings(str(container), str(host))
        result = json.loads(container.read_text())

        assert result["model"] == "opus"
        assert result["subagentModel"] == "haiku"
        assert result["hooks"] == {"PreToolUse": []}
        assert result["theme"] == "light"
        assert result["extra"] == "setting"

    def test_removes_foundry_plugin(self, tmp_path):
        container = tmp_path / "container.json"
        host = tmp_path / "host.json"

        container.write_text("{}")
        host.write_text(json.dumps({
            "enabledPlugins": {
                "foundry@claude-foundry": True,
                "pyright-lsp": True,
            }
        }))

        merge_claude_settings(str(container), str(host))
        result = json.loads(container.read_text())

        assert "foundry@claude-foundry" not in result.get("enabledPlugins", {})
        assert result["enabledPlugins"]["pyright-lsp"] is True

    def test_missing_files(self, tmp_path):
        container = tmp_path / "container.json"
        host = tmp_path / "missing.json"
        container.write_text("{}")
        merge_claude_settings(str(container), str(host))
        assert json.loads(container.read_text()) == {}


class TestEnsureClaudeFoundryMcp:
    """Tests for ensure_claude_foundry_mcp.py."""

    def test_sets_model_defaults(self, tmp_path):
        f = tmp_path / "settings.json"
        f.write_text("{}")
        ensure_claude_foundry_mcp(str(f))
        result = json.loads(f.read_text())

        assert result["model"] == "opus"
        assert result["subagentModel"] == "haiku"
        assert result["alwaysThinkingEnabled"] is True

    def test_sets_permissions(self, tmp_path):
        f = tmp_path / "settings.json"
        f.write_text("{}")
        ensure_claude_foundry_mcp(str(f))
        result = json.loads(f.read_text())

        assert "permissions" in result
        assert all(p in result["permissions"]["allow"] for p in FOUNDRY_ALLOW[:3])
        assert all(p in result["permissions"]["deny"] for p in FOUNDRY_DENY[:2])

    def test_merges_existing_permissions(self, tmp_path):
        f = tmp_path / "settings.json"
        f.write_text(json.dumps({
            "permissions": {"allow": ["CustomPerm(*)"], "deny": []}
        }))
        ensure_claude_foundry_mcp(str(f))
        result = json.loads(f.read_text())

        assert "CustomPerm(*)" in result["permissions"]["allow"]
        assert len(result["permissions"]["allow"]) > 1

    def test_sets_hooks(self, tmp_path):
        f = tmp_path / "settings.json"
        f.write_text("{}")
        ensure_claude_foundry_mcp(str(f))
        result = json.loads(f.read_text())

        assert "hooks" in result
        assert "PreToolUse" in result["hooks"]
        assert "PostToolUse" in result["hooks"]


class TestSyncOpencodeFunctions:
    """Tests for sync_opencode_foundry.py helper functions."""

    def test_is_local_plugin_string(self):
        assert is_local_plugin("/usr/lib/plugin") is True
        assert is_local_plugin("./local-plugin") is True
        assert is_local_plugin("npm-package") is False

    def test_is_local_plugin_dict(self):
        assert is_local_plugin({"path": "/local/path"}) is True
        assert is_local_plugin({"name": "npm-pkg"}) is False

    def test_plugin_spec_string(self):
        assert plugin_spec("my-plugin") == "my-plugin"

    def test_plugin_spec_dict_with_version(self):
        assert plugin_spec({"name": "pkg", "version": "1.0"}) == "pkg@1.0"

    def test_plugin_name_scoped(self):
        assert plugin_name("@scope/pkg@1.0") == "@scope/pkg"

    def test_plugin_name_simple(self):
        assert plugin_name("pkg@1.0") == "pkg"
        assert plugin_name("pkg") == "pkg"

    def test_map_plugin_to_local(self):
        result = map_plugin_to_local("my-plugin", "/plugins")
        assert result == "/plugins/my-plugin"

    def test_map_local_plugin_unchanged(self):
        result = map_plugin_to_local("/already/local", "/plugins")
        assert result == "/already/local"

    def test_command_looks_like_foundry(self):
        assert command_looks_like_foundry([]) is True
        assert command_looks_like_foundry(["foundry-mcp"]) is True
        assert command_looks_like_foundry(["uvx", "foundry-mcp"]) is True
        assert command_looks_like_foundry(["python3", "-m", "foundry_mcp.server"]) is True
        assert command_looks_like_foundry(["python", "-s", "-m", "foundry_mcp.server"]) is True
        assert command_looks_like_foundry(["node", "server.js"]) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
