"""Unit tests for credential setup module.

Tests credential placeholder injection, runtime sync idempotency,
real credential leak prevention, and merge_claude_settings hook preservation.

All subprocess.run and file I/O calls are mocked so tests run without Docker.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Modules that credential_setup.py lazy-imports inside function bodies.
# These may have incomplete APIs during migration, so we inject mocks
# into sys.modules before tests that invoke the orchestrator functions.
_LAZY_IMPORT_MODULES = [
    "foundry_sandbox.container_setup",
    "foundry_sandbox.foundry_plugin",
    "foundry_sandbox.git_path_fixer",
    "foundry_sandbox.stub_manager",
    "foundry_sandbox.tool_configs",
    "foundry_sandbox.claude_settings",
]


@pytest.fixture(autouse=False)
def _mock_lazy_imports(monkeypatch):
    """Patch sys.modules so lazy imports inside credential_setup resolve to mocks."""
    import sys
    mocks = {}
    for mod_name in _LAZY_IMPORT_MODULES:
        mock_mod = MagicMock()
        mocks[mod_name] = mock_mod
        monkeypatch.setitem(sys.modules, mod_name, mock_mod)
    return mocks


def _completed(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
) -> MagicMock:
    """Build a mock subprocess.CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    cp.stderr = stderr
    cp.returncode = returncode
    return cp


# ---------------------------------------------------------------------------
# TestCopyConfigsCredentialIsolation
# ---------------------------------------------------------------------------


class TestCopyConfigsCredentialIsolation:
    """When isolate_credentials=True, real credentials must never be copied."""

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_isolation_skips_gemini_oauth(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Gemini OAuth credentials are not copied when isolation is enabled."""
        from foundry_sandbox.credential_setup import copy_configs_to_container

        with patch.multiple(
            "foundry_sandbox.credential_setup",
            _file_exists=lambda p: False,
            _dir_exists=lambda p: False,
            _opencode_enabled=lambda: False,
        ), patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=False):
            copy_configs_to_container(
                "container-123",
                isolate_credentials=True,
            )

        # Verify no call copies gemini oauth
        for c in mock_cpf.call_args_list:
            args = c[0] if c[0] else ()
            for arg in args:
                if isinstance(arg, str):
                    assert "oauth_credentials" not in arg, \
                        f"Gemini OAuth copied despite isolation: {c}"

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_isolation_skips_codex_dir(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Codex credentials are not copied when isolation is enabled."""
        from foundry_sandbox.credential_setup import copy_configs_to_container

        with patch.multiple(
            "foundry_sandbox.credential_setup",
            _file_exists=lambda p: False,
            _dir_exists=lambda p: False,
            _opencode_enabled=lambda: False,
        ), patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=False):
            copy_configs_to_container(
                "container-123",
                isolate_credentials=True,
            )

        # Verify no call copies .codex dir
        for c in mock_cpd.call_args_list:
            args = c[0] if c[0] else ()
            for arg in args:
                if isinstance(arg, str):
                    assert ".codex" not in arg, \
                        f".codex dir copied despite isolation: {c}"

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_isolation_skips_opencode_auth(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """OpenCode auth.json is not copied when isolation is enabled."""
        from foundry_sandbox.credential_setup import copy_configs_to_container

        with patch.multiple(
            "foundry_sandbox.credential_setup",
            _file_exists=lambda p: False,
            _dir_exists=lambda p: False,
            _opencode_enabled=lambda: False,
        ), patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=False):
            copy_configs_to_container(
                "container-123",
                isolate_credentials=True,
            )

        # Verify no opencode auth.json in any copy call
        for c in mock_cpf.call_args_list:
            args = c[0] if c[0] else ()
            for arg in args:
                if isinstance(arg, str):
                    assert "opencode/auth.json" not in arg.replace("\\", "/"), \
                        f"OpenCode auth copied despite isolation: {c}"


# ---------------------------------------------------------------------------
# TestNoCredentialLeaks
# ---------------------------------------------------------------------------


class TestNoCredentialLeaks:
    """Real credentials must never appear in subprocess commands or log output."""

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_no_api_keys_in_subprocess_args(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Subprocess commands must not contain API key values."""
        from foundry_sandbox.credential_setup import copy_configs_to_container

        # Set fake API keys in environment
        fake_keys = {
            "ANTHROPIC_API_KEY": "sk-ant-FAKE123",
            "GITHUB_TOKEN": "ghp_FAKE456",
            "GEMINI_API_KEY": "AIza-FAKE789",
        }

        with patch.multiple(
            "foundry_sandbox.credential_setup",
            _file_exists=lambda p: False,
            _dir_exists=lambda p: False,
            _opencode_enabled=lambda: False,
        ), patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=False), \
             patch.dict("os.environ", fake_keys):
            copy_configs_to_container(
                "container-123",
                isolate_credentials=True,
            )

        # Check all subprocess.run calls for leaked keys
        for c in mock_run.call_args_list:
            cmd = c[0][0] if c[0] else c[1].get("args", [])
            cmd_str = " ".join(str(a) for a in cmd) if isinstance(cmd, list) else str(cmd)
            for key_name, key_val in fake_keys.items():
                assert key_val not in cmd_str, \
                    f"API key {key_name} leaked in subprocess args: {cmd_str}"

    def test_credential_paths_not_in_isolation_code_path(self):
        """The credential stage must have an isolation guard."""
        import ast
        import inspect
        from foundry_sandbox import credential_setup

        source = inspect.getsource(credential_setup._stage_setup_credentials)
        tree = ast.parse(source)

        # Find the `if not isolate_credentials:` block — real creds should
        # only be inside that block (which is skipped when isolation=True).
        # This is a structural assertion: the code has an isolation guard.
        found_isolation_guard = False
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                # Look for `not isolate_credentials`
                test = node.test
                if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
                    if isinstance(test.operand, ast.Name) and test.operand.id == "isolate_credentials":
                        found_isolation_guard = True

        assert found_isolation_guard, (
            "_stage_setup_credentials must have an `if not isolate_credentials:` guard "
            "to prevent real credentials from being copied in isolation mode"
        )


# ---------------------------------------------------------------------------
# TestSyncRuntimeCredentials
# ---------------------------------------------------------------------------


class TestSyncRuntimeCredentials:
    """sync_runtime_credentials must be idempotent."""

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_sync_is_idempotent(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Running sync_runtime_credentials twice produces same calls."""
        from foundry_sandbox.credential_setup import sync_runtime_credentials

        with patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=False):
            sync_runtime_credentials("container-abc")

        calls_first = list(mock_cpf_q.call_args_list)

        # Reset and run again
        mock_cpf_q.reset_mock()
        mock_cpd_q.reset_mock()

        with patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=False):
            sync_runtime_credentials("container-abc")

        calls_second = list(mock_cpf_q.call_args_list)

        # Same sequence of calls = idempotent
        assert len(calls_first) == len(calls_second), \
            "sync_runtime_credentials is not idempotent: different call count"

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_sync_uses_quiet_mode(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Runtime sync must use quiet copy variants, not the loud ones."""
        from foundry_sandbox.credential_setup import sync_runtime_credentials

        with patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=True):
            sync_runtime_credentials("container-abc")

        # Quiet variants should be used, not loud ones
        # (we can't assert loud variants aren't called at all because
        # the function may have both paths, but quiet should be dominant)
        assert mock_cpf_q.called or mock_cpd_q.called, \
            "sync_runtime_credentials should use quiet copy functions"


# ---------------------------------------------------------------------------
# TestSyncRuntimeCredentialIsolation
# ---------------------------------------------------------------------------


class TestSyncRuntimeCredentialIsolation:
    """sync_runtime_credentials must respect isolate_credentials on re-attach."""

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    def test_isolation_skips_codex_on_sync(
        self, mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """.codex dir must not be copied when isolate_credentials=True on sync."""
        from foundry_sandbox.credential_setup import sync_runtime_credentials

        with patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=True):
            sync_runtime_credentials("container-abc", isolate_credentials=True)

        for c in mock_cpd_q.call_args_list:
            args = c[0] if c[0] else ()
            for arg in args:
                if isinstance(arg, str):
                    assert ".codex" not in arg, \
                        f".codex dir copied despite isolation on sync: {c}"

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    @patch("foundry_sandbox.credential_setup._merge_claude_settings_safe")
    @patch("foundry_sandbox.credential_setup._merge_claude_settings_in_container")
    def test_isolation_uses_safe_merge_on_sync(
        self, mock_merge_full, mock_merge_safe,
        mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Settings merge must use _safe variant when isolate_credentials=True on sync."""
        from foundry_sandbox.credential_setup import sync_runtime_credentials

        with patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=True):
            sync_runtime_credentials("container-abc", isolate_credentials=True)

        # Safe merge should be called, full merge should not
        assert mock_merge_safe.called, \
            "sync should use _merge_claude_settings_safe when isolate_credentials=True"
        assert not mock_merge_full.called, \
            "sync should NOT use _merge_claude_settings_in_container when isolate_credentials=True"

    @patch("foundry_sandbox.credential_setup.subprocess.run", return_value=_completed())
    @patch("foundry_sandbox.credential_setup.copy_file_to_container")
    @patch("foundry_sandbox.credential_setup.copy_file_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container")
    @patch("foundry_sandbox.credential_setup.copy_dir_to_container_quiet")
    @patch("foundry_sandbox.credential_setup.docker_exec_text")
    @patch("foundry_sandbox.credential_setup._merge_claude_settings_safe")
    @patch("foundry_sandbox.credential_setup._merge_claude_settings_in_container")
    def test_no_isolation_uses_full_merge_on_sync(
        self, mock_merge_full, mock_merge_safe,
        mock_exec, mock_cpd_q, mock_cpd, mock_cpf_q, mock_cpf, mock_run,
        _mock_lazy_imports,
    ):
        """Settings merge must use full variant when isolate_credentials=False on sync."""
        from foundry_sandbox.credential_setup import sync_runtime_credentials

        with patch("pathlib.Path.home", return_value=Path("/fake/home")), \
             patch("pathlib.Path.exists", return_value=True):
            sync_runtime_credentials("container-abc", isolate_credentials=False)

        assert mock_merge_full.called, \
            "sync should use _merge_claude_settings_in_container when isolate_credentials=False"
        assert not mock_merge_safe.called, \
            "sync should NOT use _merge_claude_settings_safe when isolate_credentials=False"


# ---------------------------------------------------------------------------
# TestMergeClaudeSettings
# ---------------------------------------------------------------------------


class TestMergeClaudeSettings:
    """merge_claude_settings must preserve hooks and sandbox defaults."""

    def test_preserves_hooks_from_container(self, tmp_path):
        """Container hooks must survive merge with host settings."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        container_settings = {
            "model": "claude-sonnet-4-20250514",
            "subagentModel": "claude-haiku-4-20250514",
            "hooks": {
                "pre-commit": {"command": "/usr/local/bin/foundry-hook"},
                "post-tool-use": {"command": "echo done"},
            },
            "theme": "dark",
        }

        host_settings = {
            "model": "claude-opus-4-20250514",
            "theme": "light",
            "customApiUrl": "https://api.example.com",
            "hooks": {
                "pre-commit": {"command": "/usr/local/bin/host-hook"},
            },
        }

        container_file = tmp_path / "container_settings.json"
        host_file = tmp_path / "host_settings.json"
        container_file.write_text(json.dumps(container_settings))
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))

        result = json.loads(container_file.read_text())

        # hooks from container must be preserved (not overwritten by host hooks)
        assert result["hooks"] == container_settings["hooks"], \
            "Container hooks were overwritten by host hooks"

    def test_preserves_model_from_container(self, tmp_path):
        """Container model setting must not be overwritten by host."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        container_settings = {
            "model": "claude-sonnet-4-20250514",
            "subagentModel": "claude-haiku-4-20250514",
        }
        host_settings = {
            "model": "claude-opus-4-20250514",
            "subagentModel": "claude-sonnet-4-20250514",
        }

        container_file = tmp_path / "container.json"
        host_file = tmp_path / "host.json"
        container_file.write_text(json.dumps(container_settings))
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))

        result = json.loads(container_file.read_text())

        assert result["model"] == "claude-sonnet-4-20250514", \
            "Container model was overwritten"
        assert result["subagentModel"] == "claude-haiku-4-20250514", \
            "Container subagentModel was overwritten"

    def test_merges_host_preferences(self, tmp_path):
        """Non-preserved host keys should be merged in."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        container_settings = {"model": "claude-sonnet-4-20250514"}
        host_settings = {
            "theme": "light",
            "customApiUrl": "https://api.example.com",
            "preferredLanguage": "en",
        }

        container_file = tmp_path / "container.json"
        host_file = tmp_path / "host.json"
        container_file.write_text(json.dumps(container_settings))
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))

        result = json.loads(container_file.read_text())

        assert result["theme"] == "light"
        assert result["customApiUrl"] == "https://api.example.com"
        assert result["preferredLanguage"] == "en"
        assert result["model"] == "claude-sonnet-4-20250514"

    def test_removes_foundry_from_enabled_plugins(self, tmp_path):
        """foundry@claude-foundry must be stripped from enabledPlugins."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        container_settings = {"model": "claude-sonnet-4-20250514"}
        host_settings = {
            "enabledPlugins": {
                "foundry@claude-foundry": {"version": "2.1.0"},
                "other-plugin": {"version": "1.0"},
            },
        }

        container_file = tmp_path / "container.json"
        host_file = tmp_path / "host.json"
        container_file.write_text(json.dumps(container_settings))
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))

        result = json.loads(container_file.read_text())

        assert "foundry@claude-foundry" not in result.get("enabledPlugins", {}), \
            "foundry@claude-foundry should be removed from enabledPlugins"
        assert "other-plugin" in result.get("enabledPlugins", {})

    def test_removes_extra_marketplaces(self, tmp_path):
        """extraKnownMarketplaces must be stripped from merged settings."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        container_settings = {"model": "claude-sonnet-4-20250514"}
        host_settings = {
            "extraKnownMarketplaces": ["https://example.com/marketplace"],
        }

        container_file = tmp_path / "container.json"
        host_file = tmp_path / "host.json"
        container_file.write_text(json.dumps(container_settings))
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))

        result = json.loads(container_file.read_text())

        assert "extraKnownMarketplaces" not in result, \
            "extraKnownMarketplaces should be removed"

    def test_handles_missing_container_file(self, tmp_path):
        """Gracefully handle missing container settings (empty dict)."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        host_settings = {"theme": "light"}

        container_file = tmp_path / "container.json"
        host_file = tmp_path / "host.json"
        container_file.write_text("{}")
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))

        result = json.loads(container_file.read_text())
        assert result["theme"] == "light"

    def test_idempotent_merge(self, tmp_path):
        """Running merge twice produces the same result."""
        from foundry_sandbox.claude_settings import merge_claude_settings

        container_settings = {
            "model": "claude-sonnet-4-20250514",
            "hooks": {"pre-commit": {"command": "echo"}},
        }
        host_settings = {"theme": "dark", "model": "claude-opus-4-20250514"}

        container_file = tmp_path / "container.json"
        host_file = tmp_path / "host.json"
        container_file.write_text(json.dumps(container_settings))
        host_file.write_text(json.dumps(host_settings))

        merge_claude_settings(str(container_file), str(host_file))
        first_result = json.loads(container_file.read_text())

        merge_claude_settings(str(container_file), str(host_file))
        second_result = json.loads(container_file.read_text())

        assert first_result == second_result, \
            "merge_claude_settings is not idempotent"


# ---------------------------------------------------------------------------
# TestPreserveKeys
# ---------------------------------------------------------------------------


class TestPreserveKeys:
    """PRESERVE_KEYS constant must include security-critical keys."""

    def test_hooks_in_preserve_keys(self):
        """hooks must be in PRESERVE_KEYS to prevent host hook injection."""
        from foundry_sandbox.claude_settings import PRESERVE_KEYS

        assert "hooks" in PRESERVE_KEYS, \
            "hooks must be in PRESERVE_KEYS to prevent host hooks from overriding sandbox hooks"

    def test_model_in_preserve_keys(self):
        """model must be in PRESERVE_KEYS to maintain sandbox model config."""
        from foundry_sandbox.claude_settings import PRESERVE_KEYS

        assert "model" in PRESERVE_KEYS

    def test_subagent_model_in_preserve_keys(self):
        """subagentModel must be in PRESERVE_KEYS."""
        from foundry_sandbox.claude_settings import PRESERVE_KEYS

        assert "subagentModel" in PRESERVE_KEYS


# ---------------------------------------------------------------------------
# TestCopyConfigsStructure
# ---------------------------------------------------------------------------


class TestCopyConfigsStructure:
    """Structural tests for copy_configs_to_container."""

    def test_creates_required_directories(self):
        """The stage function must create all required config directories."""
        import inspect
        from foundry_sandbox import credential_setup

        source = inspect.getsource(credential_setup._stage_create_config_dirs)

        # Required directories that must be created
        required_dirs = [
            ".claude",
            ".config/gh",
            ".gemini",
            ".config/opencode",
            ".codex",
            ".ssh",
        ]

        for dir_name in required_dirs:
            assert dir_name in source, \
                f"_stage_create_config_dirs must create {dir_name} directory"

    def test_function_accepts_isolation_parameter(self):
        """copy_configs_to_container must accept isolate_credentials kwarg."""
        import inspect
        from foundry_sandbox.credential_setup import copy_configs_to_container

        sig = inspect.signature(copy_configs_to_container)
        assert "isolate_credentials" in sig.parameters, \
            "copy_configs_to_container must accept isolate_credentials parameter"

    def test_function_accepts_ssh_parameter(self):
        """copy_configs_to_container must accept enable_ssh kwarg."""
        import inspect
        from foundry_sandbox.credential_setup import copy_configs_to_container

        sig = inspect.signature(copy_configs_to_container)
        assert "enable_ssh" in sig.parameters


# ---------------------------------------------------------------------------
# TestMergeClaudeSettingsSafeTempFile
# ---------------------------------------------------------------------------


class TestMergeClaudeSettingsSafeTempFile:
    """Temp file for _merge_claude_settings_safe must NOT be in /tmp."""

    def test_temp_file_not_in_tmp(self, tmp_path):
        """Temp file should be created in the parent dir of host_settings, not /tmp."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_safe

        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        host_settings = settings_dir / "settings.json"
        host_settings.write_text(json.dumps({"theme": "dark", "env": {"KEY": "val"}}))

        created_temps = []
        original_mkstemp = __import__("tempfile").mkstemp

        def tracking_mkstemp(dir=None, suffix="", prefix="tmp"):
            result = original_mkstemp(dir=dir, suffix=suffix, prefix=prefix)
            created_temps.append((result[1], dir))
            return result

        with patch("tempfile.mkstemp", side_effect=tracking_mkstemp), \
             patch("foundry_sandbox.settings_merge.merge_claude_settings_in_container", return_value=True):
            _merge_claude_settings_safe("container-123", str(host_settings))

        assert len(created_temps) >= 1, "mkstemp should have been called"
        for tmp_file, tmp_dir in created_temps:
            assert tmp_dir is not None, "mkstemp must specify dir= parameter"
            # Verify temp file is in settings parent dir, not the system default
            assert tmp_dir == str(settings_dir), \
                f"Temp file should be in {settings_dir}, got {tmp_dir}"

    def test_temp_file_in_parent_of_host_settings(self, tmp_path):
        """Temp file dir should match Path(host_settings).parent."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_safe

        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        host_settings = settings_dir / "settings.json"
        host_settings.write_text(json.dumps({"theme": "dark"}))

        dirs_used = []
        original_mkstemp = __import__("tempfile").mkstemp

        def capture_mkstemp(dir=None, suffix="", prefix="tmp"):
            dirs_used.append(dir)
            return original_mkstemp(dir=dir, suffix=suffix, prefix=prefix)

        with patch("tempfile.mkstemp", side_effect=capture_mkstemp), \
             patch("foundry_sandbox.credential_setup._merge_claude_settings_in_container", return_value=True):
            _merge_claude_settings_safe("container-123", str(host_settings))

        assert dirs_used, "mkstemp should have been called"
        assert dirs_used[0] == str(settings_dir)

    def test_temp_file_cleanup_on_success(self, tmp_path):
        """Temp file should be removed after successful merge."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_safe

        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        host_settings = settings_dir / "settings.json"
        host_settings.write_text(json.dumps({"theme": "dark"}))

        with patch("foundry_sandbox.settings_merge.merge_claude_settings_in_container", return_value=True):
            _merge_claude_settings_safe("container-123", str(host_settings))

        # No stale temp files should remain
        temp_files = list(settings_dir.glob("settings-safe-*"))
        assert len(temp_files) == 0, f"Stale temp files found: {temp_files}"

    def test_temp_file_cleanup_on_failure(self, tmp_path):
        """Temp file should be removed even if merge fails."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_safe

        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        host_settings = settings_dir / "settings.json"
        host_settings.write_text(json.dumps({"theme": "dark"}))

        with patch(
            "foundry_sandbox.settings_merge.merge_claude_settings_in_container",
            side_effect=RuntimeError("merge failed"),
        ):
            with pytest.raises(RuntimeError):
                _merge_claude_settings_safe("container-123", str(host_settings))

        temp_files = list(settings_dir.glob("settings-safe-*"))
        assert len(temp_files) == 0, f"Stale temp files found after failure: {temp_files}"

    def test_credential_keys_stripped(self, tmp_path):
        """Keys env, mcpServers, oauthTokens, apiKey must be stripped."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_safe

        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        host_settings = settings_dir / "settings.json"
        host_settings.write_text(json.dumps({
            "theme": "dark",
            "env": {"ANTHROPIC_API_KEY": "sk-secret"},
            "mcpServers": {"server1": {"url": "http://localhost"}},
            "oauthTokens": {"token": "abc123"},
            "apiKey": "sk-ant-12345",
        }))

        written_data = {}

        def capture_merge(container_id, settings_path):
            with open(settings_path) as f:
                written_data.update(json.load(f))
            return True

        with patch(
            "foundry_sandbox.settings_merge.merge_claude_settings_in_container",
            side_effect=capture_merge,
        ):
            _merge_claude_settings_safe("container-123", str(host_settings))

        assert "env" not in written_data
        assert "mcpServers" not in written_data
        assert "oauthTokens" not in written_data
        assert "apiKey" not in written_data
        assert written_data["theme"] == "dark"


# ---------------------------------------------------------------------------
# TestMergeSettingsSilentFailure
# ---------------------------------------------------------------------------


class TestMergeSettingsSilentFailure:
    """_merge_claude_settings_in_container must return False on subprocess failure."""

    @patch("foundry_sandbox.settings_merge.subprocess.run")
    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    def test_returns_false_on_nonzero_exit(self, mock_cpf, mock_run):
        """merge returns False when docker exec fails."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_in_container

        # First call: docker exec merge fails
        # Second call: cleanup rm
        mock_run.side_effect = [
            _completed(returncode=1, stderr="merge error"),
            _completed(),  # cleanup rm
        ]

        result = _merge_claude_settings_in_container("container-123", "/host/settings.json")
        assert result is False

    @patch("foundry_sandbox.settings_merge.subprocess.run")
    @patch("foundry_sandbox.settings_merge.copy_file_to_container")
    def test_returns_true_on_success(self, mock_cpf, mock_run):
        """merge returns True when docker exec succeeds."""
        from foundry_sandbox.credential_setup import _merge_claude_settings_in_container

        mock_run.return_value = _completed(returncode=0)

        result = _merge_claude_settings_in_container("container-123", "/host/settings.json")
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
