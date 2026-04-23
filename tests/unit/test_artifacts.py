"""Unit tests for foundry_sandbox.artifacts — Phase 2 artifact bundles and applier."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from foundry_sandbox.artifacts import (
    ArtifactBundle,
    FileWrite,
    PolicyPatch,
    PostStep,
    _merge_bundles,
    _patch_sandbox_policy,
)


# ---------------------------------------------------------------------------
# _merge_bundles
# ---------------------------------------------------------------------------


class TestMergeBundles:
    def test_merge_bundles_concatenates_patches(self):
        a = ArtifactBundle(policy_patches=[
            PolicyPatch(op="add", path="protected_branches", value=["main"]),
        ])
        b = ArtifactBundle(policy_patches=[
            PolicyPatch(op="add", path="blocked_patterns", value=["secrets/"]),
        ])
        merged = _merge_bundles([a, b])
        assert len(merged.policy_patches) == 2
        assert merged.policy_patches[0].path == "protected_branches"
        assert merged.policy_patches[1].path == "blocked_patterns"

    def test_merge_bundles_empty(self):
        merged = _merge_bundles([])
        assert merged.policy_patches == []
        assert merged.file_writes == []

    def test_merge_bundles_file_writes(self):
        a = ArtifactBundle(file_writes=[
            FileWrite(container_path="/a", content=b"hello"),
        ])
        b = ArtifactBundle(file_writes=[
            FileWrite(container_path="/b", content=b"world"),
        ])
        merged = _merge_bundles([a, b])
        assert len(merged.file_writes) == 2

    def test_merge_bundles_env_vars_latter_wins(self):
        a = ArtifactBundle(env_vars={"KEY": "a"})
        b = ArtifactBundle(env_vars={"KEY": "b"})
        merged = _merge_bundles([a, b])
        assert merged.env_vars["KEY"] == "b"

    def test_merge_bundles_post_steps(self):
        a = ArtifactBundle(post_steps=[PostStep(cmd=["echo", "a"])])
        b = ArtifactBundle(post_steps=[PostStep(cmd=["echo", "b"])])
        merged = _merge_bundles([a, b])
        assert len(merged.post_steps) == 2


# ---------------------------------------------------------------------------
# _patch_sandbox_policy
# ---------------------------------------------------------------------------


class TestPolicyPatches:
    def test_policy_patches_are_additive(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        # Pre-existing registration
        meta = {
            "sandbox_branch": "feature-x",
            "protected_branches": ["main"],
            "allow_pr": True,
        }
        meta_path = sandboxes_dir / "test-sbx.json"
        meta_path.write_text(json.dumps(meta))

        _patch_sandbox_policy("test-sbx", [
            PolicyPatch(op="add", path="protected_branches", value=["refs/heads/staging"]),
            PolicyPatch(op="add", path="allow_pr", value=False),
        ])

        result = json.loads(meta_path.read_text())
        # Existing entries preserved, new ones appended
        assert "main" in result["protected_branches"]
        assert "refs/heads/staging" in result["protected_branches"]
        # allow_pr tightened: True AND False → False
        assert result["allow_pr"] is False
        # Other fields untouched
        assert result["sandbox_branch"] == "feature-x"

    def test_policy_patches_dedup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        meta = {"protected_branches": ["main"]}
        meta_path = sandboxes_dir / "test-sbx.json"
        meta_path.write_text(json.dumps(meta))

        _patch_sandbox_policy("test-sbx", [
            PolicyPatch(op="add", path="protected_branches", value=["main", "staging"]),
        ])

        result = json.loads(meta_path.read_text())
        assert result["protected_branches"] == ["main", "staging"]

    def test_policy_patches_new_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        _patch_sandbox_policy("new-sbx", [
            PolicyPatch(op="add", path="protected_branches", value=["refs/heads/staging"]),
        ])

        meta_path = sandboxes_dir / "new-sbx.json"
        assert meta_path.exists()
        result = json.loads(meta_path.read_text())
        assert result["protected_branches"] == ["refs/heads/staging"]

    def test_apply_policy_patches_atomic(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Verify atomic write — file is always valid JSON even after writes."""
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        meta = {"sandbox_branch": "test", "protected_branches": ["main"]}
        meta_path = sandboxes_dir / "test-sbx.json"
        meta_path.write_text(json.dumps(meta))

        _patch_sandbox_policy("test-sbx", [
            PolicyPatch(op="add", path="blocked_patterns", value=["secrets/"]),
        ])

        # File must parse cleanly
        result = json.loads(meta_path.read_text())
        assert "blocked_patterns" in result
        assert "secrets/" in result["blocked_patterns"]

    def test_empty_patches_noop(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        meta = {"sandbox_branch": "test"}
        meta_path = sandboxes_dir / "test-sbx.json"
        meta_path.write_text(json.dumps(meta))
        mtime_before = meta_path.stat().st_mtime

        _patch_sandbox_policy("test-sbx", [])

        # File should not be modified
        assert meta_path.stat().st_mtime == mtime_before

    def test_allow_pr_unset_then_set_false(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        meta = {"sandbox_branch": "test"}
        meta_path = sandboxes_dir / "test-sbx.json"
        meta_path.write_text(json.dumps(meta))

        _patch_sandbox_policy("test-sbx", [
            PolicyPatch(op="add", path="allow_pr", value=False),
        ])

        result = json.loads(meta_path.read_text())
        assert result["allow_pr"] is False

    def test_allow_pr_cannot_loosen(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("FOUNDRY_DATA_DIR", str(tmp_path))
        sandboxes_dir = tmp_path / "sandboxes"
        sandboxes_dir.mkdir()

        meta = {"allow_pr": False}
        meta_path = sandboxes_dir / "test-sbx.json"
        meta_path.write_text(json.dumps(meta))

        _patch_sandbox_policy("test-sbx", [
            PolicyPatch(op="add", path="allow_pr", value=True),
        ])

        result = json.loads(meta_path.read_text())
        # False AND True → False (cannot loosen)
        assert result["allow_pr"] is False


# ---------------------------------------------------------------------------
# Env-var apply (Phase 3)
# ---------------------------------------------------------------------------


class TestApplyEnvVars:
    def test_env_vars_applied_through_profile_d(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """_apply_env_vars writes to profile.d via sbx_exec."""
        from foundry_sandbox.artifacts import _apply_env_vars
        from unittest.mock import patch

        with patch("foundry_sandbox.artifacts.sbx_exec") as mock_exec:
            _apply_env_vars("test-sbx", {"FOO": "bar", "BAZ": "qux"})

            # Should call sbx_exec three times: profile.d, bash.bashrc, .env
            assert mock_exec.call_count == 3
            # First call: profile.d
            first_call = mock_exec.call_args_list[0]
            assert "test-sbx" in first_call.args[0]
            cmd = first_call.args[1]
            # The command is a shell script that base64 decodes into profile.d
            assert "foundry-user-services.sh" in " ".join(cmd)
            assert first_call.kwargs.get("user") == "root"

    def test_apply_env_vars_empty_is_noop(self):
        from foundry_sandbox.artifacts import _apply_env_vars
        from unittest.mock import patch

        with patch("foundry_sandbox.artifacts.sbx_exec") as mock_exec:
            _apply_env_vars("test-sbx", {})
            mock_exec.assert_not_called()


class TestApplySbxSecrets:
    def test_sbx_secrets_pushed_from_env(self, monkeypatch: pytest.MonkeyPatch):
        from foundry_sandbox.artifacts import _apply_sbx_secrets
        from unittest.mock import patch

        monkeypatch.setenv("MY_API_KEY", "secret123")

        with patch("foundry_sandbox.sbx.sbx_secret_set") as mock_set:
            _apply_sbx_secrets([("my-api", "MY_API_KEY")])
            mock_set.assert_called_once_with("my-api", "secret123")

    def test_sbx_secrets_skips_unset_env(self, monkeypatch: pytest.MonkeyPatch):
        from foundry_sandbox.artifacts import _apply_sbx_secrets
        from unittest.mock import patch

        monkeypatch.delenv("UNSET_KEY", raising=False)

        with patch("foundry_sandbox.sbx.sbx_secret_set") as mock_set:
            _apply_sbx_secrets([("unset", "UNSET_KEY")])
            mock_set.assert_not_called()
