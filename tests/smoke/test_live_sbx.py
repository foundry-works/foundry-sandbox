"""Live sbx smoke tests — full lifecycle verification.

Requires sbx binary and KVM support. Run locally via scripts/smoke-test.sh.
These tests prove the real sbx runtime path works: create, provision git safety,
run git commands through the wrapper, verify push blocking, and destroy.
"""

import json
import subprocess

import pytest

from foundry_sandbox.git_safety import (
    compute_wrapper_checksum,
    git_safety_server_is_running,
    git_safety_server_start,
    provision_git_safety,
)
from foundry_sandbox.sbx import (
    sbx_create,
    sbx_exec,
    sbx_rm,
    sbx_run,
    sbx_stop,
)


@pytest.mark.slow
@pytest.mark.requires_sbx
class TestLiveSbxSmoke:
    """Full lifecycle smoke test requiring sbx binary and KVM."""

    def test_create_sandbox_and_verify_wrapper(self, sandbox, tmp_path):
        """Create sandbox, verify wrapper exists and checksum matches."""
        # Create a minimal git repo for the sandbox
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "smoke@test.com"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Smoke Test"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        (repo_dir / "README.md").write_text("# test\n")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo_dir, check=True, capture_output=True,
        )

        # Create sandbox
        sbx_create(sandbox, agent="smoke", path=str(repo_dir), branch="main")

        # Ensure git safety server is running
        if not git_safety_server_is_running():
            git_safety_server_start()

        # Provision git safety
        result = provision_git_safety(
            sandbox,
            workspace_dir="/workspace",
            branch="main",
            repo_spec=str(repo_dir),
        )
        assert result.success, f"Provisioning failed: {result.error}"

        # Start the sandbox
        sbx_run(sandbox)

        # Verify wrapper exists inside sandbox
        which = sbx_exec(sandbox, ["which", "git"])
        assert which.returncode == 0
        assert "/usr/local/bin/git" in which.stdout.strip(), (
            f"Expected /usr/local/bin/git, got: {which.stdout}"
        )

        # Verify checksum
        expected_checksum = compute_wrapper_checksum()
        assert result.wrapper_checksum == expected_checksum

        # Cleanup
        sbx_stop(sandbox)
        sbx_rm(sandbox)

    def test_git_command_through_wrapper(self, sandbox, tmp_path):
        """Run basic git command through the wrapper proxy."""
        # Setup repo
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "smoke@test.com"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Smoke Test"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        (repo_dir / "hello.txt").write_text("hello\n")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo_dir, check=True, capture_output=True,
        )

        # Create, provision, start
        sbx_create(sandbox, agent="smoke", path=str(repo_dir), branch="main")
        if not git_safety_server_is_running():
            git_safety_server_start()

        prov = provision_git_safety(
            sandbox,
            workspace_dir="/workspace",
            branch="main",
            repo_spec=str(repo_dir),
        )
        assert prov.success

        sbx_run(sandbox)

        # Run git status through the wrapper
        result = sbx_exec(sandbox, ["git", "status"])
        assert result.returncode == 0, (
            f"git status failed: stdout={result.stdout} stderr={result.stderr}"
        )

        # Cleanup
        sbx_stop(sandbox)
        sbx_rm(sandbox)

    def test_protected_push_blocked(self, sandbox, tmp_path):
        """Protected push path is blocked by git-safety."""
        # Setup repo
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "smoke@test.com"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Smoke Test"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        (repo_dir / "file.txt").write_text("content\n")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo_dir, check=True, capture_output=True,
        )

        # Create, provision, start
        sbx_create(sandbox, agent="smoke", path=str(repo_dir), branch="main")
        if not git_safety_server_is_running():
            git_safety_server_start()

        prov = provision_git_safety(
            sandbox,
            workspace_dir="/workspace",
            branch="main",
            repo_spec=str(repo_dir),
        )
        assert prov.success

        sbx_run(sandbox)

        # Attempt push to main (should be blocked by git-safety)
        result = sbx_exec(sandbox, ["git", "push", "origin", "main"])
        # The wrapper proxies through git-safety which rejects protected branch pushes
        assert result.returncode != 0, (
            "Push to main should have been blocked"
        )

        # Cleanup
        sbx_stop(sandbox)
        sbx_rm(sandbox)

    def test_destroy_sandbox(self, sandbox, tmp_path):
        """Sandbox is fully destroyed and no longer listed."""
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "smoke@test.com"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Smoke Test"],
            cwd=repo_dir, check=True, capture_output=True,
        )
        (repo_dir / "file.txt").write_text("content\n")
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=repo_dir, check=True, capture_output=True,
        )

        # Create sandbox
        sbx_create(sandbox, agent="smoke", path=str(repo_dir), branch="main")

        # Destroy (stop then remove)
        sbx_stop(sandbox)
        sbx_rm(sandbox)

        # Verify it no longer appears in sbx ls
        result = subprocess.run(
            ["sbx", "ls", "--json"], capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            sandboxes = json.loads(result.stdout)
            names = [s.get("name", "") for s in sandboxes]
            assert sandbox not in names, f"Sandbox {sandbox} still in sbx ls"
