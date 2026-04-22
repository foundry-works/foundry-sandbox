"""Live sbx smoke tests — full lifecycle verification.

Requires sbx binary and KVM support. Run locally via scripts/smoke-test.sh.
These tests prove the real sbx runtime path works: create, provision git safety,
run git commands through the wrapper, verify push blocking, and destroy.
"""

import json
import subprocess
import time

import pytest

from foundry_sandbox.git_safety import (
    compute_wrapper_checksum,
    git_safety_server_is_running,
    git_safety_server_start,
    git_safety_server_stop,
    provision_git_safety,
)
from foundry_sandbox.sbx import (
    sbx_create,
    sbx_exec,
    sbx_rm,
    sbx_stop,
)
from foundry_sandbox.state import write_sandbox_metadata
from foundry_sandbox.models import SbxSandboxMetadata


def _init_git_repo(repo_dir, branch="main"):
    """Create a minimal git repo for sandbox testing."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--initial-branch", branch], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "smoke@test.com"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Smoke Test"], cwd=repo_dir, check=True, capture_output=True)
    (repo_dir / "README.md").write_text("# test\n")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=repo_dir, check=True, capture_output=True)


def _setup_and_provision(sandbox, tmp_path, branch="main"):
    """Create repo, sandbox, metadata, and provision git safety. Returns repo_dir."""
    repo_dir = tmp_path / "repo"
    _init_git_repo(repo_dir, branch=branch)

    sbx_create(sandbox, agent="shell", path=str(repo_dir), branch=branch)

    # Write initial metadata so provision_git_safety can patch it
    write_sandbox_metadata(
        sandbox,
        SbxSandboxMetadata(
            sbx_name=sandbox,
            agent="shell",
            repo_url=str(repo_dir),
            branch=branch,
            git_safety_enabled=False,
        ),
    )

    if not git_safety_server_is_running():
        git_safety_server_start()

    result = provision_git_safety(
        sandbox,
        workspace_dir="/workspace",
        branch=branch,
        repo_spec=str(repo_dir),
    )
    return repo_dir, result


@pytest.mark.slow
@pytest.mark.requires_sbx
class TestLiveSbxSmoke:
    """Full lifecycle smoke test requiring sbx binary and KVM."""

    def test_create_sandbox_and_verify_wrapper(self, sandbox, tmp_path):
        """Create sandbox, verify wrapper exists and checksum matches."""
        repo_dir, result = _setup_and_provision(sandbox, tmp_path)
        assert result.success, f"Provisioning failed: {result.error}"

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
        """Run basic git command through the wrapper proxy.

        The HMAC secret and config are persisted to /var/lib/foundry/ which
        survives VM restarts between sbx exec calls.
        """
        repo_dir, result = _setup_and_provision(sandbox, tmp_path)
        assert result.success, f"Provisioning failed: {result.error}"

        # Run a simple read-only git command through the wrapper
        status = sbx_exec(
            sandbox,
            ["git", "status", "--porcelain"],
        )
        assert status.returncode == 0, (
            f"git status failed: stdout={status.stdout} stderr={status.stderr}"
        )

        # Cleanup
        sbx_stop(sandbox)
        sbx_rm(sandbox)

    def test_protected_push_blocked(self, sandbox, tmp_path):
        """Protected push path is blocked by git-safety.

        The HMAC secret and config are persisted to /var/lib/foundry/ which
        survives VM restarts between sbx exec calls.
        """
        repo_dir, result = _setup_and_provision(sandbox, tmp_path, branch="main")
        assert result.success, f"Provisioning failed: {result.error}"

        # Attempt to push to the protected 'main' branch — should be blocked
        push_result = sbx_exec(
            sandbox,
            ["git", "push", "origin", "main"],
        )
        assert push_result.returncode != 0, (
            "Push to protected branch should have been blocked but succeeded"
        )

        # Cleanup
        sbx_stop(sandbox)
        sbx_rm(sandbox)

    def test_destroy_sandbox(self, sandbox, tmp_path):
        """Sandbox is fully destroyed and no longer listed."""
        repo_dir = tmp_path / "repo"
        _init_git_repo(repo_dir)

        # Create sandbox
        sbx_create(sandbox, agent="shell", path=str(repo_dir), branch="main")

        # Destroy (stop then remove)
        sbx_stop(sandbox)
        sbx_rm(sandbox)

        # Verify it no longer appears in sbx ls
        result = subprocess.run(
            ["sbx", "ls", "--json"], capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            sandboxes = data.get("sandboxes", [])
            names = [s.get("name", "") for s in sandboxes]
            assert sandbox not in names, f"Sandbox {sandbox} still in sbx ls"

    def test_deep_policy_blocks_github_merge(self, sandbox, tmp_path):
        """Deep-policy sidecar blocks PR merge and allows read-only GitHub API paths.

        Restarts the git-safety server with --deep-policy to ensure the blueprint
        is registered, then exercises both deny and allow policy paths from inside
        the sandbox using proxy-sign.sh for HMAC authentication.
        """
        # Restart server with deep-policy enabled
        git_safety_server_stop()
        start_result = git_safety_server_start(deep_policy=True)
        assert start_result.returncode == 0, (
            f"Server start with --deep-policy failed: {start_result.stderr}"
        )
        time.sleep(1)
        assert git_safety_server_is_running(), "Server not running after start"

        # Create and provision sandbox
        _setup_and_provision(sandbox, tmp_path, branch="main")

        # --- Deny path: PR merge should be blocked by policy ---
        deny_cmd = (
            'source /var/lib/foundry/git-safety.env && '
            'eval "$(proxy-sign PUT /deep-policy/github/repos/owner/repo/pulls/1/merge)" && '
            'curl -s -w \'\\nHTTP_CODE:%{http_code}\\n\' '
            '-X PUT '
            '-H "Content-Type: application/json" '
            '-H "$X_SANDBOX_ID" -H "$X_REQUEST_SIGNATURE" '
            '-H "$X_REQUEST_TIMESTAMP" -H "$X_REQUEST_NONCE" '
            '-x http://gateway.docker.internal:3128 '
            '"http://${GIT_API_HOST}:${GIT_API_PORT}/deep-policy/github/repos/owner/repo/pulls/1/merge"'
        )
        deny_result = sbx_exec(sandbox, ["sh", "-c", deny_cmd])
        deny_output = deny_result.stdout + deny_result.stderr

        assert "HTTP_CODE:403" in deny_output, (
            f"PR merge should be blocked (403), got: {deny_output}"
        )
        assert "BLOCKED" in deny_output, (
            f"Response should contain BLOCKED, got: {deny_output}"
        )

        # --- Allow path: GET commits should pass policy eval ---
        # Will fail at upstream (no real GitHub), but should NOT be a 403 block.
        allow_cmd = (
            'source /var/lib/foundry/git-safety.env && '
            'eval "$(proxy-sign GET /deep-policy/github/repos/owner/repo/commits)" && '
            'curl -s -w \'\\nHTTP_CODE:%{http_code}\\n\' '
            '-H "$X_SANDBOX_ID" -H "$X_REQUEST_SIGNATURE" '
            '-H "$X_REQUEST_TIMESTAMP" -H "$X_REQUEST_NONCE" '
            '-x http://gateway.docker.internal:3128 '
            '"http://${GIT_API_HOST}:${GIT_API_PORT}/deep-policy/github/repos/owner/repo/commits"'
        )
        allow_result = sbx_exec(sandbox, ["sh", "-c", allow_cmd])
        allow_output = allow_result.stdout + allow_result.stderr

        assert "HTTP_CODE:403" not in allow_output, (
            f"GET commits should pass policy eval, got: {allow_output}"
        )

        # Cleanup
        sbx_stop(sandbox)
        sbx_rm(sandbox)
