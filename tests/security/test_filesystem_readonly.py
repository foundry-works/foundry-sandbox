"""Filesystem boundary tests for sandbox environments.

Verifies that the sandbox enforces proper filesystem isolation:
- Root filesystem is read-only (no writes to system paths)
- Temporary filesystems (/tmp, /home/ubuntu) are writable
- Workspace directory allows file operations
- The .git directory is hidden via empty tmpfs overlay

These tests run commands inside a live sandbox container via ``docker exec``.
They mirror the filesystem checks in redteam-sandbox.sh (sections 12, 18, 24).
"""

import pytest

pytestmark = [
    pytest.mark.security,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]


def test_root_filesystem_readonly(docker_exec):
    """Root filesystem inside the sandbox must be read-only.

    Attempts to create a file in /usr/bin and verifies the operation fails,
    confirming the container's root filesystem is mounted read-only.

    Mirrors redteam-sandbox.sh (line 1345):
        touch /usr/bin/test-readonly-probe
    """
    result = docker_exec("touch", "/usr/bin/test_readonly")
    assert result.returncode != 0, (
        "Writing to /usr/bin succeeded -- root filesystem is NOT read-only.\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )


def test_tmpfs_writable(docker_exec):
    """Tmpfs mounts (/tmp and /home/ubuntu) must be writable.

    The sandbox uses tmpfs overlays for temporary directories so that
    processes can write scratch files without modifying the root filesystem.

    Mirrors redteam-sandbox.sh (lines 1400-1414):
        touch /tmp/test-tmpfs-probe
        touch ~/test-home-probe
    """
    # /tmp should be writable
    result_tmp = docker_exec("touch", "/tmp/test_write_marker")
    assert result_tmp.returncode == 0, (
        "/tmp is not writable inside the sandbox.\n"
        f"stdout: {result_tmp.stdout}\n"
        f"stderr: {result_tmp.stderr}"
    )

    # /home/ubuntu should be writable
    result_home = docker_exec("touch", "/home/ubuntu/test_write_marker")
    assert result_home.returncode == 0, (
        "/home/ubuntu is not writable inside the sandbox.\n"
        f"stdout: {result_home.stdout}\n"
        f"stderr: {result_home.stderr}"
    )


def test_workspace_writable(docker_exec):
    """The /workspace directory must be writable for project files.

    Verifies that the sandbox user can create and remove files in the
    workspace bind-mount, which is the primary working directory.
    """
    # Create a marker file
    result_create = docker_exec("touch", "/workspace/test_write_marker")
    assert result_create.returncode == 0, (
        "/workspace is not writable inside the sandbox.\n"
        f"stdout: {result_create.stdout}\n"
        f"stderr: {result_create.stderr}"
    )

    # Clean up the marker file
    result_cleanup = docker_exec("rm", "-f", "/workspace/test_write_marker")
    assert result_cleanup.returncode == 0, (
        "Failed to clean up /workspace/test_write_marker.\n"
        f"stdout: {result_cleanup.stdout}\n"
        f"stderr: {result_cleanup.stderr}"
    )


def test_git_directory_hidden(docker_exec):
    """The /workspace/.git directory must be hidden from the sandbox.

    In git shadow mode, /workspace/.git is overlaid with an empty tmpfs
    so the sandboxed process cannot read or tamper with real git metadata.
    The directory should be either:
    - An empty tmpfs mount, or
    - Missing the HEAD file (proving real git data is inaccessible)

    Mirrors redteam-sandbox.sh (lines 427-444):
        mountpoint -q /workspace/.git
        ls -A /workspace/.git | wc -l
    """
    # Check whether .git exists at all
    result_exists = docker_exec("test", "-d", "/workspace/.git")
    if result_exists.returncode != 0:
        # .git directory does not exist -- git data is fully hidden
        return

    # If .git exists, verify it does not contain real git metadata.
    # A real git directory always contains a HEAD file.
    result_head = docker_exec("test", "-f", "/workspace/.git/HEAD")
    if result_head.returncode != 0:
        # No HEAD file means real git data is not accessible -- pass
        return

    # HEAD exists; check whether the directory is an empty tmpfs overlay
    result_ls = docker_exec("ls", "-A", "/workspace/.git")
    assert result_ls.returncode == 0, (
        "Could not list /workspace/.git contents.\n"
        f"stderr: {result_ls.stderr}"
    )
    contents = result_ls.stdout.strip()
    assert contents == "", (
        "/workspace/.git contains real git data (shadow mode not active).\n"
        f"Contents: {contents}"
    )
