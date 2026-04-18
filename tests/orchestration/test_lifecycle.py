"""Core lifecycle tests for sandbox.sh.

These tests run the actual sandbox CLI and verify behavior for the
fundamental operations: create, stop/start, destroy, list, and status.

All tests require Docker and are marked as orchestration + slow.
"""

import json

import pytest

pytestmark = [
    pytest.mark.orchestration,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]


def _create_sandbox(cli, sandbox_name, local_repo):
    """Helper: create a sandbox and return the CompletedProcess."""
    result = cli(
        "new", str(local_repo),
        "--skip-key-check",
        "--name", sandbox_name,
    )
    return result


def test_create_sandbox(cli, sandbox_name, local_repo):
    """Create a sandbox and verify it exists, is listed, and is running."""
    # Create the sandbox
    result = _create_sandbox(cli, sandbox_name, local_repo)
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    # Verify sandbox appears in list output
    list_result = cli("list", "--json")
    assert list_result.returncode == 0, (
        f"sandbox list failed: {list_result.stderr}"
    )
    sandboxes = json.loads(list_result.stdout)
    names = [s["name"] for s in sandboxes]
    assert sandbox_name in names, (
        f"Sandbox {sandbox_name!r} not found in list: {names}"
    )

    # Verify status shows running
    status_result = cli("status", sandbox_name, "--json")
    assert status_result.returncode == 0, (
        f"sandbox status failed: {status_result.stderr}"
    )
    status = json.loads(status_result.stdout)
    assert "Up" in status.get("docker_status", ""), (
        f"Expected running container, got status: {status}"
    )


def test_stop_start_sandbox(cli, sandbox_name, local_repo):
    """Create, stop, then start a sandbox and verify state transitions."""
    # Create the sandbox first
    create_result = _create_sandbox(cli, sandbox_name, local_repo)
    assert create_result.returncode == 0, (
        f"sandbox new failed: {create_result.stderr}"
    )

    # Stop the sandbox
    stop_result = cli("stop", sandbox_name)
    assert stop_result.returncode == 0, (
        f"sandbox stop failed (rc={stop_result.returncode}):\n"
        f"stdout: {stop_result.stdout}\nstderr: {stop_result.stderr}"
    )

    # Verify status shows stopped/exited
    status_result = cli("status", sandbox_name, "--json")
    assert status_result.returncode == 0, (
        f"sandbox status failed after stop: {status_result.stderr}"
    )
    status = json.loads(status_result.stdout)
    docker_status = status.get("docker_status", "")
    assert "Up" not in docker_status, (
        f"Expected stopped container, got status: {status}"
    )

    # Start the sandbox again
    start_result = cli("start", sandbox_name)
    assert start_result.returncode == 0, (
        f"sandbox start failed (rc={start_result.returncode}):\n"
        f"stdout: {start_result.stdout}\nstderr: {start_result.stderr}"
    )

    # Verify status shows running again
    status_result = cli("status", sandbox_name, "--json")
    assert status_result.returncode == 0, (
        f"sandbox status failed after start: {status_result.stderr}"
    )
    status = json.loads(status_result.stdout)
    assert "Up" in status.get("docker_status", ""), (
        f"Expected running container after start, got status: {status}"
    )


def test_destroy_sandbox(cli, sandbox_name, local_repo):
    """Create then destroy a sandbox and verify it is removed."""
    # Create the sandbox first
    create_result = _create_sandbox(cli, sandbox_name, local_repo)
    assert create_result.returncode == 0, (
        f"sandbox new failed: {create_result.stderr}"
    )

    # Destroy the sandbox
    destroy_result = cli("destroy", sandbox_name, "--force")
    assert destroy_result.returncode == 0, (
        f"sandbox destroy failed (rc={destroy_result.returncode}):\n"
        f"stdout: {destroy_result.stdout}\nstderr: {destroy_result.stderr}"
    )

    # Verify sandbox no longer appears in list
    list_result = cli("list", "--json")
    assert list_result.returncode == 0, (
        f"sandbox list failed: {list_result.stderr}"
    )
    sandboxes = json.loads(list_result.stdout)
    names = [s["name"] for s in sandboxes]
    assert sandbox_name not in names, (
        f"Sandbox {sandbox_name!r} still present after destroy: {names}"
    )


def test_list_sandboxes(cli, sandbox_name, local_repo):
    """Create a sandbox and verify it appears in the JSON list output."""
    # Create the sandbox
    create_result = _create_sandbox(cli, sandbox_name, local_repo)
    assert create_result.returncode == 0, (
        f"sandbox new failed: {create_result.stderr}"
    )

    # Get the list as JSON
    list_result = cli("list", "--json")
    assert list_result.returncode == 0, (
        f"sandbox list --json failed (rc={list_result.returncode}):\n"
        f"stdout: {list_result.stdout}\nstderr: {list_result.stderr}"
    )

    # Verify valid JSON array
    sandboxes = json.loads(list_result.stdout)
    assert isinstance(sandboxes, list), (
        f"Expected JSON array from list, got: {type(sandboxes).__name__}"
    )

    # Find our sandbox in the list
    matching = [s for s in sandboxes if s.get("name") == sandbox_name]
    assert len(matching) == 1, (
        f"Expected exactly 1 sandbox named {sandbox_name!r}, "
        f"found {len(matching)} in: {[s.get('name') for s in sandboxes]}"
    )
    assert matching[0]["name"] == sandbox_name


def test_status_sandbox(cli, sandbox_name, local_repo):
    """Create a sandbox and verify the status JSON output."""
    # Create the sandbox
    create_result = _create_sandbox(cli, sandbox_name, local_repo)
    assert create_result.returncode == 0, (
        f"sandbox new failed: {create_result.stderr}"
    )

    # Get status as JSON
    status_result = cli("status", sandbox_name, "--json")
    assert status_result.returncode == 0, (
        f"sandbox status --json failed (rc={status_result.returncode}):\n"
        f"stdout: {status_result.stdout}\nstderr: {status_result.stderr}"
    )

    # Verify valid JSON object
    status = json.loads(status_result.stdout)
    assert isinstance(status, dict), (
        f"Expected JSON object from status, got: {type(status).__name__}"
    )

    # Verify it reports a running state
    docker_status = status.get("docker_status", "")
    assert "Up" in docker_status, (
        f"Expected running container, got docker_status: {docker_status!r}"
    )
