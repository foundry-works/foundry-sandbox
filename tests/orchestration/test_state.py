"""Metadata persistence tests for sandbox.sh.

Verifies that sandbox metadata is correctly written on create, persists
across container lifecycle events (stop/start), and is cleaned up on
destroy.
"""

import json
import os

import pytest

pytestmark = [
    pytest.mark.orchestration,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]

# Base directory where sandbox metadata is stored.
CLAUDE_CONFIGS_DIR = os.path.expanduser("~/.sandboxes/claude-config")


def _metadata_path(sandbox_name: str) -> str:
    """Return the expected path to metadata.json for a given sandbox."""
    return os.path.join(CLAUDE_CONFIGS_DIR, sandbox_name, "metadata.json")


def test_metadata_written_on_create(cli, sandbox_name, local_repo):
    """Creating a sandbox writes metadata.json with repo and branch info."""
    result = cli("new", str(local_repo), "--skip-key-check", "--name", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}): {result.stderr}"
    )

    path = _metadata_path(sandbox_name)
    assert os.path.isfile(path), f"metadata.json not found at {path}"

    with open(path, "r", encoding="utf-8") as fh:
        metadata = json.loads(fh.read())

    # The metadata must record the repository URL/path and branch information.
    assert "repo_url" in metadata, "metadata missing 'repo_url'"
    assert "branch" in metadata, "metadata missing 'branch'"
    assert metadata["repo_url"], "repo_url should not be empty"
    assert metadata["branch"], "branch should not be empty"


def test_metadata_persists_across_stop_start(cli, sandbox_name, local_repo):
    """Metadata survives a stop/start cycle (container lifecycle)."""
    result = cli("new", str(local_repo), "--skip-key-check", "--name", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}): {result.stderr}"
    )

    path = _metadata_path(sandbox_name)
    assert os.path.isfile(path), f"metadata.json not found at {path}"

    with open(path, "r", encoding="utf-8") as fh:
        original_content = fh.read()
    original_metadata = json.loads(original_content)

    # Stop the sandbox container.
    result = cli("stop", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox stop failed (rc={result.returncode}): {result.stderr}"
    )

    # Start it again.
    result = cli("start", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox start failed (rc={result.returncode}): {result.stderr}"
    )

    # metadata.json must still exist with identical content.
    assert os.path.isfile(path), "metadata.json missing after stop/start"

    with open(path, "r", encoding="utf-8") as fh:
        after_content = fh.read()
    after_metadata = json.loads(after_content)

    assert original_metadata == after_metadata, (
        "metadata.json content changed after stop/start cycle"
    )


def test_metadata_cleaned_on_destroy(cli, sandbox_name, local_repo):
    """Destroying a sandbox removes metadata.json and its config directory."""
    result = cli("new", str(local_repo), "--skip-key-check", "--name", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}): {result.stderr}"
    )

    path = _metadata_path(sandbox_name)
    config_dir = os.path.dirname(path)
    assert os.path.isfile(path), f"metadata.json not found at {path}"

    # Destroy the sandbox.
    result = cli("destroy", sandbox_name, "--force")
    assert result.returncode == 0, (
        f"sandbox destroy failed (rc={result.returncode}): {result.stderr}"
    )

    # metadata.json should no longer exist.
    assert not os.path.isfile(path), (
        f"metadata.json still present at {path} after destroy"
    )
    # The per-sandbox config directory should be cleaned up as well.
    assert not os.path.isdir(config_dir), (
        f"config directory still present at {config_dir} after destroy"
    )
