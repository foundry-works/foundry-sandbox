"""Shared test fixtures for foundry-git-safety."""

import os
import subprocess

import pytest

from foundry_git_safety import decision_log


@pytest.fixture(autouse=True)
def _isolate_foundry_dirs(monkeypatch, tmp_path):
    """Ensure tests never write to real ~/.foundry.

    Redirects the decision-log and data directories to per-test temp dirs
    and resets the decision-log singleton so it picks up the new paths.
    """
    log_dir = str(tmp_path / "decision-logs")
    data_dir = str(tmp_path / "foundry-data")
    monkeypatch.setenv("GIT_SAFETY_DECISION_LOG_DIR", log_dir)
    monkeypatch.setenv("FOUNDRY_DATA_DIR", data_dir)

    # Reset the singleton so the next get_decision_log_writer() call
    # picks up the new env var.
    if decision_log._writer is not None:
        decision_log._writer.close()
    decision_log._writer = None

    yield

    if decision_log._writer is not None:
        decision_log._writer.close()
    decision_log._writer = None


@pytest.fixture
def base_branch():
    return "main"


def _make_metadata(
    sandbox_branch: str = "sandbox/test-alice",
    from_branch: str = "main",
    **extra,
) -> dict:
    """Build a standard metadata dict for testing."""
    meta: dict = {
        "sandbox_branch": sandbox_branch,
        "from_branch": from_branch,
    }
    meta.update(extra)
    return meta


@pytest.fixture
def make_metadata():
    return _make_metadata


@pytest.fixture
def tmp_git_repo(tmp_path):
    """Create a minimal git repo with one commit on main."""
    env = {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    subprocess.run(
        ["git", "init", "-b", "main", str(tmp_path)],
        check=True,
        capture_output=True,
        env={**os.environ, **env},
    )
    readme = tmp_path / "README.md"
    readme.write_text("# test\n")
    subprocess.run(
        ["git", "add", "README.md"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
        env={**os.environ, **env},
    )
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=str(tmp_path),
        check=True,
        capture_output=True,
        env={**os.environ, **env},
    )
    return tmp_path


def create_pktline_data(refs: list[tuple[str, str, str]], first_capabilities: str = "") -> bytes:
    """Build raw pkt-line bytes from a list of (old_sha, new_sha, refname) tuples.

    The first ref can include capabilities after a NUL byte.
    """
    parts = []
    for i, (old_sha, new_sha, refname) in enumerate(refs):
        line = f"{old_sha} {new_sha} {refname}"
        if i == 0 and first_capabilities:
            line = f"{line}\0{first_capabilities}"
        encoded = line.encode("utf-8") + b"\n"
        length = len(encoded) + 4
        parts.append(f"{length:04x}".encode("ascii") + encoded)
    parts.append(b"0000")
    return b"".join(parts)
