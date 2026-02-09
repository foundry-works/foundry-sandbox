"""
Top-level pytest conftest.py -- shared fixtures for orchestration tests.

Provides:
    cli       - callable that runs sandbox CLI commands via subprocess
    local_repo - temporary directory with a deterministic git repo
    has_docker - session-scoped check for Docker availability
"""

import shutil
import os
import shlex
import subprocess

import pytest


@pytest.fixture(scope="session")
def has_docker():
    """Check whether Docker is available on this system.

    Returns True if the ``docker`` command is on PATH, False otherwise.
    """
    return shutil.which("docker") is not None


@pytest.fixture(autouse=False)
def requires_docker(has_docker):
    """Skip the test when Docker is not installed."""
    if not has_docker:
        pytest.skip("Docker is not available")


@pytest.fixture
def cli():
    """Return a callable that invokes the sandbox CLI.

    Reads SANDBOX_CLI env var (default ``./sandbox.sh``) and splits it with
    ``shlex.split`` so multi-token entrypoints like
    ``python3 -m foundry_sandbox.cli`` work correctly.

    Usage::

        result = cli("list")
        result = cli("new", "--name", "foo", capture_output=True)
    """
    entrypoint = shlex.split(os.environ.get("SANDBOX_CLI", "./sandbox.sh"))

    def _run(*args, **kwargs):
        cmd = entrypoint + list(args)
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        return subprocess.run(cmd, **kwargs)

    return _run


@pytest.fixture
def local_repo(tmp_path):
    """Create a temporary directory containing a deterministic git repo.

    The repo has ``main`` as its default branch, a single ``README.md``,
    and one initial commit.  Yields the ``pathlib.Path`` to the repo root.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test User",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test User",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    run_opts = {"cwd": str(repo), "env": env, "capture_output": True, "text": True}

    subprocess.run(["git", "init", "-b", "main"], check=True, **run_opts)
    (repo / "README.md").write_text("# Test Repository\n")
    subprocess.run(["git", "add", "README.md"], check=True, **run_opts)
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"], check=True, **run_opts
    )

    yield repo
