"""Security test fixtures.

Provides:
    module_local_repo - module-scoped git repo for sandbox creation
    running_sandbox   - module-scoped fixture that creates a sandbox and
                        yields its name, destroying it on teardown
    docker_exec       - helper to run commands inside the sandbox container

Shared-state contract
---------------------
``running_sandbox`` is **module-scoped** so that all security tests within a
single test module share one Docker sandbox.  This is intentional: creating and
destroying a real sandbox per test would make the suite prohibitively slow.

Consequences for test authors:

* **Tests must be read-only observers.**  They may inspect sandbox state (env
  vars, filesystem, network) but must not mutate it in ways visible to other
  tests.  If a test creates temporary artefacts (e.g. marker files), it must
  clean them up before returning.
* **Test ordering within a module is undefined.**  Do not rely on one test
  running before another.  Each test must be independently valid against a
  sandbox in its as-created state.
* **Cross-module isolation is guaranteed.**  Each test module gets its own
  sandbox instance, so mutations in ``test_credential_isolation.py`` cannot
  affect ``test_filesystem_readonly.py``.
"""

import os
import subprocess

import pytest


@pytest.fixture(scope="module")
def module_local_repo(tmp_path_factory):
    """Create a temporary git repo scoped to the test module.

    Same as the root ``local_repo`` fixture but module-scoped so it can
    be used by the module-scoped ``running_sandbox`` fixture.
    """
    repo = tmp_path_factory.mktemp("repo")

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

    return repo


def _extract_sandbox_name(stdout: str) -> str | None:
    """Extract sandbox name from CLI output.

    Looks for the line ``Setting up your sandbox: <name>``.
    """
    for line in stdout.splitlines():
        if "Setting up your sandbox:" in line:
            return line.split("Setting up your sandbox:")[-1].strip()
    return None


@pytest.fixture(scope="module")
def running_sandbox(cli, has_docker, module_local_repo):
    """Create a sandbox with default settings and tear it down after the module.

    Yields the sandbox name.  The sandbox is created with ``--skip-key-check``
    so no API keys are required during testing.  Skips the entire module
    when Docker is not available.

    **Shared-state:** This fixture is module-scoped for performance.  All tests
    in the consuming module share this single sandbox instance.  See the module
    docstring for the shared-state contract that test authors must follow.
    """
    if not has_docker:
        pytest.skip("Docker is not available")
    result = cli(
        "new", str(module_local_repo),
        "--skip-key-check",
    )
    assert result.returncode == 0, (
        f"Failed to create sandbox "
        f"(rc={result.returncode}):\n{result.stderr}"
    )
    name = _extract_sandbox_name(result.stdout)
    assert name, (
        f"Could not extract sandbox name from output:\n{result.stdout}"
    )
    yield name
    cli("destroy", name, "--force")


@pytest.fixture
def docker_exec(running_sandbox):
    """Return a callable that executes a command inside the running sandbox container.

    Usage::

        result = docker_exec("whoami")
        result = docker_exec("cat", "/etc/hostname")
    """
    container = f"sandbox-{running_sandbox}-dev-1"

    def _exec(*args, **kwargs):
        cmd = ["docker", "exec", container] + list(args)
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        return subprocess.run(cmd, **kwargs)

    return _exec
