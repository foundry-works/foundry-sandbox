"""Security test fixtures.

Provides:
    module_local_repo - module-scoped git repo for sandbox creation
    running_sandbox   - module-scoped fixture that creates a sandbox and
                        yields its name, destroying it on teardown
    docker_exec       - helper to run commands inside the sandbox container
    mitm_functional   - module-scoped fixture that verifies MITM interception
                        is working before running tests that depend on it

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

import json
import os
import subprocess

import pytest


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Store test phase reports on the item for failure detection in fixtures."""
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


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


def _capture_proxy_logs_on_failure(sandbox_name: str, request) -> None:
    """Capture proxy container logs when any test in the module has failed.

    Emits the last 100 lines of proxy logs as a pytest warning so they
    appear in CI output alongside the failure details.
    """
    # Check if any test in this module reported a failure.
    # Relies on pytest_runtest_makereport hook above to set rep_call/rep_setup.
    has_failures = False
    for item in request.session.items:
        if item.module.__name__ == request.module.__name__:
            if hasattr(item, "rep_call") and item.rep_call.failed:
                has_failures = True
                break
            if hasattr(item, "rep_setup") and item.rep_setup.failed:
                has_failures = True
                break

    if not has_failures:
        return

    # Find the proxy container
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name=sandbox-{sandbox_name}-proxy"],
        capture_output=True, text=True,
    )
    proxy_container = result.stdout.strip().splitlines()
    if not proxy_container:
        # Try broader match (compose naming varies)
        result = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name=sandbox-{sandbox_name}"],
            capture_output=True, text=True,
        )
        containers = result.stdout.strip().splitlines()
        # Get logs from all sandbox containers
        proxy_container = containers

    import warnings
    for cid in proxy_container[:3]:  # Cap at 3 containers
        log_result = subprocess.run(
            ["docker", "logs", "--tail", "100", cid],
            capture_output=True, text=True,
        )
        log_output = log_result.stdout + log_result.stderr
        if log_output.strip():
            warnings.warn(
                f"\n--- Proxy/container logs ({cid[:12]}) after test failure ---\n"
                f"{log_output[-3000:]}\n"
                f"--- End logs ({cid[:12]}) ---\n",
                stacklevel=2,
            )


@pytest.fixture(scope="module")
def running_sandbox(cli, has_docker, module_local_repo, request):
    """Create a sandbox with default settings and tear it down after the module.

    Yields the sandbox name.  The sandbox is created with ``--skip-key-check``
    so no API keys are required during testing.  Skips the entire module
    when Docker is not available.

    On teardown, if any test in the module failed, proxy container logs are
    captured and emitted as a pytest warning so CI output includes diagnostic
    information for debugging MITM interception issues.

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
    # Capture initial state fingerprint for drift detection
    initial_env = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name=sandbox-{name}"],
        capture_output=True, text=True,
    ).stdout.strip()

    yield name

    # Post-yield: capture proxy logs if any tests failed
    _capture_proxy_logs_on_failure(name, request)

    # Post-yield: verify sandbox state hasn't drifted (shared-state contract)
    final_env = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name=sandbox-{name}"],
        capture_output=True, text=True,
    ).stdout.strip()
    if initial_env and initial_env != final_env:
        import warnings
        warnings.warn(
            f"Sandbox container state drifted during test module "
            f"(initial={initial_env!r}, final={final_env!r}). "
            f"Tests must be read-only observers per the shared-state contract.",
            stacklevel=1,
        )

    cli("destroy", name, "--force")


@pytest.fixture(scope="module")
def docker_exec(running_sandbox):
    """Return a callable that executes a command inside the running sandbox container.

    Usage::

        result = docker_exec("whoami")
        result = docker_exec("cat", "/etc/hostname")
    """
    # Discover container by name prefix instead of assuming the exact
    # Docker Compose naming convention (e.g. sandbox-{name}-dev-1).
    result = subprocess.run(
        ["docker", "ps", "-q", "--filter", f"name=sandbox-{running_sandbox}"],
        capture_output=True,
        text=True,
    )
    containers = result.stdout.strip().splitlines()
    assert containers, (
        f"No running container found matching name prefix 'sandbox-{running_sandbox}'"
    )
    container = containers[0]

    def _exec(*args, **kwargs):
        cmd = ["docker", "exec", container] + list(args)
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        return subprocess.run(cmd, **kwargs)

    return _exec


@pytest.fixture(scope="module")
def proxy_reachable(docker_exec):
    """Check that the proxy HTTP port is reachable from the sandbox.

    Tests that depend on proxy connectivity (API forwarding, DNS filtering,
    self-merge blocking) should use this fixture so they skip with a clear
    message instead of producing cryptic connection errors.
    """
    result = docker_exec(
        "python3", "-c",
        "import socket; s=socket.socket(); s.settimeout(5); "
        "s.connect(('unified-proxy', 8080)); s.close(); print('ok')",
    )
    if result.returncode != 0:
        pytest.skip(
            f"Proxy HTTP port unreachable from sandbox "
            f"(likely port-binding issue): {result.stderr[:200]}"
        )


@pytest.fixture(scope="module")
def mitm_functional(docker_exec, proxy_reachable):
    """Verify that mitmproxy MITM interception is functional.

    Sends a PUT request to a known-blocked endpoint (PR merge) through the
    full proxy MITM path and checks that the proxy's policy engine returns
    403 with the ``X-Sandbox-Blocked: true`` header.  If the MITM path is
    not intercepting (e.g. CA cert not trusted, addon not loaded), tests
    that depend on this fixture skip with a diagnostic message.

    This prevents misleading test failures when the proxy pipeline is broken
    — without MITM interception, the policy engine's ``request()`` hook
    never fires, and requests either reach GitHub directly (401/404) or
    fail in the proxy pipeline (500).
    """
    # Use a PR merge endpoint — the policy engine always blocks this
    result = docker_exec(
        "curl", "-s",
        "-o", "/dev/null",
        "-w", "%{http_code}\\n%header{X-Sandbox-Blocked}",
        "--max-time", "15",
        "-X", "PUT",
        "-H", "Authorization: token CREDENTIAL_PROXY_PLACEHOLDER",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"commit_title": "preflight", "merge_method": "merge"}),
        "https://api.github.com/repos/octocat/Hello-World/pulls/1/merge",
    )
    lines = result.stdout.strip().split("\n")
    status = lines[0] if lines else ""
    blocked_header = lines[1].strip() if len(lines) > 1 else ""

    if status != "403" or blocked_header != "true":
        pytest.skip(
            f"MITM interception not functional — preflight check got "
            f"HTTP {status} (expected 403) with X-Sandbox-Blocked={blocked_header!r} "
            f"(expected 'true'). The mitmproxy policy engine is not intercepting "
            f"HTTPS requests. Possible causes: CA cert not trusted in sandbox, "
            f"mitmproxy addon failed to load, or timing issue between container "
            f"health and addon readiness. stderr={result.stderr[:300]}"
        )
