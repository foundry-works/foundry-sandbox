"""Shared fixtures for local sbx smoke tests.

Tests marked @pytest.mark.requires_sbx are automatically skipped
when the sbx binary is not available or the version is out of range.
"""

import subprocess

import pytest

from foundry_sandbox.sbx import SBX_MAX_VERSION, SBX_MIN_VERSION


def _sbx_available() -> bool:
    """Check if sbx binary is installed and at a supported version."""
    try:
        result = subprocess.run(
            ["sbx", "version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return False
        # Parse first line: "Client Version:  v0.26.1 abc123"
        raw = result.stdout.strip().split("\n")[0]
        for prefix in ("Client Version:  v", "Client Version: v"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):]
                break
        version_str = raw.split()[0] if raw else ""
        if not version_str:
            return False
        from foundry_sandbox.version_check import _parse_version

        parsed = _parse_version(version_str)
        min_parsed = _parse_version(SBX_MIN_VERSION)
        max_parsed = _parse_version(SBX_MAX_VERSION)
        if not parsed:
            return False
        return min_parsed <= parsed < max_parsed
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def pytest_collection_modifyitems(items):
    """Skip requires_sbx tests if sbx is not available."""
    if not _sbx_available():
        skip = pytest.mark.skip(reason="sbx binary not available or version out of range")
        for item in items:
            if "requires_sbx" in [m.name for m in item.iter_markers()]:
                item.add_marker(skip)


@pytest.fixture()
def sandbox_name():
    """Generate a unique sandbox name for testing."""
    import uuid

    return f"smoke-test-{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def sandbox(sandbox_name):
    """Create and destroy an sbx sandbox around each test.

    Yields the sandbox name. The sandbox is destroyed on teardown.
    """
    yield sandbox_name
    from foundry_sandbox.sbx import sbx_rm, sbx_stop

    try:
        sbx_stop(sandbox_name)
    except Exception:
        pass
    try:
        sbx_rm(sandbox_name)
    except Exception:
        pass
