"""Orchestration-specific pytest fixtures.

Provides:
    sandbox_name - unique sandbox name with automatic teardown
"""

import uuid

import pytest


@pytest.fixture
def sandbox_name(cli):
    """Generate a unique sandbox name and destroy it on teardown.

    Yields a name of the form ``test-{uuid8}`` (first 8 hex chars of a UUID4).
    After the test finishes, the sandbox is force-destroyed via the CLI.
    """
    name = f"test-{uuid.uuid4().hex[:8]}"
    yield name
    cli("destroy", name, "--force")
