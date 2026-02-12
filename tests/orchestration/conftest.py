"""Orchestration-specific pytest fixtures.

Provides:
    sandbox_name - unique sandbox name with automatic teardown
    poll         - retry/polling helper for async assertions
"""

import time
import uuid
from typing import Callable

import pytest


def wait_for(
    condition: Callable[[], bool],
    *,
    timeout: float = 30.0,
    interval: float = 1.0,
    description: str = "condition",
) -> None:
    """Poll *condition* until it returns True or *timeout* seconds elapse.

    Args:
        condition: Zero-arg callable that returns True when ready.
        timeout: Maximum wall-clock seconds to wait.
        interval: Seconds between polls.
        description: Human-readable label for error messages.

    Raises:
        TimeoutError: If the condition is not met within *timeout*.
    """
    deadline = time.monotonic() + timeout
    while True:
        if condition():
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out after {timeout}s waiting for: {description}"
            )
        time.sleep(interval)


@pytest.fixture
def poll():
    """Expose :func:`wait_for` as a pytest fixture."""
    return wait_for


@pytest.fixture
def sandbox_name(cli):
    """Generate a unique sandbox name and destroy it on teardown.

    Yields a name of the form ``test-{uuid8}`` (first 8 hex chars of a UUID4).
    After the test finishes, the sandbox is force-destroyed via the CLI.
    """
    name = f"test-{uuid.uuid4().hex[:8]}"
    yield name
    cli("destroy", name, "--force")
