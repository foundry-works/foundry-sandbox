"""Unit test fixtures."""

from unittest.mock import patch

import pytest


@pytest.fixture
def mock_subprocess_run():
    """Provide a mock for subprocess.run as a context manager."""
    with patch("subprocess.run") as mock_run:
        yield mock_run


@pytest.fixture
def mock_os_environ():
    """Provide isolated os.environ for testing env-var-dependent behavior."""
    with patch.dict("os.environ", {}, clear=True):
        yield
