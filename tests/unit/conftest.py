"""Pytest configuration for unit tests.

Autouse fixtures ensure tests are hermetic — no writes to the real
``~/.sandboxes`` directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_sandbox_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect all sandbox paths to a temp directory."""
    sandbox_home = tmp_path / "sandbox-home"
    sandbox_home.mkdir()
    monkeypatch.setenv("SANDBOX_HOME", str(sandbox_home))
