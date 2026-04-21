"""Assert that all runtime assets are bundled in the wheel.

These tests fail at import time if the package is installed from a wheel
that was built without the assets directory.
"""

from __future__ import annotations


class TestWheelAssetPresence:
    """Verify each runtime asset is resolvable from the installed package."""

    def test_git_wrapper_sbx_in_assets(self):
        """git-wrapper-sbx.sh must be in foundry_sandbox.assets."""
        from importlib.resources import files

        resource = files("foundry_sandbox.assets").joinpath("git-wrapper-sbx.sh")
        assert resource.is_file(), (
            "git-wrapper-sbx.sh not found in foundry_sandbox.assets. "
            "Check pyproject.toml [tool.hatch.build.targets.wheel] artifacts."
        )

    def test_git_wrapper_sbx_readable(self):
        from importlib.resources import files

        content = files("foundry_sandbox.assets").joinpath(
            "git-wrapper-sbx.sh"
        ).read_bytes()
        assert content.startswith(b"#!/bin/bash")

    def test_assets_package_is_importable(self):
        import importlib

        mod = importlib.import_module("foundry_sandbox.assets")
        assert mod is not None
