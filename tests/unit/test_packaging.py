"""Assert that all runtime assets are bundled in the wheel.

These tests fail at import time if the package is installed from a wheel
that was built without the assets directory.
"""

from __future__ import annotations
import re


class TestWheelAssetPresence:
    """Verify each runtime asset is resolvable from the installed package."""

    def test_git_wrapper_in_assets(self):
        """git-wrapper.sh must be in foundry_sandbox.assets."""
        from importlib.resources import files

        resource = files("foundry_sandbox.assets").joinpath("git-wrapper.sh")
        assert resource.is_file(), (
            "git-wrapper.sh not found in foundry_sandbox.assets. "
            "Check pyproject.toml [tool.hatch.build.targets.wheel] artifacts."
        )

    def test_git_wrapper_readable(self):
        from importlib.resources import files

        content = files("foundry_sandbox.assets").joinpath(
            "git-wrapper.sh"
        ).read_bytes()
        assert content.startswith(b"#!/bin/bash")

    def test_proxy_sign_in_assets(self):
        """proxy-sign.sh must be in foundry_sandbox.assets."""
        from importlib.resources import files

        resource = files("foundry_sandbox.assets").joinpath("proxy-sign.sh")
        assert resource.is_file(), (
            "proxy-sign.sh not found in foundry_sandbox.assets. "
            "Check pyproject.toml [tool.hatch.build.targets.wheel] artifacts."
        )

    def test_git_wrapper_sbx_checksum_computable(self):
        """compute_wrapper_checksum returns a valid SHA-256 hex digest."""
        from foundry_sandbox.git_safety import compute_wrapper_checksum

        checksum = compute_wrapper_checksum()
        assert re.fullmatch(r"[0-9a-f]{64}", checksum), (
            f"Expected 64-char hex digest, got: {checksum!r}"
        )

    def test_assets_package_is_importable(self):
        import importlib

        mod = importlib.import_module("foundry_sandbox.assets")
        assert mod is not None
