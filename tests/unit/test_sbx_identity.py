"""Tests for sbx CLI identity probe (H5).

Verifies that sbx_check_available rejects Docker Desktop's plugin shim
and accepts the standalone CLI.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from foundry_sandbox.sbx import sbx_check_available


class TestSbxIdentityDockerPluginRejected:
    """Docker Desktop plugin paths must be rejected."""

    def test_docker_cli_plugins_rejected(self):
        plugin_path = os.path.expanduser("~/.docker/cli-plugins/sbx")
        with patch("foundry_sandbox.sbx.shutil.which", return_value=plugin_path), \
             patch("foundry_sandbox.sbx.os.path.realpath", return_value=plugin_path), \
             patch("foundry_sandbox.sbx.check_sbx_version"):
            with pytest.raises(SystemExit):
                sbx_check_available()

    def test_macos_app_bundle_rejected(self):
        plugin_path = "/Applications/Docker.app/Contents/Resources/cli-plugins/sbx"
        with patch("foundry_sandbox.sbx.shutil.which", return_value=plugin_path), \
             patch("foundry_sandbox.sbx.os.path.realpath", return_value=plugin_path), \
             patch("foundry_sandbox.sbx.check_sbx_version"):
            with pytest.raises(SystemExit):
                sbx_check_available()

    def test_windows_plugin_rejected(self):
        plugin_path = "C:\\Program Files\\Docker\\Docker\\resources\\cli-plugins\\sbx"
        with patch("foundry_sandbox.sbx.shutil.which", return_value=plugin_path), \
             patch("foundry_sandbox.sbx.os.path.realpath", return_value=plugin_path), \
             patch("foundry_sandbox.sbx.check_sbx_version"):
            with pytest.raises(SystemExit):
                sbx_check_available()


class TestSbxIdentityStandaloneAccepted:
    """Standalone binary should pass when the probe succeeds."""

    def test_standalone_path_accepted(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"), \
             patch("foundry_sandbox.sbx.os.path.realpath", return_value="/usr/local/bin/sbx"), \
             patch("foundry_sandbox.sbx.check_sbx_version"), \
             patch("foundry_sandbox.sbx._run_standalone_probe", return_value=True):
            sbx_check_available()  # should not raise

    def test_homebrew_path_accepted(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/opt/homebrew/bin/sbx"), \
             patch("foundry_sandbox.sbx.os.path.realpath", return_value="/opt/homebrew/bin/sbx"), \
             patch("foundry_sandbox.sbx.check_sbx_version"), \
             patch("foundry_sandbox.sbx._run_standalone_probe", return_value=True):
            sbx_check_available()  # should not raise


class TestSbxIdentityUnknownPathProbeFailure:
    """Unknown path with a failing probe must be rejected."""

    def test_unknown_path_failing_probe_rejected(self):
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/opt/custom/bin/sbx"), \
             patch("foundry_sandbox.sbx.os.path.realpath", return_value="/opt/custom/bin/sbx"), \
             patch("foundry_sandbox.sbx.check_sbx_version"), \
             patch("foundry_sandbox.sbx._run_standalone_probe", return_value=False):
            with pytest.raises(SystemExit):
                sbx_check_available()

    def test_symlink_to_plugin_rejected(self):
        """Even if `which` returns a non-plugin path, realpath must reveal the truth."""
        with patch("foundry_sandbox.sbx.shutil.which", return_value="/usr/local/bin/sbx"), \
             patch("foundry_sandbox.sbx.os.path.realpath",
                   return_value=os.path.expanduser("~/.docker/cli-plugins/sbx")), \
             patch("foundry_sandbox.sbx.check_sbx_version"):
            with pytest.raises(SystemExit):
                sbx_check_available()
