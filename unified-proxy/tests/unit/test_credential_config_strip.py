"""
Unit tests for credential config stripping in git_operations.

Tests cover _strip_credential_config_overrides which removes -c credential.*=...
overrides injected by tools like GitHub CLI (gh) before command validation.
"""

import sys
from unittest import mock

# git_operations imports mitmproxy indirectly via git_policies; ensure mocks
# are in place before import.
for mod in ("mitmproxy", "mitmproxy.http", "mitmproxy.ctx", "mitmproxy.flow"):
    if mod not in sys.modules:
        sys.modules[mod] = mock.MagicMock()

from git_operations import _strip_credential_config_overrides


# ---------------------------------------------------------------------------
# No-op cases (nothing to strip)
# ---------------------------------------------------------------------------


class TestNoStrip:
    """Commands without credential config overrides pass through unchanged."""

    def test_bare_command(self):
        args, changed = _strip_credential_config_overrides(["status"])
        assert args == ["status"]
        assert changed is False

    def test_command_with_allowed_config(self):
        args, changed = _strip_credential_config_overrides(
            ["-c", "user.name=Test", "status"]
        )
        assert args == ["-c", "user.name=Test", "status"]
        assert changed is False

    def test_empty_args(self):
        args, changed = _strip_credential_config_overrides([])
        assert args == []
        assert changed is False


# ---------------------------------------------------------------------------
# Stripping -c credential.helper=... (separate args)
# ---------------------------------------------------------------------------


class TestStripSeparate:
    """Strip -c credential.*=... when -c and value are separate args."""

    def test_single_credential_helper(self):
        args, changed = _strip_credential_config_overrides(
            ["-c", "credential.helper=store", "status"]
        )
        assert args == ["status"]
        assert changed is True

    def test_credential_helper_empty_value(self):
        """gh sends -c credential.helper= (empty) to clear existing helpers."""
        args, changed = _strip_credential_config_overrides(
            ["-c", "credential.helper=", "status"]
        )
        assert args == ["status"]
        assert changed is True

    def test_credential_helper_command(self):
        """gh sends -c credential.helper=!gh auth git-credential."""
        args, changed = _strip_credential_config_overrides(
            ["-c", "credential.helper=!/usr/bin/gh auth git-credential", "status"]
        )
        assert args == ["status"]
        assert changed is True

    def test_multiple_credential_helpers(self):
        """gh typically sends two: one empty (clear) and one with command."""
        args, changed = _strip_credential_config_overrides(
            [
                "-c", "credential.helper=",
                "-c", "credential.helper=!/usr/bin/gh auth git-credential",
                "remote", "-v",
            ]
        )
        assert args == ["remote", "-v"]
        assert changed is True

    def test_credential_mixed_with_allowed(self):
        """Credential overrides stripped, other configs preserved."""
        args, changed = _strip_credential_config_overrides(
            [
                "-c", "credential.helper=",
                "-c", "user.name=Test",
                "-c", "credential.helper=!/usr/bin/gh auth git-credential",
                "status",
            ]
        )
        assert args == ["-c", "user.name=Test", "status"]
        assert changed is True

    def test_credential_useHttpPath(self):
        """Other credential.* keys are also stripped."""
        args, changed = _strip_credential_config_overrides(
            ["-c", "credential.useHttpPath=true", "push", "origin", "main"]
        )
        assert args == ["push", "origin", "main"]
        assert changed is True

    def test_credential_url_scoped(self):
        """URL-scoped credential configs (credential.https://...) are stripped."""
        args, changed = _strip_credential_config_overrides(
            ["-c", "credential.https://github.com.helper=store", "fetch"]
        )
        assert args == ["fetch"]
        assert changed is True


# ---------------------------------------------------------------------------
# Stripping -ckey=value (combined form)
# ---------------------------------------------------------------------------


class TestStripCombined:
    """Strip -ccredential.*=... when -c and value are combined."""

    def test_combined_credential_helper(self):
        args, changed = _strip_credential_config_overrides(
            ["-ccredential.helper=store", "status"]
        )
        assert args == ["status"]
        assert changed is True

    def test_combined_mixed(self):
        args, changed = _strip_credential_config_overrides(
            ["-ccredential.helper=", "-cuser.name=Test", "status"]
        )
        assert args == ["-cuser.name=Test", "status"]
        assert changed is True


# ---------------------------------------------------------------------------
# Original list not mutated
# ---------------------------------------------------------------------------


class TestImmutability:
    """Original args list is never modified."""

    def test_original_unchanged(self):
        original = ["-c", "credential.helper=store", "status"]
        copy = list(original)
        _strip_credential_config_overrides(original)
        assert original == copy


# ---------------------------------------------------------------------------
# Realistic gh pr create scenario
# ---------------------------------------------------------------------------


class TestGhPrCreate:
    """End-to-end scenario matching what gh pr create actually sends."""

    def test_gh_rev_parse(self):
        """gh runs rev-parse with credential overrides."""
        args, changed = _strip_credential_config_overrides(
            [
                "-c", "credential.helper=",
                "-c", "credential.helper=!/usr/bin/gh auth git-credential",
                "rev-parse", "--show-toplevel",
            ]
        )
        assert args == ["rev-parse", "--show-toplevel"]
        assert changed is True

    def test_gh_remote(self):
        """gh queries remotes with credential overrides."""
        args, changed = _strip_credential_config_overrides(
            [
                "-c", "credential.helper=",
                "-c", "credential.helper=!/usr/bin/gh auth git-credential",
                "remote", "-v",
            ]
        )
        assert args == ["remote", "-v"]
        assert changed is True

    def test_gh_push(self):
        """gh pushes with credential overrides."""
        args, changed = _strip_credential_config_overrides(
            [
                "-c", "credential.helper=",
                "-c", "credential.helper=!/usr/bin/gh auth git-credential",
                "push", "--set-upstream", "origin", "feature-branch",
            ]
        )
        assert args == ["push", "--set-upstream", "origin", "feature-branch"]
        assert changed is True
