"""Unit tests for foundry_sandbox.pypi_version."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from foundry_sandbox.pypi_version import PreReleaseInfo, has_newer_prerelease


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_pypi_response(releases: dict[str, list[dict]]) -> MagicMock:
    """Build a mock urllib response returning the given releases dict."""
    data = json.dumps({"releases": releases}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = data
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _file_entry(yanked: bool = False) -> dict:
    return {"yanked": yanked}


# ---------------------------------------------------------------------------
# has_newer_prerelease
# ---------------------------------------------------------------------------


class TestHasNewerPrerelease:
    """Core version comparison logic."""

    def test_pre_newer_than_stable(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry()],
            "1.1.0a1": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info == PreReleaseInfo(has_newer=True, stable="1.0.0", pre="1.1.0a1")

    def test_pre_older_than_stable(self) -> None:
        resp = _mock_pypi_response({
            "2.0.0": [_file_entry()],
            "1.5.0rc1": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is False
        assert info.stable == "2.0.0"
        assert info.pre == ""

    def test_no_prereleases(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry()],
            "1.1.0": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is False
        assert info.stable == "1.1.0"
        assert info.pre == ""

    def test_no_stable_releases(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0a1": [_file_entry()],
            "1.0.0b2": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is False

    def test_all_yanked(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry(yanked=True)],
            "2.0.0a1": [_file_entry(yanked=True)],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is False
        assert info.stable == ""
        assert info.pre == ""

    def test_empty_releases(self) -> None:
        resp = _mock_pypi_response({})
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is False

    def test_version_with_no_files_skipped(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry()],
            "2.0.0a1": [],  # no files
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is False

    def test_malformed_version_skipped(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry()],
            "not-a-version": [_file_entry()],
            "2.0.0a1": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is True
        assert info.stable == "1.0.0"
        assert info.pre == "2.0.0a1"

    def test_dev_release_counts_as_pre(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry()],
            "1.1.0.dev3": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is True
        assert info.pre == "1.1.0.dev3"

    def test_picks_latest_stable_and_pre(self) -> None:
        resp = _mock_pypi_response({
            "1.0.0": [_file_entry()],
            "1.1.0": [_file_entry()],
            "2.0.0a1": [_file_entry()],
            "2.0.0b1": [_file_entry()],
        })
        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=resp):
            info = has_newer_prerelease()
        assert info.has_newer is True
        assert info.stable == "1.1.0"
        assert info.pre == "2.0.0b1"


# ---------------------------------------------------------------------------
# Network / parse error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_network_error(self) -> None:
        with patch(
            "foundry_sandbox.pypi_version.urllib.request.urlopen",
            side_effect=OSError("network error"),
        ):
            info = has_newer_prerelease()
        assert info == PreReleaseInfo(has_newer=False, stable="", pre="")

    def test_bad_json(self) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=mock_resp):
            info = has_newer_prerelease()
        assert info == PreReleaseInfo(has_newer=False, stable="", pre="")

    def test_missing_releases_key(self) -> None:
        data = json.dumps({"info": {"version": "1.0.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.pypi_version.urllib.request.urlopen", return_value=mock_resp):
            info = has_newer_prerelease()
        assert info.has_newer is False
