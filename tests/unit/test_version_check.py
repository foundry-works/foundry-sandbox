"""Tests for foundry_sandbox.version_check."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.version_check import (
    CACHE_TTL_SECONDS,
    _cache_is_fresh,
    _fetch_latest_version,
    _is_newer,
    _parse_version,
    _print_update_notice,
    _should_check,
    check_for_update,
)


# ============================================================================
# _parse_version
# ============================================================================


class TestParseVersion:
    def test_simple(self) -> None:
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_two_part(self) -> None:
        assert _parse_version("1.2") == (1, 2)

    def test_four_part(self) -> None:
        assert _parse_version("1.2.3.4") == (1, 2, 3, 4)

    def test_prerelease(self) -> None:
        assert _parse_version("1.2.3rc1") == (1, 2, 3)

    def test_dev_suffix(self) -> None:
        assert _parse_version("1.0.0dev5") == (1, 0, 0)

    def test_empty(self) -> None:
        assert _parse_version("") == ()

    def test_single(self) -> None:
        assert _parse_version("42") == (42,)


# ============================================================================
# _is_newer
# ============================================================================


class TestIsNewer:
    def test_newer_patch(self) -> None:
        assert _is_newer("1.0.1", "1.0.0") is True

    def test_newer_minor(self) -> None:
        assert _is_newer("1.1.0", "1.0.9") is True

    def test_newer_major(self) -> None:
        assert _is_newer("2.0.0", "1.9.9") is True

    def test_same(self) -> None:
        assert _is_newer("1.0.0", "1.0.0") is False

    def test_older(self) -> None:
        assert _is_newer("1.0.0", "1.0.1") is False

    def test_different_length(self) -> None:
        assert _is_newer("1.1", "1.0.9") is True


# ============================================================================
# _should_check
# ============================================================================


class TestShouldCheck:
    def test_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)
        assert _should_check() is True

    def test_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAST_DISABLE_UPDATE_CHECK", "1")
        assert _should_check() is False

    def test_noninteractive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.setenv("SANDBOX_NONINTERACTIVE", "1")
        assert _should_check() is False

    def test_ci_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.setenv("CI", "1")
        assert _should_check() is False

    def test_ci_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.setenv("CI", "true")
        assert _should_check() is False

    def test_ci_other(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.setenv("CI", "false")
        assert _should_check() is True


# ============================================================================
# _cache_is_fresh
# ============================================================================


class TestCacheIsFresh:
    def test_missing(self, tmp_path: pytest.TempPathFactory) -> None:
        cache_path = str(tmp_path / "nonexistent.json")  # type: ignore[operator]
        assert _cache_is_fresh(cache_path) == (False, "")

    def test_fresh(self, tmp_path: pytest.TempPathFactory) -> None:
        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        with open(cache_path, "w") as f:
            json.dump({"checked_at": time.time(), "latest_version": "1.2.3"}, f)
        assert _cache_is_fresh(cache_path) == (True, "1.2.3")

    def test_stale(self, tmp_path: pytest.TempPathFactory) -> None:
        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        with open(cache_path, "w") as f:
            json.dump(
                {
                    "checked_at": time.time() - CACHE_TTL_SECONDS - 100,
                    "latest_version": "1.2.3",
                },
                f,
            )
        assert _cache_is_fresh(cache_path) == (False, "")

    def test_corrupt(self, tmp_path: pytest.TempPathFactory) -> None:
        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        with open(cache_path, "w") as f:
            f.write("not json")
        assert _cache_is_fresh(cache_path) == (False, "")

    def test_missing_fields(self, tmp_path: pytest.TempPathFactory) -> None:
        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        with open(cache_path, "w") as f:
            json.dump({"checked_at": time.time()}, f)
        assert _cache_is_fresh(cache_path) == (False, "")


# ============================================================================
# _fetch_latest_version
# ============================================================================


class TestFetchLatestVersion:
    def test_success(self) -> None:
        response_data = json.dumps({"info": {"version": "2.0.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.version_check.urllib.request.urlopen", return_value=mock_resp):
            assert _fetch_latest_version() == "2.0.0"

    def test_network_error(self) -> None:
        with patch(
            "foundry_sandbox.version_check.urllib.request.urlopen",
            side_effect=OSError("network error"),
        ):
            assert _fetch_latest_version() is None

    def test_bad_json(self) -> None:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.version_check.urllib.request.urlopen", return_value=mock_resp):
            assert _fetch_latest_version() is None

    def test_missing_version_key(self) -> None:
        response_data = json.dumps({"info": {}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.version_check.urllib.request.urlopen", return_value=mock_resp):
            assert _fetch_latest_version() is None


# ============================================================================
# _print_update_notice
# ============================================================================


class TestPrintUpdateNotice:
    def test_prints_to_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_update_notice("2.0.0", "1.0.0")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "2.0.0" in captured.err
        assert "1.0.0" in captured.err
        assert "cast upgrade" in captured.err


# ============================================================================
# check_for_update (integration)
# ============================================================================


class TestCheckForUpdate:
    def test_prints_notice_when_newer(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pytest.TempPathFactory,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)

        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        monkeypatch.setattr("foundry_sandbox.version_check.path_version_check", lambda: cache_path)
        monkeypatch.setattr("foundry_sandbox.version_check.__version__", "0.1.0", raising=False)

        response_data = json.dumps({"info": {"version": "99.0.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.version_check.urllib.request.urlopen", return_value=mock_resp):
            check_for_update()

        captured = capsys.readouterr()
        assert "99.0.0" in captured.err
        assert "cast upgrade" in captured.err

    def test_silent_when_current(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pytest.TempPathFactory,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)

        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        monkeypatch.setattr("foundry_sandbox.version_check.path_version_check", lambda: cache_path)

        # Patch __version__ in the module that the lazy import reads
        monkeypatch.setattr("foundry_sandbox.__version__", "1.0.0")

        response_data = json.dumps({"info": {"version": "1.0.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = response_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("foundry_sandbox.version_check.urllib.request.urlopen", return_value=mock_resp):
            check_for_update()

        captured = capsys.readouterr()
        assert captured.err == ""

    def test_uses_cache(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pytest.TempPathFactory,
    ) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)

        cache_path = str(tmp_path / "cache.json")  # type: ignore[operator]
        with open(cache_path, "w") as f:
            json.dump({"checked_at": time.time(), "latest_version": "1.0.0"}, f)

        monkeypatch.setattr("foundry_sandbox.version_check.path_version_check", lambda: cache_path)
        monkeypatch.setattr("foundry_sandbox.__version__", "1.0.0")

        with patch("foundry_sandbox.version_check.urllib.request.urlopen") as mock_urlopen:
            check_for_update()
            mock_urlopen.assert_not_called()

    def test_never_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)

        # Make _should_check raise to verify the outer try/except catches it
        monkeypatch.setattr(
            "foundry_sandbox.version_check._should_check",
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        # Should not raise
        check_for_update()
