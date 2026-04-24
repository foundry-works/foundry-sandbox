"""Tests for foundry_sandbox.version_check.

All network access is mocked — these tests never hit PyPI.
"""

from __future__ import annotations

import json
import time
from io import BytesIO
from pathlib import Path
import pytest

from foundry_sandbox import version_check as vc


# ---------------------------------------------------------------------------
# _should_check
# ---------------------------------------------------------------------------


class TestShouldCheck:
    def test_enabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)
        assert vc._should_check() is True

    def test_disabled_by_cast_disable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAST_DISABLE_UPDATE_CHECK", "1")
        assert vc._should_check() is False

    def test_disabled_by_noninteractive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SANDBOX_NONINTERACTIVE", "1")
        assert vc._should_check() is False

    @pytest.mark.parametrize("value", ["1", "true"])
    def test_disabled_by_ci(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("CI", value)
        assert vc._should_check() is False


# ---------------------------------------------------------------------------
# _cache_is_fresh
# ---------------------------------------------------------------------------


class TestCacheIsFresh:
    def test_missing_cache(self, tmp_path: Path) -> None:
        cache = str(tmp_path / "missing.json")
        fresh, ver = vc._cache_is_fresh(cache)
        assert fresh is False
        assert ver == ""

    def test_corrupt_json(self, tmp_path: Path) -> None:
        cache = tmp_path / "cache.json"
        cache.write_text("not json {{{")
        fresh, ver = vc._cache_is_fresh(str(cache))
        assert fresh is False
        assert ver == ""

    def test_expired_cache(self, tmp_path: Path) -> None:
        cache = tmp_path / "cache.json"
        cache.write_text(
            json.dumps(
                {"checked_at": time.time() - vc.CACHE_TTL_SECONDS - 100, "latest_version": "9.9.9"}
            )
        )
        fresh, ver = vc._cache_is_fresh(str(cache))
        assert fresh is False
        assert ver == ""

    def test_fresh_cache(self, tmp_path: Path) -> None:
        cache = tmp_path / "cache.json"
        cache.write_text(
            json.dumps({"checked_at": time.time() - 60, "latest_version": "2.0.0"})
        )
        fresh, ver = vc._cache_is_fresh(str(cache))
        assert fresh is True
        assert ver == "2.0.0"

    def test_wrong_field_types(self, tmp_path: Path) -> None:
        cache = tmp_path / "cache.json"
        cache.write_text(json.dumps({"checked_at": "not-a-number", "latest_version": "1.0"}))
        fresh, ver = vc._cache_is_fresh(str(cache))
        assert fresh is False
        assert ver == ""


# ---------------------------------------------------------------------------
# _parse_version
# ---------------------------------------------------------------------------


class TestParseVersion:
    @pytest.mark.parametrize(
        ("input_str", "expected"),
        [
            ("1.2.3", (1, 2, 3)),
            ("0.1", (0, 1)),
            ("10.20.30", (10, 20, 30)),
            ("1.2.3rc1", (1, 2, 3)),
            ("2.0.0dev0", (2, 0, 0)),
            ("1", (1,)),
        ],
    )
    def test_known_versions(self, input_str: str, expected: tuple[int, ...]) -> None:
        assert vc._parse_version(input_str) == expected


# ---------------------------------------------------------------------------
# _is_newer
# ---------------------------------------------------------------------------


class TestIsNewer:
    def test_newer(self) -> None:
        assert vc._is_newer("2.0.0", "1.0.0") is True

    def test_equal(self) -> None:
        assert vc._is_newer("1.0.0", "1.0.0") is False

    def test_older(self) -> None:
        assert vc._is_newer("1.0.0", "2.0.0") is False

    def test_different_lengths(self) -> None:
        assert vc._is_newer("1.1", "1.0.0") is True


# ---------------------------------------------------------------------------
# _fetch_latest_version (mocked network)
# ---------------------------------------------------------------------------


def _mock_response(data: dict) -> object:
    """Return an object with .read() returning JSON-encoded *data*."""
    return BytesIO(json.dumps(data).encode())


def _mock_url_error() -> Exception:
    from urllib.error import URLError

    return URLError("network down")


class TestFetchLatestVersion:
    def test_valid_pypi_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {"info": {"version": "3.5.1"}}
        monkeypatch.setattr(
            vc.urllib.request,
            "urlopen",
            lambda req, timeout=5: _mock_response(payload),
        )
        assert vc._fetch_latest_version() == "3.5.1"

    def test_malformed_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            vc.urllib.request,
            "urlopen",
            lambda req, timeout=5: BytesIO(b"not-json"),
        )
        assert vc._fetch_latest_version() is None

    def test_missing_version_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = {"info": {}}
        monkeypatch.setattr(
            vc.urllib.request,
            "urlopen",
            lambda req, timeout=5: _mock_response(payload),
        )
        assert vc._fetch_latest_version() is None

    def test_url_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*a: object, **kw: object) -> None:
            raise _mock_url_error()

        monkeypatch.setattr(vc.urllib.request, "urlopen", _raise)
        assert vc._fetch_latest_version() is None


# ---------------------------------------------------------------------------
# check_for_update (top-level: must never raise)
# ---------------------------------------------------------------------------


class TestCheckForUpdate:
    def test_swallows_exceptions(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """check_for_update must never propagate exceptions."""

        def _boom(*a: object, **kw: object) -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(vc, "_check_for_update_inner", _boom)
        # Should not raise
        vc.check_for_update()

    def test_skips_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CI", "1")
        # Patch inner to detect whether it would run
        monkeypatch.setattr(vc, "_fetch_latest_version", lambda: "_unexpected_")
        vc.check_for_update()
        # No assertion needed — just confirming no crash and no network call.

    def test_prints_notice_on_newer(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.delenv("CAST_DISABLE_UPDATE_CHECK", raising=False)
        monkeypatch.delenv("SANDBOX_NONINTERACTIVE", raising=False)
        monkeypatch.delenv("CI", raising=False)

        monkeypatch.setattr(vc, "__version__", "1.0.0", raising=False)
        # Force a fresh fetch returning a newer version.
        monkeypatch.setattr(vc, "_fetch_latest_version", lambda: "2.0.0")
        cache_path = str(tmp_path / "vc.json")
        monkeypatch.setattr(vc.path_version_check, "__call__", lambda: Path(cache_path))
        # Bypass _should_check
        monkeypatch.setattr(vc, "_should_check", lambda: True)

        vc._check_for_update_inner()
        captured = capsys.readouterr()
        assert "Update available" in captured.err
