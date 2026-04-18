"""PyPI version check for the cast CLI.

Queries PyPI for the latest foundry-sandbox version, caches the result
for 24 hours, and prints a stderr notice when a newer version is available.

All errors are caught — this module never crashes the CLI.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from foundry_sandbox.config import load_json, write_json
from foundry_sandbox.paths import path_version_check
from foundry_sandbox.utils import BOLD, RESET, YELLOW, log_debug

PYPI_URL = "https://pypi.org/pypi/foundry-sandbox/json"
CACHE_TTL_SECONDS = 86400  # 24 hours
FETCH_TIMEOUT_SECONDS = 5


def check_for_update() -> None:
    """Check PyPI for a newer version and print a notice if found.

    Never raises — all errors are swallowed and logged via log_debug().
    """
    try:
        _check_for_update_inner()
    except Exception as exc:  # noqa: BLE001
        log_debug(f"Version check failed: {exc}")


def _check_for_update_inner() -> None:
    if not _should_check():
        log_debug("Version check skipped (disabled by environment)")
        return

    cache_path = str(path_version_check())

    fresh, cached_version = _cache_is_fresh(cache_path)
    if fresh and cached_version:
        log_debug(f"Version check: using cached version {cached_version}")
        latest: str = cached_version
    else:
        fetched = _fetch_latest_version()
        if fetched is None:
            return
        _update_cache(cache_path, fetched)
        latest = fetched

    from foundry_sandbox import __version__ as current

    if _is_newer(latest, current):
        _print_update_notice(latest, current)


def _should_check() -> bool:
    """Return False if version checking is disabled by environment."""
    if os.environ.get("CAST_DISABLE_UPDATE_CHECK") == "1":
        return False
    if os.environ.get("SANDBOX_NONINTERACTIVE") == "1":
        return False
    ci = os.environ.get("CI", "")
    if ci in ("1", "true"):
        return False
    return True


def _cache_is_fresh(cache_path: str) -> tuple[bool, str]:
    """Read the version-check cache and return (is_fresh, latest_version).

    Returns (False, "") if the cache is missing, corrupt, or expired.
    """
    data = load_json(cache_path)
    if not data:
        return False, ""

    checked_at = data.get("checked_at")
    latest_version = data.get("latest_version")
    if not isinstance(checked_at, (int, float)) or not isinstance(latest_version, str):
        return False, ""

    age = time.time() - checked_at
    if age > CACHE_TTL_SECONDS:
        log_debug(f"Version check cache expired (age={age:.0f}s)")
        return False, ""

    return True, latest_version


def _fetch_latest_version() -> str | None:
    """Fetch the latest version string from PyPI. Returns None on failure."""
    try:
        req = urllib.request.Request(PYPI_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read())
        version = data.get("info", {}).get("version")
        if isinstance(version, str) and version:
            log_debug(f"Version check: PyPI latest = {version}")
            return version
        log_debug("Version check: unexpected PyPI response structure")
        return None
    except (urllib.error.URLError, json.JSONDecodeError, OSError, KeyError) as exc:
        log_debug(f"Version check: fetch failed: {exc}")
        return None


def _update_cache(cache_path: str, latest_version: str) -> None:
    """Write the version-check cache file."""
    try:
        write_json(
            cache_path,
            {
                "checked_at": time.time(),
                "latest_version": latest_version,
            },
        )
    except OSError as exc:
        log_debug(f"Version check: cache write failed: {exc}")


def _is_newer(latest: str, current: str) -> bool:
    """Return True if *latest* is strictly newer than *current*."""
    return _parse_version(latest) > _parse_version(current)


def _parse_version(s: str) -> tuple[int, ...]:
    """Parse a version string like '1.2.3' into a tuple of ints.

    Non-numeric suffixes (e.g. 'rc1', 'dev0') on any segment are stripped,
    so '1.2.3rc1' parses as (1, 2, 3).
    """
    parts: list[int] = []
    for segment in s.split("."):
        # Strip non-digit suffix
        digits = ""
        for ch in segment:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            parts.append(int(digits))
    return tuple(parts)


def _print_update_notice(latest: str, current: str) -> None:
    """Print an update notice to stderr."""
    print(
        f"\n{YELLOW}{BOLD}Update available:{RESET} "
        f"foundry-sandbox {BOLD}{latest}{RESET} "
        f"(current: {current}). "
        f"Run {BOLD}cast upgrade{RESET} to update.",
        file=sys.stderr,
    )
