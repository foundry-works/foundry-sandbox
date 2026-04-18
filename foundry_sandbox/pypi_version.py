"""PyPI version query for foundry-mcp.

Fetches the PyPI JSON API and classifies the latest stable vs pre-release
versions so the wizard can offer a pre-release upgrade option.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import NamedTuple

from packaging.version import Version, parse as parse_version

PYPI_URL = "https://pypi.org/pypi/foundry-mcp/json"
_TIMEOUT = 5  # seconds


class PreReleaseInfo(NamedTuple):
    """Result of a pre-release availability check."""

    has_newer: bool
    """True if a pre-release version newer than stable exists."""

    stable: str
    """Latest stable version string (empty if none found)."""

    pre: str
    """Latest pre-release version string (empty if none newer than stable)."""


def has_newer_prerelease() -> PreReleaseInfo:
    """Check PyPI for a foundry-mcp pre-release newer than the latest stable.

    Returns:
        PreReleaseInfo with comparison results.
        On network/parse errors, returns has_newer=False so the wizard skips silently.
    """
    try:
        req = urllib.request.Request(PYPI_URL, headers={
            "Accept": "application/json",
            "User-Agent": "foundry-sandbox",
        })
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return PreReleaseInfo(has_newer=False, stable="", pre="")

    releases = data.get("releases", {})
    if not releases:
        return PreReleaseInfo(has_newer=False, stable="", pre="")

    best_stable: Version | None = None
    best_pre: Version | None = None

    for ver_str, files in releases.items():
        # Skip versions with no files or where all files are yanked
        if not files or all(f.get("yanked", False) for f in files):
            continue
        try:
            ver = parse_version(ver_str)
        except Exception:
            continue

        if ver.is_prerelease or ver.is_devrelease:
            if best_pre is None or ver > best_pre:
                best_pre = ver
        else:
            if best_stable is None or ver > best_stable:
                best_stable = ver

    stable_str = str(best_stable) if best_stable else ""
    pre_str = ""
    has_newer = False

    if best_pre is not None and best_stable is not None and best_pre > best_stable:
        pre_str = str(best_pre)
        has_newer = True

    return PreReleaseInfo(has_newer=has_newer, stable=stable_str, pre=pre_str)
