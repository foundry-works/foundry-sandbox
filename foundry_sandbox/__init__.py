"""foundry-sandbox - Docker-based sandbox environment for running Claude Code."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("foundry-sandbox")
except PackageNotFoundError:
    __version__ = "0.13.0"  # fallback for editable installs / dev
