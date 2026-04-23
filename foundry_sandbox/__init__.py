"""foundry-sandbox - Git policy and workflow layer for AI coding agents in Docker sbx microVMs."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("foundry-sandbox")
except PackageNotFoundError:
    __version__ = "0.21.0"  # fallback for editable installs / dev
