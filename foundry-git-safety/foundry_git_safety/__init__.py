"""Foundry Git Safety — standalone git safety layer for sandbox environments."""

__version__ = "0.1.0"

try:
    from importlib.metadata import version

    __version__ = version("foundry-git-safety")
except ImportError:
    __version__ = "unknown"
