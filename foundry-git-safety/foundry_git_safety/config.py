"""Configuration loader for foundry-git-safety.

Loads foundry.yaml and push-file-restrictions.yaml configuration files
with support for environment variable overrides.
"""

import fnmatch
import logging
import os
import posixpath
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .schemas.foundry_yaml import FoundryConfig


class ConfigError(Exception):
    """Exception raised for configuration errors."""

    pass


@dataclass
class ValidationResult:
    """Result of file restriction validation."""

    blocked: bool
    reason: str = ""
    warned_files: list[str] = field(default_factory=list)


@dataclass
class FileRestrictionsData:
    """Configuration for push/commit file restrictions."""

    blocked_patterns: list[str]
    warned_patterns: list[str]
    warn_action: str  # "log" or "reject"

    def __post_init__(self) -> None:
        if not isinstance(self.blocked_patterns, list):
            raise ConfigError("blocked_patterns must be a list")
        if not isinstance(self.warned_patterns, list):
            raise ConfigError("warned_patterns must be a list")
        if self.warn_action not in ("log", "reject"):
            raise ConfigError(
                f"warn_action must be 'log' or 'reject', got '{self.warn_action}'"
            )


def _matches_pattern(path: str, pattern: str) -> bool:
    """Check if a file path matches a single restriction pattern."""
    if pattern.endswith("/"):
        return path.startswith(pattern)

    has_glob = "*" in pattern or "?" in pattern
    if has_glob:
        basename = os.path.basename(path)
        return fnmatch.fnmatch(basename, pattern) or fnmatch.fnmatch(path, pattern)

    return os.path.basename(path) == pattern


def matches_any(path: str, patterns: list[str]) -> bool:
    """Check if a file path matches any pattern in a list."""
    return any(_matches_pattern(path, p) for p in patterns)


def check_file_restrictions(
    changed_files: list[str],
    config: FileRestrictionsData,
) -> ValidationResult:
    """Check a list of changed file paths against blocked/warned patterns."""
    normalized = []
    for f in changed_files:
        f = posixpath.normpath(f)
        if ".." in f.split("/"):
            return ValidationResult(
                blocked=True, reason=f"Path traversal detected: {f}"
            )
        if f.startswith("./"):
            f = f[2:]
        normalized.append(f)

    blocked = [f for f in normalized if matches_any(f, config.blocked_patterns)]
    if blocked:
        return ValidationResult(
            blocked=True,
            reason=f"Push modifies blocked files: {', '.join(blocked)}",
        )

    warned = [f for f in normalized if matches_any(f, config.warned_patterns)]
    if warned and config.warn_action == "reject":
        return ValidationResult(
            blocked=True,
            reason=f"Push modifies restricted files: {', '.join(warned)}",
        )
    if warned:
        return ValidationResult(
            blocked=False, warned_files=warned,
        )

    return ValidationResult(blocked=False)


def _load_yaml_file(file_path: str) -> dict[str, Any]:
    """Load and parse a YAML file."""
    path = Path(file_path)

    if not path.exists():
        raise ConfigError(f"Configuration file not found: {file_path}")

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse YAML file {file_path}: {e}")
    except Exception as e:
        raise ConfigError(f"Failed to read configuration file {file_path}: {e}")

    if not isinstance(data, dict):
        raise ConfigError(
            f"Invalid configuration file {file_path}: "
            f"expected YAML dictionary, got {type(data).__name__}"
        )

    return data


def load_foundry_config(path: str | None = None) -> FoundryConfig:
    """Load and validate foundry.yaml configuration.

    Returns a FoundryConfig with defaults for any missing sections.
    If path is not provided, looks for foundry.yaml in the current directory
    and FOUNDRY_CONFIG_PATH environment variable.

    Args:
        path: Optional path to foundry.yaml.

    Returns:
        Validated FoundryConfig instance.

    Raises:
        ConfigError: If configuration is invalid.
    """
    if path is None:
        path = os.environ.get(
            "FOUNDRY_CONFIG_PATH",
            "foundry.yaml",
        )

    path_obj = Path(path)
    if not path_obj.exists():
        return FoundryConfig()

    data = _load_yaml_file(path)
    try:
        return FoundryConfig(**data)
    except Exception as e:
        raise ConfigError(f"Invalid foundry.yaml configuration: {e}")


def load_file_restrictions_config(
    path: str | None = None,
) -> FileRestrictionsData:
    """Load and validate file restrictions configuration from YAML.

    Args:
        path: Optional path to push-file-restrictions.yaml.

    Returns:
        Validated FileRestrictionsData instance.

    Raises:
        ConfigError: If configuration is invalid or missing required fields.
    """
    if path is None:
        path = os.environ.get(
            "FOUNDRY_FILE_RESTRICTIONS_PATH",
        )
        if path is None:
            try:
                from importlib.resources import files
                config_dir = files("foundry_git_safety").joinpath("default_config")
                path = str(config_dir.joinpath("push-file-restrictions.yaml"))
            except (ImportError, TypeError):
                # Fallback for dev/editable installs
                path = os.path.join(
                    os.path.dirname(__file__), "default_config",
                    "push-file-restrictions.yaml",
                )

    data = _load_yaml_file(path)

    required_fields = ["blocked_patterns", "warned_patterns", "warn_action"]
    missing = [f for f in required_fields if f not in data]
    if missing:
        raise ConfigError(
            f"Missing required fields in {path}: {', '.join(missing)}"
        )

    blocked = data["blocked_patterns"]
    if not isinstance(blocked, list):
        raise ConfigError(f"blocked_patterns must be a list in {path}")

    warned = data["warned_patterns"]
    if not isinstance(warned, list):
        raise ConfigError(f"warned_patterns must be a list in {path}")

    return FileRestrictionsData(
        blocked_patterns=[str(p) for p in blocked],
        warned_patterns=[str(p) for p in warned],
        warn_action=str(data["warn_action"]),
    )


class _FileRestrictionsCache:
    """TTL-based cache for file restrictions configuration.

    Avoids re-reading the YAML file on every request while still
    picking up changes within the TTL window.
    """

    def __init__(self, ttl: float = 30.0) -> None:
        self._config: FileRestrictionsData | None = None
        self._loaded_at: float = 0.0
        self._ttl = ttl

    def get(self, path: str | None = None) -> FileRestrictionsData:
        if path is not None:
            return load_file_restrictions_config(path)
        now = time.time()
        if self._config is not None and (now - self._loaded_at) < self._ttl:
            return self._config
        self._config = load_file_restrictions_config()
        self._loaded_at = now
        return self._config

    def invalidate(self) -> None:
        self._config = None
        self._loaded_at = 0.0


_file_restrictions_cache = _FileRestrictionsCache()


def get_file_restrictions_config(
    path: str | None = None,
) -> FileRestrictionsData:
    """Get the file restrictions config, loading and caching on first call."""
    return _file_restrictions_cache.get(path)


logger = logging.getLogger(__name__)
