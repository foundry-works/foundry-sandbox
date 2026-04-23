"""Config loader for user-defined service credential injection.

Dual-read: foundry.yaml user_services wins over legacy config/user-services.yaml.
When the legacy file is used, a deprecation warning is logged pointing to foundry.yaml
migration. The proxy routes live in foundry-git-safety.
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_SEARCH_PATHS = [
    Path("config/user-services.yaml"),
]

_LEGACY_DEPRECATION_MSG = (
    "config/user-services.yaml is deprecated — migrate to foundry.yaml user_services. "
    "See docs/configuration.md for the new schema."
)


def _slug(name: str) -> str:
    """Convert a service name to a URL-safe slug."""
    return slug(name)


def slug(name: str) -> str:
    """Convert a service name to a URL-safe slug (public for reuse)."""
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "unknown"


def _load_legacy(path: str | Path) -> list[dict[str, Any]]:
    """Load user-defined services from the legacy YAML config."""
    from foundry_git_safety.schemas.foundry_yaml import UserServicesConfig  # type: ignore[import-not-found,import-untyped,unused-ignore]

    path = Path(path)
    if not path.exists():
        return []

    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load user services config: %s", exc)
        return []

    if not raw:
        return []

    try:
        config = UserServicesConfig(**raw)
    except Exception as exc:
        logger.warning("Invalid user services config: %s", exc)
        return []

    return [s.model_dump() for s in config.services]


def load_user_services(
    path: str | Path | None = None,
    *,
    foundry_services: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Load user-defined services with dual-read semantics.

    Priority:
      1. foundry.yaml user_services (passed as foundry_services)
      2. Explicit path argument
      3. FOUNDRY_USER_SERVICES_PATH env var
      4. ./config/user-services.yaml

    Returns list of service dicts, or empty list if no config found.
    """
    if foundry_services:
        return foundry_services

    if path is None:
        env_path = os.environ.get("FOUNDRY_USER_SERVICES_PATH")
        if env_path:
            path = Path(env_path)
        else:
            for candidate in _DEFAULT_SEARCH_PATHS:
                if candidate.exists():
                    path = candidate
                    break

    if path is None:
        return []

    result = _load_legacy(path)
    if result:
        logger.warning(_LEGACY_DEPRECATION_MSG)
    return result


@lru_cache(maxsize=1)
def get_user_services() -> list[dict[str, Any]]:
    """Cached accessor for user-defined services."""
    return load_user_services()


def clear_cache() -> None:
    """Clear the cached user services (for testing or config reload)."""
    get_user_services.cache_clear()


def get_proxy_env_overrides(
    port: int = 8083,
    host: str = "host.docker.internal",
) -> dict[str, str]:
    """Return env var overrides that point sandbox tools at the proxy.

    Returns {ENV_VAR_NAME: proxy_base_url} for each declared service.
    """
    services = get_user_services()
    if not services:
        return {}

    overrides: dict[str, str] = {}
    for svc in services:
        name = str(svc["name"])
        env_var = str(svc["env_var"])
        s = _slug(name)
        proxy_url = f"http://{host}:{port}/proxy/{s}"
        overrides[env_var] = proxy_url
    return overrides
