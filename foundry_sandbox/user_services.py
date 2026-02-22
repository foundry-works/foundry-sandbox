"""User-defined service configuration loader.

Reads config/user-services.yaml to discover user-defined API services
for credential injection and proxy allowlisting.

Schema is shared with unified-proxy/user_services.py (ProxyUserService).
Changes to the YAML schema must be reflected in both loaders.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from foundry_sandbox.utils import log_debug, log_warn

__all__ = ["UserService", "UserServiceConfigError", "find_user_services_path", "load_user_services"]

# In-process cache keyed by resolved path.  No TTL or file-mtime
# invalidation — suitable for short-lived CLI invocations only.
# Use _clear_cache() in tests to reset between test cases.
_cache: dict[str, list["UserService"]] = {}


def _clear_cache() -> None:
    """Clear the load_user_services() result cache (for testing)."""
    _cache.clear()


_ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

# Domain must be a bare hostname (optionally with dots), no scheme/path/whitespace.
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")

_VALID_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
)

_DEFAULT_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

_DEFAULT_PATHS = ["/**"]


@dataclass
class UserService:
    """A user-defined API service from user-services.yaml."""

    name: str
    env_var: str
    domain: str
    header: str
    format: str  # "bearer" or "value"
    methods: list[str] = field(default_factory=lambda: list(_DEFAULT_METHODS))
    paths: list[str] = field(default_factory=lambda: list(_DEFAULT_PATHS))


class UserServiceConfigError(Exception):
    """Raised when user-services.yaml is invalid."""


def find_user_services_path() -> str | None:
    """Resolve the path to user-services.yaml.

    Search order:
    1. FOUNDRY_USER_SERVICES_PATH environment variable
    2. config/user-services.yaml (relative to project root)

    Returns:
        Resolved path string, or None if no file found.
    """
    env_path = os.environ.get("FOUNDRY_USER_SERVICES_PATH")
    if env_path:
        if Path(env_path).is_file():
            log_debug(f"user-services: resolved from FOUNDRY_USER_SERVICES_PATH={env_path}")
            return env_path
        log_warn(f"user-services: FOUNDRY_USER_SERVICES_PATH={env_path} does not exist")
        return None

    default_path = str(Path(__file__).resolve().parent.parent / "config" / "user-services.yaml")
    if Path(default_path).is_file():
        log_debug(f"user-services: resolved at {default_path}")
        return default_path

    log_debug("user-services: no config file found")
    return None


def _validate_service(entry: dict[str, object], index: int) -> UserService:
    """Validate a single service entry from the YAML and return a UserService.

    Raises:
        UserServiceConfigError: On validation failure.
    """
    prefix = f"services[{index}]"

    # Required fields
    for field_name in ("name", "env_var", "domain", "header", "format"):
        if field_name not in entry:
            raise UserServiceConfigError(f"{prefix}: missing required field '{field_name}'")

    name = str(entry["name"])
    env_var = str(entry["env_var"])
    domain = str(entry["domain"])
    header = str(entry["header"])
    fmt = str(entry["format"])

    if not name:
        raise UserServiceConfigError(f"{prefix}: 'name' cannot be empty")
    if not _ENV_VAR_RE.match(env_var):
        raise UserServiceConfigError(
            f"{prefix}: 'env_var' must match [A-Z_][A-Z0-9_]*, got '{env_var}'"
        )
    if not domain:
        raise UserServiceConfigError(f"{prefix}: 'domain' cannot be empty")
    if not _DOMAIN_RE.match(domain):
        raise UserServiceConfigError(
            f"{prefix}: 'domain' must be a bare hostname (no scheme, path, or whitespace), got '{domain}'"
        )
    if not header:
        raise UserServiceConfigError(f"{prefix}: 'header' cannot be empty")
    if fmt not in ("bearer", "value"):
        raise UserServiceConfigError(
            f"{prefix}: 'format' must be 'bearer' or 'value', got '{fmt}'"
        )

    # Optional fields with defaults
    methods = _DEFAULT_METHODS
    if "methods" in entry:
        raw_methods = entry["methods"]
        if not isinstance(raw_methods, list) or not raw_methods:
            raise UserServiceConfigError(f"{prefix}: 'methods' must be a non-empty list")
        methods = []
        for m in raw_methods:
            upper_m = str(m).upper()
            if upper_m not in _VALID_HTTP_METHODS:
                raise UserServiceConfigError(
                    f"{prefix}: invalid HTTP method '{m}'. "
                    f"Valid: {', '.join(sorted(_VALID_HTTP_METHODS))}"
                )
            methods.append(upper_m)

    paths = _DEFAULT_PATHS
    if "paths" in entry:
        raw_paths = entry["paths"]
        if not isinstance(raw_paths, list) or not raw_paths:
            raise UserServiceConfigError(f"{prefix}: 'paths' must be a non-empty list")
        paths = []
        for p in raw_paths:
            p_str = str(p)
            if not p_str:
                raise UserServiceConfigError(f"{prefix}: path entries cannot be empty")
            paths.append(p_str)

    return UserService(
        name=name,
        env_var=env_var,
        domain=domain,
        header=header,
        format=fmt,
        methods=methods,
        paths=paths,
    )


def load_user_services(path: str | None = None) -> list[UserService]:
    """Load user-defined services from YAML config.

    Args:
        path: Explicit path to user-services.yaml. If None, uses
              find_user_services_path() to resolve.

    Returns:
        List of validated UserService instances. Empty list if no config found.

    Raises:
        UserServiceConfigError: If the YAML is present but invalid.
    """
    resolved = path or find_user_services_path()
    if resolved is None:
        return []

    cache_key = str(Path(resolved).resolve())
    if cache_key in _cache:
        return list(_cache[cache_key])

    try:
        with open(resolved) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise UserServiceConfigError(f"Failed to parse {resolved}: {exc}") from exc
    except OSError as exc:
        raise UserServiceConfigError(f"Failed to read {resolved}: {exc}") from exc

    if not isinstance(data, dict):
        raise UserServiceConfigError(
            f"Expected YAML dict in {resolved}, got {type(data).__name__}"
        )

    version = data.get("version")
    if version is not None and str(version) != "1":
        log_warn(f"user-services: unknown version '{version}' in {resolved}, attempting to load anyway")

    services_data = data.get("services")
    if services_data is None:
        raise UserServiceConfigError(f"Missing 'services' key in {resolved}")
    if not isinstance(services_data, list):
        raise UserServiceConfigError(f"'services' must be a list in {resolved}")

    services = []
    for i, entry in enumerate(services_data):
        if not isinstance(entry, dict):
            raise UserServiceConfigError(f"services[{i}] must be a mapping in {resolved}")
        services.append(_validate_service(entry, i))

    # Check for duplicate domains/env_vars within the config
    seen_domains: dict[str, str] = {}
    seen_env_vars: dict[str, str] = {}
    for svc in services:
        if svc.domain in seen_domains:
            log_warn(
                f"user-services: duplicate domain '{svc.domain}' "
                f"(service '{svc.name}' conflicts with '{seen_domains[svc.domain]}')"
            )
        else:
            seen_domains[svc.domain] = svc.name
        if svc.env_var in seen_env_vars:
            log_warn(
                f"user-services: duplicate env_var '{svc.env_var}' "
                f"(service '{svc.name}' conflicts with '{seen_env_vars[svc.env_var]}')"
            )
        else:
            seen_env_vars[svc.env_var] = svc.name

    log_debug(f"user-services: loaded {len(services)} service(s) from {resolved}")
    _cache[cache_key] = services
    return list(services)
