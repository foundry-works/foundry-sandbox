"""Shared proxy-side loader for user-defined services.

Reads /etc/unified-proxy/user-services.yaml (or override path) and provides
ProxyUserService dataclass instances consumed by credential_injector.py,
generate_squid_config.py, and config.py.

Schema is shared with foundry_sandbox/user_services.py (UserService).
Changes to the YAML schema must be reflected in both loaders.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

logger = logging.getLogger(__name__)

__all__ = ["ProxyUserService", "load_proxy_user_services"]

_ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

# Domain must be a bare hostname (optionally with dots), no scheme/path/whitespace.
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$")

_VALID_HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
)

_DEFAULT_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

_DEFAULT_PATHS = ["/**"]

_REQUIRED_FIELDS = ("name", "env_var", "domain", "header", "format")

_VALID_FORMATS = ("bearer", "value")

_DEFAULT_PATH = "/etc/unified-proxy/user-services.yaml"


@dataclass
class ProxyUserService:
    """A user-defined API service loaded from user-services.yaml."""

    name: str
    env_var: str
    domain: str
    header: str
    format: str  # "bearer" or "value"
    methods: List[str] = field(default_factory=lambda: list(_DEFAULT_METHODS))
    paths: List[str] = field(default_factory=lambda: list(_DEFAULT_PATHS))


def load_proxy_user_services(
    path: Optional[str] = None,
) -> List[ProxyUserService]:
    """Load user-defined services from YAML config.

    Args:
        path: Path to user-services.yaml. Defaults to
              /etc/unified-proxy/user-services.yaml.

    Returns:
        List of validated ProxyUserService instances.
        Empty list if file not found or malformed (logs warning on errors).
    """
    resolved = path or _DEFAULT_PATH

    if not Path(resolved).is_file():
        logger.info("user-services: no config at %s", resolved)
        return []

    try:
        with open(resolved) as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("user-services: failed to read %s: %s", resolved, exc)
        return []

    if not isinstance(data, dict):
        logger.warning("user-services: expected dict in %s, got %s", resolved, type(data).__name__)
        return []

    version = data.get("version")
    if version is not None and str(version) != "1":
        logger.warning("user-services: unknown version '%s' in %s, attempting to load anyway", version, resolved)

    services_data = data.get("services")
    if not isinstance(services_data, list):
        logger.warning("user-services: missing or invalid 'services' key in %s", resolved)
        return []

    services: List[ProxyUserService] = []
    for i, entry in enumerate(services_data):
        svc = _parse_entry(entry, i, resolved)
        if svc is not None:
            services.append(svc)

    # Warn about duplicate domains/env_vars within the config
    seen_domains: dict[str, str] = {}
    seen_env_vars: dict[str, str] = {}
    for svc in services:
        if svc.domain in seen_domains:
            logger.warning(
                "user-services: duplicate domain '%s' (service '%s' conflicts with '%s')",
                svc.domain, svc.name, seen_domains[svc.domain],
            )
        else:
            seen_domains[svc.domain] = svc.name
        if svc.env_var in seen_env_vars:
            logger.warning(
                "user-services: duplicate env_var '%s' (service '%s' conflicts with '%s')",
                svc.env_var, svc.name, seen_env_vars[svc.env_var],
            )
        else:
            seen_env_vars[svc.env_var] = svc.name

    logger.info("user-services: loaded %d service(s) from %s", len(services), resolved)
    return services


def _parse_entry(
    entry: object, index: int, file_path: str
) -> Optional[ProxyUserService]:
    """Parse and validate a single service entry. Returns None on error."""
    prefix = f"services[{index}]"

    if not isinstance(entry, dict):
        logger.warning("user-services: %s must be a mapping in %s", prefix, file_path)
        return None

    # Required fields
    for field_name in _REQUIRED_FIELDS:
        if field_name not in entry:
            logger.warning(
                "user-services: %s missing '%s' in %s", prefix, field_name, file_path
            )
            return None

    name = str(entry["name"])
    env_var = str(entry["env_var"])
    domain = str(entry["domain"])
    header = str(entry["header"])
    fmt = str(entry["format"])

    if not name or not domain or not header:
        logger.warning("user-services: %s has empty required field in %s", prefix, file_path)
        return None
    if not _DOMAIN_RE.match(domain):
        logger.warning(
            "user-services: %s invalid domain '%s' (must be bare ASCII hostname, no scheme/path/whitespace) in %s",
            prefix, domain, file_path,
        )
        return None
    if not _ENV_VAR_RE.match(env_var):
        logger.warning(
            "user-services: %s invalid env_var '%s' in %s", prefix, env_var, file_path
        )
        return None
    if fmt not in _VALID_FORMATS:
        logger.warning(
            "user-services: %s format must be 'bearer' or 'value', got '%s' in %s",
            prefix, fmt, file_path,
        )
        return None

    # Optional: methods
    methods = list(_DEFAULT_METHODS)
    if "methods" in entry:
        raw = entry["methods"]
        if not isinstance(raw, list) or not raw:
            logger.warning("user-services: %s 'methods' must be a non-empty list in %s", prefix, file_path)
            return None
        methods = []
        for m in raw:
            upper_m = str(m).upper()
            if upper_m not in _VALID_HTTP_METHODS:
                logger.warning(
                    "user-services: %s invalid method '%s' in %s", prefix, m, file_path
                )
                return None
            methods.append(upper_m)

    # Optional: paths
    paths = list(_DEFAULT_PATHS)
    if "paths" in entry:
        raw = entry["paths"]
        if not isinstance(raw, list) or not raw:
            logger.warning("user-services: %s 'paths' must be a non-empty list in %s", prefix, file_path)
            return None
        paths = [str(p) for p in raw]
        if any(not p for p in paths):
            logger.warning("user-services: %s has empty path entry in %s", prefix, file_path)
            return None

    return ProxyUserService(
        name=name,
        env_var=env_var,
        domain=domain,
        header=header,
        format=fmt,
        methods=methods,
        paths=paths,
    )
