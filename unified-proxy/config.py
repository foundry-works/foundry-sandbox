"""Configuration loader for unified proxy.

Loads and validates policy.yaml and allowlist.yaml configuration files
with support for environment variable overrides.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

import yaml


class ConfigError(Exception):
    """Exception raised for configuration errors."""

    pass


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    capacity: int
    refill_rate: float

    def __post_init__(self):
        """Validate rate limit configuration."""
        if self.capacity <= 0:
            raise ConfigError(f"Rate limit capacity must be positive, got {self.capacity}")
        if self.refill_rate <= 0:
            raise ConfigError(
                f"Rate limit refill_rate must be positive, got {self.refill_rate}"
            )


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""

    failure_threshold: int
    recovery_timeout: int
    success_threshold: int

    def __post_init__(self):
        """Validate circuit breaker configuration."""
        if self.failure_threshold <= 0:
            raise ConfigError(
                f"Circuit breaker failure_threshold must be positive, got {self.failure_threshold}"
            )
        if self.recovery_timeout <= 0:
            raise ConfigError(
                f"Circuit breaker recovery_timeout must be positive, got {self.recovery_timeout}"
            )
        if self.success_threshold <= 0:
            raise ConfigError(
                f"Circuit breaker success_threshold must be positive, got {self.success_threshold}"
            )


@dataclass
class BlockedPatternConfig:
    """Configuration for a blocked request pattern."""

    method: str
    path_pattern: str
    _compiled_pattern: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        """Validate and compile pattern."""
        if not self.method:
            raise ConfigError("Blocked pattern method cannot be empty")
        if not self.path_pattern:
            raise ConfigError("Blocked pattern path_pattern cannot be empty")

        # Validate method is a valid HTTP method
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        if self.method.upper() not in valid_methods:
            raise ConfigError(
                f"Invalid HTTP method '{self.method}'. "
                f"Valid methods: {', '.join(sorted(valid_methods))}"
            )

        # Compile regex pattern
        try:
            self._compiled_pattern = re.compile(self.path_pattern)
        except re.error as e:
            raise ConfigError(f"Invalid regex pattern '{self.path_pattern}': {e}")

    def matches(self, method: str, path: str) -> bool:
        """Check if the given method and path match this pattern.

        Args:
            method: HTTP method to check.
            path: URL path to check.

        Returns:
            True if the pattern matches, False otherwise.
        """
        if self.method.upper() != method.upper():
            return False
        if self._compiled_pattern is None:
            return False
        return self._compiled_pattern.match(path) is not None


@dataclass
class PolicyConfig:
    """Policy configuration loaded from policy.yaml."""

    version: str
    default_action: str
    rate_limits: Dict[str, RateLimitConfig]
    circuit_breaker: CircuitBreakerConfig
    blocked_patterns: List[BlockedPatternConfig]

    def __post_init__(self):
        """Validate policy configuration."""
        # Validate version format
        if not self.version:
            raise ConfigError("Policy version cannot be empty")

        # Validate default action
        if self.default_action not in ("allow", "deny"):
            raise ConfigError(
                f"Policy default_action must be 'allow' or 'deny', got '{self.default_action}'"
            )

        # Validate rate limits exist
        if not self.rate_limits:
            raise ConfigError("Policy must have at least one rate limit configuration")

        # Validate default rate limit exists
        if "default" not in self.rate_limits:
            raise ConfigError("Policy rate_limits must include a 'default' configuration")


@dataclass
class HttpEndpointConfig:
    """HTTP endpoint allowlist configuration."""

    host: str
    methods: List[str]
    paths: List[str]

    def __post_init__(self):
        """Validate HTTP endpoint configuration."""
        if not self.host:
            raise ConfigError("HTTP endpoint host cannot be empty")

        if not self.methods:
            raise ConfigError(f"HTTP endpoint {self.host} must have at least one method")

        # Validate HTTP methods
        valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
        for method in self.methods:
            if method.upper() not in valid_methods:
                raise ConfigError(
                    f"Invalid HTTP method '{method}' for endpoint {self.host}. "
                    f"Valid methods: {', '.join(sorted(valid_methods))}"
                )

        if not self.paths:
            raise ConfigError(f"HTTP endpoint {self.host} must have at least one path")


@dataclass
class AllowlistConfig:
    """Allowlist configuration loaded from allowlist.yaml."""

    version: str
    domains: List[str]
    http_endpoints: List[HttpEndpointConfig]

    def __post_init__(self):
        """Validate allowlist configuration."""
        # Validate version format
        if not self.version:
            raise ConfigError("Allowlist version cannot be empty")

        # Validate domains exist
        if not self.domains:
            raise ConfigError("Allowlist must have at least one domain")

        # Validate domain formats
        for domain in self.domains:
            if not domain:
                raise ConfigError("Allowlist domain cannot be empty")
            # Basic validation - must not contain protocol or path
            if "://" in domain:
                raise ConfigError(
                    f"Invalid domain '{domain}': must not include protocol (http://)"
                )
            if "/" in domain.rstrip("/"):
                raise ConfigError(
                    f"Invalid domain '{domain}': must not include path components"
                )

        # Validate http_endpoints
        if not self.http_endpoints:
            raise ConfigError("Allowlist must have at least one HTTP endpoint")


def get_config_path(filename: str) -> str:
    """Get configuration file path from environment or use default.

    Args:
        filename: Name of the config file (e.g., 'policy.yaml', 'allowlist.yaml').

    Returns:
        Absolute path to the configuration file.

    Environment Variables:
        PROXY_POLICY_PATH: Override path for policy.yaml
        PROXY_ALLOWLIST_PATH: Override path for allowlist.yaml
    """
    # Map filenames to environment variables
    env_vars = {
        "policy.yaml": "PROXY_POLICY_PATH",
        "allowlist.yaml": "PROXY_ALLOWLIST_PATH",
    }

    env_var = env_vars.get(filename)
    if env_var and os.environ.get(env_var):
        return os.environ[env_var]

    # Default location
    return f"/etc/unified-proxy/{filename}"


def _load_yaml_file(file_path: str) -> Dict[str, Any]:
    """Load and parse a YAML file.

    Args:
        file_path: Path to the YAML file.

    Returns:
        Parsed YAML content as a dictionary.

    Raises:
        ConfigError: If file not found or YAML parsing fails.
    """
    path = Path(file_path)

    if not path.exists():
        raise ConfigError(
            f"Configuration file not found: {file_path}\n"
            f"Expected location: {file_path}\n"
            f"Hint: You can override the location with environment variables:\n"
            f"  - PROXY_POLICY_PATH for policy.yaml\n"
            f"  - PROXY_ALLOWLIST_PATH for allowlist.yaml"
        )

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse YAML file {file_path}: {e}")
    except Exception as e:
        raise ConfigError(f"Failed to read configuration file {file_path}: {e}")

    if not isinstance(data, dict):
        raise ConfigError(
            f"Invalid configuration file {file_path}: expected YAML dictionary, got {type(data).__name__}"
        )

    return data


def load_policy_config(path: Optional[str] = None) -> PolicyConfig:
    """Load and validate policy configuration.

    Args:
        path: Optional path to policy.yaml. If not provided, uses
              environment variable PROXY_POLICY_PATH or default location.

    Returns:
        Validated PolicyConfig instance.

    Raises:
        ConfigError: If configuration is invalid or missing required fields.
    """
    if path is None:
        path = get_config_path("policy.yaml")

    data = _load_yaml_file(path)

    # Validate required top-level fields
    required_fields = ["version", "default_action", "rate_limits", "circuit_breaker"]
    missing_fields = [f for f in required_fields if f not in data]
    if missing_fields:
        raise ConfigError(
            f"Missing required fields in {path}: {', '.join(missing_fields)}"
        )

    # Parse rate limits
    try:
        rate_limits_data = data["rate_limits"]
        if not isinstance(rate_limits_data, dict):
            raise ConfigError("rate_limits must be a dictionary")

        rate_limits = {}
        for key, value in rate_limits_data.items():
            if not isinstance(value, dict):
                raise ConfigError(f"rate_limits.{key} must be a dictionary")
            if "capacity" not in value:
                raise ConfigError(f"rate_limits.{key} missing required field 'capacity'")
            if "refill_rate" not in value:
                raise ConfigError(
                    f"rate_limits.{key} missing required field 'refill_rate'"
                )
            rate_limits[key] = RateLimitConfig(
                capacity=int(value["capacity"]),
                refill_rate=float(value["refill_rate"]),
            )
    except (KeyError, ValueError, TypeError) as e:
        raise ConfigError(f"Invalid rate_limits configuration: {e}")

    # Parse circuit breaker
    try:
        cb_data = data["circuit_breaker"]
        if not isinstance(cb_data, dict):
            raise ConfigError("circuit_breaker must be a dictionary")

        required_cb_fields = ["failure_threshold", "recovery_timeout", "success_threshold"]
        missing_cb_fields = [f for f in required_cb_fields if f not in cb_data]
        if missing_cb_fields:
            raise ConfigError(
                f"circuit_breaker missing required fields: {', '.join(missing_cb_fields)}"
            )

        circuit_breaker = CircuitBreakerConfig(
            failure_threshold=int(cb_data["failure_threshold"]),
            recovery_timeout=int(cb_data["recovery_timeout"]),
            success_threshold=int(cb_data["success_threshold"]),
        )
    except (ValueError, TypeError) as e:
        raise ConfigError(f"Invalid circuit_breaker configuration: {e}")

    # Parse blocked patterns (optional field)
    blocked_patterns = []
    if "blocked_patterns" in data:
        patterns_data = data["blocked_patterns"]
        if not isinstance(patterns_data, list):
            raise ConfigError("blocked_patterns must be a list")

        for i, pattern in enumerate(patterns_data):
            if not isinstance(pattern, dict):
                raise ConfigError(f"blocked_patterns[{i}] must be a dictionary")
            if "method" not in pattern:
                raise ConfigError(f"blocked_patterns[{i}] missing required field 'method'")
            if "path_pattern" not in pattern:
                raise ConfigError(
                    f"blocked_patterns[{i}] missing required field 'path_pattern'"
                )

            blocked_patterns.append(
                BlockedPatternConfig(
                    method=pattern["method"],
                    path_pattern=pattern["path_pattern"],
                )
            )

    return PolicyConfig(
        version=str(data["version"]),
        default_action=str(data["default_action"]),
        rate_limits=rate_limits,
        circuit_breaker=circuit_breaker,
        blocked_patterns=blocked_patterns,
    )


def load_allowlist_config(path: Optional[str] = None) -> AllowlistConfig:
    """Load and validate allowlist configuration.

    Args:
        path: Optional path to allowlist.yaml. If not provided, uses
              environment variable PROXY_ALLOWLIST_PATH or default location.

    Returns:
        Validated AllowlistConfig instance.

    Raises:
        ConfigError: If configuration is invalid or missing required fields.
    """
    if path is None:
        path = get_config_path("allowlist.yaml")

    data = _load_yaml_file(path)

    # Validate required top-level fields
    required_fields = ["version", "domains", "http_endpoints"]
    missing_fields = [f for f in required_fields if f not in data]
    if missing_fields:
        raise ConfigError(
            f"Missing required fields in {path}: {', '.join(missing_fields)}"
        )

    # Parse domains
    domains_data = data["domains"]
    if not isinstance(domains_data, list):
        raise ConfigError("domains must be a list")

    domains = [str(d) for d in domains_data]

    # Parse HTTP endpoints
    endpoints_data = data["http_endpoints"]
    if not isinstance(endpoints_data, list):
        raise ConfigError("http_endpoints must be a list")

    http_endpoints = []
    for i, endpoint in enumerate(endpoints_data):
        if not isinstance(endpoint, dict):
            raise ConfigError(f"http_endpoints[{i}] must be a dictionary")
        if "host" not in endpoint:
            raise ConfigError(f"http_endpoints[{i}] missing required field 'host'")
        if "methods" not in endpoint:
            raise ConfigError(f"http_endpoints[{i}] missing required field 'methods'")
        if "paths" not in endpoint:
            raise ConfigError(f"http_endpoints[{i}] missing required field 'paths'")

        if not isinstance(endpoint["methods"], list):
            raise ConfigError(f"http_endpoints[{i}].methods must be a list")
        if not isinstance(endpoint["paths"], list):
            raise ConfigError(f"http_endpoints[{i}].paths must be a list")

        http_endpoints.append(
            HttpEndpointConfig(
                host=str(endpoint["host"]),
                methods=[str(m) for m in endpoint["methods"]],
                paths=[str(p) for p in endpoint["paths"]],
            )
        )

    return AllowlistConfig(
        version=str(data["version"]),
        domains=domains,
        http_endpoints=http_endpoints,
    )
