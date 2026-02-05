"""Unified proxy for credential isolation and request routing."""

try:
    from .registry import ContainerConfig, ContainerRegistry
    from .config import (
        ConfigError,
        PolicyConfig,
        AllowlistConfig,
        RateLimitConfig,
        CircuitBreakerConfig,
        BlockedPatternConfig,
        HttpEndpointConfig,
        load_policy_config,
        load_allowlist_config,
        get_config_path,
    )

    __all__ = [
        "ContainerConfig",
        "ContainerRegistry",
        "ConfigError",
        "PolicyConfig",
        "AllowlistConfig",
        "RateLimitConfig",
        "CircuitBreakerConfig",
        "BlockedPatternConfig",
        "HttpEndpointConfig",
        "load_policy_config",
        "load_allowlist_config",
        "get_config_path",
    ]
except ImportError:
    # Allow running as a non-package (e.g., during testing)
    __all__ = []
