"""Exception hierarchy for foundry-sandbox.

Provides a structured exception tree so callers can catch broad
categories (``SandboxError``) or specific failure modes.

This module is a base-layer module: it must NOT import from any
other ``foundry_sandbox`` submodule.
"""

from __future__ import annotations


class SandboxError(Exception):
    """Base exception for all foundry-sandbox errors."""


class ValidationError(SandboxError):
    """Input validation failures (bad names, invalid arguments, etc.)."""


class SetupError(SandboxError):
    """Failures during sandbox creation / setup."""


class ProxyError(SandboxError):
    """Failures communicating with the unified proxy."""


class DockerError(SandboxError):
    """Failures in Docker operations (compose, exec, network, etc.)."""
