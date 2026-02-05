"""Structured JSON logging configuration.

This module provides a centralized logging configuration for the unified proxy,
with support for:
- JSON-formatted log output for machine parsing
- Correlation IDs (request_id, container_id) for request tracing
- Configurable log levels via environment variables
- Thread-local context for correlation IDs

Usage:
    from logging_config import setup_logging, get_logger, set_context

    # Initialize logging at application startup
    setup_logging()

    # Get a logger for your module
    logger = get_logger(__name__)

    # Set correlation context for the current request
    set_context(request_id="req-123", container_id="container-abc")

    # Log with automatic context injection
    logger.info("Processing request")
    # Output: {"timestamp": "...", "level": "INFO", "message": "Processing request",
    #          "request_id": "req-123", "container_id": "container-abc", ...}

    # Clear context when request completes
    clear_context()
"""

import json
import logging
import os
import sys
import time
from contextvars import ContextVar
from typing import Any, Optional

# Context variables for correlation IDs (thread-safe)
_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_container_id: ContextVar[Optional[str]] = ContextVar("container_id", default=None)
_extra_context: ContextVar[dict] = ContextVar("extra_context", default={})

# Configuration from environment
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "json")  # "json" or "text"
LOG_INCLUDE_TIMESTAMP = os.environ.get("LOG_INCLUDE_TIMESTAMP", "true").lower() == "true"
LOG_INCLUDE_LOCATION = os.environ.get("LOG_INCLUDE_LOCATION", "true").lower() == "true"


def set_context(
    request_id: Optional[str] = None,
    container_id: Optional[str] = None,
    **extra: Any,
) -> None:
    """Set correlation context for the current async context / thread.

    Args:
        request_id: Unique request identifier for tracing.
        container_id: Container identifier for the request source.
        **extra: Additional context fields to include in logs.
    """
    if request_id is not None:
        _request_id.set(request_id)
    if container_id is not None:
        _container_id.set(container_id)
    if extra:
        current = _extra_context.get()
        _extra_context.set({**current, **extra})


def get_context() -> dict[str, Any]:
    """Get the current correlation context.

    Returns:
        Dictionary with request_id, container_id, and any extra context.
    """
    context = {}
    request_id = _request_id.get()
    if request_id:
        context["request_id"] = request_id
    container_id = _container_id.get()
    if container_id:
        context["container_id"] = container_id
    extra = _extra_context.get()
    if extra:
        context.update(extra)
    return context


def clear_context() -> None:
    """Clear all correlation context for the current async context / thread."""
    _request_id.set(None)
    _container_id.set(None)
    _extra_context.set({})


class JSONFormatter(logging.Formatter):
    """JSON log formatter with correlation ID support.

    Produces logs in the format:
    {
        "timestamp": "2024-01-15T10:30:00.123456Z",
        "level": "INFO",
        "logger": "mymodule",
        "message": "Something happened",
        "request_id": "req-123",
        "container_id": "container-abc",
        "location": "mymodule.py:42:my_function",
        "extra_field": "extra_value"
    }
    """

    def __init__(
        self,
        include_timestamp: bool = True,
        include_location: bool = True,
    ):
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_location = include_location

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON.

        Args:
            record: The log record to format.

        Returns:
            JSON-formatted log string.
        """
        log_dict: dict[str, Any] = {}

        # Timestamp in ISO 8601 format with Z suffix
        if self.include_timestamp:
            log_dict["timestamp"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.gmtime(record.created),
            ) + f".{int(record.msecs * 1000):06d}Z"

        # Standard fields
        log_dict["level"] = record.levelname
        log_dict["logger"] = record.name
        log_dict["message"] = record.getMessage()

        # Correlation context (from context variables)
        context = get_context()
        log_dict.update(context)

        # Source location
        if self.include_location:
            log_dict["location"] = f"{record.filename}:{record.lineno}:{record.funcName}"

        # Exception info if present
        if record.exc_info:
            log_dict["exception"] = self.formatException(record.exc_info)

        # Extra fields from the log call (excluding standard LogRecord attributes)
        standard_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "pathname", "process", "processName", "relativeCreated",
            "stack_info", "exc_info", "exc_text", "thread", "threadName",
            "message", "taskName",
        }
        for key, value in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                log_dict[key] = value

        return json.dumps(log_dict, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter with correlation ID support.

    Produces logs in the format:
    2024-01-15T10:30:00.123456Z INFO [mymodule] [req-123/container-abc] Something happened
    """

    def __init__(
        self,
        include_timestamp: bool = True,
        include_location: bool = False,
    ):
        super().__init__()
        self.include_timestamp = include_timestamp
        self.include_location = include_location

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as human-readable text.

        Args:
            record: The log record to format.

        Returns:
            Text-formatted log string.
        """
        parts = []

        # Timestamp
        if self.include_timestamp:
            timestamp = time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.gmtime(record.created),
            ) + f".{int(record.msecs * 1000):06d}Z"
            parts.append(timestamp)

        # Level and logger
        parts.append(record.levelname)
        parts.append(f"[{record.name}]")

        # Correlation context
        context = get_context()
        if context:
            ctx_parts = []
            if "request_id" in context:
                ctx_parts.append(context["request_id"])
            if "container_id" in context:
                ctx_parts.append(context["container_id"])
            if ctx_parts:
                parts.append(f"[{'/'.join(ctx_parts)}]")

        # Message
        parts.append(record.getMessage())

        # Location
        if self.include_location:
            parts.append(f"({record.filename}:{record.lineno})")

        result = " ".join(parts)

        # Exception info
        if record.exc_info:
            result += "\n" + self.formatException(record.exc_info)

        return result


def setup_logging(
    level: Optional[str] = None,
    format_type: Optional[str] = None,
    include_timestamp: Optional[bool] = None,
    include_location: Optional[bool] = None,
) -> None:
    """Configure the root logger with the specified settings.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
               Defaults to LOG_LEVEL environment variable or INFO.
        format_type: Log format ("json" or "text").
                     Defaults to LOG_FORMAT environment variable or "json".
        include_timestamp: Include timestamp in logs.
                          Defaults to LOG_INCLUDE_TIMESTAMP env var or True.
        include_location: Include source location in logs.
                         Defaults to LOG_INCLUDE_LOCATION env var or True.
    """
    # Apply defaults from environment
    level = level or LOG_LEVEL
    format_type = format_type or LOG_FORMAT
    if include_timestamp is None:
        include_timestamp = LOG_INCLUDE_TIMESTAMP
    if include_location is None:
        include_location = LOG_INCLUDE_LOCATION

    # Create formatter
    if format_type.lower() == "json":
        formatter = JSONFormatter(
            include_timestamp=include_timestamp,
            include_location=include_location,
        )
    else:
        formatter = TextFormatter(
            include_timestamp=include_timestamp,
            include_location=include_location,
        )

    # Configure handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.

    This is a convenience wrapper around logging.getLogger that ensures
    the logging configuration has been applied.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Configured Logger instance.
    """
    return logging.getLogger(name)


class LogContext:
    """Context manager for setting correlation context.

    Usage:
        with LogContext(request_id="req-123", container_id="container-abc"):
            logger.info("Processing")  # Will include request_id and container_id
        # Context automatically cleared after the block
    """

    def __init__(
        self,
        request_id: Optional[str] = None,
        container_id: Optional[str] = None,
        **extra: Any,
    ):
        self.request_id = request_id
        self.container_id = container_id
        self.extra = extra
        self._tokens: dict[str, Any] = {}

    def __enter__(self) -> "LogContext":
        # Save current values
        self._tokens["request_id"] = _request_id.get()
        self._tokens["container_id"] = _container_id.get()
        self._tokens["extra"] = _extra_context.get()

        # Set new values
        if self.request_id is not None:
            _request_id.set(self.request_id)
        if self.container_id is not None:
            _container_id.set(self.container_id)
        if self.extra:
            current = _extra_context.get()
            _extra_context.set({**current, **self.extra})

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Restore previous values
        _request_id.set(self._tokens.get("request_id"))
        _container_id.set(self._tokens.get("container_id"))
        _extra_context.set(self._tokens.get("extra", {}))


def generate_request_id() -> str:
    """Generate a unique request ID.

    Returns:
        A unique identifier string (UUID4 format).
    """
    import uuid
    return str(uuid.uuid4())


# Flask integration helpers
def flask_request_middleware(app):
    """Add request logging middleware to a Flask app.

    This middleware:
    - Generates a request_id for each request (or uses X-Request-ID header)
    - Sets logging context with request_id and container_id (from X-Container-Id)
    - Logs request start and completion

    Args:
        app: Flask application instance.
    """
    logger = get_logger("http")

    @app.before_request
    def before_request():
        from flask import request, g

        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID") or generate_request_id()
        g.request_id = request_id

        # Get container ID from header (if present)
        container_id = request.headers.get("X-Container-ID")

        # Set logging context
        set_context(
            request_id=request_id,
            container_id=container_id,
            method=request.method,
            path=request.path,
        )

        # Log request start
        logger.info(
            f"{request.method} {request.path}",
            extra={"event": "request_start"},
        )

        # Store start time for duration calculation
        g.request_start_time = time.time()

    @app.after_request
    def after_request(response):
        from flask import request, g

        # Calculate duration
        duration_ms = None
        if hasattr(g, "request_start_time"):
            duration_ms = (time.time() - g.request_start_time) * 1000

        # Log request completion
        logger.info(
            f"{request.method} {request.path} -> {response.status_code}",
            extra={
                "event": "request_complete",
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        # Add request ID to response headers
        if hasattr(g, "request_id"):
            response.headers["X-Request-ID"] = g.request_id

        return response

    @app.teardown_request
    def teardown_request(exception=None):
        # Clear logging context
        clear_context()

        if exception:
            logger.error(
                f"Request failed with exception: {exception}",
                exc_info=True,
            )


# Initialize logging when module is imported (with defaults)
# Applications can call setup_logging() again to customize
setup_logging()


class _ConnectionLifecycleFilter(logging.Filter):
    """Suppress noisy mitmproxy connection lifecycle log messages."""

    _NOISY_PREFIXES = (
        "client connect",
        "client disconnect",
        "server connect",
        "server disconnect",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return not any(msg.startswith(prefix) for prefix in self._NOISY_PREFIXES)


logging.getLogger("mitmproxy.proxy.server").addFilter(_ConnectionLifecycleFilter())
