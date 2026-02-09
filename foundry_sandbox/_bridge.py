"""Shared bridge dispatcher for shell-to-Python calls.

Provides a unified interface for dispatching shell commands to Python callables,
with standardized JSON envelope responses for success and failure cases.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Any, Callable


def bridge_main(dispatch: dict[str, Callable]) -> None:
    """Main entry point for the bridge dispatcher.

    Reads the command name from sys.argv[1], looks it up in the dispatch table,
    calls it with remaining arguments, and returns a JSON envelope response.

    Args:
        dispatch: Dictionary mapping command names to callables.

    Exit codes:
        0: Success (JSON envelope with ok=true)
        1: Known error (JSON envelope with ok=false)
        2+: Crash (no JSON on stdout, traceback to stderr if SANDBOX_DEBUG=1)

    JSON Envelopes:
        Success: {"ok": true, "result": <value>, "error": null}
        Failure: {"ok": false, "result": null, "error": {"code": <str>, "message": <str>}}
    """
    try:
        # Validate dispatch table
        if not dispatch or not isinstance(dispatch, dict):
            _emit_error_envelope(
                code="invalid_dispatch_table",
                message="Dispatch table must be a non-empty dictionary",
            )
            sys.exit(1)

        # Extract command name from arguments
        if len(sys.argv) < 2:
            _emit_error_envelope(
                code="missing_command",
                message="No command specified (expected: command [args...])",
            )
            sys.exit(1)

        command = sys.argv[1]
        args = sys.argv[2:]

        # Look up command in dispatch table
        if command not in dispatch:
            _emit_error_envelope(
                code="unknown_command",
                message=f"Unknown command: {command}",
            )
            sys.exit(1)

        # Call the command handler
        handler = dispatch[command]
        try:
            result = handler(*args)
            _emit_success_envelope(result)
            sys.exit(0)
        except (ValueError, KeyError, TypeError) as e:
            # Known error types
            _emit_error_envelope(
                code=type(e).__name__,
                message=str(e),
            )
            sys.exit(1)

    except Exception as e:
        # Unexpected crash
        _emit_crash(e)
        sys.exit(2)


def _emit_success_envelope(result: Any) -> None:
    """Emit a success envelope to stdout."""
    envelope = {
        "ok": True,
        "result": result,
        "error": None,
    }
    print(json.dumps(envelope))


def _emit_error_envelope(code: str, message: str) -> None:
    """Emit an error envelope to stdout."""
    envelope = {
        "ok": False,
        "result": None,
        "error": {
            "code": code,
            "message": message,
        },
    }
    print(json.dumps(envelope))


def _emit_crash(exc: Exception) -> None:
    """Handle a crash by emitting traceback to stderr if SANDBOX_DEBUG is set."""
    if os.environ.get("SANDBOX_DEBUG") == "1":
        traceback.print_exc(file=sys.stderr)
