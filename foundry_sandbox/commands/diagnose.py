"""Diagnose command — collect diagnostic information for support.

Gathers sbx diagnostics, git safety server health/readiness, decision
log entries, and system version info. Each source is collected
independently with graceful degradation.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import click

# Patterns for secret redaction
_SECRET_PATTERNS = [
    re.compile(
        r'(hmac.?secret["\s:=]+)["\']?[a-f0-9]{64}["\']?',
        re.IGNORECASE,
    ),
    re.compile(
        r'(api.?key["\s:=]+)["\']?sk-[a-zA-Z0-9]{20,}["\']?',
        re.IGNORECASE,
    ),
    re.compile(
        r'(token["\s:=]+)["\']?ghp_[a-zA-Z0-9]{36}["\']?',
    ),
]


def _redact_secrets(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r'\1[REDACTED]', text)
    return text


def _collect_versions() -> dict[str, str]:
    versions = {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }
    for tool in ("sbx", "git"):
        try:
            result = subprocess.run(
                [tool, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            versions[tool] = result.stdout.strip().split("\n")[0]
        except (OSError, subprocess.TimeoutExpired):
            versions[tool] = "not found"
    return versions


def _collect_sbx_diagnose() -> dict[str, str]:
    from foundry_sandbox.sbx import sbx_diagnose

    try:
        result = sbx_diagnose()
        output = result.stdout.strip() if result.stdout else ""
        if result.returncode != 0:
            output += f"\n(exit code {result.returncode})"
        return {"output": _redact_secrets(output)}
    except Exception as exc:
        return {"error": str(exc)}


def _collect_git_safety_health() -> dict[str, Any]:
    from foundry_sandbox.git_safety import git_safety_server_health

    try:
        return git_safety_server_health() or {"reachable": False}
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


def _collect_git_safety_readiness() -> dict[str, Any]:
    from foundry_sandbox.git_safety import git_safety_readiness

    try:
        return git_safety_readiness() or {"ready": False}
    except Exception as exc:
        return {"ready": False, "error": str(exc)}


def _collect_decision_log(n: int = 50) -> dict[str, Any]:
    log_dir = os.environ.get(
        "GIT_SAFETY_DECISION_LOG_DIR",
        os.path.expanduser("~/.foundry/logs"),
    )
    log_path = Path(log_dir) / "decisions.jsonl"
    entries = []
    if log_path.exists():
        try:
            with open(log_path) as f:
                lines = f.readlines()
            for line in lines[-n:]:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
    return {"count": len(entries), "entries": entries}


@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def diagnose(json_output: bool) -> None:
    """Collect diagnostic information for support."""
    data: dict[str, Any] = {
        "versions": _collect_versions(),
        "sbx_diagnose": _collect_sbx_diagnose(),
        "git_safety": {
            "health": _collect_git_safety_health(),
            "readiness": _collect_git_safety_readiness(),
        },
        "decision_log": _collect_decision_log(),
    }

    if json_output:
        click.echo(json.dumps(data, indent=2, default=str))
        return

    # Human-readable output
    click.echo("=== Versions ===")
    for k, v in data["versions"].items():
        click.echo(f"  {k}: {v}")

    click.echo("\n=== sbx Diagnostics ===")
    output = data["sbx_diagnose"].get("output", "")
    error = data["sbx_diagnose"].get("error")
    if error:
        click.echo(f"  Error: {error}")
    elif output:
        for line in output.split("\n"):
            click.echo(f"  {line}")

    click.echo("\n=== Git Safety Server ===")
    health = data["git_safety"]["health"]
    if health.get("reachable") is False and "error" in health:
        click.echo(f"  Status: unreachable ({health['error']})")
    else:
        status = health.get("status", "unknown")
        click.echo(f"  Status: {status}")
        if health.get("config_valid") is not None:
            click.echo(f"  Config valid: {health['config_valid']}")
        if health.get("uptime_seconds") is not None:
            click.echo(f"  Uptime: {health['uptime_seconds']}s")

    readiness = data["git_safety"]["readiness"]
    ready = readiness.get("ready", False)
    click.echo(f"  Ready: {ready}")
    checks = readiness.get("checks", {})
    for name, check in checks.items():
        ok = check.get("ok", False)
        detail = check.get("detail", "")
        marker = "ok" if ok else "FAIL"
        click.echo(f"    {name}: [{marker}] {detail}")

    click.echo("\n=== Decision Log ===")
    log_info = data["decision_log"]
    click.echo(f"  Recent entries: {log_info['count']}")
    for entry in log_info["entries"][-10:]:
        ts = entry.get("timestamp", "?")
        outcome = entry.get("outcome", "?")
        verb = entry.get("verb", "?")
        sandbox = entry.get("sandbox", "?")
        rule = entry.get("rule", "")
        click.echo(f"  [{ts}] {outcome} {verb} sandbox={sandbox} rule={rule}")
