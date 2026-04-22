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


def _collect_sbx_diagnose() -> dict[str, Any]:
    from foundry_sandbox.sbx import sbx_diagnose

    try:
        parsed = sbx_diagnose(parse=True)
        if isinstance(parsed, dict):
            if "error" in parsed and "raw" in parsed:
                # JSON parse failure — return raw output alongside error
                raw = parsed.get("raw", "")
                return {
                    "output": _redact_secrets(raw or ""),
                    "error": parsed["error"],
                }
            return {"parsed": parsed}
        # Shouldn't happen, but handle gracefully
        return {"output": str(parsed)}
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


def _collect_tamper_events(n: int = 20) -> list[dict[str, Any]]:
    """Collect recent wrapper_tamper events from the decision log."""
    log_dir = os.environ.get(
        "GIT_SAFETY_DECISION_LOG_DIR",
        os.path.expanduser("~/.foundry/logs"),
    )
    log_path = Path(log_dir) / "decisions.jsonl"
    events: list[dict[str, Any]] = []
    if not log_path.exists():
        return events
    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("verb") == "wrapper_tamper":
                    events.append(entry)
    except OSError:
        pass
    return events[-n:]


def _collect_tamper_counter() -> dict[str, Any]:
    """Collect the server-side tamper event counter from /metrics."""
    import urllib.request

    result: dict[str, Any] = {"total": 0, "reachable": False}
    try:
        req = urllib.request.Request("http://127.0.0.1:8083/metrics")
        with urllib.request.urlopen(req, timeout=3) as resp:
            text = resp.read().decode()
        result["reachable"] = True
        for line in text.splitlines():
            if line.startswith("wrapper_tamper_events_total") and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        result["total"] += int(parts[-1])
                    except ValueError:
                        pass
    except Exception:
        pass
    return result


def _collect_isolation() -> dict[str, Any]:
    """Check kernel separation between host and running sandboxes."""
    from foundry_sandbox.sbx import sbx_exec, sbx_is_running, sbx_ls

    # Host kernel
    try:
        host_result = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, timeout=5,
        )
        host_kernel = host_result.stdout.strip() if host_result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        host_kernel = ""

    sandboxes: list[dict[str, str]] = []
    for sb in sbx_ls():
        name = sb.get("name", "")
        if not name or not sbx_is_running(name):
            continue
        try:
            result = sbx_exec(name, ["uname", "-r"], quiet=True)
            kernel = result.stdout.strip() if result.returncode == 0 else ""
        except Exception:
            kernel = ""
        status = "ok" if kernel and kernel != host_kernel else "warn"
        sandboxes.append({"name": name, "kernel": kernel, "status": status})

    return {"host_kernel": host_kernel, "sandboxes": sandboxes}


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
        "tamper_events": _collect_tamper_events(),
        "tamper_counter": _collect_tamper_counter(),
        "isolation": _collect_isolation(),
    }

    if json_output:
        click.echo(json.dumps(data, indent=2, default=str))
        return

    # Human-readable output
    click.echo("=== Versions ===")
    for k, v in data["versions"].items():
        click.echo(f"  {k}: {v}")

    click.echo("\n=== sbx Diagnostics ===")
    sbx_diag = data["sbx_diagnose"]
    error = sbx_diag.get("error")
    parsed = sbx_diag.get("parsed")
    output = sbx_diag.get("output")
    if error and not parsed:
        click.echo(f"  Error: {error}")
        if output:
            for line in output.split("\n"):
                click.echo(f"  {line}")
    elif parsed:
        for key, value in parsed.items():
            click.echo(f"  {key}: {value}")
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

    click.echo("\n=== Wrapper Tamper Events ===")
    tamper_counter = data["tamper_counter"]
    tamper_events = data["tamper_events"]
    server_total = tamper_counter.get("total", 0)
    server_reachable = tamper_counter.get("reachable", False)

    if server_reachable:
        click.echo(f"  Server counter: {server_total} total")
    else:
        click.echo("  Server counter: unreachable")

    if not tamper_events and server_total == 0:
        click.echo("  No wrapper tamper events recorded.")
    else:
        log_count = len(tamper_events)
        click.echo(f"  Decision log entries: {log_count}")
        if server_reachable and server_total > log_count:
            click.echo(
                f"  WARNING: {server_total - log_count} event(s) not in decision log"
                " (degraded log)"
            )
        for evt in tamper_events[-10:]:
            ts = evt.get("timestamp", "?")
            sb = evt.get("sandbox", "?")
            action = evt.get("outcome", "?")
            expected = str(evt.get("expected_sha256", ""))[:12]
            actual = str(evt.get("actual_sha256", ""))[:12]
            click.echo(
                f"  [{ts}] {sb}: {action} "
                f"(expected={expected}... actual={actual}...)"
            )

    click.echo("\n=== Kernel Isolation ===")
    isolation = data["isolation"]
    host_k = isolation["host_kernel"]
    click.echo(f"  Host kernel: {host_k or 'unknown'}")
    for sb in isolation["sandboxes"]:
        marker = sb["status"].upper()
        click.echo(f"  {sb['name']}: [{marker}] kernel={sb['kernel'] or 'unreachable'}")
