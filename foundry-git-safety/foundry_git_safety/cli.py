"""CLI entry point for foundry-git-safety."""

import os
import signal
import sys

import click

_DEFAULT_PID_FILE = "/tmp/foundry-git-safety.pid"


def _read_pid(pid_file: str) -> int | None:
    try:
        with open(pid_file) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


@click.group()
def main() -> None:
    """Foundry Git Safety — standalone git safety layer."""


@main.command()
@click.option("--config", "config_path", default=None, help="Path to foundry.yaml")
@click.option("--foreground", is_flag=True, help="Run in foreground (no daemon)")
@click.option("--port", default=None, type=int, help="Override server port")
@click.option("--pid-file", default=_DEFAULT_PID_FILE, help="PID file path")
def start(config_path: str | None, foreground: bool, port: int | None, pid_file: str) -> None:
    """Start the git safety server."""
    from .config import load_foundry_config
    from .logging_config import setup_logging

    cfg = load_foundry_config(config_path)
    setup_logging()

    server_port = port or cfg.git_safety.server.port
    server_host = cfg.git_safety.server.host
    data_dir = cfg.git_safety.server.data_dir

    # Ensure data directory exists
    os.makedirs(os.path.join(data_dir, "sandboxes"), exist_ok=True)

    if foreground:
        _run_server(server_host, server_port, data_dir, cfg)
    else:
        _daemonize(server_host, server_port, data_dir, cfg, pid_file)


def _run_server(host: str, port: int, data_dir: str, cfg) -> None:
    from .server import create_git_api, run_tcp_server

    app = create_git_api(data_dir=data_dir)
    run_tcp_server(app, host=host, port=port)


def _daemonize(host: str, port: int, data_dir: str, cfg, pid_file: str) -> None:
    existing_pid = _read_pid(pid_file)
    if existing_pid and _is_alive(existing_pid):
        click.echo(f"Server already running (PID {existing_pid})")
        sys.exit(1)

    pid = os.fork()
    if pid > 0:
        # Parent writes PID and exits
        with open(pid_file, "w") as f:
            f.write(str(pid))
        click.echo(f"Started git safety server (PID {pid})")
        sys.exit(0)

    # Child continues
    os.setsid()
    try:
        _run_server(host, port, data_dir, cfg)
    except Exception as exc:
        # Write startup error to stderr (parent has already exited,
        # but this at least gets it into any redirected logs)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@main.command()
@click.option("--pid-file", default=_DEFAULT_PID_FILE, help="PID file path")
def stop(pid_file: str) -> None:
    """Stop the git safety server."""
    pid = _read_pid(pid_file)
    if pid is None:
        click.echo("Server not running (no PID file)")
        sys.exit(1)

    if not _is_alive(pid):
        click.echo(f"Server not running (PID {pid} is stale)")
        os.unlink(pid_file)
        sys.exit(1)

    os.kill(pid, signal.SIGTERM)
    click.echo(f"Stopped git safety server (PID {pid})")
    try:
        os.unlink(pid_file)
    except FileNotFoundError:
        pass


@main.command()
@click.option("--pid-file", default=_DEFAULT_PID_FILE, help="PID file path")
@click.option("--config", "config_path", default=None, help="Path to foundry.yaml")
def status(pid_file: str, config_path: str | None) -> None:
    """Check server status."""
    import json
    import urllib.request

    from .config import load_foundry_config

    pid = _read_pid(pid_file)
    if pid is None:
        click.echo("Server not running (no PID file)")
        sys.exit(1)

    if not _is_alive(pid):
        click.echo(f"Server not running (PID {pid} is stale)")
        sys.exit(1)

    # Read port from config
    cfg = load_foundry_config(config_path)
    port = cfg.git_safety.server.port

    # Health check
    try:
        resp = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/health", timeout=2
        )
        data = json.loads(resp.read())
        click.echo(f"Server running (PID {pid}, status: {data.get('status', 'unknown')})")
    except Exception as exc:
        click.echo(f"Server running (PID {pid}) but health check failed: {exc}")
        sys.exit(1)


@main.command()
@click.option("--config", "config_path", default=None, help="Path to foundry.yaml")
def validate(config_path: str | None) -> None:
    """Validate foundry.yaml configuration."""
    from .config import load_foundry_config

    try:
        cfg = load_foundry_config(config_path)
        click.echo(f"Configuration valid (version {cfg.version})")
        click.echo(f"  Server: {cfg.git_safety.server.host}:{cfg.git_safety.server.port}")
        click.echo(f"  Protected branches: {cfg.git_safety.protected_branches.enabled}")
        click.echo(f"  Branch isolation: {cfg.git_safety.branch_isolation.enabled}")
        click.echo(f"  GitHub API filter: {cfg.git_safety.github_api.enabled}")
    except Exception as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
