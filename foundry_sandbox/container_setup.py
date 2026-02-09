"""Container user and environment setup.

Migrated from lib/container_config.sh: ensure_container_user, install_pip_requirements,
block_pypi_after_install, ssh_agent_preflight.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from foundry_sandbox.constants import (
    CONTAINER_HOME,
    CONTAINER_USER,
    SSH_AGENT_CONTAINER_SOCK,
    get_sandbox_sync_ssh,
    get_sandbox_verbose,
)
from foundry_sandbox.container_io import copy_file_to_container
from foundry_sandbox.utils import log_debug, log_info, log_warn


def ensure_container_user(container_id: str) -> None:
    """Verify the container user exists (built into image via SANDBOX_USERNAME).

    If user doesn't match, warn to rebuild. Skip if using default ubuntu user.

    Args:
        container_id: The container to verify the user in.
    """
    # Skip if using default ubuntu user
    if CONTAINER_USER == "ubuntu":
        return

    # Verify user exists in the image
    cmd = ["docker", "exec", container_id, "id", CONTAINER_USER]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        log_warn(f"User {CONTAINER_USER} not found in image.")
        log_warn(f"Rebuild with: SANDBOX_USERNAME={CONTAINER_USER} cast build")


def install_pip_requirements(
    container_id: str,
    requirements_path: str,
    *,
    quiet: bool = False,
) -> None:
    """Install Python packages from requirements.txt into the container.

    Supports auto-detection, host paths (copied in), and workspace-relative paths.
    After installation completes, block_pypi_after_install() adds iptables DROP
    rules to prevent future PyPI access from within the sandbox.

    Args:
        container_id: The container to install packages in.
        requirements_path: Path specification (auto, host path, or workspace-relative).
        quiet: If True, suppress non-warning output.
    """
    if not requirements_path:
        return

    container_req_path = ""

    if requirements_path == "auto":
        # Check if /workspace/requirements.txt exists in container
        cmd = ["docker", "exec", container_id, "test", "-f", "/workspace/requirements.txt"]
        if get_sandbox_verbose():
            print(f"+ {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(cmd, capture_output=True, check=False)

        if result.returncode == 0:
            container_req_path = "/workspace/requirements.txt"
            if not quiet:
                log_info("Auto-detected requirements.txt")
        else:
            if not quiet:
                log_debug("No requirements.txt found (auto-detect)")
            return
    elif requirements_path.startswith("/") or requirements_path.startswith("~/"):
        # Host path - copy into container
        expanded_path = requirements_path
        if expanded_path.startswith("~/"):
            expanded_path = str(Path.home() / expanded_path[2:])

        if not Path(expanded_path).is_file():
            if not quiet:
                log_warn(f"Requirements file not found: {expanded_path}")
            return

        container_req_path = "/tmp/sandbox-requirements.txt"
        if not copy_file_to_container(container_id, expanded_path, container_req_path):
            return
    else:
        # Workspace-relative path
        container_req_path = f"/workspace/{requirements_path}"
        cmd = ["docker", "exec", container_id, "test", "-f", container_req_path]
        if get_sandbox_verbose():
            print(f"+ {' '.join(cmd)}", file=sys.stderr)
        result = subprocess.run(cmd, capture_output=True, check=False)

        if result.returncode != 0:
            if not quiet:
                log_warn(f"Requirements file not found: {container_req_path}")
            return

    if not quiet:
        log_info(f"Installing Python packages from {container_req_path}...")

    # Run pip install (PyPI is in unified-proxy allowlist, so this works through the proxy)
    cmd = [
        "docker", "exec", "-u", CONTAINER_USER, container_id,
        "pip", "install", "--no-warn-script-location", "-r", container_req_path,
    ]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode == 0:
        if not quiet:
            log_info("Python packages installed successfully")
    else:
        if not quiet:
            log_warn("Some pip packages failed to install (continuing)")

    # Block PyPI access after install (only in credential-isolation mode)
    # Check if /etc/resolv.conf contains gateway or 172. (proxy DNS)
    cmd = ["docker", "exec", container_id, "grep", "-q", "gateway\\|172\\.", "/etc/resolv.conf"]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, check=False)

    if result.returncode == 0:
        block_pypi_after_install(container_id, quiet=quiet)

    # Clean up temp file
    if container_req_path == "/tmp/sandbox-requirements.txt":
        cmd = ["docker", "exec", container_id, "rm", "-f", container_req_path]
        if get_sandbox_verbose():
            print(f"+ {' '.join(cmd)}", file=sys.stderr)
        subprocess.run(cmd, capture_output=True, check=False)


def block_pypi_after_install(container_id: str, *, quiet: bool = False) -> None:
    """Block PyPI access after pip install completes.

    Resolves PyPI domains and adds iptables DROP rules to prevent future access.
    This allows pip install to work during setup but blocks it afterward.

    Args:
        container_id: The container to add firewall rules to.
        quiet: If True, suppress non-warning output.
    """
    pypi_domains = ["pypi.org", "files.pythonhosted.org"]

    if not quiet:
        log_info("Blocking PyPI access post-install...")

    # Resolve each domain and add DROP rules for all IPs
    for domain in pypi_domains:
        # Resolve domain to IPs (may return multiple)
        cmd = ["docker", "exec", container_id, "getent", "hosts", domain]
        if get_sandbox_verbose():
            print(f"+ {' '.join(cmd)}", file=sys.stderr)

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            if not quiet:
                log_debug(f"Could not resolve {domain} (may already be blocked)")
            continue

        # Parse IPs from output (first column, deduplicated)
        ips = set()
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if parts:
                ips.add(parts[0])

        for ip in sorted(ips):
            # Check if rule already exists to avoid duplicates
            check_cmd = [
                "docker", "exec", container_id, "sudo", "iptables",
                "-C", "OUTPUT", "-d", ip, "-j", "DROP",
            ]
            if get_sandbox_verbose():
                print(f"+ {' '.join(check_cmd)}", file=sys.stderr)

            check_result = subprocess.run(check_cmd, capture_output=True, check=False)
            if check_result.returncode == 0:
                if not quiet:
                    log_debug(f"DROP rule for {ip} already exists")
                continue

            # Insert DROP rule at beginning of OUTPUT chain
            insert_cmd = [
                "docker", "exec", container_id, "sudo", "iptables",
                "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP",
            ]
            if get_sandbox_verbose():
                print(f"+ {' '.join(insert_cmd)}", file=sys.stderr)

            insert_result = subprocess.run(insert_cmd, capture_output=True, check=False)
            if insert_result.returncode == 0:
                if not quiet:
                    log_debug(f"Added DROP rule for {domain} ({ip})")
            else:
                if not quiet:
                    log_warn(f"Failed to add DROP rule for {ip}")

    if not quiet:
        log_info("PyPI access blocked")


def ssh_agent_preflight(
    container_id: str,
    *,
    enable_ssh: bool = False,
    quiet: bool = False,
) -> None:
    """Validate SSH agent forwarding with diagnostic messages.

    Checks if SSH agent socket is available and accessible inside the container.
    Provides helpful warnings based on common failure modes.

    Args:
        container_id: The container to check SSH agent in.
        enable_ssh: If False, skip the check immediately.
        quiet: If True, skip the check immediately.
    """
    if not enable_ssh or quiet:
        return

    # Check SSH_AUTH_SOCK on host
    ssh_agent_sock = os.environ.get("SSH_AUTH_SOCK", "")
    if not ssh_agent_sock:
        log_warn("SSH agent not detected; plugin installs may use HTTPS or prompt for passphrase.")
        return

    # Check socket exists in container at SSH_AGENT_CONTAINER_SOCK
    cmd = ["docker", "exec", container_id, "test", "-S", SSH_AGENT_CONTAINER_SOCK]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    result = subprocess.run(cmd, capture_output=True, check=False)
    if result.returncode != 0:
        log_warn(f"SSH agent socket not available at {SSH_AGENT_CONTAINER_SOCK} inside container.")
        return

    # Run ssh-add -l with SSH_AUTH_SOCK set to SSH_AGENT_CONTAINER_SOCK
    cmd = [
        "docker", "exec", "-u", CONTAINER_USER, container_id,
        "sh", "-c", f"SSH_AUTH_SOCK={SSH_AGENT_CONTAINER_SOCK} ssh-add -l",
    ]
    if get_sandbox_verbose():
        print(f"+ {' '.join(cmd)}", file=sys.stderr)

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ssh_add_output = result.stdout + result.stderr

    if result.returncode == 0:
        log_info("SSH agent forwarding looks active.")
        return

    # Based on output: log appropriate warnings
    if "The agent has no identities" in ssh_add_output:
        log_warn("SSH agent is available but has no identities; run ssh-add on the host.")
    elif "Error connecting to agent" in ssh_add_output:
        log_warn(f"SSH agent is mounted but not accessible by {CONTAINER_USER}.")
    elif "Permission denied" in ssh_add_output:
        log_warn(f"SSH agent socket is not readable by {CONTAINER_USER}.")
    elif "command not found" in ssh_add_output:
        log_warn("ssh-add is not available inside the container.")
    else:
        log_warn("SSH agent check failed; plugin installs may prompt for passphrase.")
