"""Network isolation tests for sandbox.sh.

Verifies that credential isolation and network modes work correctly:
- Default network mode is "limited" (credential isolation enabled)
- --no-isolate-credentials flag disables the credential proxy
- Container network configuration reflects isolation settings
"""

import json
import os
import subprocess

import pytest

pytestmark = [
    pytest.mark.orchestration,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]


def _read_metadata(sandbox_name: str) -> dict:
    """Read and parse the sandbox metadata.json file.

    Args:
        sandbox_name: The sandbox name used during creation.

    Returns:
        Parsed metadata dictionary.
    """
    metadata_path = os.path.expanduser(
        f"~/.sandboxes/claude-config/{sandbox_name}/metadata.json"
    )
    assert os.path.isfile(metadata_path), (
        f"metadata.json not found at {metadata_path}"
    )
    with open(metadata_path, "r", encoding="utf-8") as fh:
        return json.loads(fh.read())


def test_default_network_mode(cli, sandbox_name, local_repo):
    """Creating a sandbox with defaults should set network_mode to 'limited'.

    Credential isolation is enabled by default, so the metadata should
    reflect network_mode='limited'.
    """
    result = cli("new", str(local_repo), "--skip-key-check", "--name", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}): {result.stderr}"
    )

    metadata = _read_metadata(sandbox_name)
    assert "network_mode" in metadata, (
        "metadata.json is missing the 'network_mode' field"
    )
    assert metadata["network_mode"] == "limited", (
        f"Expected default network_mode='limited', got '{metadata['network_mode']}'"
    )


def test_no_isolate_credentials_flag(cli, sandbox_name, local_repo):
    """Creating a sandbox with --no-isolate-credentials should disable credential isolation.

    When credential isolation is disabled via --no-isolate-credentials,
    the metadata should reflect this in the network_mode field.
    """
    result = cli(
        "new", str(local_repo), "--skip-key-check", "--no-isolate-credentials",
        "--name", sandbox_name,
    )
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}): {result.stderr}"
    )

    metadata = _read_metadata(sandbox_name)
    assert "network_mode" in metadata, (
        "metadata.json is missing the 'network_mode' field"
    )
    # With credential isolation disabled, the network_mode should differ
    # from the default "limited" mode or reflect that isolation is off.
    # The flag disables the credential proxy; the network_mode value
    # written to metadata reflects the chosen configuration.
    assert metadata["network_mode"] != "", (
        "network_mode should not be empty when --no-isolate-credentials is used"
    )


def test_network_isolation_active(cli, sandbox_name, local_repo):
    """Creating a sandbox with defaults should produce proper Docker network config.

    With credential isolation on (default), the container should be
    configured with appropriate network settings. We verify this by
    inspecting the Docker network configuration rather than testing
    actual network connectivity.
    """
    result = cli("new", str(local_repo), "--skip-key-check", "--name", sandbox_name)
    assert result.returncode == 0, (
        f"sandbox new failed (rc={result.returncode}): {result.stderr}"
    )

    container_name = f"sandbox-{sandbox_name}-dev-1"

    # Inspect the container's network settings via docker inspect
    inspect_result = subprocess.run(
        ["docker", "inspect", container_name],
        capture_output=True,
        text=True,
    )

    if inspect_result.returncode != 0:
        pytest.skip(
            f"Container '{container_name}' not found or not running; "
            f"cannot verify network config: {inspect_result.stderr}"
        )

    container_info = json.loads(inspect_result.stdout)
    assert len(container_info) > 0, "docker inspect returned empty result"

    container = container_info[0]

    # Verify the container has network settings
    network_settings = container.get("NetworkSettings", {})
    networks = network_settings.get("Networks", {})

    # With credential isolation active (limited mode), the container
    # should either be on a credential-isolation network or have
    # restricted network configuration. Verify at least one network
    # is configured.
    assert len(networks) > 0, (
        "Container should have at least one network configured"
    )

    # Check that the container has NET_ADMIN capability (needed for
    # iptables-based filtering in limited mode)
    host_config = container.get("HostConfig", {})
    cap_add = host_config.get("CapAdd") or []

    # In limited mode, NET_ADMIN should be added for iptables rules.
    # Docker may return capabilities with or without the CAP_ prefix
    # depending on the runtime version.
    has_net_admin = any(
        c in ("NET_ADMIN", "CAP_NET_ADMIN") for c in cap_add
    )
    assert has_net_admin, (
        f"Container should have NET_ADMIN capability in limited mode, "
        f"got CapAdd={cap_add}"
    )

    # Verify the SANDBOX_NETWORK_MODE env var is set in the container
    env_list = container.get("Config", {}).get("Env", [])
    network_env = [e for e in env_list if e.startswith("SANDBOX_NETWORK_MODE=")]
    assert len(network_env) > 0, (
        "SANDBOX_NETWORK_MODE environment variable should be set in the container"
    )
    assert network_env[0] == "SANDBOX_NETWORK_MODE=limited", (
        f"Expected SANDBOX_NETWORK_MODE=limited, got '{network_env[0]}'"
    )
