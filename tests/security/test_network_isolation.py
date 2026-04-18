"""Network isolation tests for sandbox environments.

Verifies that sandboxed containers cannot:
- Create raw sockets (CAP_NET_RAW dropped)
- Resolve unknown/unauthorized domains
- Reach arbitrary external IPs directly
- Access cloud metadata endpoints (169.254.169.254)

Allowed traffic (e.g., github.com via DNS) is also verified.

These tests run commands inside a live sandbox container via ``docker exec``.
"""

import pytest

pytestmark = [
    pytest.mark.security,
    pytest.mark.slow,
    pytest.mark.usefixtures("requires_docker"),
]


def test_cap_net_raw_dropped(docker_exec):
    """CAP_NET_RAW must be dropped — raw socket creation should fail.

    Without this capability, tools like ``ping`` (which uses ICMP raw sockets)
    and arbitrary raw-socket sniffing are blocked.
    """
    result = docker_exec(
        "python3", "-c",
        "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)",
    )
    # Raw socket creation should fail with "Operation not permitted"
    assert result.returncode != 0, (
        "Raw socket creation succeeded — CAP_NET_RAW is not dropped"
    )
    assert "Operation not permitted" in result.stderr or "PermissionError" in result.stderr, (
        f"Unexpected error (expected 'Operation not permitted'): {result.stderr[:300]}"
    )


def test_dns_filtering_blocks_unknown_domain(docker_exec):
    """DNS queries for unknown/unauthorized domains must fail.

    The DNS filter addon blocks resolution of domains not on the allowlist.
    """
    result = docker_exec(
        "python3", "-c",
        "import socket; socket.getaddrinfo('evil-exfiltration-domain.example.com', 443)",
    )
    assert result.returncode != 0, (
        "DNS resolution for unauthorized domain succeeded — DNS filter not working"
    )


def test_dns_filtering_allows_github(docker_exec, proxy_reachable):
    """DNS resolution for github.com must succeed (it's on the allowlist)."""
    result = docker_exec(
        "python3", "-c",
        "import socket; addrs = socket.getaddrinfo('github.com', 443); "
        "assert len(addrs) > 0, 'No addresses returned'",
    )
    assert result.returncode == 0, (
        f"DNS resolution for github.com failed: {result.stderr[:300]}"
    )


def test_external_network_unreachable(docker_exec):
    """Direct IP access to external hosts must be blocked by network policy.

    Uses a well-known public IP (Google DNS 8.8.8.8) to verify that outbound
    connections not going through the proxy are blocked.
    """
    result = docker_exec(
        "python3", "-c",
        "import socket; s = socket.socket(); s.settimeout(5); "
        "s.connect(('8.8.8.8', 53))",
    )
    assert result.returncode != 0, (
        "Direct external network access succeeded — firewall rules not applied"
    )


def test_metadata_service_unreachable(docker_exec):
    """Cloud metadata endpoint (169.254.169.254) must be unreachable.

    AWS/GCP/Azure metadata services are a common SSRF target. The sandbox
    firewall must block access to this link-local address.
    """
    result = docker_exec(
        "python3", "-c",
        "import socket; s = socket.socket(); s.settimeout(5); "
        "s.connect(('169.254.169.254', 80))",
    )
    assert result.returncode != 0, (
        "Metadata service (169.254.169.254) is reachable — firewall gap"
    )
