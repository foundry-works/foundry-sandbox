"""
Container Identity mitmproxy Addon

Identifies containers by source IP address with optional X-Container-Id header
validation. Attaches container configuration to flow metadata for use by
downstream addons (credential injection, policy enforcement, etc.).

Security Model:
- Primary identity: Source IP address (cannot be spoofed without NET_RAW capability)
- Secondary validation: X-Container-Id header (optional, for defense in depth)
- Header stripping: X-Container-Id is removed before forwarding to prevent leakage

Error Responses:
- 403 Forbidden: Unknown source IP, mismatched header, or expired registration (if TTL enabled)
"""

import os
import sys
from typing import Optional

from mitmproxy import connection, http
from mitmproxy.flow import Flow

from logging_config import get_logger

# Add parent directory to path for registry import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from registry import ContainerConfig, ContainerRegistry  # noqa: E402

logger = get_logger(__name__)

# Header used for optional container identity validation
CONTAINER_ID_HEADER = "X-Container-Id"

# Metadata key for attaching container config to flow
FLOW_METADATA_KEY = "container_config"

# Base directory where bare repos are stored (proxy-side mount point)
REPOS_BASE_DIR = os.environ.get(
    "REPOS_BASE_DIR", "/home/ubuntu/.sandboxes/repos"
)

# Global registry instance (initialized in load())
_registry: Optional[ContainerRegistry] = None

# Store real client IPs extracted from CONNECT-level XFF headers.
# For HTTPS CONNECT tunnels, Squid sets XFF on the outer CONNECT request,
# but mitmproxy's request() hook fires on inner (decrypted) requests which
# don't carry XFF. The http_connect handler captures the real IP here.
_connect_real_ips: dict[int, str] = {}  # id(client_conn) -> real IP


class ContainerIdentityAddon:
    """Mitmproxy addon for container identity verification.

    This addon runs early in the request lifecycle to identify the
    requesting container and attach its configuration to the flow.
    Subsequent addons can use this to make policy decisions.
    """

    def __init__(self, registry: Optional[ContainerRegistry] = None):
        """Initialize the addon.

        Args:
            registry: Optional registry instance. If not provided,
                      uses the global registry initialized in load().
        """
        self._registry = registry

    @property
    def registry(self) -> ContainerRegistry:
        """Get the registry instance."""
        if self._registry is not None:
            return self._registry
        if _registry is not None:
            return _registry
        raise RuntimeError("ContainerRegistry not initialized")

    def load(self, loader):
        """Called when addon is loaded."""
        logger.info("Container identity addon loaded")

    def http_connect(self, flow: http.HTTPFlow) -> None:
        """Extract real client IP from CONNECT-level XFF header.

        For HTTPS CONNECT tunnels through Squid, XFF is set on the outer
        CONNECT request but not on the inner decrypted requests. Store the
        real IP so request() can use it for container identity resolution.
        """
        source_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        if source_ip == "127.0.0.1":
            xff = flow.request.headers.get("X-Forwarded-For", "")
            if xff:
                real_ip = xff.split(",")[0].strip()
                _connect_real_ips[id(flow.client_conn)] = real_ip

    def client_disconnected(self, client: connection.Client) -> None:
        """Clean up stored CONNECT-level IPs when client disconnects."""
        _connect_real_ips.pop(id(client), None)

    def request(self, flow: http.HTTPFlow) -> None:
        """Process incoming request to identify container.

        Args:
            flow: The mitmproxy HTTP flow.
        """
        # Get source IP from client connection
        client_address = flow.client_conn.peername
        if client_address is None:
            self._deny_request(flow, "No client address available")
            return

        source_ip = client_address[0]

        # When Squid's cache_peer forwards traffic, the TCP source is
        # 127.0.0.1 (Squid itself).  Recover the real container IP:
        # 1. CONNECT tunnel: use IP from CONNECT-level XFF (stored by http_connect)
        # 2. Plain HTTP: use request-level XFF (set by Squid forwarded_for truncate)
        if source_ip == "127.0.0.1":
            real_ip = _connect_real_ips.get(id(flow.client_conn))
            if real_ip:
                source_ip = real_ip
            else:
                xff = flow.request.headers.get("X-Forwarded-For", "")
                if xff:
                    source_ip = xff.split(",")[0].strip()
            # Strip XFF before forwarding to prevent leakage to upstream
            if "X-Forwarded-For" in flow.request.headers:
                del flow.request.headers["X-Forwarded-For"]

        # Look up container by source IP
        container_config = self.registry.get_by_ip(source_ip)

        if container_config is None:
            self._deny_request(
                flow,
                f"Unknown source IP: {source_ip}",
                log_level="warning",
            )
            return

        # Check for expired registration (belt and suspenders - get_by_ip also checks)
        if container_config.is_expired:
            self._deny_request(
                flow,
                f"Expired registration for container {container_config.container_id}",
                log_level="warning",
            )
            return

        # Optional: Validate X-Container-Id header if present
        header_container_id = flow.request.headers.get(CONTAINER_ID_HEADER)
        if header_container_id is not None:
            if header_container_id != container_config.container_id:
                self._deny_request(
                    flow,
                    f"Container ID mismatch: header={header_container_id}, "
                    f"registered={container_config.container_id}",
                    log_level="warning",
                )
                return

            # Strip header before forwarding (prevent leakage to upstream)
            del flow.request.headers[CONTAINER_ID_HEADER]
            logger.debug(
                f"Validated and stripped {CONTAINER_ID_HEADER} header "
                f"for container {container_config.container_id}"
            )

        # Enrich metadata with bare_repo_path if repo is known
        metadata = container_config.metadata or {}
        if "bare_repo_path" not in metadata:
            repo = metadata.get("repo", "")
            if repo and "/" in repo:
                # Only attempt enrichment for owner/repo style paths
                # (not absolute filesystem paths like /tmp/...).
                # If the format is unexpected, skip enrichment rather
                # than rejecting the request — the git_proxy addon will
                # handle missing bare_repo_path for git operations.
                parts = repo.split("/")
                if len(parts) == 2 and parts[0] and parts[1]:
                    owner, repo_name = parts
                    # Reject path traversal in repo metadata to prevent
                    # pointing bare_repo_path at arbitrary filesystem
                    # locations.
                    if ".." in owner or ".." in repo_name:
                        logger.warning(
                            f"Rejecting repo with path traversal: {repo}"
                        )
                        self._deny_request(
                            flow,
                            "Invalid repo metadata: path traversal detected",
                            log_level="warning",
                        )
                        return
                    candidate_path = os.path.join(
                        REPOS_BASE_DIR, owner, repo_name + ".git"
                    )
                    real_path = os.path.realpath(candidate_path)
                    real_base = os.path.realpath(REPOS_BASE_DIR)
                    if not real_path.startswith(real_base + os.sep) and real_path != real_base:
                        logger.warning(
                            f"Rejecting repo path escaping base dir: "
                            f"{candidate_path} -> {real_path}"
                        )
                        self._deny_request(
                            flow,
                            "Invalid repo metadata: path escapes base directory",
                            log_level="warning",
                        )
                        return
                    metadata["bare_repo_path"] = real_path
                    container_config.metadata = metadata

        # Attach container config to flow metadata for downstream addons
        flow.metadata[FLOW_METADATA_KEY] = container_config

        logger.debug(
            f"Identified request from container {container_config.container_id} "
            f"(IP: {source_ip}) to {flow.request.pretty_host}"
        )

    def _deny_request(
        self,
        flow: http.HTTPFlow,
        reason: str,
        log_level: str = "info",
    ) -> None:
        """Deny the request with a 403 Forbidden response.

        Args:
            flow: The mitmproxy HTTP flow.
            reason: Human-readable reason for denial (logged, not sent to client).
            log_level: Log level for the denial message.
        """
        # Log the denial
        log_fn = getattr(logger, log_level, logger.info)
        log_fn(f"Denying request: {reason}")

        # Create 403 response
        flow.response = http.Response.make(
            403,
            b"Forbidden: Container identity verification failed",
            {"Content-Type": "text/plain"},
        )


def get_container_config(flow: Flow) -> Optional[ContainerConfig]:
    """Helper function to get container config from flow metadata.

    This is the primary API for other addons to access the identified
    container's configuration.

    Args:
        flow: The mitmproxy flow.

    Returns:
        ContainerConfig if container was identified, None otherwise.
    """
    return flow.metadata.get(FLOW_METADATA_KEY)


def load(loader):
    """Module-level load function for mitmproxy.

    Initializes the global registry and registers the addon.
    """
    global _registry

    # Get database path from environment or use default
    db_path = os.environ.get(
        "REGISTRY_DB_PATH",
        "/var/lib/unified-proxy/registry.db",
    )

    try:
        _registry = ContainerRegistry(db_path=db_path)
        logger.info(f"Container registry initialized at {db_path}")
    except Exception as e:
        logger.error(f"Failed to initialize container registry: {e}")
        raise


# Export addon class for mitmproxy
addons = [ContainerIdentityAddon()]
