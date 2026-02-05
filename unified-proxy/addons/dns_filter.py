"""
DNS Query Filtering mitmproxy Addon

Filters DNS queries based on container identity and allowlist policy.
Uses the PolicyEngine to check domain allowlists and blocks unauthorized
DNS resolutions by returning NXDOMAIN.

Security Model:
- DNS filtering provides first layer of defense before HTTP proxy
- Source IP identifies container (using ContainerRegistry)
- Allowlist enforced at DNS level prevents resolution of unauthorized domains
- All DNS queries logged with structured JSON for audit trail

Flow:
1. Intercept DNS query (dns_request hook)
2. Identify container by source IP
3. Check queried domain against allowlist
4. Allow (normal resolution) or block (NXDOMAIN)
5. Log query with container_id, query_type, query_name, response

Error Handling:
- Unknown containers: Block with NXDOMAIN
- Domains not in allowlist: Block with NXDOMAIN
"""

import os
import sys
from typing import Optional

from mitmproxy import dns, ctx

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from registry import ContainerRegistry
from logging_config import get_logger, set_context, clear_context
from config import load_allowlist_config, ConfigError

# Global registry instance (initialized in load())
_registry: Optional[ContainerRegistry] = None

# Global allowlist (loaded from config in load())
_allowlist_domains: Optional[list[str]] = None

# Logger
logger = get_logger(__name__)

# Default allowlist (fallback if config loading fails)
# Supports both exact domains and wildcard patterns (*.domain.com)
DEFAULT_ALLOWLIST = [
    "github.com",
    "*.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "pypi.org",
    "*.pypi.org",
    "files.pythonhosted.org",
    "npmjs.org",
    "*.npmjs.org",
    "registry.npmjs.org",
]


class DNSFilterAddon:
    """Mitmproxy addon for DNS query filtering.

    This addon intercepts DNS queries and enforces allowlist policy
    before domains are resolved. Blocked queries receive NXDOMAIN
    responses.
    """

    def __init__(
        self,
        registry: Optional[ContainerRegistry] = None,
        allowlist: Optional[list[str]] = None,
    ):
        """Initialize the DNS filter addon.

        Args:
            registry: Optional registry instance. If not provided,
                      uses the global registry initialized in load().
            allowlist: Optional list of allowed domains. If not provided,
                      uses allowlist from config (or DEFAULT_ALLOWLIST as fallback).
        """
        self._registry = registry
        # Use provided allowlist, or global config, or default fallback
        if allowlist is not None:
            self._allowlist = allowlist
        elif _allowlist_domains is not None:
            self._allowlist = _allowlist_domains
        else:
            self._allowlist = DEFAULT_ALLOWLIST

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
        ctx.log.info("DNS filter addon loaded")
        ctx.log.info(f"DNS allowlist: {', '.join(self._allowlist)}")

    def dns_request(self, flow: dns.DNSFlow) -> None:
        """Process DNS request to enforce allowlist policy.

        Args:
            flow: The mitmproxy DNS flow.
        """
        # Get the DNS question
        question = flow.request.question
        if not question:
            ctx.log.warn("DNS request without question")
            return

        query_name = question.name.decode() if isinstance(question.name, bytes) else question.name
        query_type = self._get_query_type_name(question.type)

        # Get source IP from client connection
        client_address = flow.client_conn.peername
        if client_address is None:
            ctx.log.warn(f"DNS query for {query_name} with no client address")
            self._block_query(flow, query_name, query_type, "unknown", "no_client_address")
            return

        source_ip = client_address[0]

        # Look up container by source IP
        container_config = self.registry.get_by_ip(source_ip)

        if container_config is None:
            ctx.log.warn(f"DNS query from unknown IP {source_ip} for {query_name}")
            self._block_query(flow, query_name, query_type, "unknown", "unknown_container")
            return

        container_id = container_config.container_id

        # Set logging context for structured logging
        set_context(container_id=container_id)

        # Check if domain is in allowlist
        if self._is_allowed(query_name):
            # Allow the query to proceed normally
            self._log_query(container_id, query_type, query_name, "allowed")
            ctx.log.debug(f"DNS query allowed: {container_id} -> {query_name} ({query_type})")
        else:
            # Block the query with NXDOMAIN
            self._block_query(flow, query_name, query_type, container_id, "not_in_allowlist")

        # Clear logging context
        clear_context()

    def _is_allowed(self, domain: str) -> bool:
        """Check if a domain is in the allowlist.

        Supports:
        - Exact matches: "example.com"
        - Wildcard prefixes: "*.example.com" matches "api.example.com"
        - Case-insensitive matching (DNS names are case-insensitive per RFC 4343)

        Args:
            domain: The domain name to check (without trailing dot).

        Returns:
            True if domain is allowed, False otherwise.
        """
        # Normalize domain (remove trailing dot, lowercase for case-insensitive matching)
        domain = domain.rstrip(".").lower()

        for pattern in self._allowlist:
            pattern_lower = pattern.lower()

            # Exact match
            if pattern_lower == domain:
                return True

            # Wildcard match: *.example.com matches api.example.com
            if pattern_lower.startswith("*."):
                base_domain = pattern_lower[2:]  # Remove "*."
                if domain.endswith("." + base_domain) or domain == base_domain:
                    return True

        return False

    def _block_query(
        self,
        flow: dns.DNSFlow,
        query_name: str,
        query_type: str,
        container_id: str,
        reason: str,
    ) -> None:
        """Block a DNS query by responding with NXDOMAIN.

        Args:
            flow: The DNS flow to block.
            query_name: The queried domain name.
            query_type: The query type (A, AAAA, etc.).
            container_id: The container making the request.
            reason: Reason for blocking (for logging).
        """
        # Create NXDOMAIN response
        flow.response = flow.request.fail(dns.response_codes.NXDOMAIN)

        # Log the blocked query
        self._log_query(container_id, query_type, query_name, "blocked", reason=reason)
        ctx.log.info(f"DNS query blocked: {container_id} -> {query_name} ({query_type}): {reason}")

    def _log_query(
        self,
        container_id: str,
        query_type: str,
        query_name: str,
        response: str,
        reason: Optional[str] = None,
    ) -> None:
        """Log a DNS query with structured JSON logging.

        Args:
            container_id: Container making the query.
            query_type: DNS query type (A, AAAA, etc.).
            query_name: Queried domain name.
            response: Response action (allowed/blocked).
            reason: Optional reason for blocking.
        """
        log_data = {
            "event": "dns_query",
            "query_type": query_type,
            "query_name": query_name,
            "response": response,
        }

        if reason:
            log_data["reason"] = reason

        logger.info(
            f"DNS query: {query_name} ({query_type}) -> {response}",
            extra=log_data,
        )

    def _get_query_type_name(self, query_type: int) -> str:
        """Get human-readable name for DNS query type.

        Args:
            query_type: Numeric DNS query type.

        Returns:
            Query type name (A, AAAA, CNAME, etc.) or numeric string.
        """
        # Common DNS query types
        type_names = {
            1: "A",          # IPv4 address
            2: "NS",         # Name server
            5: "CNAME",      # Canonical name
            6: "SOA",        # Start of authority
            12: "PTR",       # Pointer
            15: "MX",        # Mail exchange
            16: "TXT",       # Text
            28: "AAAA",      # IPv6 address
            33: "SRV",       # Service
            257: "CAA",      # Certification authority authorization
        }

        # Try to get from dns.types if available
        try:
            if hasattr(dns, "types"):
                for attr in dir(dns.types):
                    if not attr.startswith("_"):
                        value = getattr(dns.types, attr)
                        if isinstance(value, int) and value == query_type:
                            return attr
        except Exception:
            pass

        # Fall back to our mapping
        return type_names.get(query_type, str(query_type))


def load(loader):
    """Module-level load function for mitmproxy.

    Initializes the global registry and loads allowlist configuration.
    """
    global _registry, _allowlist_domains

    # Get database path from environment or use default
    db_path = os.environ.get(
        "REGISTRY_DB_PATH",
        "/var/lib/unified-proxy/registry.db",
    )

    try:
        _registry = ContainerRegistry(db_path=db_path)
        ctx.log.info(f"DNS filter using registry at {db_path}")
    except Exception as e:
        ctx.log.error(f"Failed to initialize container registry for DNS filter: {e}")
        raise

    # Load allowlist configuration
    try:
        allowlist_config = load_allowlist_config()
        _allowlist_domains = allowlist_config.domains
        ctx.log.info(f"DNS filter loaded {len(_allowlist_domains)} domains from config")
    except ConfigError as e:
        ctx.log.warn(f"Failed to load allowlist config: {e}")
        ctx.log.warn("DNS filter using default allowlist")
        _allowlist_domains = DEFAULT_ALLOWLIST
    except Exception as e:
        ctx.log.error(f"Unexpected error loading allowlist: {e}")
        _allowlist_domains = DEFAULT_ALLOWLIST


# Export addon class for mitmproxy
addons = [DNSFilterAddon()]
