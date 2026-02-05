"""Container identity registry with SQLite persistence.

This module provides a thread-safe registry for container identities,
backed by SQLite with WAL mode for optimal concurrent access.
"""

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ContainerConfig:
    """Configuration and identity for a registered container."""

    container_id: str
    ip_address: str
    registered_at: float
    last_seen: float
    ttl_seconds: int = 86400  # 24 hours default
    metadata: Optional[dict] = None

    @property
    def is_expired(self) -> bool:
        """Check if the registration has expired based on TTL."""
        return time.time() > (self.last_seen + self.ttl_seconds)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "container_id": self.container_id,
            "ip_address": self.ip_address,
            "registered_at": self.registered_at,
            "last_seen": self.last_seen,
            "ttl_seconds": self.ttl_seconds,
            "metadata": self.metadata,
        }

    @classmethod
    def from_row(cls, row: tuple) -> "ContainerConfig":
        """Create from SQLite row tuple."""
        import json

        return cls(
            container_id=row[0],
            ip_address=row[1],
            registered_at=row[2],
            last_seen=row[3],
            ttl_seconds=row[4],
            metadata=json.loads(row[5]) if row[5] else None,
        )


class ContainerRegistry:
    """Thread-safe container registry with SQLite persistence.

    Uses WAL mode for optimal concurrent read/write access and
    a write-through cache for fast lookups by IP address.
    """

    def __init__(self, db_path: str = "/var/lib/unified-proxy/registry.db"):
        """Initialize the registry.

        Args:
            db_path: Path to SQLite database file. Parent directories
                     will be created if they don't exist.
        """
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Write-through cache: IP -> ContainerConfig
        self._cache: dict[str, ContainerConfig] = {}
        self._cache_lock = threading.RLock()

        # Initialize database
        self._init_db()

        # Load existing entries into cache
        self._refresh_cache()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a new database connection with proper settings."""
        conn = sqlite3.connect(
            str(self._db_path),
            timeout=5.0,  # busy_timeout equivalent for Python sqlite3
            isolation_level=None,  # autocommit mode for better WAL performance
        )
        # Configure connection
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS containers (
                    container_id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL UNIQUE,
                    registered_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    ttl_seconds INTEGER NOT NULL DEFAULT 86400,
                    metadata TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_containers_ip
                ON containers(ip_address)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_containers_last_seen
                ON containers(last_seen)
            """)
        finally:
            conn.close()

    def _refresh_cache(self) -> None:
        """Reload entire cache from database."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("""
                SELECT container_id, ip_address, registered_at, last_seen,
                       ttl_seconds, metadata
                FROM containers
            """)
            rows = cursor.fetchall()

            with self._cache_lock:
                self._cache.clear()
                for row in rows:
                    config = ContainerConfig.from_row(row)
                    self._cache[config.ip_address] = config
        finally:
            conn.close()

    def _load_by_ip(self, ip_address: str) -> Optional[ContainerConfig]:
        """Load a container config by IP address from the database."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT container_id, ip_address, registered_at, last_seen,
                       ttl_seconds, metadata
                FROM containers
                WHERE ip_address = ?
                """,
                (ip_address,),
            )
            row = cursor.fetchone()
        finally:
            conn.close()

        if not row:
            return None

        config = ContainerConfig.from_row(row)
        if config.is_expired:
            self._remove_from_db(config.container_id)
            return None

        with self._cache_lock:
            self._cache[ip_address] = config

        return config

    def _load_by_container_id(self, container_id: str) -> Optional[ContainerConfig]:
        """Load a container config by container ID from the database."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT container_id, ip_address, registered_at, last_seen,
                       ttl_seconds, metadata
                FROM containers
                WHERE container_id = ?
                """,
                (container_id,),
            )
            row = cursor.fetchone()
        finally:
            conn.close()

        if not row:
            return None

        config = ContainerConfig.from_row(row)
        if config.is_expired:
            self._remove_from_db(config.container_id)
            return None

        with self._cache_lock:
            self._cache[config.ip_address] = config

        return config

    def get_by_ip(self, ip_address: str) -> Optional[ContainerConfig]:
        """Look up container configuration by IP address.

        Args:
            ip_address: The container's IP address.

        Returns:
            ContainerConfig if found and not expired, None otherwise.
        """
        with self._cache_lock:
            config = self._cache.get(ip_address)
            if config is not None:
                if config.is_expired:
                    # Auto-cleanup expired entry
                    self._remove_from_db(config.container_id)
                    del self._cache[ip_address]
                    return None
                return config

        # Cache miss: load from DB (handles cross-process updates)
        return self._load_by_ip(ip_address)

    def get_by_container_id(self, container_id: str) -> Optional[ContainerConfig]:
        """Look up container configuration by container ID.

        Args:
            container_id: The container's unique identifier.

        Returns:
            ContainerConfig if found and not expired, None otherwise.
        """
        with self._cache_lock:
            for config in self._cache.values():
                if config.container_id == container_id:
                    if config.is_expired:
                        self._remove_from_db(container_id)
                        del self._cache[config.ip_address]
                        return None
                    return config

        # Cache miss: load from DB (handles cross-process updates)
        return self._load_by_container_id(container_id)

    def register(
        self,
        container_id: str,
        ip_address: str,
        ttl_seconds: int = 86400,
        metadata: Optional[dict] = None,
    ) -> ContainerConfig:
        """Register a new container or update existing registration.

        Uses write-through strategy: writes to DB first, then updates cache.

        Args:
            container_id: Unique container identifier.
            ip_address: Container's IP address.
            ttl_seconds: Time-to-live in seconds (default 24 hours).
            metadata: Optional metadata dictionary.

        Returns:
            The registered ContainerConfig.

        Raises:
            sqlite3.IntegrityError: If IP is already registered to different container.
        """
        import json

        now = time.time()

        conn = self._get_connection()
        try:
            # Check for IP conflict with different container
            cursor = conn.execute(
                "SELECT container_id FROM containers WHERE ip_address = ?",
                (ip_address,),
            )
            existing = cursor.fetchone()
            if existing and existing[0] != container_id:
                raise ValueError(
                    f"IP {ip_address} already registered to container {existing[0]}"
                )

            # Upsert the registration
            metadata_json = json.dumps(metadata) if metadata else None
            conn.execute(
                """
                INSERT INTO containers
                    (container_id, ip_address, registered_at, last_seen, ttl_seconds, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(container_id) DO UPDATE SET
                    ip_address = excluded.ip_address,
                    last_seen = excluded.last_seen,
                    ttl_seconds = excluded.ttl_seconds,
                    metadata = excluded.metadata
                """,
                (container_id, ip_address, now, now, ttl_seconds, metadata_json),
            )
        finally:
            conn.close()

        # Update cache (write-through)
        config = ContainerConfig(
            container_id=container_id,
            ip_address=ip_address,
            registered_at=now,
            last_seen=now,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
        with self._cache_lock:
            # Remove old IP mapping if container moved IPs
            for ip, cached in list(self._cache.items()):
                if cached.container_id == container_id and ip != ip_address:
                    del self._cache[ip]
            self._cache[ip_address] = config

        return config

    def renew(self, container_id: str) -> Optional[ContainerConfig]:
        """Renew a container's registration by updating last_seen.

        Args:
            container_id: The container to renew.

        Returns:
            Updated ContainerConfig if found, None otherwise.
        """
        now = time.time()

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                UPDATE containers SET last_seen = ?
                WHERE container_id = ?
                RETURNING container_id, ip_address, registered_at, last_seen,
                          ttl_seconds, metadata
                """,
                (now, container_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
        finally:
            conn.close()

        # Update cache
        config = ContainerConfig.from_row(row)
        with self._cache_lock:
            self._cache[config.ip_address] = config

        return config

    def unregister(self, container_id: str) -> bool:
        """Unregister a container.

        Args:
            container_id: The container to unregister.

        Returns:
            True if container was registered and removed, False otherwise.
        """
        # Get IP before removal for cache invalidation
        config = self.get_by_container_id(container_id)
        if config is None:
            return False

        self._remove_from_db(container_id)

        # Invalidate cache
        with self._cache_lock:
            if config.ip_address in self._cache:
                del self._cache[config.ip_address]

        return True

    def _remove_from_db(self, container_id: str) -> None:
        """Remove a container from the database."""
        conn = self._get_connection()
        try:
            conn.execute(
                "DELETE FROM containers WHERE container_id = ?",
                (container_id,),
            )
        finally:
            conn.close()

    def cleanup_expired(self) -> int:
        """Remove all expired registrations.

        Returns:
            Number of expired registrations removed.
        """
        now = time.time()

        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                DELETE FROM containers
                WHERE (last_seen + ttl_seconds) < ?
                """,
                (now,),
            )
            count = cursor.rowcount
        finally:
            conn.close()

        # Refresh cache to remove expired entries
        self._refresh_cache()

        return count

    def list_all(self) -> list[ContainerConfig]:
        """List all registered containers.

        Returns:
            List of all ContainerConfig entries (including expired).
        """
        with self._cache_lock:
            return list(self._cache.values())

    def count(self) -> int:
        """Return count of registered containers."""
        with self._cache_lock:
            return len(self._cache)

    def close(self) -> None:
        """Clean up resources."""
        # SQLite connections are created per-operation, nothing to close
        with self._cache_lock:
            self._cache.clear()
