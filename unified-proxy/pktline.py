"""
Git pkt-line Protocol Parser

Parses git pkt-line format for push ref analysis in the git proxy addon.
Used to extract ref updates from git-receive-pack requests for policy enforcement
(detecting force pushes, branch deletions, etc.).

Git Protocol Documentation:
https://git-scm.com/docs/protocol-common#_pkt_line_format

Each pkt-line starts with a 4-character hex length prefix (including the 4 bytes
of the length itself). A length of '0000' indicates a flush packet (end of section).

For push operations, ref updates follow the format:
<old-sha> <new-sha> <refname>\0<capabilities>  (first line)
<old-sha> <new-sha> <refname>                   (subsequent lines)
"""

from dataclasses import dataclass
from typing import BinaryIO, Iterator, List, Optional, Tuple

# Zero SHA for detecting branch creation/deletion
ZERO_SHA = "0" * 40

# Default configuration for pkt-line reading
DEFAULT_MAX_PKTLINE_BYTES = 65536
DEFAULT_PKTLINE_CHUNK_SIZE = 8192


@dataclass
class PktLineRef:
    """Represents a single ref update from a git push.

    Attributes:
        old_sha: SHA of the current ref on remote (ZERO_SHA for new refs)
        new_sha: SHA being pushed (ZERO_SHA for deletions)
        refname: Full ref name (e.g., 'refs/heads/main')
        capabilities: Git protocol capabilities (only present on first ref)
    """

    old_sha: str
    new_sha: str
    refname: str
    capabilities: str = ""

    def is_creation(self) -> bool:
        """Check if this ref update creates a new branch/tag."""
        return self.old_sha == ZERO_SHA and self.new_sha != ZERO_SHA

    def is_deletion(self) -> bool:
        """Check if this ref update deletes a branch/tag."""
        return self.new_sha == ZERO_SHA

    def is_update(self) -> bool:
        """Check if this ref update modifies an existing ref."""
        return self.old_sha != ZERO_SHA and self.new_sha != ZERO_SHA


def parse_pktline(data: bytes) -> List[PktLineRef]:
    """
    Parse git pkt-line format from git-receive-pack request body.

    Git uses pkt-line format for protocol communication. Each line starts with
    a 4-character hex length prefix (including the 4 bytes of the length itself).
    A length of '0000' indicates a flush packet (end of section).

    For push operations, the format is:
    <old-sha> <new-sha> <refname>\0<capabilities>
    or for subsequent lines:
    <old-sha> <new-sha> <refname>

    Args:
        data: Raw bytes from git-receive-pack request body

    Returns:
        List of PktLineRef objects representing each ref update
    """
    updates: List[PktLineRef] = []
    pos = 0

    while pos < len(data):
        # Read 4-byte length prefix
        if pos + 4 > len(data):
            break

        try:
            length_hex = data[pos : pos + 4].decode("ascii")
            length = int(length_hex, 16)
        except (ValueError, UnicodeDecodeError):
            break

        # Flush packet (0000) marks end of section
        if length == 0:
            pos += 4
            continue

        # Length includes the 4-byte prefix itself
        if length < 4 or pos + length > len(data):
            break

        # Extract line content (excluding length prefix)
        line_data = data[pos + 4 : pos + length]
        pos += length

        # Skip empty lines
        if not line_data:
            continue

        # Try to decode as UTF-8
        try:
            line = line_data.decode("utf-8").rstrip("\n")
        except UnicodeDecodeError:
            continue

        # Parse ref update line: <old-sha> <new-sha> <refname>[\0<capabilities>]
        # First line may have capabilities after null byte
        capabilities = ""
        if "\0" in line:
            line, capabilities = line.split("\0", 1)

        parts = line.split(" ", 2)
        if len(parts) >= 3:
            old_sha, new_sha, refname = parts[0], parts[1], parts[2]
            # Validate SHA format (40 hex characters)
            if len(old_sha) == 40 and len(new_sha) == 40:
                updates.append(
                    PktLineRef(
                        old_sha=old_sha,
                        new_sha=new_sha,
                        refname=refname,
                        capabilities=capabilities,
                    )
                )

    return updates


def read_pktline_prefix(
    stream: BinaryIO,
    max_bytes: int = DEFAULT_MAX_PKTLINE_BYTES,
    chunk_size: int = DEFAULT_PKTLINE_CHUNK_SIZE,
) -> Tuple[bytes, Optional[int], Optional[str]]:
    """
    Read and parse the pkt-line header section from a git-receive-pack body.

    This function reads from the stream until it finds a flush packet (0000)
    which marks the end of the ref update section. It's bounded by max_bytes
    to prevent memory exhaustion from malicious clients.

    Args:
        stream: Binary stream to read from (e.g., request body)
        max_bytes: Maximum bytes to read before returning error
        chunk_size: Size of chunks to read from stream

    Returns:
        Tuple of (buffer_bytes, pktline_end, error):
            buffer_bytes: All bytes read from the stream (may include packfile bytes)
            pktline_end: Index of end-of-header (flush packet), or None if not found
            error: None on success, otherwise one of:
                   'max_exceeded', 'invalid_length', 'eof'
    """
    buf = bytearray()
    pos = 0

    while True:
        # Parse as many pkt-lines as possible from current buffer
        while True:
            if len(buf) - pos < 4:
                break
            try:
                length_hex = buf[pos : pos + 4].decode("ascii")
                length = int(length_hex, 16)
            except (ValueError, UnicodeDecodeError):
                return bytes(buf), None, "invalid_length"

            # Flush packet marks end of header section
            if length == 0:
                return bytes(buf), pos + 4, None

            if length < 4:
                return bytes(buf), None, "invalid_length"

            # Need more data for this pkt-line
            if len(buf) - pos < length:
                break

            pos += length

        # Need more data from stream
        if len(buf) >= max_bytes:
            return bytes(buf), None, "max_exceeded"

        to_read = min(chunk_size, max_bytes - len(buf))
        chunk = stream.read(to_read)
        if not chunk:
            return bytes(buf), None, "eof"
        buf.extend(chunk)


def iter_prefixed_stream(
    prefix: bytes,
    stream: BinaryIO,
    chunk_size: int = DEFAULT_PKTLINE_CHUNK_SIZE,
) -> Iterator[bytes]:
    """
    Yield a previously-read prefix, then stream the remainder.

    This is useful for forwarding a request body upstream after reading
    just the pkt-line header for policy checking. Keeps memory usage bounded
    while forwarding the full request body.

    Args:
        prefix: Bytes already read from the stream
        stream: Binary stream to continue reading from
        chunk_size: Size of chunks to read

    Yields:
        Bytes chunks - first the prefix, then chunks from the stream
    """
    if prefix:
        yield prefix
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        yield chunk
