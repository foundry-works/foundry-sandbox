"""Unit tests for pkt-line parser.

Tests the pktline module which parses git pkt-line format for push ref analysis.
Used to extract ref updates from git-receive-pack requests for policy enforcement.

Note: pktline.py has no mitmproxy dependencies, so these tests can run
directly without mocking.
"""

import io
import os
import sys

import pytest

# Add unified-proxy to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from pktline import (
    DEFAULT_MAX_PKTLINE_BYTES,
    DEFAULT_PKTLINE_CHUNK_SIZE,
    ZERO_SHA,
    PktLineRef,
    iter_prefixed_stream,
    parse_pktline,
    read_pktline_prefix,
)


def create_pktline(old_sha, new_sha, refname, capabilities=""):
    """Create a single pkt-line encoded ref update.

    Args:
        old_sha: 40-char hex SHA
        new_sha: 40-char hex SHA
        refname: Full ref name
        capabilities: Optional capabilities string

    Returns:
        bytes: Encoded pkt-line
    """
    if capabilities:
        content = f"{old_sha} {new_sha} {refname}\0{capabilities}\n"
    else:
        content = f"{old_sha} {new_sha} {refname}\n"
    length = len(content) + 4
    return f"{length:04x}".encode() + content.encode()


def create_pktline_data(refs):
    """Create complete pkt-line data with flush packet.

    Args:
        refs: List of (old_sha, new_sha, refname, [capabilities]) tuples

    Returns:
        bytes: Complete pkt-line data with flush packet
    """
    data = b""
    for i, ref in enumerate(refs):
        old_sha, new_sha, refname = ref[:3]
        caps = ref[3] if len(ref) > 3 else ("report-status" if i == 0 else "")
        data += create_pktline(old_sha, new_sha, refname, caps)
    data += b"0000"  # Flush packet
    return data


class TestPktLineRefDataclass:
    """Tests for the PktLineRef dataclass."""

    def test_basic_creation(self):
        """Test basic PktLineRef creation."""
        ref = PktLineRef(
            old_sha="a" * 40,
            new_sha="b" * 40,
            refname="refs/heads/main",
            capabilities="report-status",
        )

        assert ref.old_sha == "a" * 40
        assert ref.new_sha == "b" * 40
        assert ref.refname == "refs/heads/main"
        assert ref.capabilities == "report-status"

    def test_is_deletion(self):
        """Test deletion detection."""
        # Deletion: new_sha is ZERO_SHA
        deletion = PktLineRef("a" * 40, ZERO_SHA, "refs/heads/old-branch")
        assert deletion.is_deletion() is True

        # Not deletion: normal update
        update = PktLineRef("a" * 40, "b" * 40, "refs/heads/main")
        assert update.is_deletion() is False

    def test_is_creation(self):
        """Test creation detection."""
        # Creation: old_sha is ZERO_SHA
        creation = PktLineRef(ZERO_SHA, "b" * 40, "refs/heads/new-branch")
        assert creation.is_creation() is True

        # Not creation: normal update
        update = PktLineRef("a" * 40, "b" * 40, "refs/heads/main")
        assert update.is_creation() is False

    def test_is_update(self):
        """Test update detection."""
        # Update: both SHAs are non-zero
        update = PktLineRef("a" * 40, "b" * 40, "refs/heads/main")
        assert update.is_update() is True

        # Not update: creation
        creation = PktLineRef(ZERO_SHA, "b" * 40, "refs/heads/new-branch")
        assert creation.is_update() is False

        # Not update: deletion
        deletion = PktLineRef("a" * 40, ZERO_SHA, "refs/heads/old-branch")
        assert deletion.is_update() is False

    def test_default_capabilities(self):
        """Test that capabilities defaults to empty string."""
        ref = PktLineRef("a" * 40, "b" * 40, "refs/heads/main")
        assert ref.capabilities == ""


class TestBasicPktLineParsing:
    """Tests for basic pkt-line parsing."""

    def test_single_ref_update(self):
        """Test parsing a single ref update."""
        old_sha = "a" * 40
        new_sha = "b" * 40
        data = create_pktline_data([(old_sha, new_sha, "refs/heads/main")])

        refs = parse_pktline(data)

        assert len(refs) == 1
        assert refs[0].old_sha == old_sha
        assert refs[0].new_sha == new_sha
        assert refs[0].refname == "refs/heads/main"
        assert refs[0].capabilities == "report-status"

    def test_single_ref_without_capabilities(self):
        """Test parsing a ref without capabilities."""
        old_sha = "a" * 40
        new_sha = "b" * 40
        # Create manually without capabilities
        data = create_pktline(old_sha, new_sha, "refs/heads/main", "") + b"0000"

        refs = parse_pktline(data)

        assert len(refs) == 1
        assert refs[0].capabilities == ""

    def test_tag_ref(self):
        """Test parsing a tag ref."""
        data = create_pktline_data([("a" * 40, "b" * 40, "refs/tags/v1.0.0")])

        refs = parse_pktline(data)

        assert len(refs) == 1
        assert refs[0].refname == "refs/tags/v1.0.0"


class TestDeletionDetection:
    """Tests for deletion detection."""

    def test_branch_deletion(self):
        """Test that branch deletion is detected."""
        old_sha = "c" * 40
        data = create_pktline_data([(old_sha, ZERO_SHA, "refs/heads/feature")])

        refs = parse_pktline(data)

        assert len(refs) == 1
        assert refs[0].is_deletion() is True
        assert refs[0].new_sha == ZERO_SHA

    def test_tag_deletion(self):
        """Test that tag deletion is detected."""
        old_sha = "d" * 40
        data = create_pktline_data([(old_sha, ZERO_SHA, "refs/tags/old-tag")])

        refs = parse_pktline(data)

        assert len(refs) == 1
        assert refs[0].is_deletion() is True

    def test_creation_not_deletion(self):
        """Test that branch creation is not marked as deletion."""
        new_sha = "e" * 40
        data = create_pktline_data([(ZERO_SHA, new_sha, "refs/heads/new-branch")])

        refs = parse_pktline(data)

        assert len(refs) == 1
        assert refs[0].is_deletion() is False
        assert refs[0].is_creation() is True


class TestMultiRefParsing:
    """Tests for multi-ref push parsing."""

    def test_two_refs(self):
        """Test parsing two ref updates."""
        refs_input = [
            ("a" * 40, "b" * 40, "refs/heads/main"),
            ("c" * 40, "d" * 40, "refs/heads/feature"),
        ]
        data = create_pktline_data(refs_input)

        refs = parse_pktline(data)

        assert len(refs) == 2
        assert refs[0].refname == "refs/heads/main"
        assert refs[1].refname == "refs/heads/feature"
        # Only first ref has capabilities
        assert refs[0].capabilities != ""
        assert refs[1].capabilities == ""

    def test_many_refs(self):
        """Test parsing many ref updates."""
        refs_input = [
            (f"{i:040x}", f"{i+1:040x}", f"refs/heads/branch-{i}")
            for i in range(10)
        ]
        data = create_pktline_data(refs_input)

        refs = parse_pktline(data)

        assert len(refs) == 10
        for i, ref in enumerate(refs):
            assert ref.refname == f"refs/heads/branch-{i}"

    def test_mixed_operations(self):
        """Test parsing mixed create/update/delete operations."""
        refs_input = [
            (ZERO_SHA, "b" * 40, "refs/heads/new-branch"),  # Create
            ("c" * 40, "d" * 40, "refs/heads/update-branch"),  # Update
            ("e" * 40, ZERO_SHA, "refs/heads/delete-branch"),  # Delete
        ]
        data = create_pktline_data(refs_input)

        refs = parse_pktline(data)

        assert len(refs) == 3
        assert refs[0].is_creation() is True
        assert refs[1].is_update() is True
        assert refs[2].is_deletion() is True


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_data(self):
        """Test parsing empty data."""
        refs = parse_pktline(b"")
        assert refs == []

    def test_flush_packet_only(self):
        """Test parsing flush packet only."""
        refs = parse_pktline(b"0000")
        assert refs == []

    def test_invalid_hex_length(self):
        """Test handling of invalid hex length prefix."""
        refs = parse_pktline(b"ZZZZ" + b"garbage data")
        assert refs == []

    def test_truncated_data(self):
        """Test handling of truncated pkt-line data."""
        # Claim 100 bytes but provide less
        refs = parse_pktline(b"0064" + b"short")
        assert refs == []

    def test_length_too_small(self):
        """Test handling of length less than 4."""
        refs = parse_pktline(b"0003")
        assert refs == []

    def test_non_utf8_content(self):
        """Test handling of non-UTF8 content."""
        # Create valid length but invalid UTF-8 content
        content = b"\xff\xfe\x00\x01"
        length = len(content) + 4
        data = f"{length:04x}".encode() + content + b"0000"
        refs = parse_pktline(data)
        # Should skip non-UTF8 line but not crash
        assert refs == []

    def test_malformed_ref_line(self):
        """Test handling of malformed ref line (not enough parts)."""
        content = b"just-one-part\n"
        length = len(content) + 4
        data = f"{length:04x}".encode() + content + b"0000"
        refs = parse_pktline(data)
        assert refs == []

    def test_invalid_sha_length(self):
        """Test handling of invalid SHA length."""
        # SHA too short
        content = b"abc def refs/heads/main\n"
        length = len(content) + 4
        data = f"{length:04x}".encode() + content + b"0000"
        refs = parse_pktline(data)
        assert refs == []

    def test_multiple_flush_packets(self):
        """Test handling of multiple flush packets."""
        ref_data = create_pktline("a" * 40, "b" * 40, "refs/heads/main")
        data = ref_data + b"0000" + b"0000" + b"0000"
        refs = parse_pktline(data)
        assert len(refs) == 1


class TestReadPktLinePrefix:
    """Tests for the read_pktline_prefix streaming function."""

    def test_basic_read(self):
        """Test basic streaming read."""
        data = create_pktline_data([("a" * 40, "b" * 40, "refs/heads/main")])
        stream = io.BytesIO(data + b"packfile-data")

        buf, pktline_end, err = read_pktline_prefix(stream)

        assert err is None
        assert pktline_end is not None
        assert pktline_end == len(data)
        refs = parse_pktline(buf[:pktline_end])
        assert len(refs) == 1

    def test_max_exceeded(self):
        """Test max_bytes limit."""
        data = create_pktline_data([("a" * 40, "b" * 40, "refs/heads/main")])
        # Add more data after flush to trigger reading
        stream = io.BytesIO(data + b"x" * 1000)

        # Set max_bytes smaller than the actual data
        buf, pktline_end, err = read_pktline_prefix(
            io.BytesIO(b"0100" + b"x" * 252),  # Claims 256 bytes, will exceed limit
            max_bytes=100,
        )

        assert err == "max_exceeded"
        assert pktline_end is None

    def test_invalid_length(self):
        """Test invalid length prefix in stream."""
        stream = io.BytesIO(b"XXXX" + b"garbage")

        buf, pktline_end, err = read_pktline_prefix(stream)

        assert err == "invalid_length"
        assert pktline_end is None

    def test_eof_before_flush(self):
        """Test EOF before flush packet."""
        # Pkt-line without flush packet
        ref_data = create_pktline("a" * 40, "b" * 40, "refs/heads/main")
        stream = io.BytesIO(ref_data)  # No flush packet

        buf, pktline_end, err = read_pktline_prefix(stream)

        assert err == "eof"
        assert pktline_end is None

    def test_chunk_size_handling(self):
        """Test with small chunk size."""
        data = create_pktline_data([("a" * 40, "b" * 40, "refs/heads/main")])
        stream = io.BytesIO(data)

        buf, pktline_end, err = read_pktline_prefix(stream, chunk_size=8)

        assert err is None
        assert pktline_end == len(data)


class TestIterPrefixedStream:
    """Tests for the iter_prefixed_stream function."""

    def test_basic_iteration(self):
        """Test basic stream iteration with prefix."""
        prefix = b"prefix-data"
        stream = io.BytesIO(b"stream-data")

        result = b"".join(iter_prefixed_stream(prefix, stream))

        assert result == b"prefix-datastream-data"

    def test_empty_prefix(self):
        """Test iteration with empty prefix."""
        stream = io.BytesIO(b"stream-only")

        result = b"".join(iter_prefixed_stream(b"", stream))

        assert result == b"stream-only"

    def test_empty_stream(self):
        """Test iteration with empty stream."""
        prefix = b"prefix-only"
        stream = io.BytesIO(b"")

        result = b"".join(iter_prefixed_stream(prefix, stream))

        assert result == b"prefix-only"

    def test_chunked_reading(self):
        """Test that stream is read in chunks."""
        prefix = b"pre"
        stream = io.BytesIO(b"stream-data-that-is-longer")

        chunks = list(iter_prefixed_stream(prefix, stream, chunk_size=5))

        # First chunk is prefix, then chunks of 5 bytes
        assert chunks[0] == b"pre"
        assert all(len(c) <= 5 for c in chunks[1:])
        assert b"".join(chunks) == b"prestream-data-that-is-longer"


class TestConstants:
    """Tests for module constants."""

    def test_zero_sha(self):
        """Test ZERO_SHA constant."""
        assert ZERO_SHA == "0" * 40
        assert len(ZERO_SHA) == 40

    def test_default_constants(self):
        """Test default configuration constants."""
        assert DEFAULT_MAX_PKTLINE_BYTES == 65536
        assert DEFAULT_PKTLINE_CHUNK_SIZE == 8192


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
