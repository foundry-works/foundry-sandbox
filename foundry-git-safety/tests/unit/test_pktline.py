"""Tests for foundry_git_safety.pktline — git pkt-line protocol parser."""

import io

import pytest

from foundry_git_safety.pktline import (
    ZERO_SHA,
    PktLineRef,
    iter_prefixed_stream,
    parse_pktline,
    read_pktline_prefix,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha(n: int) -> str:
    """Return a 40-char hex SHA-like string from an integer."""
    return f"{n:040x}"


def _pktline(lines: list[bytes], include_flush: bool = True) -> bytes:
    """Build raw pkt-line data from a list of raw line payloads."""
    parts = []
    for line in lines:
        length = 4 + len(line)
        parts.append(f"{length:04x}".encode("ascii") + line)
    if include_flush:
        parts.append(b"0000")
    return b"".join(parts)


# ---------------------------------------------------------------------------
# TestPktLineRef
# ---------------------------------------------------------------------------


class TestPktLineRef:
    """Tests for the PktLineRef dataclass helper methods."""

    def test_is_creation(self):
        """old_sha == ZERO_SHA and new_sha != ZERO_SHA is a creation."""
        ref = PktLineRef(old_sha=ZERO_SHA, new_sha=_sha(1), refname="refs/heads/main")
        assert ref.is_creation() is True
        assert ref.is_deletion() is False
        assert ref.is_update() is False

    def test_is_deletion(self):
        """new_sha == ZERO_SHA is a deletion."""
        ref = PktLineRef(old_sha=_sha(1), new_sha=ZERO_SHA, refname="refs/heads/main")
        assert ref.is_deletion() is True
        assert ref.is_creation() is False
        assert ref.is_update() is False

    def test_is_update(self):
        """Both old and new are non-ZERO is an update."""
        ref = PktLineRef(old_sha=_sha(1), new_sha=_sha(2), refname="refs/heads/main")
        assert ref.is_update() is True
        assert ref.is_creation() is False
        assert ref.is_deletion() is False

    def test_update_with_zero_old_is_creation_not_update(self):
        """When old_sha is ZERO_SHA, it is a creation, not an update."""
        ref = PktLineRef(old_sha=ZERO_SHA, new_sha=_sha(9), refname="refs/heads/feature")
        assert ref.is_creation() is True
        assert ref.is_update() is False


# ---------------------------------------------------------------------------
# TestParsePktline
# ---------------------------------------------------------------------------


class TestParsePktline:
    """Tests for parse_pktline()."""

    def test_single_ref_update(self):
        """Parse a single ref update line with trailing flush."""
        old = _sha(1)
        new = _sha(2)
        payload = f"{old} {new} refs/heads/main\n".encode()
        data = _pktline([payload])
        refs = parse_pktline(data)
        assert len(refs) == 1
        assert refs[0].old_sha == old
        assert refs[0].new_sha == new
        assert refs[0].refname == "refs/heads/main"
        assert refs[0].capabilities == ""

    def test_multiple_updates(self):
        """Parse multiple ref updates in a single body."""
        old_a, new_a = _sha(1), _sha(2)
        old_b, new_b = _sha(3), _sha(4)
        line_a = f"{old_a} {new_a} refs/heads/main\n".encode()
        line_b = f"{old_b} {new_b} refs/heads/feature\n".encode()
        data = _pktline([line_a, line_b])
        refs = parse_pktline(data)
        assert len(refs) == 2
        assert refs[0].refname == "refs/heads/main"
        assert refs[1].refname == "refs/heads/feature"

    def test_first_line_with_capabilities(self):
        """First line can carry capabilities after a NUL byte."""
        old = _sha(1)
        new = _sha(2)
        raw = f"{old} {new} refs/heads/main\0report-status side-band\n".encode()
        data = _pktline([raw])
        refs = parse_pktline(data)
        assert len(refs) == 1
        assert refs[0].capabilities == "report-status side-band"

    def test_flush_packet_skipped(self):
        """Flush packets (0000) are skipped and do not produce refs."""
        data = b"0000" * 3  # three flush packets in a row
        refs = parse_pktline(data)
        assert refs == []

    def test_empty_input_returns_empty(self):
        """Empty bytes input returns an empty list."""
        assert parse_pktline(b"") == []

    def test_invalid_length_prefix_stops_parsing(self):
        """A non-hex length prefix causes the parser to stop."""
        old = _sha(1)
        new = _sha(2)
        good_line = f"{old} {new} refs/heads/main\n".encode()
        good_pkt = _pktline([good_line])
        # Prepend garbage that is not valid hex
        bad_prefix = b"ZZZZ"
        data = bad_prefix + good_pkt
        refs = parse_pktline(data)
        # Parser hits 'ZZZZ', fails to decode hex, and breaks out
        assert refs == []

    def test_truncated_data_stops(self):
        """Data that ends mid-pktline does not crash; partial lines are dropped."""
        old = _sha(1)
        new = _sha(2)
        line = f"{old} {new} refs/heads/main\n".encode()
        full = _pktline([line])
        # Truncate after the length prefix so the payload is incomplete
        truncated = full[:6]
        refs = parse_pktline(truncated)
        assert refs == []

    def test_non_40_char_shas_rejected(self):
        """SHAs that are not exactly 40 hex chars are silently rejected."""
        # Use short "SHAs" (only 10 chars) so they fail the len==40 check
        line = b"aaaaaa1111 bbbbbb2222 refs/heads/main\n"
        data = _pktline([line])
        refs = parse_pktline(data)
        assert refs == []


# ---------------------------------------------------------------------------
# TestReadPktlinePrefix
# ---------------------------------------------------------------------------


class TestReadPktlinePrefix:
    """Tests for read_pktline_prefix()."""

    def test_reads_until_flush_returns_end_index(self):
        """Successfully reads pkt-line section and returns flush index."""
        old = _sha(1)
        new = _sha(2)
        line = f"{old} {new} refs/heads/main\n".encode()
        pktline_data = _pktline([line])
        # Append extra bytes after flush to simulate packfile data
        packfile = b"PACK....some pack data"
        full = pktline_data + packfile

        stream = io.BytesIO(full)
        buf, end_idx, error = read_pktline_prefix(stream)

        assert error is None
        assert end_idx is not None
        assert end_idx == len(pktline_data)
        assert buf == full
        # Stream position should be at end of what we read from stream
        # (read_pktline_prefix reads in chunks so it may read past flush)
        assert stream.tell() > 0

    def test_max_exceeded_error(self):
        """Returns 'max_exceeded' when input exceeds max_bytes."""
        # Build data larger than the max_bytes limit
        old = _sha(1)
        new = _sha(2)
        line = f"{old} {new} refs/heads/main\n".encode()
        # Create many lines — no flush packet so it keeps reading
        lines = [line] * 100
        data_no_flush = b""
        for l in lines:
            length = 4 + len(l)
            data_no_flush += f"{length:04x}".encode("ascii") + l

        stream = io.BytesIO(data_no_flush)
        buf, end_idx, error = read_pktline_prefix(stream, max_bytes=64)
        assert error == "max_exceeded"
        assert end_idx is None

    def test_invalid_length_error(self):
        """Returns 'invalid_length' when a non-hex prefix is encountered."""
        # Start with valid hex prefix '0005' (length=5), then put junk for next pktline
        data = b"0005X" + b"GGGGsome data"
        stream = io.BytesIO(data)
        buf, end_idx, error = read_pktline_prefix(stream)
        assert error == "invalid_length"
        assert end_idx is None

    def test_eof_error_on_empty_stream(self):
        """Returns 'eof' when the stream is empty (no flush packet found)."""
        stream = io.BytesIO(b"")
        buf, end_idx, error = read_pktline_prefix(stream)
        assert error == "eof"
        assert end_idx is None
        assert buf == b""

    def test_chunked_reading(self):
        """Handles reading across small chunk boundaries."""
        old = _sha(1)
        new = _sha(2)
        line = f"{old} {new} refs/heads/main\n".encode()
        pktline_data = _pktline([line])

        stream = io.BytesIO(pktline_data)
        # Use a tiny chunk size to force multiple reads
        buf, end_idx, error = read_pktline_prefix(stream, chunk_size=4)
        assert error is None
        assert end_idx is not None


# ---------------------------------------------------------------------------
# TestIterPrefixedStream
# ---------------------------------------------------------------------------


class TestIterPrefixedStream:
    """Tests for iter_prefixed_stream()."""

    def test_yields_prefix_then_chunks(self):
        """First yields the prefix, then yields stream chunks."""
        prefix = b"hello "
        remaining = b"world"
        stream = io.BytesIO(remaining)
        chunks = list(iter_prefixed_stream(prefix, stream, chunk_size=1024))
        assert chunks == [b"hello ", b"world"]

    def test_empty_prefix_just_yields_stream(self):
        """An empty prefix results in only stream chunks."""
        stream = io.BytesIO(b"data")
        chunks = list(iter_prefixed_stream(b"", stream, chunk_size=1024))
        assert chunks == [b"data"]

    def test_empty_stream_yields_prefix_only(self):
        """An empty stream still yields the prefix."""
        stream = io.BytesIO(b"")
        chunks = list(iter_prefixed_stream(b"prefix-data", stream, chunk_size=1024))
        assert chunks == [b"prefix-data"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
