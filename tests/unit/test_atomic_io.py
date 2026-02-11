"""Unit tests for foundry_sandbox/atomic_io.py.

Tests atomic file writes, file locking primitives, and error handling.
"""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest

from foundry_sandbox.atomic_io import (
    LOCK_TIMEOUT_SECONDS,
    atomic_write,
    atomic_write_unlocked,
    file_lock,
)


# ============================================================================
# atomic_write_unlocked tests
# ============================================================================


class TestAtomicWriteUnlocked:
    """Tests for atomic_write_unlocked()."""

    def test_creates_file_with_content(self, tmp_path):
        """Should create the file with the expected content."""
        target = tmp_path / "test.txt"
        atomic_write_unlocked(target, "hello world")
        assert target.read_text() == "hello world"

    def test_file_has_0600_permissions(self, tmp_path):
        """Created file should have 0o600 permissions (from mkstemp)."""
        target = tmp_path / "test.txt"
        atomic_write_unlocked(target, "content")
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600

    def test_creates_parent_dirs(self, tmp_path):
        """Should create missing parent directories."""
        target = tmp_path / "a" / "b" / "c" / "test.txt"
        atomic_write_unlocked(target, "deep")
        assert target.read_text() == "deep"

    def test_preserves_original_on_error(self, tmp_path):
        """Original file should be preserved if the write fails."""
        target = tmp_path / "test.txt"
        target.write_text("original")

        # Force an error by making the parent directory read-only
        # after creating the temp file — simulate os.replace failure.
        # Instead, use a simpler approach: pass a path object that
        # makes os.replace fail.
        class BadPath(type(target)):
            """Path subclass where os.replace will fail."""

        # Instead, test with a direct mock approach
        import unittest.mock as mock

        with mock.patch("foundry_sandbox.atomic_io.os.replace", side_effect=OSError("boom")):
            with pytest.raises(OSError, match="boom"):
                atomic_write_unlocked(target, "new content")

        assert target.read_text() == "original"

    def test_cleans_up_temp_on_failure(self, tmp_path):
        """Temp file should be removed on write failure."""
        target = tmp_path / "test.txt"

        import unittest.mock as mock

        with mock.patch("foundry_sandbox.atomic_io.os.replace", side_effect=OSError("boom")):
            with pytest.raises(OSError):
                atomic_write_unlocked(target, "content")

        # Only the target dir should exist, no stale .tmp files
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert len(tmp_files) == 0, f"Stale temp files found: {tmp_files}"

    def test_overwrites_existing_file(self, tmp_path):
        """Should overwrite existing file content."""
        target = tmp_path / "test.txt"
        target.write_text("old")
        atomic_write_unlocked(target, "new")
        assert target.read_text() == "new"


# ============================================================================
# file_lock tests
# ============================================================================


class TestFileLock:
    """Tests for file_lock() context manager."""

    def test_creates_sidecar_lock_file(self, tmp_path):
        """Should create a .lock sidecar file."""
        target = tmp_path / "data.json"
        target.write_text("{}")

        with file_lock(target):
            lock_path = target.with_suffix(".json.lock")
            assert lock_path.exists()

    def test_shared_locks_coexist(self, tmp_path):
        """Multiple shared locks should be acquirable simultaneously."""
        target = tmp_path / "data.json"
        target.write_text("{}")

        with file_lock(target, shared=True):
            # Acquiring a second shared lock should not block
            with file_lock(target, shared=True):
                pass  # success — both shared locks held

    def test_lock_released_on_exit(self, tmp_path):
        """Lock should be released when context exits."""
        target = tmp_path / "data.json"
        target.write_text("{}")

        with file_lock(target):
            pass

        # Should be able to acquire exclusive lock again
        with file_lock(target):
            pass

    def test_exclusive_lock_blocks(self, tmp_path):
        """An exclusive lock held in the same process should block acquisition with short timeout."""
        import fcntl as _fcntl
        import foundry_sandbox.atomic_io as _aio

        target = tmp_path / "data.json"
        target.write_text("{}")
        lock_path = target.with_suffix(".json.lock")

        # Manually hold an exclusive lock on the sidecar file
        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        _fcntl.flock(fd, _fcntl.LOCK_EX)

        original = _aio.LOCK_TIMEOUT_SECONDS
        _aio.LOCK_TIMEOUT_SECONDS = 0.3
        try:
            with pytest.raises(OSError, match="Timed out"):
                with file_lock(target):
                    pass
        finally:
            _aio.LOCK_TIMEOUT_SECONDS = original
            _fcntl.flock(fd, _fcntl.LOCK_UN)
            os.close(fd)


# ============================================================================
# atomic_write tests
# ============================================================================


class TestAtomicWrite:
    """Tests for atomic_write() (write-through-lock)."""

    def test_basic_write(self, tmp_path):
        """Should write content through the lock."""
        target = tmp_path / "test.txt"
        atomic_write(target, "hello")
        assert target.read_text() == "hello"

    def test_creates_lock_file(self, tmp_path):
        """Should create a sidecar lock file."""
        target = tmp_path / "test.json"
        atomic_write(target, "{}")
        assert target.with_suffix(".json.lock").exists()

    def test_file_permissions(self, tmp_path):
        """Written file should have 0o600 permissions."""
        target = tmp_path / "test.txt"
        atomic_write(target, "secure")
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600
