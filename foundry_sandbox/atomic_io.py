"""Shared atomic I/O primitives for crash-safe file writes.

Provides file locking (via ``fcntl.flock()``) and atomic write-via-rename
so that concurrent processes and mid-write crashes never leave corrupted
files on disk.

WARNING: ``fcntl.flock()`` provides only advisory locking and does not
work reliably on NFS or other networked filesystems.  Keep protected
files on local disk.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

LOCK_TIMEOUT_SECONDS = 30


@contextlib.contextmanager
def file_lock(path: Path, *, shared: bool = False) -> Iterator[None]:
    """Acquire a file lock for *path* using a sidecar ``.lock`` file.

    Uses non-blocking attempts with a retry loop so that a stuck lock
    never blocks indefinitely.

    Args:
        path: The file being protected.
        shared: If ``True`` acquire a shared (read) lock; otherwise exclusive.

    Raises:
        OSError: If the lock cannot be acquired within the timeout.
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        lock_op = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(fd, lock_op)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise OSError(
                        f"Timed out after {LOCK_TIMEOUT_SECONDS}s waiting for lock on {path}. "
                        f"If no other process is running, remove {lock_path} and retry."
                    )
                time.sleep(0.1)
        yield
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_write_unlocked(path: Path, content: str) -> None:
    """Write content atomically with 600 permissions (caller holds lock).

    Uses write-to-temp + os.replace() to avoid corrupted files on crash.
    The caller MUST already hold an exclusive lock on *path* via file_lock().
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write(path: Path, content: str) -> None:
    """Write content to a file atomically with 600 permissions.

    Uses write-to-temp + os.replace() to avoid corrupted files on crash.
    Acquires an exclusive file lock for the duration of the write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with file_lock(path):
        atomic_write_unlocked(path, content)
