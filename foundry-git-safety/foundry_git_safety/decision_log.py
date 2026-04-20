"""Size-rotated append-only JSON Lines decision log.

Writes structured decision entries to ``~/.foundry/logs/decisions.jsonl``
with automatic rotation when the file exceeds a configured size.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _default_log_dir() -> str:
    return os.environ.get(
        "GIT_SAFETY_DECISION_LOG_DIR",
        os.path.expanduser("~/.foundry/logs"),
    )


class DecisionLogWriter:
    """Append-only JSON Lines decision log with size-based rotation."""

    def __init__(
        self,
        log_dir: str | None = None,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        self._log_dir = Path(log_dir or _default_log_dir())
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._lock = threading.Lock()
        self._current_fd = None
        self._current_size: int = 0
        self._log_path = self._log_dir / "decisions.jsonl"

    def _ensure_open(self) -> None:
        if self._current_fd is not None:
            return
        self._log_dir.mkdir(parents=True, exist_ok=True)
        if self._log_path.exists():
            self._current_size = self._log_path.stat().st_size
        else:
            self._current_size = 0
        self._current_fd = open(self._log_path, "a")  # noqa: SIM115

    def write(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, default=str) + "\n"
        with self._lock:
            self._ensure_open()
            if (
                self._current_size > 0
                and self._current_size + len(line) > self._max_bytes
            ):
                self._rotate()
            assert self._current_fd is not None
            self._current_fd.write(line)
            self._current_fd.flush()
            self._current_size += len(line)

    def _rotate(self) -> None:
        if self._current_fd is not None:
            self._current_fd.close()
            self._current_fd = None
        # Shift backups: .5 -> delete, .4 -> .5, ..., .1 -> .2
        for i in range(self._backup_count, 0, -1):
            src = Path(f"{self._log_path}.{i}")
            if i == self._backup_count:
                src.unlink(missing_ok=True)
            else:
                dst = Path(f"{self._log_path}.{i + 1}")
                if src.exists():
                    src.rename(dst)
        # Current -> .1
        if self._log_path.exists():
            self._log_path.rename(Path(f"{self._log_path}.1"))
        self._current_size = 0
        self._ensure_open()

    def close(self) -> None:
        with self._lock:
            if self._current_fd is not None:
                self._current_fd.close()
                self._current_fd = None

    def read_last_n(self, n: int = 50) -> list[dict[str, Any]]:
        """Read the last N entries from the current log file."""
        entries: list[dict[str, Any]] = []
        if not self._log_path.exists():
            return entries
        with open(self._log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return entries[-n:]


# Module-level singleton
_writer: DecisionLogWriter | None = None
_writer_lock = threading.Lock()


def get_decision_log_writer() -> DecisionLogWriter:
    global _writer
    with _writer_lock:
        if _writer is None:
            _writer = DecisionLogWriter()
        return _writer


def write_decision(
    *,
    sandbox: str,
    branch: str = "",
    rule: str,
    verb: str,
    outcome: str,
    **extra: Any,
) -> None:
    """Write a structured decision log entry."""
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sandbox": sandbox,
        "branch": branch,
        "rule": rule,
        "verb": verb,
        "outcome": outcome,
    }
    if extra:
        entry.update(extra)
    get_decision_log_writer().write(entry)
