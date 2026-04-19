"""Tests for foundry_git_safety.operations."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from foundry_git_safety.operations import (
    AUDIT_OUTPUT_TRUNCATE,
    SandboxSemaphorePool,
    _translate_paths,
    audit_log,
)


# ---------------------------------------------------------------------------
# TestAuditLog
# ---------------------------------------------------------------------------


class TestAuditLog:
    """Tests for audit_log(...) structured logging."""

    def test_emits_to_audit_logger(self):
        """Emits an info-level log to the git_audit logger."""
        with patch("foundry_git_safety.operations.audit_logger") as mock_logger:
            mock_logger.info = MagicMock()
            mock_logger.warning = MagicMock()

            audit_log(
                event="command_executed",
                action="push",
                decision="allow",
            )

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert call_args[0][0] == "git.%s"
        assert call_args[0][1] == "command_executed"

    def test_truncates_stdout_at_limit(self):
        """stdout is truncated at AUDIT_OUTPUT_TRUNCATE characters."""
        long_output = "x" * (AUDIT_OUTPUT_TRUNCATE + 500)

        with patch("foundry_git_safety.operations.audit_logger") as mock_logger:
            mock_logger.info = MagicMock()
            mock_logger.warning = MagicMock()

            audit_log(
                event="command_executed",
                action="push",
                decision="allow",
                stdout=long_output,
            )

        # The extra dict is passed as the `extra` kwarg to the logger
        call_kwargs = mock_logger.info.call_args
        # audit_log passes `extra=entry` as a kwarg to log_fn
        entry = call_kwargs[1].get("extra") if call_kwargs[1] else None
        if entry is None:
            # Try as keyword argument
            entry = call_kwargs.kwargs.get("extra")
        assert entry is not None
        assert len(entry["stdout"]) == AUDIT_OUTPUT_TRUNCATE
        assert entry.get("stdout_truncated") is True

    def test_deny_level_uses_warning(self):
        """When decision is 'deny', the warning log function is used."""
        with patch("foundry_git_safety.operations.audit_logger") as mock_logger:
            mock_logger.info = MagicMock()
            mock_logger.warning = MagicMock()

            audit_log(
                event="command_blocked",
                action="push",
                decision="deny",
                reason="protected branch",
            )

        mock_logger.warning.assert_called_once()
        mock_logger.info.assert_not_called()

    def test_request_id_generated_when_not_provided(self):
        """A UUID request_id is auto-generated when not provided."""
        with patch("foundry_git_safety.operations.audit_logger") as mock_logger:
            mock_logger.info = MagicMock()
            mock_logger.warning = MagicMock()

            audit_log(event="test", action="test", decision="allow")

        entry = mock_logger.info.call_args.kwargs.get("extra")
        assert entry is not None
        assert "request_id" in entry
        # UUID format check: 8-4-4-4-12 hex chars
        assert len(entry["request_id"].split("-")) == 5

    def test_extra_kwargs_added_to_entry(self):
        """Extra keyword arguments are included in the log entry."""
        with patch("foundry_git_safety.operations.audit_logger") as mock_logger:
            mock_logger.info = MagicMock()
            mock_logger.warning = MagicMock()

            audit_log(
                event="test",
                action="test",
                decision="allow",
                custom_field="custom_value",
            )

        entry = mock_logger.info.call_args.kwargs.get("extra")
        assert entry is not None
        assert entry["custom_field"] == "custom_value"

    def test_stderr_truncated_at_limit(self):
        """stderr is truncated at AUDIT_OUTPUT_TRUNCATE characters."""
        long_stderr = "e" * (AUDIT_OUTPUT_TRUNCATE + 200)

        with patch("foundry_git_safety.operations.audit_logger") as mock_logger:
            mock_logger.info = MagicMock()
            mock_logger.warning = MagicMock()

            audit_log(
                event="test",
                action="test",
                decision="allow",
                stderr=long_stderr,
            )

        entry = mock_logger.info.call_args.kwargs.get("extra")
        assert entry is not None
        assert len(entry["stderr"]) == AUDIT_OUTPUT_TRUNCATE
        assert entry.get("stderr_truncated") is True


# ---------------------------------------------------------------------------
# TestSandboxSemaphorePool
# ---------------------------------------------------------------------------


class TestSandboxSemaphorePool:
    """Tests for SandboxSemaphorePool get(), cleanup()."""

    def test_creates_semaphore_per_sandbox(self):
        """get() creates a new asyncio.Semaphore for an unseen sandbox_id."""
        pool = SandboxSemaphorePool(max_concurrent=2)
        sem = pool.get("sandbox-1")
        assert isinstance(sem, asyncio.Semaphore)

    def test_same_semaphore_returned_for_same_sandbox(self):
        """get() returns the same semaphore for the same sandbox_id."""
        pool = SandboxSemaphorePool(max_concurrent=3)
        sem1 = pool.get("sandbox-1")
        sem2 = pool.get("sandbox-1")
        assert sem1 is sem2

    def test_different_sandboxes_get_different_semaphores(self):
        """Different sandbox IDs get distinct semaphores."""
        pool = SandboxSemaphorePool(max_concurrent=3)
        sem1 = pool.get("sandbox-1")
        sem2 = pool.get("sandbox-2")
        assert sem1 is not sem2

    def test_cleanup_removes_semaphore(self):
        """cleanup() removes the semaphore for a sandbox."""
        pool = SandboxSemaphorePool(max_concurrent=3)
        sem = pool.get("sandbox-1")
        pool.cleanup("sandbox-1")
        sem_after = pool.get("sandbox-1")
        assert sem_after is not sem

    def test_cleanup_nonexistent_is_noop(self):
        """cleanup() on a nonexistent sandbox_id does not raise."""
        pool = SandboxSemaphorePool(max_concurrent=3)
        pool.cleanup("nonexistent")  # Should not raise

    def test_max_concurrent_enforced(self):
        """Semaphore has the correct _value matching max_concurrent."""
        pool = SandboxSemaphorePool(max_concurrent=4)
        sem = pool.get("sandbox-abc")
        assert sem._value == 4


# ---------------------------------------------------------------------------
# TestTranslatePaths
# ---------------------------------------------------------------------------


class TestTranslatePaths:
    """Tests for _translate_paths(text, real_repo, client_root)."""

    def test_translates_real_repo_root_to_client_root(self):
        """Lines starting with the real repo path are translated."""
        text = "/git-workspace/repo/src/main.py"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert result == "/workspace/src/main.py"

    def test_translates_path_after_whitespace(self):
        """Lines containing the repo path after whitespace are translated."""
        text = "  /git-workspace/repo/src/main.py"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert result == "  /workspace/src/main.py"

    def test_translates_path_after_tab(self):
        """Lines containing the repo path after a tab are translated."""
        text = "\t/git-workspace/repo/src/main.py"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert result == "\t/workspace/src/main.py"

    def test_skips_non_matching_lines(self):
        """Lines that don't contain the repo path are left unchanged."""
        text = "This is just a log message with no paths."
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert result == text

    def test_handles_git_status_prefix(self):
        """Lines starting with git status short-format codes are translated."""
        text = "M /git-workspace/repo/src/main.py"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert result == "M /workspace/src/main.py"

    def test_handles_fatal_error_prefix(self):
        """Lines starting with 'fatal: ' are translated."""
        text = "fatal: could not open '/git-workspace/repo/.git'"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert "/workspace/" in result
        assert "/git-workspace/repo" not in result

    def test_handles_multiline(self):
        """Each line is independently checked for translation."""
        text = (
            "M /git-workspace/repo/src/main.py\n"
            "no path here\n"
            "A /git-workspace/repo/README.md"
        )
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        lines = result.split("\n")
        assert lines[0] == "M /workspace/src/main.py"
        assert lines[1] == "no path here"
        assert lines[2] == "A /workspace/README.md"

    def test_error_prefix_translated(self):
        """Lines starting with 'error: ' are translated."""
        text = "error: pathspec '/git-workspace/repo/bad' did not match"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert "/workspace/" in result

    def test_warning_prefix_translated(self):
        """Lines starting with 'warning: ' are translated."""
        text = "warning: CRLF will be replaced by LF in /git-workspace/repo/file.txt"
        result = _translate_paths(text, "/git-workspace/repo", "/workspace")
        assert "/workspace/" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
