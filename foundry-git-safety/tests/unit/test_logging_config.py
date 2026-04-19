"""Tests for foundry_git_safety.logging_config."""

import json
import logging

import pytest

from foundry_git_safety.logging_config import (
    JSONFormatter,
    LogContext,
    TextFormatter,
    clear_context,
    generate_request_id,
    get_context,
    set_context,
    setup_logging,
)


class TestJSONFormatter:
    def test_output_is_valid_json(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            "test", logging.INFO, "test.py", 1, "hello", (), None
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["message"] == "hello"

    def test_includes_level_and_logger(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            "mymod", logging.WARNING, "f.py", 10, "warn msg", (), None
        )
        parsed = json.loads(formatter.format(record))
        assert parsed["level"] == "WARNING"
        assert parsed["logger"] == "mymod"

    def test_includes_correlation_context(self):
        set_context(request_id="req-1", container_id="c-1")
        try:
            formatter = JSONFormatter(include_timestamp=False, include_location=False)
            record = logging.LogRecord("t", logging.INFO, "f.py", 1, "m", (), None)
            parsed = json.loads(formatter.format(record))
            assert parsed["request_id"] == "req-1"
            assert parsed["container_id"] == "c-1"
        finally:
            clear_context()

    def test_includes_exception_info(self):
        formatter = JSONFormatter(include_timestamp=False, include_location=False)
        try:
            raise ValueError("boom")
        except ValueError:
            record = logging.LogRecord("t", logging.ERROR, "f.py", 1, "err", (), None)
            record.exc_info = (ValueError, ValueError("boom"), record.exc_info[2] if record.exc_info else None)
            import sys
            record.exc_info = sys.exc_info()
            parsed = json.loads(formatter.format(record))
            assert "exception" in parsed
            assert "ValueError" in parsed["exception"]


class TestTextFormatter:
    def test_expected_format_with_timestamp(self):
        formatter = TextFormatter(include_timestamp=True, include_location=False)
        record = logging.LogRecord("mymod", logging.INFO, "f.py", 1, "hello", (), None)
        output = formatter.format(record)
        assert "INFO" in output
        assert "[mymod]" in output
        assert "hello" in output

    def test_context_bracket_formatting(self):
        set_context(request_id="r1", container_id="c1")
        try:
            formatter = TextFormatter(include_timestamp=False, include_location=False)
            record = logging.LogRecord("t", logging.INFO, "f.py", 1, "m", (), None)
            output = formatter.format(record)
            assert "[r1/c1]" in output
        finally:
            clear_context()

    def test_no_context_when_empty(self):
        clear_context()
        formatter = TextFormatter(include_timestamp=False, include_location=False)
        record = logging.LogRecord("t", logging.INFO, "f.py", 1, "m", (), None)
        output = formatter.format(record)
        # Should not have the context bracket like [r1/c1]
        assert " [r1/c1]" not in output


class TestLogContext:
    def test_sets_and_clears_context(self):
        with LogContext(request_id="r1"):
            assert get_context().get("request_id") == "r1"
        assert get_context().get("request_id") is None

    def test_nested_context_restores_previous(self):
        set_context(request_id="outer")
        try:
            with LogContext(request_id="inner"):
                assert get_context()["request_id"] == "inner"
            assert get_context()["request_id"] == "outer"
        finally:
            clear_context()

    def test_extra_fields_merged(self):
        with LogContext(custom_key="value"):
            ctx = get_context()
            assert ctx.get("custom_key") == "value"


class TestSetGetClearContext:
    def test_set_then_get(self):
        set_context(request_id="r1", container_id="c1")
        ctx = get_context()
        assert ctx["request_id"] == "r1"
        assert ctx["container_id"] == "c1"
        clear_context()

    def test_clear_removes_all(self):
        set_context(request_id="r1", extra_key="v")
        clear_context()
        assert get_context() == {}

    def test_extra_kwargs_preserved(self):
        set_context(custom_field="test")
        assert get_context().get("custom_field") == "test"
        clear_context()


class TestSetupLogging:
    def test_configures_root_logger_level(self):
        setup_logging(level="DEBUG", format_type="json")
        root = logging.getLogger()
        assert root.level == logging.DEBUG
        # Cleanup
        logging.getLogger().setLevel(logging.WARNING)

    def test_clears_existing_handlers(self):
        root = logging.getLogger()
        root.addHandler(logging.StreamHandler())
        setup_logging(level="INFO", format_type="text")
        assert len(root.handlers) == 1
        # Cleanup
        root.handlers.clear()


class TestGenerateRequestId:
    def test_returns_uuid_format(self):
        rid = generate_request_id()
        assert len(rid) == 36
        assert rid.count("-") == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
