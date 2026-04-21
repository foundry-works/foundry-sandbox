"""Unit tests for the decision log writer."""

import json
from pathlib import Path

import pytest

from foundry_git_safety.decision_log import (
    DecisionLogWriter,
    configure_decision_log,
    write_decision,
)


@pytest.fixture
def log_dir(tmp_path):
    return str(tmp_path / "logs")


@pytest.fixture
def writer(log_dir):
    w = DecisionLogWriter(log_dir=log_dir, max_bytes=1024, backup_count=3)
    yield w
    w.close()


class TestDecisionLogWriter:
    def test_creates_file_on_write(self, writer, log_dir):
        writer.write({"test": "entry"})
        log_path = Path(log_dir) / "decisions.jsonl"
        assert log_path.exists()

    def test_json_lines_format(self, writer, log_dir):
        writer.write({"sandbox": "sbx-1", "outcome": "allow"})
        writer.write({"sandbox": "sbx-2", "outcome": "deny"})
        log_path = Path(log_dir) / "decisions.jsonl"
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["sandbox"] == "sbx-1"
        assert json.loads(lines[1])["outcome"] == "deny"

    def test_rotation(self, writer, log_dir):
        # Fill past max_bytes (1024)
        for i in range(100):
            writer.write({"i": i, "padding": "x" * 50})
        log_path = Path(log_dir) / "decisions.jsonl"
        assert log_path.exists()
        # At least one backup should exist
        backup1 = Path(f"{log_path}.1")
        assert backup1.exists()

    def test_backup_count_limit(self, writer, log_dir):
        for i in range(500):
            writer.write({"i": i, "padding": "x" * 50})
        # backup_count=3, so max files: .1, .2, .3
        log_path = Path(log_dir) / "decisions.jsonl"
        assert not Path(f"{log_path}.4").exists()

    def test_close_and_reopen(self, log_dir):
        w1 = DecisionLogWriter(log_dir=log_dir, max_bytes=1024)
        w1.write({"first": True})
        w1.close()
        w2 = DecisionLogWriter(log_dir=log_dir, max_bytes=1024)
        w2.write({"second": True})
        w2.close()
        log_path = Path(log_dir) / "decisions.jsonl"
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_read_last_n(self, writer):
        for i in range(20):
            writer.write({"i": i})
        entries = writer.read_last_n(5)
        assert len(entries) == 5
        assert entries[-1]["i"] == 19

    def test_read_last_n_empty(self, writer):
        assert writer.read_last_n(5) == []

    def test_read_last_n_missing_file(self, tmp_path):
        w = DecisionLogWriter(log_dir=str(tmp_path / "nonexistent"))
        assert w.read_last_n(5) == []


class TestWriteDecision:
    def test_write_decision_convenience(self, log_dir, monkeypatch):
        from foundry_git_safety import decision_log
        monkeypatch.setattr(decision_log, "_writer", None)
        monkeypatch.setenv("GIT_SAFETY_DECISION_LOG_DIR", log_dir)
        write_decision(
            sandbox="sbx-1",
            branch="feature",
            rule="branch_isolation",
            verb="push",
            outcome="deny",
        )
        log_path = Path(log_dir) / "decisions.jsonl"
        entry = json.loads(log_path.read_text().strip())
        assert entry["sandbox"] == "sbx-1"
        assert entry["outcome"] == "deny"
        assert entry["verb"] == "push"
        assert "timestamp" in entry


class TestConfigureDecisionLog:
    def test_configure_creates_writer_at_new_path(self, tmp_path, monkeypatch):
        from foundry_git_safety import decision_log

        monkeypatch.setattr(decision_log, "_writer", None)
        new_dir = str(tmp_path / "custom-logs")
        writer = configure_decision_log(log_dir=new_dir)
        writer.write({"test": "configured"})
        assert (Path(new_dir) / "decisions.jsonl").exists()
        writer.close()

    def test_configure_replaces_existing_writer(self, tmp_path, monkeypatch):
        from foundry_git_safety import decision_log

        monkeypatch.setattr(decision_log, "_writer", None)
        dir_a = str(tmp_path / "logs-a")
        dir_b = str(tmp_path / "logs-b")

        w = configure_decision_log(log_dir=dir_a)
        w.write({"loc": "a"})
        configure_decision_log(log_dir=dir_b)
        write_decision(sandbox="sbx", rule="test", verb="push", outcome="allow")

        assert (Path(dir_a) / "decisions.jsonl").exists()
        assert (Path(dir_b) / "decisions.jsonl").exists()
        # Only the initial write in dir_a
        lines_a = (Path(dir_a) / "decisions.jsonl").read_text().strip().split("\n")
        assert len(lines_a) == 1
        # The new write went to dir_b
        lines_b = (Path(dir_b) / "decisions.jsonl").read_text().strip().split("\n")
        assert len(lines_b) == 1

        # Clean up singleton
        decision_log._writer.close()
        monkeypatch.setattr(decision_log, "_writer", None)

    def test_same_path_is_noop(self, tmp_path, monkeypatch):
        from foundry_git_safety import decision_log

        monkeypatch.setattr(decision_log, "_writer", None)
        log_dir = str(tmp_path / "logs")
        w1 = configure_decision_log(log_dir=log_dir)
        w2 = configure_decision_log(log_dir=log_dir)
        assert w1 is w2
        w1.close()
        monkeypatch.setattr(decision_log, "_writer", None)
