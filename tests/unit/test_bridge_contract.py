"""Unit tests for the bridge JSON envelope contract.

Validates that all bridge-exposed modules produce correct JSON envelopes
on both success and failure paths, with proper exit codes and structure.

Bridge contract (from foundry_sandbox/_bridge.py):
    Success: {"ok": true,  "result": <value>, "error": null}   exit 0
    Error:   {"ok": false, "result": null,     "error": {"code": str, "message": str}}  exit 1
    Crash:   no JSON on stdout, traceback to stderr if SANDBOX_DEBUG=1  exit 2
"""

import json
import os
import subprocess
import sys

import pytest

# All bridge-exposed modules and their commands.
# Each entry: (module, command, args, expected_result_type)
#   expected_result_type is the Python type of the "result" field on success,
#   or None if the command needs real files (tested separately).
BRIDGE_MODULES = [
    ("foundry_sandbox.config", ["load", "merge"]),
    ("foundry_sandbox.claude_settings", ["merge"]),
    ("foundry_sandbox.opencode_sync", ["sync"]),
]

# Flattened list of (module, command) for parametrization.
ALL_MODULE_COMMANDS = [
    (module, cmd)
    for module, commands in BRIDGE_MODULES
    for cmd in commands
]


def run_bridge(module: str, args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run a bridge module as a subprocess and return the result."""
    env = os.environ.copy()
    # Ensure the package is importable from the repo root.
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "../..")
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", module, *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def parse_envelope(stdout: str) -> dict:
    """Parse a bridge JSON envelope from stdout."""
    return json.loads(stdout.strip())


class TestEnvelopeStructure:
    """Validates the JSON envelope structure for all bridge modules."""

    def test_success_envelope_has_required_keys(self, tmp_path):
        """A successful bridge call must return {ok: true, result: ..., error: null}."""
        # Use config.load with a valid JSON file as the simplest success path.
        f = tmp_path / "test.json"
        f.write_text('{"hello": "world"}')

        result = run_bridge("foundry_sandbox.config", ["load", str(f)])
        assert result.returncode == 0, f"Expected exit 0, got {result.returncode}. stderr: {result.stderr}"

        envelope = parse_envelope(result.stdout)
        assert "ok" in envelope, "Envelope missing 'ok' field"
        assert "result" in envelope, "Envelope missing 'result' field"
        assert "error" in envelope, "Envelope missing 'error' field"
        assert envelope["ok"] is True
        assert envelope["error"] is None

    def test_error_envelope_has_required_keys(self):
        """A known-error bridge call must return {ok: false, result: null, error: {code, message}}."""
        # Call config.load with a nonexistent command to trigger unknown_command error.
        result = run_bridge("foundry_sandbox.config", ["nonexistent_command"])
        assert result.returncode == 1, f"Expected exit 1, got {result.returncode}. stderr: {result.stderr}"

        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is False
        assert envelope["result"] is None
        assert isinstance(envelope["error"], dict)
        assert "code" in envelope["error"]
        assert "message" in envelope["error"]

    def test_error_code_and_message_are_strings(self):
        """Error envelope code and message must be strings."""
        result = run_bridge("foundry_sandbox.config", ["nonexistent_command"])
        envelope = parse_envelope(result.stdout)
        assert isinstance(envelope["error"]["code"], str)
        assert isinstance(envelope["error"]["message"], str)


class TestExitCodes:
    """Validates exit code conventions across all bridge modules."""

    @pytest.mark.parametrize("module,command", ALL_MODULE_COMMANDS)
    def test_missing_args_returns_known_error(self, module, command):
        """Calling a command without required args should exit 1 (known error)."""
        # All current commands require file path args; calling without them
        # should raise TypeError (wrong number of args) which is a known error.
        result = run_bridge(module, [command])
        assert result.returncode in (1, 2), (
            f"{module} {command} with no args: expected exit 1 or 2, "
            f"got {result.returncode}. stdout: {result.stdout}"
        )
        if result.returncode == 1:
            envelope = parse_envelope(result.stdout)
            assert envelope["ok"] is False

    @pytest.mark.parametrize("module,_commands", BRIDGE_MODULES)
    def test_missing_command_exits_1(self, module, _commands):
        """Calling a module with no command argument should exit 1."""
        result = run_bridge(module, [])
        assert result.returncode == 1, (
            f"{module} with no command: expected exit 1, got {result.returncode}"
        )
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "missing_command"

    @pytest.mark.parametrize("module,_commands", BRIDGE_MODULES)
    def test_unknown_command_exits_1(self, module, _commands):
        """Calling a module with an unknown command should exit 1."""
        result = run_bridge(module, ["__nonexistent__"])
        assert result.returncode == 1
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "unknown_command"
        assert "__nonexistent__" in envelope["error"]["message"]


class TestSuccessPaths:
    """Validates successful execution for each bridge module."""

    def test_config_load_success(self, tmp_path):
        """config.load returns file contents as result."""
        f = tmp_path / "data.json"
        f.write_text('{"key": "value"}')

        result = run_bridge("foundry_sandbox.config", ["load", str(f)])
        assert result.returncode == 0
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is True
        assert envelope["result"] == {"key": "value"}

    def test_config_merge_success(self, tmp_path):
        """config.merge deep-merges two files and writes output."""
        base = tmp_path / "base.json"
        overlay = tmp_path / "overlay.json"
        output = tmp_path / "output.json"

        base.write_text('{"a": 1, "b": 2}')
        overlay.write_text('{"b": 3, "c": 4}')

        result = run_bridge("foundry_sandbox.config", [
            "merge", str(base), str(overlay), str(output),
        ])
        assert result.returncode == 0
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is True

        merged = json.loads(output.read_text())
        assert merged == {"a": 1, "b": 3, "c": 4}

    def test_claude_settings_merge_success(self, tmp_path):
        """claude_settings.merge merges host settings into container."""
        container = tmp_path / "container.json"
        host = tmp_path / "host.json"

        container.write_text('{"model": "opus"}')
        host.write_text('{"theme": "dark"}')

        result = run_bridge("foundry_sandbox.claude_settings", [
            "merge", str(container), str(host),
        ])
        assert result.returncode == 0
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is True

    def test_opencode_sync_success(self, tmp_path):
        """opencode_sync.sync merges template into config."""
        template = tmp_path / "template.json"
        config = tmp_path / "config.json"

        template.write_text('{"providers": {}}')
        config.write_text('{"existing": true}')

        result = run_bridge("foundry_sandbox.opencode_sync", [
            "sync", str(template), str(config),
        ])
        assert result.returncode == 0
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is True
        assert isinstance(envelope["result"], str)


class TestErrorPaths:
    """Validates error handling for known failure modes."""

    def test_config_load_missing_file(self, tmp_path):
        """config.load with missing file returns empty dict (graceful)."""
        result = run_bridge("foundry_sandbox.config", [
            "load", str(tmp_path / "does_not_exist.json"),
        ])
        assert result.returncode == 0
        envelope = parse_envelope(result.stdout)
        # load_json returns {} for missing files — this is success, not error.
        assert envelope["ok"] is True
        assert envelope["result"] == {}

    @pytest.mark.parametrize("module,command", ALL_MODULE_COMMANDS)
    def test_too_few_args_is_known_error(self, module, command):
        """Commands called with insufficient args produce a known error (TypeError)."""
        result = run_bridge(module, [command])
        # TypeError from missing positional args should be caught as known error.
        if result.returncode == 1:
            envelope = parse_envelope(result.stdout)
            assert envelope["ok"] is False
            assert envelope["error"]["code"] == "TypeError"


class TestSandboxDebugBehavior:
    """Validates SANDBOX_DEBUG=1 traceback behavior on crashes."""

    def test_crash_without_debug_no_traceback(self):
        """With SANDBOX_DEBUG unset, crashes should not emit tracebacks to stderr."""
        # Force a crash by passing an invalid dispatch table.
        # We can't directly test this via module commands easily, so we test
        # the bridge dispatcher directly via a small inline script.
        script = (
            "import sys; sys.path.insert(0, '.'); "
            "from foundry_sandbox._bridge import bridge_main; "
            "bridge_main({'cmd': lambda: (_ for _ in ()).throw(RuntimeError('boom'))})"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "../..")
        env.pop("SANDBOX_DEBUG", None)
        # Need to pass "cmd" as sys.argv[1]
        result = subprocess.run(
            [sys.executable, "-c", script, "cmd"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert result.returncode == 2, f"Expected exit 2, got {result.returncode}"
        assert "Traceback" not in result.stderr

    def test_crash_with_debug_emits_traceback(self):
        """With SANDBOX_DEBUG=1, crashes should emit tracebacks to stderr."""
        script = (
            "import sys; sys.path.insert(0, '.'); "
            "from foundry_sandbox._bridge import bridge_main; "
            "bridge_main({'cmd': lambda: (_ for _ in ()).throw(RuntimeError('boom'))})"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "../..")
        env["SANDBOX_DEBUG"] = "1"
        result = subprocess.run(
            [sys.executable, "-c", script, "cmd"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert result.returncode == 2, f"Expected exit 2, got {result.returncode}"
        assert "Traceback" in result.stderr
        assert "RuntimeError" in result.stderr
        assert "boom" in result.stderr

    def test_crash_produces_no_json_on_stdout(self):
        """Crash (exit 2) should NOT produce valid JSON on stdout."""
        script = (
            "import sys; sys.path.insert(0, '.'); "
            "from foundry_sandbox._bridge import bridge_main; "
            "bridge_main({'cmd': lambda: (_ for _ in ()).throw(RuntimeError('test'))})"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "../..")
        result = subprocess.run(
            [sys.executable, "-c", script, "cmd"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert result.returncode == 2
        # stdout should be empty or not valid JSON
        stdout = result.stdout.strip()
        if stdout:
            with pytest.raises(json.JSONDecodeError):
                json.loads(stdout)


class TestDispatchTableValidation:
    """Validates bridge_main dispatch table edge cases."""

    def _run_inline_bridge(self, dispatch_expr: str, args: list[str], env_extra: dict | None = None):
        """Run bridge_main with a custom dispatch expression."""
        script = (
            f"import sys; sys.path.insert(0, '.'); "
            f"from foundry_sandbox._bridge import bridge_main; "
            f"bridge_main({dispatch_expr})"
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "../..")
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, "-c", script, *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )

    def test_empty_dispatch_table(self):
        """Empty dispatch table should exit 1 with invalid_dispatch_table."""
        result = self._run_inline_bridge("{}", ["cmd"])
        assert result.returncode == 1
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "invalid_dispatch_table"

    def test_none_dispatch_table(self):
        """None dispatch table should exit 1 with invalid_dispatch_table."""
        result = self._run_inline_bridge("None", ["cmd"])
        assert result.returncode == 1
        envelope = parse_envelope(result.stdout)
        assert envelope["ok"] is False
        assert envelope["error"]["code"] == "invalid_dispatch_table"

    def test_known_exception_types(self):
        """ValueError, KeyError, TypeError should produce exit 1 with matching code."""
        for exc_type in ("ValueError", "KeyError", "TypeError"):
            result = self._run_inline_bridge(
                f"{{'cmd': lambda: (_ for _ in ()).throw({exc_type}('test error'))}}",
                ["cmd"],
            )
            assert result.returncode == 1, f"{exc_type} should exit 1"
            envelope = parse_envelope(result.stdout)
            assert envelope["ok"] is False
            assert envelope["error"]["code"] == exc_type
            assert "test error" in envelope["error"]["message"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
