"""Import latency gate tests for foundry_sandbox bridge modules.

Ensures that each bridge-callable module can be imported within 300ms,
preventing accidental dependency bloat that would slow shell-to-Python calls.

The CLI --help latency gate is deferred to Phase 4 (CLI entrypoint).
"""

import os
import subprocess
import sys

import pytest

# All bridge-callable modules that shell scripts invoke via python3 -m.
BRIDGE_MODULES = [
    "foundry_sandbox.config",
    "foundry_sandbox.claude_settings",
    "foundry_sandbox.opencode_sync",
]

# Internal modules that are imported transitively.
INTERNAL_MODULES = [
    "foundry_sandbox",
    "foundry_sandbox._bridge",
    "foundry_sandbox.constants",
    "foundry_sandbox.models",
    "foundry_sandbox.paths",
    "foundry_sandbox.utils",
]

IMPORT_BUDGET_MS = 300


def measure_import_ms(module: str) -> float:
    """Measure wall-clock import time for a module via subprocess.

    Uses a fresh Python process to avoid warm-cache effects from prior imports.
    Returns elapsed time in milliseconds.
    """
    script = (
        "import time; "
        "start = time.perf_counter(); "
        f"import {module}; "
        "elapsed = (time.perf_counter() - start) * 1000; "
        "print(f'{elapsed:.2f}')"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(os.path.dirname(__file__), "../..")
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )
    assert result.returncode == 0, (
        f"Failed to import {module}. stderr: {result.stderr}"
    )
    return float(result.stdout.strip())


class TestBridgeModuleImportLatency:
    """Each bridge-callable module must import within the latency budget."""

    @pytest.mark.parametrize("module", BRIDGE_MODULES)
    def test_import_under_budget(self, module):
        """Bridge module {module} must import in <{IMPORT_BUDGET_MS}ms."""
        elapsed = measure_import_ms(module)
        assert elapsed < IMPORT_BUDGET_MS, (
            f"{module} import took {elapsed:.1f}ms, "
            f"exceeds {IMPORT_BUDGET_MS}ms budget"
        )


class TestInternalModuleImportLatency:
    """Internal modules should also be fast to import."""

    @pytest.mark.parametrize("module", INTERNAL_MODULES)
    def test_import_under_budget(self, module):
        """Internal module {module} must import in <{IMPORT_BUDGET_MS}ms."""
        elapsed = measure_import_ms(module)
        assert elapsed < IMPORT_BUDGET_MS, (
            f"{module} import took {elapsed:.1f}ms, "
            f"exceeds {IMPORT_BUDGET_MS}ms budget"
        )


class TestCLILatency:
    """CLI entrypoint latency gate — deferred to Phase 4."""

    @pytest.mark.skip(reason="CLI entrypoint not yet implemented (Phase 4)")
    def test_cli_help_under_budget(self):
        """CLI --help must complete in <500ms (placeholder for Phase 4)."""
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
