"""Verify no cyclic imports between Phase 5 modules.

Ensures that credential_setup.py, tool_configs.py, and container_io.py can
all be imported without circular import errors, and that container_io.py
remains a leaf dependency (imports only from base layer).

Complements test_import_layering.py (AST-based global cycle detection) with
runtime import verification and Phase 5-specific dependency constraints.
"""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "foundry_sandbox"

PHASE5_MODULES = [
    "container_io",
    "tool_configs",
    "credential_setup",
]

# container_io.py is a leaf: it may only import from these base-layer modules.
CONTAINER_IO_ALLOWED_IMPORTS = {"constants", "utils", "_bridge", "__init__"}


def _get_foundry_imports(module_path: Path) -> set[str]:
    """Parse a Python file and return all foundry_sandbox submodule names it imports.

    Inspects both top-level and nested (lazy) imports.
    """
    source = module_path.read_text()
    tree = ast.parse(source, filename=str(module_path))

    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("foundry_sandbox"):
                parts = node.module.split(".")
                if len(parts) >= 2:
                    imports.add(parts[1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("foundry_sandbox."):
                    parts = alias.name.split(".")
                    if len(parts) >= 2:
                        imports.add(parts[1])
    return imports


class TestPhase5RuntimeImports:
    """All Phase 5 modules must be importable without errors."""

    @pytest.mark.parametrize("module", PHASE5_MODULES)
    def test_module_importable(self, module):
        """Import each Phase 5 module in a subprocess to detect circular import errors."""
        result = subprocess.run(
            [sys.executable, "-c", f"import foundry_sandbox.{module}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Failed to import foundry_sandbox.{module}:\n"
            f"stderr: {result.stderr}"
        )


class TestContainerIOLeafDependency:
    """container_io.py must only import from base-layer modules."""

    def test_container_io_imports_only_base(self):
        module_path = PACKAGE_DIR / "container_io.py"
        if not module_path.exists():
            pytest.skip("container_io.py not found")

        imports = _get_foundry_imports(module_path)
        violations = imports - CONTAINER_IO_ALLOWED_IMPORTS
        assert not violations, (
            f"container_io.py imports non-base foundry_sandbox modules: {sorted(violations)}. "
            f"container_io.py is a leaf dependency and may only import from: "
            f"{sorted(CONTAINER_IO_ALLOWED_IMPORTS)}"
        )

    def test_container_io_not_imported_by_tool_configs(self):
        """tool_configs.py should not import container_io (keeps them independent)."""
        module_path = PACKAGE_DIR / "tool_configs.py"
        if not module_path.exists():
            pytest.skip("tool_configs.py not found")

        imports = _get_foundry_imports(module_path)
        assert "container_io" not in imports, (
            "tool_configs.py imports container_io. These should remain independent "
            "siblings — both are leaf dependencies used by credential_setup.py."
        )


class TestCredentialSetupPeerImports:
    """credential_setup.py must import peer modules without cycles."""

    def test_credential_setup_imports_container_io(self):
        """credential_setup.py declares a top-level import of container_io."""
        module_path = PACKAGE_DIR / "credential_setup.py"
        if not module_path.exists():
            pytest.skip("credential_setup.py not found")

        imports = _get_foundry_imports(module_path)
        assert "container_io" in imports, (
            "credential_setup.py should import container_io (I/O primitives)"
        )

    def test_credential_setup_imports_tool_configs(self):
        """credential_setup.py declares a (lazy) import of tool_configs."""
        module_path = PACKAGE_DIR / "credential_setup.py"
        if not module_path.exists():
            pytest.skip("credential_setup.py not found")

        imports = _get_foundry_imports(module_path)
        assert "tool_configs" in imports, (
            "credential_setup.py should import tool_configs (tool configuration)"
        )

    def test_no_reverse_dependency_from_container_io(self):
        """container_io must NOT import credential_setup (would create cycle)."""
        module_path = PACKAGE_DIR / "container_io.py"
        if not module_path.exists():
            pytest.skip("container_io.py not found")

        imports = _get_foundry_imports(module_path)
        assert "credential_setup" not in imports, (
            "container_io.py imports credential_setup — this creates a circular dependency. "
            "container_io.py is a leaf and must not import from credential_setup."
        )

    def test_no_reverse_dependency_from_tool_configs(self):
        """tool_configs must NOT import credential_setup (would create cycle)."""
        module_path = PACKAGE_DIR / "tool_configs.py"
        if not module_path.exists():
            pytest.skip("tool_configs.py not found")

        imports = _get_foundry_imports(module_path)
        assert "credential_setup" not in imports, (
            "tool_configs.py imports credential_setup — this creates a circular dependency. "
            "tool_configs.py must not import from credential_setup."
        )


class TestImportOrderIndependence:
    """Importing Phase 5 modules in any order must succeed."""

    def test_container_io_then_credential_setup(self):
        """Import container_io before credential_setup in a subprocess."""
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import foundry_sandbox.container_io; import foundry_sandbox.credential_setup",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Failed importing container_io then credential_setup:\n"
            f"stderr: {result.stderr}"
        )

    def test_credential_setup_then_container_io(self):
        """Import credential_setup before container_io in a subprocess."""
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import foundry_sandbox.credential_setup; import foundry_sandbox.container_io",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Failed importing credential_setup then container_io:\n"
            f"stderr: {result.stderr}"
        )

    def test_tool_configs_then_credential_setup(self):
        """Import tool_configs before credential_setup in a subprocess."""
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import foundry_sandbox.tool_configs; import foundry_sandbox.credential_setup",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Failed importing tool_configs then credential_setup:\n"
            f"stderr: {result.stderr}"
        )

    def test_all_phase5_modules_together(self):
        """Import all three Phase 5 modules in a single subprocess."""
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import foundry_sandbox.container_io; "
                "import foundry_sandbox.tool_configs; "
                "import foundry_sandbox.credential_setup",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Failed importing all Phase 5 modules together:\n"
            f"stderr: {result.stderr}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
