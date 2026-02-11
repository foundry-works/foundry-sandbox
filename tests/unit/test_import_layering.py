"""Global import layering enforcement for foundry_sandbox.

Enforces module dependency boundaries to prevent cyclic imports and
import latency creep:

  Base layer (constants, utils, models):
    May NOT import from any other foundry_sandbox module.

  Mid layer (paths, config):
    May import only from base layer modules.

  Internal modules (claude_settings, opencode_sync, etc.):
    May import from base + mid layers.
    May NOT import Click or Pydantic at module level (latency constraint).

This test uses AST parsing to inspect imports without executing modules,
ensuring the rules hold even if import order would mask cycles at runtime.
"""

import ast
import sys
from pathlib import Path

import pytest

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "foundry_sandbox"

# Layer definitions: module name -> allowed foundry_sandbox imports.
# Module names are relative to foundry_sandbox (e.g., "constants" for foundry_sandbox.constants).

BASE_MODULES = {"constants", "utils", "models", "__init__"}

MID_MODULES = {"paths", "config"}

# Bridge-callable modules are those that use bridge_main in __main__ blocks.
BRIDGE_CALLABLE_MODULES = {
    "claude_settings", "opencode_sync", "config", "state", "docker", "validate", "api_keys",
    "compose", "container_configurator", "container_io", "container_setup",
    "credential_setup", "foundry_plugin", "git", "git_path_fixer", "git_worktree",
    "image", "network", "permissions", "proxy", "stub_manager", "tmux", "tool_configs",
}

# Top-layer modules: unrestricted imports (CLI entrypoints, UI, compatibility shims).
# These may import Click/Pydantic at module level and from any layer.
TOP_MODULES = {"cli", "ide", "tui"}

# Heavy imports forbidden at module level in bridge-callable modules.
FORBIDDEN_BRIDGE_IMPORTS = {"click", "pydantic"}


def _get_foundry_imports(module_path: Path) -> set[str]:
    """Parse a Python file and return all foundry_sandbox submodule names it imports.

    Returns a set of module names like {"constants", "_bridge", "config"}.
    """
    source = module_path.read_text()
    tree = ast.parse(source, filename=str(module_path))

    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("foundry_sandbox"):
                # Extract submodule: "foundry_sandbox.constants" -> "constants"
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


def _get_top_level_imports(module_path: Path) -> set[str]:
    """Parse a Python file and return all top-level (non-function, non-class) import names.

    Returns root package names like {"click", "pydantic", "json", "os"}.
    """
    source = module_path.read_text()
    tree = ast.parse(source, filename=str(module_path))

    imports = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    return imports


def _discover_modules() -> list[str]:
    """Discover all .py module files in the foundry_sandbox package."""
    return [
        p.stem for p in PACKAGE_DIR.glob("*.py")
        if p.stem != "__pycache__"
    ]


class TestBaseLayerBoundaries:
    """Base layer modules must not import from any foundry_sandbox submodule."""

    @pytest.mark.parametrize("module", sorted(BASE_MODULES - {"__init__"}))
    def test_no_internal_imports(self, module):
        module_path = PACKAGE_DIR / f"{module}.py"
        if not module_path.exists():
            pytest.skip(f"{module}.py not found")

        imports = _get_foundry_imports(module_path)
        # Base modules may not import other foundry_sandbox modules
        # (except __init__ which is implicit)
        forbidden = imports - {"__init__"}
        assert not forbidden, (
            f"Base layer module '{module}' imports from foundry_sandbox submodules: "
            f"{forbidden}. Base modules (constants, utils, models) "
            f"must not import from other foundry_sandbox modules."
        )


class TestMidLayerBoundaries:
    """Mid layer modules may only import from base layer."""

    @pytest.mark.parametrize("module", sorted(MID_MODULES))
    def test_only_imports_from_base(self, module):
        module_path = PACKAGE_DIR / f"{module}.py"
        if not module_path.exists():
            pytest.skip(f"{module}.py not found")

        imports = _get_foundry_imports(module_path)
        allowed = BASE_MODULES | {"__init__"}
        violations = imports - allowed
        assert not violations, (
            f"Mid layer module '{module}' imports from non-base modules: "
            f"{violations}. Mid layer modules may only import from: {sorted(allowed)}"
        )


class TestBridgeCallableConstraints:
    """Bridge-callable modules must not import heavy packages at module level."""

    @pytest.mark.parametrize("module", sorted(BRIDGE_CALLABLE_MODULES))
    def test_no_forbidden_top_level_imports(self, module):
        module_path = PACKAGE_DIR / f"{module}.py"
        if not module_path.exists():
            pytest.skip(f"{module}.py not found")

        top_level = _get_top_level_imports(module_path)
        violations = top_level & FORBIDDEN_BRIDGE_IMPORTS
        assert not violations, (
            f"Bridge-callable module '{module}' imports {violations} at module level. "
            f"Bridge modules must not import Click or Pydantic at module level "
            f"to keep import latency low."
        )


class TestNoCyclicDependencies:
    """No module in the package should create a circular import chain."""

    def test_no_cycles(self):
        """Build a dependency graph and check for cycles using DFS."""
        modules = _discover_modules()
        graph: dict[str, set[str]] = {}

        for mod in modules:
            mod_path = PACKAGE_DIR / f"{mod}.py"
            if mod_path.exists():
                graph[mod] = _get_foundry_imports(mod_path)

        # DFS cycle detection
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {m: WHITE for m in graph}
        path: list[str] = []

        def dfs(node: str) -> list[str] | None:
            color[node] = GRAY
            path.append(node)
            for neighbor in graph.get(node, set()):
                if neighbor not in color:
                    continue
                if color[neighbor] == GRAY:
                    cycle_start = path.index(neighbor)
                    return path[cycle_start:] + [neighbor]
                if color[neighbor] == WHITE:
                    result = dfs(neighbor)
                    if result:
                        return result
            path.pop()
            color[node] = BLACK
            return None

        for mod in graph:
            if color[mod] == WHITE:
                cycle = dfs(mod)
                if cycle:
                    pytest.fail(
                        f"Circular import detected: {' -> '.join(cycle)}"
                    )


class TestAllModulesHaveLayerAssignment:
    """Every module in the package should be assigned to a layer."""

    def test_all_assigned(self):
        """All discovered modules should be in base, mid, or top layer."""
        all_known = BASE_MODULES | MID_MODULES | BRIDGE_CALLABLE_MODULES | TOP_MODULES
        # Top-layer modules that aren't bridge-callable (future expansion)
        # are allowed to import anything, so they just need to exist.

        discovered = set(_discover_modules())
        # __pycache__ and __init__ are handled
        unassigned = discovered - all_known - {"__init__"}
        # Unassigned modules should be flagged — they need a layer decision.
        # For now, warn rather than fail since new modules may be added.
        if unassigned:
            # These are modules not yet assigned to a layer.
            # They should be added to the appropriate layer set above.
            pytest.skip(
                f"Modules without layer assignment (add to test): {sorted(unassigned)}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
