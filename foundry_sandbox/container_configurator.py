"""Container configuration orchestrator with dependency injection.

Provides ContainerConfigurator class that makes the call graph from
copy_configs_to_container explicit and testable. Dependencies are
constructor-injected for testing, auto-imported for production use.
"""
from __future__ import annotations

from types import ModuleType


class ContainerConfigurator:
    """Orchestrates container configuration with injectable dependencies.

    Makes the call graph from copy_configs_to_container explicit and testable.
    Each dependency module is injected via constructor, enabling unit tests to
    verify call sequence and mock individual modules.
    """

    def __init__(
        self,
        container_setup: ModuleType | None = None,
        foundry_plugin: ModuleType | None = None,
        stub_manager: ModuleType | None = None,
        git_path_fixer: ModuleType | None = None,
        credential_setup: ModuleType | None = None,
        tool_configs: ModuleType | None = None,
        container_io: ModuleType | None = None,
    ) -> None:
        """Accept all 7 module dependencies.

        If any dependency is None, import the real module lazily.
        This allows both production use (auto-import) and testing (mock injection).

        Args:
            container_setup: Module for container setup operations
            foundry_plugin: Module for Foundry MCP plugin setup
            stub_manager: Module for stub file management
            git_path_fixer: Module for Git safe.directory configuration
            credential_setup: Module for credential configuration
            tool_configs: Module for tool configuration
            container_io: Module for container I/O operations
        """
        self._container_setup = container_setup
        self._foundry_plugin = foundry_plugin
        self._stub_manager = stub_manager
        self._git_path_fixer = git_path_fixer
        self._credential_setup = credential_setup
        self._tool_configs = tool_configs
        self._container_io = container_io

    @property
    def container_setup(self) -> ModuleType:
        """Lazy-load container_setup module if not injected."""
        if self._container_setup is None:
            import foundry_sandbox.container_setup as container_setup
            self._container_setup = container_setup
        return self._container_setup

    @property
    def foundry_plugin(self) -> ModuleType:
        """Lazy-load foundry_plugin module if not injected."""
        if self._foundry_plugin is None:
            import foundry_sandbox.foundry_plugin as foundry_plugin
            self._foundry_plugin = foundry_plugin
        return self._foundry_plugin

    @property
    def stub_manager(self) -> ModuleType:
        """Lazy-load stub_manager module if not injected."""
        if self._stub_manager is None:
            import foundry_sandbox.stub_manager as stub_manager
            self._stub_manager = stub_manager
        return self._stub_manager

    @property
    def git_path_fixer(self) -> ModuleType:
        """Lazy-load git_path_fixer module if not injected."""
        if self._git_path_fixer is None:
            import foundry_sandbox.git_path_fixer as git_path_fixer
            self._git_path_fixer = git_path_fixer
        return self._git_path_fixer

    @property
    def credential_setup(self) -> ModuleType:
        """Lazy-load credential_setup module if not injected."""
        if self._credential_setup is None:
            import foundry_sandbox.credential_setup as credential_setup
            self._credential_setup = credential_setup
        return self._credential_setup

    @property
    def tool_configs(self) -> ModuleType:
        """Lazy-load tool_configs module if not injected."""
        if self._tool_configs is None:
            import foundry_sandbox.tool_configs as tool_configs
            self._tool_configs = tool_configs
        return self._tool_configs

    @property
    def container_io(self) -> ModuleType:
        """Lazy-load container_io module if not injected."""
        if self._container_io is None:
            import foundry_sandbox.container_io as container_io
            self._container_io = container_io
        return self._container_io

    def configure(
        self,
        container_id: str,
        *,
        skip_plugins: bool = False,
        enable_ssh: bool = False,
        working_dir: str = "",
        isolate_credentials: bool = False,
        from_branch: str = "",
        branch: str = "",
        repo_url: str = "",
    ) -> None:
        """Run full container configuration sequence.

        Delegates to credential_setup.copy_configs_to_container with all args.

        Args:
            container_id: ID of the container to configure
            skip_plugins: If True, skip Foundry plugin installation
            enable_ssh: If True, enable SSH agent forwarding
            working_dir: Working directory path in container
            isolate_credentials: If True, isolate credentials from host
            from_branch: Source branch for Git operations
            branch: Target branch for Git operations
            repo_url: Repository URL for Git operations
        """
        self.credential_setup.copy_configs_to_container(
            container_id,
            skip_plugins=skip_plugins,
            enable_ssh=enable_ssh,
            working_dir=working_dir,
            isolate_credentials=isolate_credentials,
            from_branch=from_branch,
            branch=branch,
            repo_url=repo_url,
        )

    def sync_credentials(self, container_id: str) -> None:
        """Sync runtime credentials on attach.

        Delegates to credential_setup.sync_runtime_credentials.

        Args:
            container_id: ID of the container to sync credentials for
        """
        self.credential_setup.sync_runtime_credentials(container_id)


def create_configurator(**overrides: ModuleType | None) -> ContainerConfigurator:
    """Create a ContainerConfigurator with default dependencies.

    Accepts keyword overrides for any dependency module.

    Args:
        **overrides: Keyword arguments to override default dependencies.
            Valid keys: container_setup, foundry_plugin, stub_manager,
            git_path_fixer, credential_setup, tool_configs, container_io

    Returns:
        ContainerConfigurator instance with specified or default dependencies
    """
    return ContainerConfigurator(**overrides)
