from __future__ import annotations

from pydantic import BaseModel, Field


class SbxSandboxMetadata(BaseModel):
    """Metadata for an sbx-based sandbox.

    Replaces the docker-compose-based SandboxMetadata. Stores only fields
    relevant to the sbx backend.
    """

    backend: str = "sbx"
    """Backend identifier (always 'sbx')."""

    sbx_name: str
    """Sandbox name as known to sbx CLI."""

    agent: str
    """Agent type: claude, codex, copilot, gemini, kiro, opencode, shell."""

    repo_url: str
    """Repository URL."""

    branch: str
    """Branch name."""

    from_branch: str = ""
    """Source branch for PR creation."""

    network_profile: str = "balanced"
    """Network policy profile: balanced, allow-all, deny-all."""

    git_safety_enabled: bool = True
    """Whether git safety server is active for this sandbox."""

    workspace_dir: str = "/workspace"
    """Workspace mount path inside the sandbox container."""

    working_dir: str = ""
    """Working directory relative path."""

    pip_requirements: str = ""
    """Path to pip requirements file or 'auto'."""

    allow_pr: bool = False
    """Whether to allow PR creation."""

    enable_opencode: bool = False
    """Whether to enable OpenCode."""

    enable_zai: bool = False
    """Whether to enable ZAI."""

    copies: list[str] = Field(default_factory=list)
    """List of copy specifications (host:container)."""

    template: str = ""
    """Template tag used to create the sandbox (empty = no template)."""

    user_services: dict[str, str] = Field(default_factory=dict)
    """Maps env var name to proxy URL for user-defined services."""

    wrapper_checksum: str = ""
    """SHA-256 hex digest of the expected git wrapper script."""

    wrapper_last_verified: str = ""
    """ISO 8601 UTC timestamp of last successful integrity verification."""

    template_managed: bool = False
    """True if the template was created by cast preset save and eligible for auto-cleanup."""

    workspace_path: str = ""
    """Host-side path to the sbx-managed worktree (set after sbx create)."""


class CastNewPreset(BaseModel):
    """Structured representation of cast-new preset arguments."""

    repo: str
    """Repository URL or org/repo shorthand."""

    agent: str = "claude"
    """Agent type."""

    branch: str = ""
    """Target branch name."""

    from_branch: str = ""
    """Base branch for PR creation."""

    working_dir: str = ""
    """Working directory relative path."""

    pip_requirements: str = ""
    """Path to pip requirements file or 'auto'."""

    allow_pr: bool = False
    """Whether to allow PR creation."""

    network_profile: str = "balanced"
    """Network policy profile."""

    enable_opencode: bool = False
    """Whether to enable OpenCode."""

    enable_zai: bool = False
    """Whether to enable ZAI."""

    copies: list[str] = Field(default_factory=list)
    """List of copy specifications (host:container)."""

    template: str = ""
    """Template tag to use when recreating from this preset."""

    template_managed: bool = False
    """True if the template was created by cast preset save and eligible for auto-cleanup."""
