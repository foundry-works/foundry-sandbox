from __future__ import annotations

from pydantic import BaseModel, Field


class SandboxMetadata(BaseModel):
    """Pydantic model for sandbox metadata.

    Matches the structure of metadata.json files used in sandbox configurations.
    All fields validate on construction using Pydantic V2.
    """

    repo_url: str
    """Repository URL (required)."""

    branch: str
    """Branch name (required)."""

    from_branch: str = ""
    """Source branch for PR creation."""

    network_mode: str = "limited"
    """Network mode: limited, host-only, or none."""

    sync_ssh: int = 0
    """Whether to sync SSH credentials (0 or 1)."""

    ssh_mode: str = "always"
    """SSH mode: always or disabled."""

    working_dir: str = ""
    """Working directory relative path."""

    sparse_checkout: bool = False
    """Whether to use sparse checkout."""

    pip_requirements: str = ""
    """Path to pip requirements file or 'auto'."""

    allow_pr: bool = False
    """Whether to allow PR creation."""

    enable_opencode: bool = False
    """Whether to enable OpenCode."""

    enable_zai: bool = False
    """Whether to enable ZAI."""

    mounts: list[str] = Field(default_factory=list)
    """List of mount specifications (host:container[:ro])."""

    copies: list[str] = Field(default_factory=list)
    """List of copy specifications (host:container)."""
