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


class CastNewPreset(BaseModel):
    """Structured representation of cast-new preset arguments.

    Replaces the raw dict used in state.py for preset persistence.
    """

    repo: str
    """Repository URL or org/repo shorthand."""

    branch: str = ""
    """Target branch name."""

    from_branch: str = ""
    """Base branch for PR creation."""

    working_dir: str = ""
    """Working directory relative path."""

    sparse: bool = False
    """Whether to use sparse checkout."""

    pip_requirements: str = ""
    """Path to pip requirements file or 'auto'."""

    allow_pr: bool = False
    """Whether to allow PR creation."""

    network_mode: str = "limited"
    """Network mode: limited, host-only, or none."""

    sync_ssh: bool = False
    """Whether to sync SSH credentials."""

    enable_opencode: bool = False
    """Whether to enable OpenCode."""

    enable_zai: bool = False
    """Whether to enable ZAI."""

    mounts: list[str] = Field(default_factory=list)
    """List of mount specifications (host:container[:ro])."""

    copies: list[str] = Field(default_factory=list)
    """List of copy specifications (host:container)."""


class ProxyRegistration(BaseModel):
    """Metadata passed to proxy registration API.

    Built in new_setup.py and start.py, consumed by proxy.setup_proxy_registration().
    """

    repo: str = ""
    """Repository spec (org/repo format)."""

    allow_pr: bool = False
    """Whether PR operations are allowed."""

    sandbox_branch: str = ""
    """Branch checked out in the sandbox."""

    from_branch: str = ""
    """Base branch for PR creation."""


class CredentialPlaceholders(BaseModel):
    """Credential placeholder env vars for sandbox credential isolation.

    Returned by docker.setup_credential_placeholders(), consumed by compose_up().
    """

    sandbox_anthropic_api_key: str = ""
    """Placeholder or empty for Anthropic API key."""

    sandbox_claude_oauth: str = ""
    """Placeholder or empty for Claude OAuth token."""

    sandbox_gemini_api_key: str = ""
    """Placeholder or empty for Gemini API key."""

    sandbox_zhipu_api_key: str = ""
    """Placeholder or empty for Zhipu API key."""

    sandbox_enable_tavily: str = "0"
    """Whether Tavily is enabled ('0' or '1')."""

    def to_env_dict(self) -> dict[str, str]:
        """Convert to uppercase env var dict for backward compatibility with compose_up()."""
        return {
            "SANDBOX_ANTHROPIC_API_KEY": self.sandbox_anthropic_api_key,
            "SANDBOX_CLAUDE_OAUTH": self.sandbox_claude_oauth,
            "SANDBOX_GEMINI_API_KEY": self.sandbox_gemini_api_key,
            "SANDBOX_ZHIPU_API_KEY": self.sandbox_zhipu_api_key,
            "SANDBOX_ENABLE_TAVILY": self.sandbox_enable_tavily,
        }
