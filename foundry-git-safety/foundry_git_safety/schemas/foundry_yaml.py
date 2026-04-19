"""Pydantic models for foundry.yaml configuration schema."""

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class GitSafetyServerConfig(BaseModel):
    """Git safety server configuration."""

    host: str = "127.0.0.1"
    port: int = 8083
    secrets_path: str = "/run/secrets/sandbox-hmac"
    data_dir: str = "/var/lib/foundry-git-safety"

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v


class ProtectedBranchesConfig(BaseModel):
    """Protected branch enforcement configuration."""

    enabled: bool = True
    patterns: List[str] = Field(default_factory=lambda: [
        "refs/heads/main",
        "refs/heads/master",
        "refs/heads/release/*",
        "refs/heads/production",
    ])


class FileRestrictionsConfig(BaseModel):
    """Push/commit file restrictions configuration."""

    blocked_patterns: List[str] = Field(default_factory=lambda: [
        ".github/workflows/",
        ".github/actions/",
        "Makefile",
        "Justfile",
        "Taskfile.yml",
        ".pre-commit-config.yaml",
        "CODEOWNERS",
        ".github/FUNDING.yml",
        ".env*",
    ])
    warned_patterns: List[str] = Field(default_factory=lambda: [
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "requirements-*.txt",
        "Gemfile",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "docker-compose*.yml",
        "Dockerfile",
    ])
    warn_action: str = "reject"

    @field_validator("warn_action")
    @classmethod
    def validate_warn_action(cls, v: str) -> str:
        if v not in ("log", "reject"):
            raise ValueError(f"warn_action must be 'log' or 'reject', got '{v}'")
        return v


class BranchIsolationConfig(BaseModel):
    """Branch isolation configuration."""

    enabled: bool = True
    well_known_branches: List[str] = Field(default_factory=lambda: [
        "main", "master", "develop", "production",
    ])
    well_known_prefixes: List[str] = Field(default_factory=lambda: [
        "release/", "hotfix/",
    ])


class GitHubAPIConfig(BaseModel):
    """GitHub API filtering configuration."""

    enabled: bool = True
    proxy_port: int = 8084
    allow_pr_operations: bool = False
    allowed_hosts: List[str] = Field(default_factory=lambda: [
        "api.github.com",
        "uploads.github.com",
    ])

    @field_validator("proxy_port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v


class RateLimitsConfig(BaseModel):
    """Rate limiting configuration."""

    burst: int = 300
    sustained: int = 120
    global_ceiling: int = 1000

    @field_validator("burst", "sustained", "global_ceiling")
    @classmethod
    def validate_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"Rate limit must be positive, got {v}")
        return v


class GitSafetyConfig(BaseModel):
    """Top-level git_safety section of foundry.yaml."""

    server: GitSafetyServerConfig = Field(default_factory=GitSafetyServerConfig)
    protected_branches: ProtectedBranchesConfig = Field(
        default_factory=ProtectedBranchesConfig
    )
    file_restrictions: FileRestrictionsConfig = Field(
        default_factory=FileRestrictionsConfig
    )
    branch_isolation: BranchIsolationConfig = Field(
        default_factory=BranchIsolationConfig
    )
    github_api: GitHubAPIConfig = Field(default_factory=GitHubAPIConfig)
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)


class FoundryConfig(BaseModel):
    """Root foundry.yaml configuration."""

    version: str = "1.0"
    git_safety: GitSafetyConfig = Field(default_factory=GitSafetyConfig)
