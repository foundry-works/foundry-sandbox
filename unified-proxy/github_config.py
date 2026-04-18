"""
GitHub API Configuration - Single source of truth for GitHub API hosts

This module consolidates GitHub-related configuration to ensure consistency
between:
- github-api-filter.py: Operation filtering (what GitHub API endpoints are allowed)
- addons/credential_injector.py: Credential injection (must have matching PROVIDER_MAP entries)
- config/allowlist.yaml: Egress filtering (must include these hosts)

When adding new GitHub API hosts:
1. Add to GITHUB_API_HOSTS below
2. Add to PROVIDER_MAP in addons/credential_injector.py (for credential injection)
3. Add to config/allowlist.yaml (for egress filtering)
"""

# GitHub API hosts that receive credential injection and operation filtering
# - api.github.com: Main API endpoint (REST + GraphQL)
# - uploads.github.com: Release asset uploads
GITHUB_API_HOSTS = [
    "api.github.com",
    "uploads.github.com",
]
