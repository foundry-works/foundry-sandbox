"""
GitHub API Configuration - Single source of truth for GitHub API hosts

This module consolidates GitHub-related configuration to ensure consistency
between:
- github-api-filter.py: Operation filtering (what GitHub API endpoints are allowed)
- inject-credentials.py: Credential injection (must have matching PROVIDER_MAP entries)
- gateway/allowlist.conf: Egress filtering (must include these hosts)

When adding new GitHub API hosts:
1. Add to GITHUB_API_HOSTS below
2. Add to PROVIDER_MAP in inject-credentials.py (for credential injection)
3. Add to gateway/allowlist.conf (for egress filtering)
4. Regenerate firewall-allowlist.generated: cd gateway && ./build-configs.sh
"""

# GitHub API hosts that receive credential injection and operation filtering
# - api.github.com: Main API endpoint (REST + GraphQL)
# - uploads.github.com: Release asset uploads
GITHUB_API_HOSTS = [
    "api.github.com",
    "uploads.github.com",
]
