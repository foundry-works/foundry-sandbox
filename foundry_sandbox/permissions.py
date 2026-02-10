"""Workspace permission management for sandbox containers.

Migrated from lib/permissions.sh. Installs foundry permissions (allow/deny
rules) into the container's ~/.claude/settings.json, merging additively
with any existing permissions.
"""

from __future__ import annotations

import json
import subprocess

from foundry_sandbox.constants import CONTAINER_USER, TIMEOUT_DOCKER_EXEC
from foundry_sandbox.utils import log_debug

# Foundry permissions based on claude-foundry v2.1.0
FOUNDRY_ALLOW = [
    "Skill(foundry:*)",
    "mcp__plugin_foundry_foundry-mcp__*",
    "mcp__tavily-mcp__*",
    "Bash(git add:*)",
    "Bash(git branch:*)",
    "Bash(git checkout:*)",
    "Bash(git clone:*)",
    "Bash(git commit:*)",
    "Bash(git config:*)",
    "Bash(git diff:*)",
    "Bash(git fetch:*)",
    "Bash(git init:*)",
    "Bash(git log:*)",
    "Bash(git ls-files:*)",
    "Bash(git merge:*)",
    "Bash(git mv:*)",
    "Bash(git pull:*)",
    "Bash(git push:*)",
    "Bash(git remote:*)",
    "Bash(git restore:*)",
    "Bash(git rev-parse:*)",
    "Bash(git revert:*)",
    "Bash(git show:*)",
    "Bash(git stash:*)",
    "Bash(git status:*)",
    "Bash(git switch:*)",
    "Bash(git tag:*)",
    "Bash(gh issue create:*)",
    "Bash(gh issue list:*)",
    "Bash(gh issue view:*)",
    "Bash(gh pr checkout:*)",
    "Bash(gh pr create:*)",
    "Bash(gh pr list:*)",
    "Bash(gh pr status:*)",
    "Bash(gh pr view:*)",
    "Bash(gh repo clone:*)",
    "Bash(gh repo view:*)",
    "Bash(pytest:*)",
    "Bash(agent:*)",
    "Bash(claude:*)",
    "Bash(claude-agent:*)",
    "Bash(codex:*)",
    "Bash(gemini:*)",
    "Bash(opencode:*)",
    "Read(/workspace/**)",
    "Write(/workspace/**)",
    "Edit(/workspace/**)",
]

FOUNDRY_DENY = [
    "Read(/workspace/**/specs/**/*.json)",
    "Bash(gh api:*)",
    "Bash(gh repo delete:*)",
    "Bash(gh release delete:*)",
    "Bash(gh secret:*)",
    "Bash(gh variable:*)",
]


# Python script to execute inside the container for permission installation.
# Kept as a string to be piped via docker exec stdin.
_INSTALL_SCRIPT = '''
import json
import os

SETTINGS_DIR = os.path.expanduser("~/.claude")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

FOUNDRY_ALLOW = {allow_json}
FOUNDRY_DENY = {deny_json}

def merge_permissions(existing, foundry):
    combined = set(existing) | set(foundry)
    return sorted(combined)

def main():
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    settings = {{}}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
        except (json.JSONDecodeError, IOError):
            settings = {{}}

    existing_allow = settings.get("permissions", {{}}).get("allow", [])
    merged_allow = merge_permissions(existing_allow, FOUNDRY_ALLOW)

    existing_deny = settings.get("permissions", {{}}).get("deny", [])
    merged_deny = merge_permissions(existing_deny, FOUNDRY_DENY)

    if "permissions" not in settings:
        settings["permissions"] = {{}}
    settings["permissions"]["allow"] = merged_allow
    settings["permissions"]["deny"] = merged_deny

    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2, sort_keys=True)
        f.write('\\n')

if __name__ == "__main__":
    main()
'''


def install_workspace_permissions(container_id: str) -> None:
    """Install foundry permissions into container's Claude settings.

    Executes a Python script inside the container that merges foundry
    allow/deny permissions with any existing permissions in
    ~/.claude/settings.json.

    Args:
        container_id: Docker container ID or name.
    """
    log_debug("Installing foundry permissions into workspace...")

    script = _INSTALL_SCRIPT.format(
        allow_json=json.dumps(FOUNDRY_ALLOW),
        deny_json=json.dumps(FOUNDRY_DENY),
    )

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-"],
        input=script,
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )
    if result.returncode != 0:
        from foundry_sandbox.utils import log_error
        log_error(
            f"Failed to install workspace permissions (exit {result.returncode}): "
            f"{result.stderr.strip() if result.stderr else 'unknown error'}"
        )
        raise RuntimeError(f"Permission installation failed in container {container_id}")
