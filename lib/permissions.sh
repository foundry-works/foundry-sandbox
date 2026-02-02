#!/bin/bash

# Foundry permissions installation for sandbox workspaces

install_workspace_permissions() {
    local container_id="$1"
    log_info "Installing foundry permissions into workspace..."

    docker exec -u "$CONTAINER_USER" -i "$container_id" python3 - <<'PY'
import json
import os

SETTINGS_DIR = os.path.expanduser("~/.claude")
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "settings.json")

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

def merge_permissions(existing, foundry):
    """Merge permissions additively, preserving existing and adding foundry ones."""
    combined = set(existing) | set(foundry)
    return sorted(combined)

def main():
    # Create settings directory if needed
    os.makedirs(SETTINGS_DIR, exist_ok=True)

    # Load existing settings or start with empty dict
    settings = {}
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
        except (json.JSONDecodeError, IOError):
            settings = {}

    # Merge allow permissions
    existing_allow = settings.get("permissions", {}).get("allow", [])
    merged_allow = merge_permissions(existing_allow, FOUNDRY_ALLOW)

    # Merge deny permissions
    existing_deny = settings.get("permissions", {}).get("deny", [])
    merged_deny = merge_permissions(existing_deny, FOUNDRY_DENY)

    # Update settings structure
    if "permissions" not in settings:
        settings["permissions"] = {}
    settings["permissions"]["allow"] = merged_allow
    settings["permissions"]["deny"] = merged_deny

    # Write with proper formatting
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f, indent=2, sort_keys=True)
        f.write('\n')

    print(f"  Installed foundry permissions to {SETTINGS_FILE}")

if __name__ == "__main__":
    main()
PY
}
