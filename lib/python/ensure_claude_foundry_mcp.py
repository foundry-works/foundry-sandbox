"""Configure Claude settings with Foundry MCP permissions and hooks.

Extracted from lib/container_config.sh ensure_claude_foundry_mcp() function.
Sets model defaults, hooks configuration, and Foundry permission allowlists.

Usage:
    python3 ensure_claude_foundry_mcp.py [settings_path]
    Default settings_path: /home/ubuntu/.claude/settings.json
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from json_config import load_json, write_json


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

DEFAULT_HOOKS = {
    "PreToolUse": [
        {
            "matcher": "Read",
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/block-json-specs"}]
        },
        {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/block-spec-bash-access"}]
        }
    ],
    "PostToolUse": [
        {
            "hooks": [{"type": "command", "command": "/home/ubuntu/.claude/hooks/context-monitor"}]
        }
    ]
}


def ensure_claude_foundry_mcp(path: str) -> None:
    """Configure Claude settings with Foundry defaults and permissions.

    Args:
        path: Path to Claude settings.json.
    """
    data = load_json(path)

    # Force model settings
    data["model"] = "opus"
    data["subagentModel"] = "haiku"
    data["alwaysThinkingEnabled"] = True

    # Configure hooks
    data["hooks"] = DEFAULT_HOOKS

    # Merge permissions
    if "permissions" not in data:
        data["permissions"] = {}
    existing_allow = set(data["permissions"].get("allow", []))
    existing_deny = set(data["permissions"].get("deny", []))
    data["permissions"]["allow"] = sorted(existing_allow | set(FOUNDRY_ALLOW))
    data["permissions"]["deny"] = sorted(existing_deny | set(FOUNDRY_DENY))

    # Remove foundry plugin from enabledPlugins
    if "enabledPlugins" in data:
        data["enabledPlugins"].pop("foundry@claude-foundry", None)
        if not data["enabledPlugins"]:
            del data["enabledPlugins"]

    write_json(path, data)


if __name__ == "__main__":
    settings_path = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/.claude/settings.json"
    ensure_claude_foundry_mcp(settings_path)
