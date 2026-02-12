"""Add tavily-mcp to OpenCode's MCP configuration.

Runs inside the container via: docker exec ... python3 - < this_file
"""

import json
import os

config_path = "/home/ubuntu/.config/opencode/opencode.json"


def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


data = load_json(config_path)
if not isinstance(data, dict):
    data = {}

# Ensure mcp section exists and is a dict
mcp = data.get("mcp")
if not isinstance(mcp, dict):
    mcp = {}
    data["mcp"] = mcp

# Add tavily-mcp if not already configured
if "tavily-mcp" not in mcp:
    mcp["tavily-mcp"] = {
        "command": ["tavily-mcp"]
    }

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
