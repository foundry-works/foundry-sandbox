"""Set OpenCode autoupdate to off in ~/.config/opencode/opencode.json.

Runs inside the container via: docker exec ... python3 - < this_file
"""

import json
import os

config_path = "/home/ubuntu/.config/opencode/opencode.json"
os.makedirs(os.path.dirname(config_path), exist_ok=True)


def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


data = load_json(config_path)
if not isinstance(data, dict):
    data = {}

changed = False

# Disable autoupdate (can be "on", "off", or "notify")
if data.get("autoupdate") != "off":
    data["autoupdate"] = "off"
    changed = True

if changed or not os.path.exists(config_path):
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
