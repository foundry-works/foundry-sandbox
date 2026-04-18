"""Set default model in OpenCode config if not already set.

Reads SANDBOX_OPENCODE_DEFAULT_MODEL from environment.

Runs inside the container via: docker exec ... python3 - < this_file
"""

import json
import os

config_path = "/home/ubuntu/.config/opencode/opencode.json"
default_model = os.environ.get("SANDBOX_OPENCODE_DEFAULT_MODEL", "").strip()
if not default_model:
    raise SystemExit(0)


def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


data = load_json(config_path)
if not isinstance(data, dict):
    data = {}

model = data.get("model")
if not model:
    data["model"] = default_model
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
