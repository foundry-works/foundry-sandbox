"""Configure or remove claude-statusline in Claude settings.json.

Expects _ACTION variable to be set before this script is executed:
  _ACTION = "set"    -> set statusLine to use bundled binary
  _ACTION = "remove" -> remove statusLine from settings

Runs inside the container via: docker exec ... python3 - < this_file
(with _ACTION prepended by the caller)
"""

import json
import os

path = "/home/ubuntu/.claude/settings.json"

if _ACTION == "set":  # noqa: F821 - injected by caller
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}
    else:
        data = {}

    # Always set to bundled binary (replaces any network-dependent commands like npx)
    data["statusLine"] = {
        "type": "command",
        "command": "claude-statusline",
        "padding": 0
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

elif _ACTION == "remove":  # noqa: F821 - injected by caller
    if not os.path.exists(path):
        raise SystemExit(0)

    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        data = {}

    if "statusLine" in data:
        data.pop("statusLine", None)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
