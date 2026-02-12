"""Set Claude onboarding flags and defaults in ~/.claude.json.

Sets hasCompletedOnboarding=True, githubRepoPaths={}, projects={},
skillUsage={}, autoUpdates=False, autoCompactEnabled=False in both
~/.claude.json and ~/.claude/.claude.json.

Runs inside the container via: docker exec ... python3 - < this_file
"""

import json
import os

paths = [
    "/home/ubuntu/.claude.json",
    "/home/ubuntu/.claude/.claude.json",
]

for path in paths:
    data = {}
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {}

    if not isinstance(data, dict):
        data = {}

    changed = False
    if data.get("hasCompletedOnboarding") is not True:
        data["hasCompletedOnboarding"] = True
        changed = True
    if data.get("githubRepoPaths") != {}:
        data["githubRepoPaths"] = {}
        changed = True
    if data.get("projects") != {}:
        data["projects"] = {}
        changed = True
    if data.get("skillUsage") != {}:
        data["skillUsage"] = {}
        changed = True
    if data.get("autoUpdates") is not False:
        data["autoUpdates"] = False
        changed = True
    if data.get("autoCompactEnabled") is not False:
        data["autoCompactEnabled"] = False
        changed = True
    if changed or not os.path.exists(path):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        except PermissionError:
            # In some environments (CI, Docker read-only overlays), the
            # secondary path ~/.claude/.claude.json may not be writable.
            # The primary ~/.claude.json is sufficient for Claude to work.
            import sys
            print(f"Warning: cannot write {path} (PermissionError), skipping", file=sys.stderr)
            continue
