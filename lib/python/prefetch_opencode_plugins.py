"""Prefetch OpenCode npm plugins inside container.

Reads plugin list from ~/.config/opencode/opencode.json, generates a
package.json in ~/.cache/opencode, and runs bun/npm install.

Runs inside the container via: docker exec ... python3 - < this_file
"""

import json
import os
import shutil
import subprocess
import sys

config_path = "/home/ubuntu/.config/opencode/opencode.json"
cache_dir = "/home/ubuntu/.cache/opencode"


def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def is_local_plugin(plugin):
    if isinstance(plugin, str):
        return plugin.startswith(("/", "./", "../", "~/"))
    if isinstance(plugin, dict):
        path = plugin.get("path") or plugin.get("file") or plugin.get("src")
        if isinstance(path, str):
            return path.startswith(("/", "./", "../", "~/"))
    return False


def plugin_spec(plugin):
    if isinstance(plugin, str):
        return plugin
    if isinstance(plugin, dict):
        for key in ("name", "package", "npm", "module"):
            value = plugin.get(key)
            if isinstance(value, str):
                version = plugin.get("version")
                if isinstance(version, str) and version:
                    return f"{value}@{version}"
                return value
    return None


def split_spec(spec):
    if spec.startswith("@"):
        if "@" in spec[1:]:
            name, _, version = spec.rpartition("@")
            return name, version
        return spec, ""
    if "@" in spec:
        name, version = spec.split("@", 1)
        return name, version
    return spec, ""


config = load_json(config_path)
plugins = config.get("plugin")
if not isinstance(plugins, list):
    raise SystemExit(0)

deps = {}
for plugin in plugins:
    if is_local_plugin(plugin):
        continue
    spec = plugin_spec(plugin)
    if not spec:
        continue
    name, version = split_spec(spec)
    if not name:
        continue
    deps[name] = version or "latest"

if not deps:
    raise SystemExit(0)

os.makedirs(cache_dir, exist_ok=True)
pkg_path = os.path.join(cache_dir, "package.json")
existing = load_json(pkg_path)
existing_deps = existing.get("dependencies") if isinstance(existing, dict) else {}
if not isinstance(existing_deps, dict):
    existing_deps = {}

changed = False
for name, version in deps.items():
    if existing_deps.get(name) != version:
        existing_deps[name] = version
        changed = True

if changed or not os.path.exists(pkg_path):
    with open(pkg_path, "w") as f:
        json.dump({"dependencies": existing_deps}, f, indent=2)
        f.write("\n")

node_modules = os.path.join(cache_dir, "node_modules")
all_installed = True
for name in deps:
    parts = name.split("/")
    path = os.path.join(node_modules, *parts)
    if not os.path.isdir(path):
        all_installed = False
        break

if all_installed:
    raise SystemExit(0)

installer = None
if shutil.which("bun"):
    installer = ["bun", "install"]
elif shutil.which("npm"):
    installer = ["npm", "install", "--no-fund", "--no-audit"]

if not installer:
    print("OpenCode plugin prefetch skipped: bun/npm not available", file=sys.stderr)
    raise SystemExit(0)

try:
    subprocess.check_call(installer, cwd=cache_dir)
except Exception as exc:
    print(f"OpenCode plugin prefetch failed: {exc}", file=sys.stderr)
    sys.exit(1)
