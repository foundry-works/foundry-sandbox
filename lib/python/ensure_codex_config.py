"""Configure Codex defaults in ~/.codex/config.toml.

Sets approval_policy="on-failure", sandbox_mode="danger-full-access",
check_for_update_on_startup=false, analytics.enabled=false.
Adds tavily-mcp if SANDBOX_ENABLE_TAVILY=1 (read from environment).

Runs inside the container via: docker exec ... python3 - < this_file
"""

import os
import re

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None

path = "/home/ubuntu/.codex/config.toml"
os.makedirs(os.path.dirname(path), exist_ok=True)

default_approval_policy_line = 'approval_policy = "on-failure"'
default_sandbox_mode_line = 'sandbox_mode = "danger-full-access"'
default_update_line = "check_for_update_on_startup = false"
default_analytics_lines = ["[analytics]", "enabled = false"]
default_tavily_mcp_lines = ["[mcp_servers.tavily-mcp]", 'command = "tavily-mcp"', "args = []"]

# Only include tavily-mcp if Tavily is enabled (API key available on host)
include_tavily = os.environ.get("SANDBOX_ENABLE_TAVILY", "0") == "1"

if not os.path.exists(path):
    with open(path, "w") as f:
        root_lines = [
            default_approval_policy_line,
            default_sandbox_mode_line,
            default_update_line,
        ]
        content = "\n".join(root_lines) + "\n\n" + "\n".join(default_analytics_lines)
        if include_tavily:
            content += "\n\n" + "\n".join(default_tavily_mcp_lines)
        f.write(content + "\n")
    raise SystemExit(0)

with open(path, "r") as f:
    text = f.read()

data = {}
if tomllib is not None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        data = {}

missing_update = "check_for_update_on_startup" not in data
if missing_update:
    if re.search(r"(?m)^\s*check_for_update_on_startup\s*=", text):
        missing_update = False
missing_approval_policy = "approval_policy" not in data
if missing_approval_policy:
    if re.search(r"(?m)^\s*approval_policy\s*=", text):
        missing_approval_policy = False
missing_sandbox_mode = "sandbox_mode" not in data
if missing_sandbox_mode:
    if re.search(r"(?m)^\s*sandbox_mode\s*=", text):
        missing_sandbox_mode = False
analytics = data.get("analytics") if isinstance(data, dict) else None
missing_analytics_enabled = not (isinstance(analytics, dict) and "enabled" in analytics)

# Check if tavily-mcp MCP server is configured (only if API key is available)
mcp_servers = data.get("mcp_servers") if isinstance(data, dict) else None
missing_tavily_mcp = False
if include_tavily:
    missing_tavily_mcp = not (isinstance(mcp_servers, dict) and "tavily-mcp" in mcp_servers)
    if missing_tavily_mcp:
        # Also check raw text for section header
        if re.search(r"(?m)^\s*\[mcp_servers\.tavily-mcp\]", text):
            missing_tavily_mcp = False

inline_changed = False
if missing_analytics_enabled:
    inline_re = re.compile(r"(?m)^(\s*analytics\s*=\s*\{)([^}]*)\}(\s*(#.*)?)$")
    match = inline_re.search(text)
    if match:
        inner = match.group(2)
        if not re.search(r"\benabled\s*=", inner):
            inner_clean = inner.strip()
            if inner_clean:
                new_inner = inner_clean + ", enabled = false"
            else:
                new_inner = "enabled = false"
            new_line = match.group(1) + new_inner + "}" + match.group(3)
            text = text[:match.start()] + new_line + text[match.end():]
            inline_changed = True

prepend_lines = []
append_lines = []

# Root-level settings must be prepended to avoid ending up under a section header
if missing_approval_policy:
    prepend_lines.append(default_approval_policy_line)
if missing_sandbox_mode:
    prepend_lines.append(default_sandbox_mode_line)
if missing_update:
    prepend_lines.append(default_update_line)

if missing_analytics_enabled and not inline_changed:
    append_lines.append("")
    append_lines.extend(default_analytics_lines)

if missing_tavily_mcp:
    append_lines.append("")
    append_lines.extend(default_tavily_mcp_lines)

changed = inline_changed or bool(prepend_lines) or bool(append_lines)
if changed:
    if prepend_lines:
        prepend_text = "\n".join(prepend_lines) + "\n\n"
        text = prepend_text + text
    if append_lines:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "\n".join(append_lines).rstrip() + "\n"
    with open(path, "w") as f:
        f.write(text)
