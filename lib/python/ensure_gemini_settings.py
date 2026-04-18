"""Configure Gemini defaults in ~/.gemini/settings.json.

Sets general.disableAutoUpdate=true, general.disableUpdateNag=true,
general.previewFeatures=true, telemetry.enabled=false,
privacy.usageStatisticsEnabled=false.
Adds tavily-mcp to mcpServers if SANDBOX_ENABLE_TAVILY=1 (read from environment).

Runs inside the container via: docker exec ... python3 - < this_file
"""

import json
import os

path = "/home/ubuntu/.gemini/settings.json"
os.makedirs(os.path.dirname(path), exist_ok=True)

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

general = data.get("general")
if not isinstance(general, dict):
    general = {}
if "disableAutoUpdate" not in general:
    general["disableAutoUpdate"] = True
    changed = True
if "disableUpdateNag" not in general:
    general["disableUpdateNag"] = True
    changed = True
if "previewFeatures" not in general:
    general["previewFeatures"] = True
    changed = True
if general:
    data["general"] = general

telemetry = data.get("telemetry")
if not isinstance(telemetry, dict):
    telemetry = {}
if "enabled" not in telemetry:
    telemetry["enabled"] = False
    changed = True
if telemetry:
    data["telemetry"] = telemetry

privacy = data.get("privacy")
if not isinstance(privacy, dict):
    privacy = {}
if "usageStatisticsEnabled" not in privacy:
    privacy["usageStatisticsEnabled"] = False
    changed = True
if privacy:
    data["privacy"] = privacy

# Add tavily-mcp to mcpServers (only if Tavily is enabled - API key on host)
enable_tavily = os.environ.get("SANDBOX_ENABLE_TAVILY", "0") == "1"
if enable_tavily:
    mcp_servers = data.get("mcpServers")
    if not isinstance(mcp_servers, dict):
        mcp_servers = {}
    if "tavily-mcp" not in mcp_servers:
        mcp_servers["tavily-mcp"] = {
            "command": "tavily-mcp",
            "args": []
        }
        changed = True
    if mcp_servers:
        data["mcpServers"] = mcp_servers

if changed or not os.path.exists(path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
