"""User-configurable skills system for sandbox containers.

Skills are defined in ~/.sandboxes/skills.toml and selected per-sandbox
via ``cast new --skill <name>``. Each skill can provide:
  - A host directory to mount into the container
  - An MCP server registration
  - Permission allow/deny rules
  - Stub files to append to /workspace/
  - Environment variables
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

from foundry_sandbox.constants import CONTAINER_HOME, CONTAINER_USER, TIMEOUT_DOCKER_EXEC
from foundry_sandbox.utils import log_debug, log_step, log_warn


@dataclass
class SkillConfig:
    """Configuration for a single skill."""

    name: str
    path: str = ""
    """Host directory to mount into container."""

    mount_target: str = ""
    """Container mount point (default: /skills/<name>)."""

    mcp_server: dict[str, object] | None = None
    """MCP server config: {"command": "...", "args": [...]}."""

    permissions_allow: list[str] = field(default_factory=list)
    permissions_deny: list[str] = field(default_factory=list)

    stubs: list[str] = field(default_factory=list)
    """Files in skill dir to append to /workspace/."""

    env: dict[str, str] = field(default_factory=dict)
    """Extra env vars. $VAR prefix = resolve from host env."""


def _skills_toml_path() -> Path:
    """Return the path to the skills config file."""
    from foundry_sandbox.constants import get_sandbox_home
    return get_sandbox_home() / "skills.toml"


def load_skills_config() -> dict[str, SkillConfig]:
    """Read ~/.sandboxes/skills.toml and return a dict of SkillConfig.

    Returns empty dict if the file doesn't exist or is invalid.
    """
    path = _skills_toml_path()
    if not path.is_file():
        return {}

    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        log_warn(f"Failed to parse {path}: {exc}")
        return {}

    skills_section = data.get("skills", {})
    if not isinstance(skills_section, dict):
        return {}

    result: dict[str, SkillConfig] = {}
    for name, cfg in skills_section.items():
        if not isinstance(cfg, dict):
            log_warn(f"Skipping skill '{name}': expected a table, got {type(cfg).__name__}")
            continue
        mcp = cfg.get("mcp_server")
        if isinstance(mcp, dict):
            mcp = dict(mcp)  # normalize from toml
        else:
            mcp = None
        result[name] = SkillConfig(
            name=name,
            path=str(cfg.get("path", "")),
            mount_target=str(cfg.get("mount_target", "")),
            mcp_server=mcp,
            permissions_allow=list(cfg.get("permissions_allow", [])),
            permissions_deny=list(cfg.get("permissions_deny", [])),
            stubs=list(cfg.get("stubs", [])),
            env={str(k): str(v) for k, v in cfg.get("env", {}).items()},
        )

    return result


def resolve_skill_env(env_dict: dict[str, str]) -> dict[str, str]:
    """Resolve $VAR references from host environment.

    Values starting with '$' are replaced with the corresponding
    host environment variable value.
    """
    resolved: dict[str, str] = {}
    for key, value in env_dict.items():
        if value.startswith("$"):
            host_var = value[1:]
            host_value = os.environ.get(host_var)
            if host_value is None:
                log_warn(f"Skill env ${host_var} not found in host environment, using empty string")
                resolved[key] = ""
            else:
                resolved[key] = host_value
        else:
            resolved[key] = value
    return resolved


def get_skill_mounts(skill_names: list[str], skills_config: dict[str, SkillConfig]) -> list[str]:
    """Return list of volume mount strings for the given skills.

    Args:
        skill_names: List of skill names to include.
        skills_config: Full skills configuration.

    Returns:
        List of "host_path:container_path:ro" mount strings.
    """
    mounts: list[str] = []
    for name in skill_names:
        skill = skills_config.get(name)
        if not skill or not skill.path:
            continue
        host_path = os.path.expanduser(skill.path)
        mount_target = skill.mount_target or f"/skills/{name}"
        mounts.append(f"{host_path}:{mount_target}:ro")
    return mounts


def get_skill_env(skill_names: list[str], skills_config: dict[str, SkillConfig]) -> dict[str, str]:
    """Return merged env dict for the given skills.

    Args:
        skill_names: List of skill names to include.
        skills_config: Full skills configuration.

    Returns:
        Merged environment variables with $VAR references resolved.
    """
    merged: dict[str, str] = {}
    for name in skill_names:
        skill = skills_config.get(name)
        if not skill:
            continue
        merged.update(resolve_skill_env(skill.env))
    return merged


def get_skill_permissions(
    skill_names: list[str],
    skills_config: dict[str, SkillConfig],
) -> tuple[list[str], list[str]]:
    """Return merged (allow, deny) permission lists for the given skills.

    Args:
        skill_names: List of skill names to include.
        skills_config: Full skills configuration.

    Returns:
        Tuple of (allow_list, deny_list).
    """
    allow: list[str] = []
    deny: list[str] = []
    for name in skill_names:
        skill = skills_config.get(name)
        if not skill:
            continue
        allow.extend(skill.permissions_allow)
        deny.extend(skill.permissions_deny)
    return allow, deny


def install_skills_to_container(
    container_id: str,
    skill_names: list[str],
    skills_config: dict[str, SkillConfig],
) -> None:
    """Register MCP servers and append stubs for skills in a container.

    Args:
        container_id: Docker container ID or name.
        skill_names: List of skill names to install.
        skills_config: Full skills configuration.
    """
    if not skill_names:
        return

    # Register MCP servers
    mcp_servers: dict[str, object] = {}
    for name in skill_names:
        skill = skills_config.get(name)
        if not skill or not skill.mcp_server:
            continue
        mcp_servers[name] = skill.mcp_server

    if mcp_servers:
        _register_mcp_servers(container_id, mcp_servers)

    # Append stubs
    for name in skill_names:
        skill = skills_config.get(name)
        if not skill or not skill.stubs or not skill.path:
            continue
        host_path = Path(os.path.expanduser(skill.path))
        for stub_file in skill.stubs:
            stub_path = host_path / stub_file
            if stub_path.is_file():
                _append_stub_to_workspace(container_id, stub_path, stub_file)

    log_step(f"Skills installed: {', '.join(skill_names)}")


def _register_mcp_servers(container_id: str, servers: dict[str, object]) -> None:
    """Register MCP servers in both Claude JSON config files."""
    servers_json = json.dumps(servers)
    python_script = f'''
import json, os

servers = {servers_json}

for path in ["{CONTAINER_HOME}/.claude.json", "{CONTAINER_HOME}/.claude/.claude.json"]:
    data = {{}}
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = {{}}

    if not isinstance(data, dict):
        data = {{}}

    if "mcpServers" not in data:
        data["mcpServers"] = {{}}

    changed = False
    for name, config in servers.items():
        if name not in data["mcpServers"]:
            data["mcpServers"][name] = config
            changed = True

    if changed:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\\n")
'''

    result = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, "-i", container_id, "python3", "-c", python_script],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode != 0:
        log_warn(f"Failed to register MCP servers: {result.stderr}")
    else:
        log_debug(f"Registered MCP servers: {list(servers.keys())}")


def _append_stub_to_workspace(container_id: str, stub_path: Path, target_name: str) -> None:
    """Append a stub file to /workspace/<target_name> in the container.

    Uses an HTML comment marker for idempotency — repeated calls won't
    duplicate the content.
    """
    target = f"/workspace/{target_name}"
    content = stub_path.read_text()
    if not content.strip():
        return

    # Check if already appended (idempotency via marker)
    marker = f"<!-- cast-skill-stub:{stub_path.name} -->"
    check = subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, container_id,
         "grep", "-qF", marker, target],
        capture_output=True, check=False, timeout=TIMEOUT_DOCKER_EXEC,
    )
    if check.returncode == 0:
        log_debug(f"Skill stub {stub_path.name} already installed, skipping")
        return

    # Ensure target exists
    subprocess.run(
        ["docker", "exec", "-u", CONTAINER_USER, container_id, "touch", target],
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    # Prepend marker and append
    content_with_marker = f"{marker}\n{content}"
    result = subprocess.run(
        ["docker", "exec", "-i", "-u", CONTAINER_USER, container_id,
         "sh", "-c", f"cat >> {target}"],
        input=content_with_marker,
        text=True,
        capture_output=True,
        check=False,
        timeout=TIMEOUT_DOCKER_EXEC,
    )

    if result.returncode == 0:
        log_debug(f"Appended {stub_path.name} to {target}")
    else:
        log_debug(f"Failed to append {stub_path.name}: {result.stderr}")
