"""Skills management commands.

List, inspect, and initialize user-configurable skills for sandbox containers.
"""
from __future__ import annotations

import click

from foundry_sandbox.skills import _skills_toml_path, load_skills_config


@click.group()
def skills() -> None:
    """Manage sandbox skills."""


@skills.command("list")
def skills_list() -> None:
    """List all configured skills."""
    config = load_skills_config()
    if not config:
        path = _skills_toml_path()
        click.echo(f"No skills configured in {path}")
        click.echo("Run 'cast skills init' to create an example config.")
        return

    click.echo()
    click.echo(f"{'Name':<25} {'Path':<35} {'MCP':<5} {'Perms'}")
    click.echo(f"{'─' * 25} {'─' * 35} {'─' * 5} {'─' * 5}")
    for name, skill in config.items():
        path_display = skill.path or "(none)"
        if len(path_display) > 33:
            path_display = "…" + path_display[-32:]
        has_mcp = "yes" if skill.mcp_server else "no"
        perm_count = len(skill.permissions_allow) + len(skill.permissions_deny)
        click.echo(f"{name:<25} {path_display:<35} {has_mcp:<5} {perm_count}")
    click.echo()


@skills.command("show")
@click.argument("name")
def skills_show(name: str) -> None:
    """Show details of a specific skill."""
    config = load_skills_config()
    skill = config.get(name)
    if not skill:
        click.echo(f"Skill '{name}' not found.")
        available = list(config.keys())
        if available:
            click.echo(f"Available: {', '.join(available)}")
        return

    click.echo()
    click.echo(f"  Name:          {skill.name}")
    click.echo(f"  Path:          {skill.path or '(none)'}")
    click.echo(f"  Mount target:  {skill.mount_target or f'/skills/{skill.name}'}")
    if skill.mcp_server:
        click.echo(f"  MCP server:    {skill.mcp_server}")
    if skill.permissions_allow:
        click.echo(f"  Allow:         {skill.permissions_allow}")
    if skill.permissions_deny:
        click.echo(f"  Deny:          {skill.permissions_deny}")
    if skill.stubs:
        click.echo(f"  Stubs:         {skill.stubs}")
    if skill.env:
        click.echo(f"  Env:           {skill.env}")
    click.echo()


@skills.command("init")
def skills_init() -> None:
    """Create an example skills.toml if it doesn't exist."""
    path = _skills_toml_path()
    if path.is_file():
        click.echo(f"Skills config already exists: {path}")
        return

    example = """\
# Skills configuration for foundry-sandbox
# Each skill defines resources to mount into sandboxes.
# Use: cast new --skill <name> or select in the wizard.

[skills]

# [skills.my-research-tool]
# # Host directory to mount into the container (read-only)
# path = "~/GitHub/my-research-tool"
# # Where to mount inside the container (optional, defaults to /skills/<name>)
# # mount_target = "/skills/my-research-tool"
#
# # MCP server to register (optional)
# # mcp_server = { command = "python", args = ["/skills/my-research-tool/server.py"] }
#
# # Extra permissions for this skill (optional)
# # permissions_allow = ["Bash(my-tool:*)"]
# # permissions_deny = []
#
# # Stub files from the skill directory to append to /workspace/ (optional)
# # stubs = ["SKILL_GUIDE.md"]
#
# # Environment variables (optional, $VAR resolves from host env)
# # env = { MY_API_KEY = "$MY_API_KEY" }
"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(example)
    click.echo(f"Created example skills config: {path}")
    click.echo("Edit it to define your skills, then use 'cast new --skill <name>'.")
