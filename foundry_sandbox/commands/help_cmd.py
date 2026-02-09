"""Help command — show detailed usage information.

Migrated from commands/help.sh (60 lines).
"""

from __future__ import annotations

import click


HELP_TEXT = """\
AI Dev Sandbox - Ephemeral worktree-based development environments

Usage: cast <command> [args]

Commands:
  new <repo> [branch] [from] [options]  Create sandbox from repo
  new --last                            Repeat last cast new command
  new --preset <name>                   Use a saved preset
  repeat                                Alias for 'new --last'
  preset list                           List saved presets
  preset show <name>                    Show preset details
  preset delete <name>                  Delete a preset
  list [--json]                         List all sandboxes
  attach <name>                         Attach to a sandbox
  start <name>                          Start a stopped sandbox
  stop <name>                           Stop a sandbox (keeps worktree)
  destroy <name> [-f] [-y]              Destroy sandbox and worktree (confirms first)
  destroy-all                           Destroy all sandboxes (double confirmation)
  build                                 Build/rebuild the sandbox image
  config [--json]                       Show config and checks
  prune [-f] [--json]                   Remove orphaned configs
  status [name] [--json]                Show sandbox status
  info [--json]                         Show config + status
  refresh-credentials [name]            Refresh credentials in running sandbox
  upgrade [--local]                     Upgrade to latest version
  help                                  Show this help

New sandbox options:
  --mount, -v src:dst[:ro]              Mount host path into container
  --copy, -c src:dst                    Copy host path into container (once at creation)
  --network, -n <mode>                  Network isolation: limited, host-only, none
  --with-ssh                            Enable SSH agent forwarding
  --with-opencode                       Enable OpenCode setup
  --with-zai                            Enable ZAI Claude alias
  --no-isolate-credentials              Pass API keys directly (disable isolation)
  --wd <path>                           Working directory within repo
  --sparse                              Enable sparse checkout (requires --wd)
  --pip-requirements, -r <path>         Install Python packages
  --allow-pr                            Allow PR operations
  --save-as <name>                      Save this configuration as a preset
  --with-ide[=name]                     Launch IDE (cursor, zed, code) then terminal
  --ide-only[=name]                     Launch IDE only, skip terminal
  --no-ide                              Skip IDE selection prompt

Examples:
  cast new user/repo                              # checkout main
  cast new .                                      # use current repo/branch
  cast new user/repo feature-branch               # checkout existing branch
  cast new user/repo my-feature main              # new branch from main
  cast new user/repo feat --wd packages/app       # monorepo subdirectory
  cast new user/repo feat --save-as myproject     # save as preset
  cast new --preset myproject                     # use saved preset
  cast new --last                                 # repeat last command
  cast repeat                                     # same as above
  cast attach repo-feature-branch
  cast list"""


@click.command("help")
def help_cmd() -> None:
    """Show detailed usage information."""
    click.echo(HELP_TEXT)
