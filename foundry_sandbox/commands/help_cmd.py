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
  preset list                           List saved presets
  preset show <name>                    Show preset details
  preset save <name> [--sandbox <name>] Save preset with filesystem snapshot
  preset delete <name>                  Delete a preset
  list [--json]                         List all sandboxes
  attach <name>                         Attach to a sandbox
  start <name>                          Start a stopped sandbox
  stop <name>                           Stop a sandbox (keeps worktree)
  destroy <name> [-f] [-y]              Destroy sandbox and worktree (confirms first)
  destroy-all                           Destroy all sandboxes (double confirmation)
  config [--json]                       Show config and checks
  status [name] [--json]                Show sandbox status
  refresh-creds [name]                  Refresh credentials in running sandbox
  git-mode [name] --mode <host|sandbox> Toggle git path mode for host/sandbox
  help                                  Show this help

New sandbox options:
  --agent <type>                        Agent type (claude, codex, copilot, gemini, kiro, opencode, shell)
  --copy, -c src:dst                    Copy host path into sandbox (once at creation)
  --wd <path>                           Working directory within repo
  --pip-requirements, -r <path>         Install Python packages
  --allow-pr                            Allow PR operations
  --with-opencode                       Enable OpenCode setup
  --with-zai                            Enable ZAI Claude alias
  --save-as <name>                      Save this configuration as a preset
  --name <name>                         Override auto-generated sandbox name
  --skip-key-check                      Skip API key validation

Examples:
  cast new user/repo                              # checkout main
  cast new .                                      # use current repo/branch
  cast new user/repo feature-branch               # checkout existing branch
  cast new user/repo my-feature main              # new branch from main
  cast new user/repo feat --wd packages/app       # monorepo subdirectory
  cast new user/repo feat --agent codex           # use Codex agent
  cast new user/repo feat --save-as myproject     # save as preset
  cast preset save mysetup --sandbox my-sandbox   # save preset with snapshot
  cast new --preset myproject                     # use saved preset
  cast new --last                                 # repeat last command
  cast attach repo-feature-branch
  cast list"""


@click.command("help")
def help_cmd() -> None:
    """Show detailed usage information."""
    click.echo(HELP_TEXT)
