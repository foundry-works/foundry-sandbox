"""Shared types, constants, and utility functions for branch isolation.

Extracted from branch_isolation.py to reduce module size and allow
independent reuse by git_operations.py and branch_output_filter.py.
"""

import re
from dataclasses import dataclass
from typing import FrozenSet, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Git Binary
# ---------------------------------------------------------------------------

GIT_BINARY = "/usr/bin/git"

# ---------------------------------------------------------------------------
# Validation Error
# ---------------------------------------------------------------------------


@dataclass
class ValidationError:
    """Validation failure with reason."""

    reason: str
    field: Optional[str] = None

    def to_dict(self) -> dict:
        result = {"error": self.reason}
        if self.field:
            result["field"] = self.field
        return result


# ---------------------------------------------------------------------------
# Global Flags
# ---------------------------------------------------------------------------

# Global flags that consume the next argument as their value.
# Used by get_subcommand_args() to skip over value arguments.
GLOBAL_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
})


# ---------------------------------------------------------------------------
# Subcommand Extraction
# ---------------------------------------------------------------------------


def get_subcommand_args(
    args: List[str],
) -> Tuple[Optional[str], List[str], List[str]]:
    """Extract the git subcommand and its arguments from a full arg list.

    Handles global flags (-c key=val, -C <path>, --git-dir, --work-tree,
    --namespace) and the ``--`` global-options terminator.

    Args:
        args: Git command arguments (without the ``git`` prefix).

    Returns:
        (subcommand, subcommand_args, config_pairs) where subcommand is
        None if no subcommand was found.  config_pairs contains any
        ``-c key=value`` strings encountered before the subcommand.
    """
    idx = 0
    config_pairs: List[str] = []

    while idx < len(args):
        arg = args[idx]

        # '--' terminates global options; next arg is the subcommand
        if arg == "--":
            idx += 1
            break

        # Collect -c key=value pairs
        if arg == "-c" and idx + 1 < len(args):
            config_pairs.append(args[idx + 1])
            idx += 2
            continue
        elif arg.startswith("-c") and len(arg) > 2:
            # Compact -ckey=value form
            config_pairs.append(arg[2:])
            idx += 1
            continue

        # Skip global value flags and their argument
        if arg in GLOBAL_VALUE_FLAGS and idx + 1 < len(args):
            idx += 2
            continue
        # Handle --flag=value form for global value flags
        flag_name = arg.split("=", 1)[0]
        if flag_name in GLOBAL_VALUE_FLAGS and "=" in arg:
            idx += 1
            continue

        # First non-flag argument is the subcommand
        if not arg.startswith("-"):
            break

        idx += 1

    if idx >= len(args):
        return None, [], config_pairs

    return args[idx], args[idx + 1:], config_pairs


def get_subcommand(args: List[str]) -> Optional[str]:
    """Return the git subcommand from *args*, or None."""
    subcmd, _, _ = get_subcommand_args(args)
    return subcmd


# ---------------------------------------------------------------------------
# Branch Constants
# ---------------------------------------------------------------------------

WELL_KNOWN_BRANCHES: FrozenSet[str] = frozenset({
    "main", "master", "develop", "production",
})

WELL_KNOWN_BRANCH_PREFIXES: Tuple[str, ...] = (
    "release/", "hotfix/",
)


# ---------------------------------------------------------------------------
# SHA Constants
# ---------------------------------------------------------------------------

# Minimum length for a hex string to be treated as a SHA hash.
#
# Why 12?  Git's default `core.abbrev` is "auto" which typically produces
# 7-12 character abbreviations depending on the number of objects.  Using 12
# as the floor avoids false-positives on short hex tokens (config values,
# color codes, partial file names) while still accepting the longest default
# abbreviations.  Collision risk: 12 hex chars = 48 bits ~ 2.8 x 10^14
# possible prefixes, making accidental collisions negligible for repos under
# ~10^7 objects.  As defense-in-depth, SHA arguments passing this check are
# also verified via `_check_sha_reachability` to confirm they are ancestors
# of allowed branches, so a false-positive here cannot leak data.
_MIN_SHA_LENGTH = 12

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")

# Timeout for SHA reachability git subprocess calls (seconds).
SHA_CHECK_TIMEOUT = 10


def _is_sha_like(token: str) -> bool:
    """Return True if *token* looks like a SHA hash (12-40 hex chars).

    The 12-char minimum (``_MIN_SHA_LENGTH``) balances false-positive
    avoidance against accepting git's default abbreviated SHAs.  See the
    comment on ``_MIN_SHA_LENGTH`` for collision analysis.  Callers that
    need stronger assurance should follow up with ``_check_sha_reachability``.
    """
    return (
        _MIN_SHA_LENGTH <= len(token) <= 40
        and all(c in _HEX_CHARS for c in token)
    )


# ---------------------------------------------------------------------------
# Output Filtering Regex Constants
# ---------------------------------------------------------------------------

# Matches plain and verbose branch output lines:
#   "* main"  /  "  feature/x"  /  "  feature abc1234 commit msg"
#   "  feature   abc1234 [origin/feature] commit msg"  (verbose -vv)
# Groups: indicator (* or spaces), branch_name, rest (optional)
_BRANCH_LINE_RE = re.compile(
    r"^(?P<indicator>[* ] )"           # "* " or "  "
    r"(?P<branch>\S+)"                 # branch name
    r"(?P<rest>.*)$"                   # optional verbose info
)

# Matches remote branch lines from `git branch -a`:
#   "  remotes/origin/main"
#   "  remotes/origin/HEAD -> origin/main"
_REMOTE_BRANCH_LINE_RE = re.compile(
    r"^(?P<indent>\s+)"
    r"remotes/(?P<remote>[^/]+)/"
    r"(?P<branch>\S+)"
    r"(?P<rest>.*)$"
)

# Matches lines containing full ref paths (for-each-ref, show-ref, ls-remote)
# e.g. "abc123 refs/heads/feature" or "refs/heads/feature abc123 commit msg"
_REF_IN_LINE_RE = re.compile(r"refs/heads/([^\s]+)")

# Matches SHA-anchored decoration lines in git log output:
#   "abc1234 (HEAD -> main, tag: v1.0, origin/feature)"
_DECORATION_LINE_RE = re.compile(
    r"^(?P<prefix>[0-9a-fA-F]+\s+)"   # SHA + whitespace
    r"\((?P<decorations>[^)]+)\)"       # parenthesized decorations
    r"(?P<suffix>.*)$"                  # rest of line
)

# Matches custom %d format decorations (parenthesized):
#   " (HEAD -> main, tag: v1.0, origin/feature)"
_CUSTOM_D_RE = re.compile(
    r"\((?P<decorations>[^)]+)\)"
)

# Patterns that may contain branch names in stderr output
_STDERR_REF_RE = re.compile(
    r"refs/heads/(?P<branch>[^\s'\"]+)"
    r"|refs/remotes/[^/]+/(?P<remote_branch>[^\s'\"]+)"
)

# Bare branch names in single-quoted contexts (e.g. 'sandbox/other').
# Only matches tokens containing "/" to avoid false-positives on file paths
# and other single-quoted strings.
_STDERR_BARE_BRANCH_RE = re.compile(
    r"'(?P<bare_branch>[^\s'\"]+/[^\s'\"]+)'"
)


# ---------------------------------------------------------------------------
# Base Branch Normalization
# ---------------------------------------------------------------------------


def _normalize_base_branch(base_branch: Optional[str]) -> Optional[str]:
    """Normalize a base branch name from metadata to a bare branch name."""
    if not base_branch:
        return None
    if base_branch.startswith("refs/heads/"):
        base_branch = base_branch[len("refs/heads/"):]
    elif base_branch.startswith("refs/remotes/"):
        parts = base_branch.split("/", 3)
        if len(parts) >= 4:
            base_branch = parts[3]
        else:
            return None
    else:
        for remote in ("origin", "upstream"):
            prefix = f"{remote}/"
            if base_branch.startswith(prefix):
                base_branch = base_branch[len(prefix):]
                break
    return base_branch or None


# ---------------------------------------------------------------------------
# Branch Name Validation
# ---------------------------------------------------------------------------


def _is_allowed_branch_name(
    name: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> bool:
    """Check if a bare branch name is allowed for this sandbox.

    Allowed: the sandbox's own branch, well-known branches,
    the sandbox's base branch (if any), and branches matching
    well-known prefixes.
    """
    if name == sandbox_branch:
        return True
    if base_branch and name == base_branch:
        return True
    if name in WELL_KNOWN_BRANCHES:
        return True
    for prefix in WELL_KNOWN_BRANCH_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


# ---------------------------------------------------------------------------
# Ref Enumeration Commands
# ---------------------------------------------------------------------------

# Commands that enumerate refs (used by both branch_isolation and
# branch_output_filter for dispatch).
REF_ENUM_CMDS: FrozenSet[str] = frozenset({
    "for-each-ref", "ls-remote", "show-ref",
})
