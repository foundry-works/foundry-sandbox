"""Branch isolation enforcement for multi-sandbox git proxy.

Validates that each sandbox can only access its own branch, well-known
branches (main, master, develop, production, release/*, hotfix/*), tags,
and SHA hashes reachable from allowed branches.

Security model:
- Fail-closed: metadata present but missing sandbox_branch blocks all refs
- Input validation: blocks commands that reference disallowed branches
- SHA reachability: verifies SHA args are ancestors of allowed branches
- Output filtering: strips disallowed branch names from git output

Shared types and constants live in branch_types.py.
Output filtering functions live in branch_output_filter.py.
This module re-exports both for backward compatibility.
"""

import logging
import os
import re
import subprocess
from typing import FrozenSet, List, Optional, Tuple

# Re-export shared types and constants from branch_types
from branch_types import (  # noqa: F401
    GIT_BINARY,
    GLOBAL_VALUE_FLAGS,
    REF_ENUM_CMDS,
    SHA_CHECK_TIMEOUT,
    ValidationError,
    WELL_KNOWN_BRANCHES,
    WELL_KNOWN_BRANCH_PREFIXES,
    _BRANCH_LINE_RE,
    _CUSTOM_D_RE,
    _DECORATION_LINE_RE,
    _HEX_CHARS,
    _MIN_SHA_LENGTH,
    _REF_IN_LINE_RE,
    _REMOTE_BRANCH_LINE_RE,
    _STDERR_BARE_BRANCH_RE,
    _STDERR_REF_RE,
    _is_allowed_branch_name,
    _is_sha_like,
    _normalize_base_branch,
    get_subcommand,
    get_subcommand_args,
)

# Re-export output filter functions from branch_output_filter
from branch_output_filter import (  # noqa: F401
    _filter_branch_output,
    _filter_custom_format_decorations,
    _filter_log_decorations,
    _filter_ref_enum_output,
    _is_allowed_short_ref_token,
    _log_has_bare_D_format,
    _log_has_custom_decoration_format,
    _log_has_source_flag,
    _filter_log_source_refs,
    filter_ref_listing_output,
    filter_stderr_branch_refs,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bare Repo Resolution
# ---------------------------------------------------------------------------


def resolve_bare_repo_path(repo_root: str) -> Optional[str]:
    """Follow the worktree .git -> gitdir -> commondir chain to find the bare repo.

    Git worktrees have a ``.git`` *file* (not directory) that contains a
    ``gitdir:`` pointer to the worktree's gitdir directory.  That gitdir
    in turn has a ``commondir`` file pointing (absolute or relative) to the
    shared bare repo.

    Security: all resolved paths are validated with ``os.path.realpath()``
    to prevent symlink/traversal attacks via crafted ``.git`` or
    ``commondir`` files.

    Args:
        repo_root: The worktree's working directory root.

    Returns:
        Normalized absolute path to the bare repo directory, or None if
        the chain cannot be resolved.
    """
    try:
        real_root = os.path.realpath(repo_root)
        dot_git = os.path.join(real_root, ".git")

        # If .git is a directory, this IS the git dir (not a worktree)
        if os.path.isdir(dot_git):
            # Check for commondir inside .git
            commondir_file = os.path.join(dot_git, "commondir")
            if os.path.isfile(commondir_file):
                with open(commondir_file, "r") as f:
                    commondir = f.read().strip()
                if os.path.isabs(commondir):
                    resolved = os.path.realpath(commondir)
                else:
                    resolved = os.path.realpath(
                        os.path.join(dot_git, commondir)
                    )
                return resolved
            # No commondir — .git itself is the git dir
            return os.path.realpath(dot_git)

        # .git is a file — read gitdir pointer
        if not os.path.isfile(dot_git):
            return None

        with open(dot_git, "r") as f:
            content = f.read().strip()

        if not content.startswith("gitdir:"):
            return None

        gitdir = content[len("gitdir:"):].strip()
        if not os.path.isabs(gitdir):
            gitdir = os.path.join(real_root, gitdir)
        gitdir = os.path.realpath(gitdir)

        if not os.path.isdir(gitdir):
            return None

        # Read commondir from gitdir
        commondir_file = os.path.join(gitdir, "commondir")
        if not os.path.isfile(commondir_file):
            # No commondir — gitdir itself is the bare repo
            return gitdir

        with open(commondir_file, "r") as f:
            commondir = f.read().strip()

        if os.path.isabs(commondir):
            bare_path = os.path.realpath(commondir)
        else:
            bare_path = os.path.realpath(os.path.join(gitdir, commondir))

        if not os.path.isdir(bare_path):
            return None

        return bare_path

    except (OSError, IOError):
        return None


# ---------------------------------------------------------------------------
# Branch Isolation Constants (local to this module)
# ---------------------------------------------------------------------------

# Commands that accept ref arguments for reading (not switching branches)
_REF_READING_CMDS: FrozenSet[str] = frozenset({
    "log", "show", "diff", "blame", "cherry-pick", "merge", "rebase",
    "reset", "rev-list", "diff-tree", "rev-parse", "shortlog", "describe",
    "name-rev", "archive", "format-patch",
    "cat-file", "ls-tree",
})

# REF_ENUM_CMDS is imported from branch_types (canonical location).
# Keep local alias for backward compatibility with existing references.
_REF_ENUM_CMDS = REF_ENUM_CMDS

# Notes sub-subcommands (used in branch isolation for positional arg parsing)
_NOTES_SUBCMDS: FrozenSet[str] = frozenset({
    "list", "add", "copy", "append", "edit", "show",
    "merge", "remove", "prune",
})

# Flags that implicitly reference all branches/refs
_IMPLICIT_ALL_REF_FLAGS: FrozenSet[str] = frozenset({
    "--all", "--branches", "--remotes", "--glob",
})

# Flag prefixes that implicitly reference refs with patterns
_IMPLICIT_REF_FLAG_PREFIXES: Tuple[str, ...] = (
    "--branches=", "--remotes=", "--glob=",
)

# Ref-reading flags that consume the next argument as a value.
# This prevents option values (e.g. ``-n 5``) from being misclassified as refs.
_REF_READING_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-n", "--max-count", "--skip",
    "--since", "--until", "--after", "--before",
    "--author", "--committer", "--grep",
    "-G", "-S",
    "--date", "--format", "--pretty",
    "--decorate-refs", "--decorate-refs-exclude",
    "--output", "-o",
    "--word-diff-regex",
    "--find-object",
    "--min-parents", "--max-parents",
    "--diff-merges",
    "--relative", "--src-prefix", "--dst-prefix",
    "-L",
})

# Regex to strip revision suffixes (~N, ^N, @{...}) from ref names
_REV_SUFFIX_RE = re.compile(r"([~^]\d*|@\{[^}]*\})+$")

# fetch/pull flags that consume the next argument as a value
_FETCH_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
    "-j", "--jobs", "--negotiation-tip", "--server-option", "-o",
    "--upload-pack", "--refmap", "--recurse-submodules-default",
    "--filter",
})

# checkout/switch flags that consume the next argument as a value
_CHECKOUT_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-b", "-B",       # checkout: create branch
    "-c", "-C",       # switch: create branch
    "--orphan",       # checkout: create orphan branch
    "--conflict",     # checkout: conflict style
    "--pathspec-from-file",
})

# checkout/switch flags that indicate branch creation (next arg is new branch name)
_BRANCH_CREATE_FLAGS: FrozenSet[str] = frozenset({
    "-b", "-B", "-c", "-C", "--orphan",
})

_TAG_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "-m", "--message", "-F", "--file", "-u", "--local-user",
    "--cleanup", "--sort",
})

# push flags that consume the next argument as a value
_PUSH_VALUE_FLAGS: FrozenSet[str] = frozenset({
    "--repo", "--receive-pack", "--exec", "--push-option", "-o",
})


# ---------------------------------------------------------------------------
# Input Validation: Helpers
# ---------------------------------------------------------------------------


def _strip_rev_suffixes(ref: str) -> str:
    """Strip trailing ~N, ^N, @{...} chains from a ref string.

    Examples:
        HEAD~3       -> HEAD
        main^^       -> main
        HEAD~2^3     -> HEAD
        main@{1}     -> main
        abc123~2^3   -> abc123
    """
    return _REV_SUFFIX_RE.sub("", ref)



# _is_allowed_branch_name is imported from branch_types (canonical location).


def _is_allowed_ref(
    ref: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> bool:
    """Check if a ref argument is allowed under branch isolation.

    Allows: HEAD, @{...} forms, own sandbox branch, well-known branches,
    tags, SHA hashes (>= 12 hex chars), range operators (checked recursively).
    Blocks: FETCH_HEAD, other sandbox branches, short hex strings.
    """
    # Handle range operators recursively
    for sep in ("...", ".."):
        if sep in ref:
            parts = ref.split(sep, 1)
            return all(
                _is_allowed_ref(p, sandbox_branch, base_branch) for p in parts if p
            )

    # Strip revision suffixes
    base = _strip_rev_suffixes(ref)

    # FETCH_HEAD is always blocked (could contain cross-branch data)
    if base == "FETCH_HEAD":
        return False

    # HEAD and @{} forms are always allowed
    if base == "HEAD" or base.startswith("@{"):
        return True

    # Stash refs are allowed (stash@{ is defensive — _strip_rev_suffixes
    # normally handles @{N} forms, but this catches malformed variants)
    if base == "stash" or base.startswith("stash@{"):
        return True

    # Tags are always allowed (refs/tags/... or tag name checked by git)
    if base.startswith("refs/tags/") or base.startswith("tags/"):
        return True

    # Remote tracking refs: apply branch name isolation to the branch part.
    # Handle any remote name (origin, upstream, etc.) — split on the remote
    # component rather than hardcoding "origin".
    if base.startswith("refs/remotes/"):
        # refs/remotes/<remote>/<branch...>
        parts = base.split("/", 3)
        if len(parts) >= 4:
            return _is_allowed_branch_name(parts[3], sandbox_branch, base_branch)
        # Incomplete path like "refs/remotes/origin" — deny
        return False

    # Short remote form: <remote>/<branch> — only match when not a
    # refs/heads/ or refs/tags/ path (handled below/above).
    # We detect this by checking for a "/" and confirming the prefix
    # is not a known ref namespace.
    # Precedence: try as a slashed branch name first (e.g. "release/1.0"),
    # then fall back to interpreting as <remote>/<branch>.  This avoids
    # misclassifying legitimate branch names that contain "/" as remote refs.
    if "/" in base and not base.startswith("refs/"):
        prefix, _, branch_part = base.partition("/")
        if not _is_allowed_branch_name(base, sandbox_branch, base_branch):
            # Not an allowed branch name as-is, try as remote/branch
            if branch_part:
                return _is_allowed_branch_name(
                    branch_part, sandbox_branch, base_branch
                )
            return False
        # Allowed as a slashed branch name (e.g. "release/1.0")
        return True

    # Full ref paths
    if base.startswith("refs/heads/"):
        branch_name = base[len("refs/heads/"):]
        return _is_allowed_branch_name(branch_name, sandbox_branch, base_branch)

    # SHA hashes (hex strings of sufficient length) are always allowed
    if _is_sha_like(base):
        return True

    # Bare branch names
    return _is_allowed_branch_name(base, sandbox_branch, base_branch)


# ---------------------------------------------------------------------------
# Input Validation: Main Entry Point
# ---------------------------------------------------------------------------


def validate_branch_isolation(
    args: List[str],
    metadata: Optional[dict],
) -> Optional[ValidationError]:
    """Validate git command args for branch isolation.

    Enforces that a sandbox can only access its own branch, well-known
    branches, tags, and SHA hashes.  Commands that enumerate refs
    (for-each-ref, ls-remote, show-ref, branch --list) return None here
    and are handled by output filtering instead.

    Args:
        args: Git command arguments (without ``git`` prefix).
        metadata: Container metadata dict (must contain ``sandbox_branch``).

    Returns:
        None if allowed, ValidationError if blocked.
    """
    if metadata is None:
        return None
    sandbox_branch = metadata.get("sandbox_branch")
    if not sandbox_branch:
        return ValidationError(
            "Branch isolation: metadata present but missing sandbox_branch"
        )
    base_branch = _normalize_base_branch(metadata.get("from_branch"))

    subcommand, sub_args, _ = get_subcommand_args(args)
    if subcommand is None:
        return None  # will be caught by validate_command

    # --- branch deletion guard ---
    if subcommand == "branch":
        delete_mode = False
        i = 0
        while i < len(sub_args):
            a = sub_args[i]
            if a in ("-d", "-D", "--delete"):
                delete_mode = True
            elif delete_mode and not a.startswith("-"):
                if not _is_allowed_branch_name(a, sandbox_branch, base_branch):
                    return ValidationError(
                        f"Branch isolation: cannot delete branch '{a}'"
                    )
            i += 1
        return None  # branch listing handled by output filtering

    # --- ref enum commands (handled by output filtering) ---
    if subcommand in _REF_ENUM_CMDS:
        return None

    # --- checkout / switch ---
    if subcommand in ("checkout", "switch"):
        return _validate_checkout_isolation(sub_args, sandbox_branch, base_branch)

    # --- fetch / pull ---
    if subcommand in ("fetch", "pull"):
        return _validate_fetch_isolation(sub_args, sandbox_branch, base_branch)

    # --- push ---
    if subcommand == "push":
        return _validate_push_isolation(sub_args, sandbox_branch, base_branch)

    # --- worktree add ---
    if subcommand == "worktree" and sub_args and sub_args[0] == "add":
        return _validate_worktree_add_isolation(
            sub_args[1:], sandbox_branch, base_branch
        )

    # --- bisect start ---
    if subcommand == "bisect" and sub_args and sub_args[0] == "start":
        for a in sub_args[1:]:
            if a == "--":
                break
            if not a.startswith("-") and not _is_allowed_ref(
                a, sandbox_branch, base_branch
            ):
                return ValidationError(
                    f"Branch isolation: ref '{a}' not allowed in bisect"
                )
        return None

    # --- reflog ---
    if subcommand == "reflog":
        # reflog show <ref> — check the ref
        reflog_args = sub_args
        if reflog_args and reflog_args[0] in ("show", "expire", "delete"):
            reflog_args = reflog_args[1:]
        for a in reflog_args:
            if a == "--":
                break
            if not a.startswith("-") and not _is_allowed_ref(
                a, sandbox_branch, base_branch
            ):
                return ValidationError(
                    f"Branch isolation: ref '{a}' not allowed in reflog"
                )
        return None

    # --- notes ---
    if subcommand == "notes":
        # Check --ref=<ref> flag value
        skip_next = False
        pending_ref_check = False
        for a in sub_args:
            if skip_next:
                skip_next = False
                if pending_ref_check:
                    pending_ref_check = False
                    if not _is_allowed_ref(a, sandbox_branch, base_branch):
                        return ValidationError(
                            f"Branch isolation: ref '{a}' not allowed in notes"
                        )
                continue
            if a.startswith("--ref="):
                ref_val = a[len("--ref="):]
                if not _is_allowed_ref(ref_val, sandbox_branch, base_branch):
                    return ValidationError(
                        f"Branch isolation: ref '{ref_val}' not allowed in notes"
                    )
            elif a == "--ref":
                skip_next = True
                pending_ref_check = True

        # Check positional args (skip sub-subcommand and flags)
        positionals: List[str] = []
        seen_subcmd = False
        for a in sub_args:
            if a == "--":
                break
            if a.startswith("-"):
                continue
            if not seen_subcmd and a in _NOTES_SUBCMDS:
                seen_subcmd = True
                continue
            positionals.append(a)

        for a in positionals:
            if not _is_allowed_ref(a, sandbox_branch, base_branch):
                return ValidationError(
                    f"Branch isolation: ref '{a}' not allowed in notes"
                )
        return None

    # --- ref-reading commands (log, show, diff, blame, etc.) ---
    if subcommand in _REF_READING_CMDS:
        return _validate_ref_reading_isolation(
            sub_args, sandbox_branch, base_branch
        )

    # --- tag with commit-ish argument ---
    if subcommand == "tag":
        return _validate_tag_isolation(sub_args, sandbox_branch, base_branch)

    return None


# ---------------------------------------------------------------------------
# Input Validation: Per-Command Helpers
# ---------------------------------------------------------------------------


def _validate_checkout_isolation(
    sub_args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[ValidationError]:
    """Validate checkout/switch args for branch isolation."""
    creating_branch = False
    skip_next = False
    positionals: List[str] = []
    start_point: Optional[str] = None

    i = 0
    while i < len(sub_args):
        a = sub_args[i]
        if a == "--":
            break  # rest are pathspecs
        if skip_next:
            skip_next = False
            i += 1
            continue

        if a in _BRANCH_CREATE_FLAGS:
            creating_branch = True
            # Next arg is the new branch name (skip it)
            skip_next = True
            i += 1
            continue

        if a in _CHECKOUT_VALUE_FLAGS:
            skip_next = True
            i += 1
            continue

        # Handle --flag=value form
        flag_name = a.split("=", 1)[0]
        if flag_name in _CHECKOUT_VALUE_FLAGS:
            if flag_name in _BRANCH_CREATE_FLAGS:
                creating_branch = True
            i += 1
            continue

        if not a.startswith("-"):
            positionals.append(a)

        i += 1

    if creating_branch:
        # When creating a branch, the start-point (if any) is the last positional
        if positionals:
            start_point = positionals[-1]
            if not _is_allowed_ref(start_point, sandbox_branch, base_branch):
                return ValidationError(
                    f"Branch isolation: start-point '{start_point}' not allowed"
                )
    else:
        # Switching to a branch: first positional is the target
        if positionals:
            target = positionals[0]
            if not _is_allowed_ref(target, sandbox_branch, base_branch):
                return ValidationError(
                    f"Branch isolation: cannot switch to '{target}'. "
                    f"If this is a file path, use -- to separate paths from refs."
                )

    return None


def _validate_fetch_isolation(
    sub_args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[ValidationError]:
    """Validate fetch/pull args for branch isolation."""
    skip_next = False
    positionals: List[str] = []

    for i, a in enumerate(sub_args):
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue

        # Block --all (fetches all remotes, exposing all branches)
        if a == "--all":
            return ValidationError(
                "Branch isolation: 'fetch --all' not allowed (exposes all branches)"
            )

        # Skip flags that consume the next argument
        if a in _FETCH_VALUE_FLAGS:
            skip_next = True
            continue
        # Handle --flag=value form
        if "=" in a and a.split("=", 1)[0] in _FETCH_VALUE_FLAGS:
            continue

        if not a.startswith("-"):
            positionals.append(a)

    # First positional is the remote name (always allowed), rest are refspecs
    for refspec in positionals[1:]:
        # Handle +src:dst refspec format
        spec = refspec.lstrip("+")
        src, _, dst = spec.partition(":")
        if src and not _is_allowed_ref(src, sandbox_branch, base_branch):
            return ValidationError(
                f"Branch isolation: refspec source '{src}' not allowed"
            )
        if dst and not _is_allowed_ref(dst, sandbox_branch, base_branch):
            return ValidationError(
                f"Branch isolation: refspec destination '{dst}' not allowed"
            )

    return None


def _validate_push_isolation(
    sub_args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[ValidationError]:
    """Validate push args for branch isolation.

    Ensures that a sandbox can only push to its own branch and well-known
    branches.  Blocks --all and --mirror (defense-in-depth; also blocked
    by check_push_protected_branches).
    """
    skip_next = False
    positionals: List[str] = []

    for a in sub_args:
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue

        # Block --all and --mirror (expose/overwrite all branches)
        if a in ("--all", "--mirror"):
            return ValidationError(
                f"Branch isolation: 'push {a}' not allowed (affects all branches)"
            )

        # Skip flags that consume the next argument
        if a in _PUSH_VALUE_FLAGS:
            skip_next = True
            continue
        # Handle --flag=value form
        if "=" in a and a.split("=", 1)[0] in _PUSH_VALUE_FLAGS:
            continue

        # Handle compact -o<value> form
        if a.startswith("-o") and a != "-o":
            continue

        if not a.startswith("-"):
            positionals.append(a)

    # First positional is the remote name (always allowed), rest are refspecs
    for refspec in positionals[1:]:
        # Strip force prefix
        spec = refspec.lstrip("+")

        if ":" in spec:
            src, dst = spec.split(":", 1)
            if not src and dst:
                # Delete refspec (:dst) — check dst as branch name
                if not _is_allowed_branch_name(dst, sandbox_branch, base_branch):
                    return ValidationError(
                        f"Branch isolation: cannot delete remote branch '{dst}'"
                    )
            else:
                # src:dst — check both sides
                if src and not _is_allowed_ref(src, sandbox_branch, base_branch):
                    return ValidationError(
                        f"Branch isolation: push source '{src}' not allowed"
                    )
                if dst and not _is_allowed_ref(dst, sandbox_branch, base_branch):
                    return ValidationError(
                        f"Branch isolation: push destination '{dst}' not allowed"
                    )
        else:
            # Bare refspec — check as ref
            if spec and not _is_allowed_ref(spec, sandbox_branch, base_branch):
                return ValidationError(
                    f"Branch isolation: push ref '{spec}' not allowed"
                )

    return None


def _validate_worktree_add_isolation(
    sub_args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[ValidationError]:
    """Validate worktree add args for branch isolation."""
    skip_next = False
    positionals: List[str] = []

    for a in sub_args:
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if a in ("-b", "-B"):
            skip_next = True  # next is branch name (new, allowed)
            continue
        if not a.startswith("-"):
            positionals.append(a)

    # worktree add <path> [<commit-ish>]
    # First positional is path, second is commit-ish
    if len(positionals) >= 2:
        commit_ish = positionals[1]
        if not _is_allowed_ref(commit_ish, sandbox_branch, base_branch):
            return ValidationError(
                f"Branch isolation: commit-ish '{commit_ish}' not allowed "
                f"in worktree add"
            )

    return None


def _validate_tag_isolation(
    sub_args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[ValidationError]:
    """Validate tag args for branch isolation.

    ``git tag <tagname> [<commit-ish>]`` -- the commit-ish (if present)
    must be an allowed ref.  We also block ``-d`` on tags we do not own
    (handled elsewhere), but the main concern here is the commit-ish
    argument that lets a sandbox read from another branch.
    """
    skip_next = False
    positionals: List[str] = []

    for a in sub_args:
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if a in _TAG_VALUE_FLAGS:
            skip_next = True
            continue
        if "=" in a and a.split("=", 1)[0] in _TAG_VALUE_FLAGS:
            continue
        if a.startswith("-"):
            continue
        positionals.append(a)

    # tag <tagname> [<commit-ish>]
    # First positional is the tag name (always allowed), second is commit-ish
    if len(positionals) >= 2:
        commit_ish = positionals[1]
        if not _is_allowed_ref(commit_ish, sandbox_branch, base_branch):
            return ValidationError(
                f"Branch isolation: commit-ish '{commit_ish}' not allowed "
                f"in tag creation"
            )

    return None


def _validate_ref_reading_isolation(
    sub_args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[ValidationError]:
    """Validate ref-reading command args for branch isolation.

    Blocks --all/--branches/--remotes/--glob flags and checks each
    positional ref argument.
    """
    for a in sub_args:
        if a == "--":
            break  # rest are pathspecs
        if a in _IMPLICIT_ALL_REF_FLAGS:
            return ValidationError(
                f"Branch isolation: flag '{a}' not allowed (exposes all branches)"
            )
        for prefix in _IMPLICIT_REF_FLAG_PREFIXES:
            if a.startswith(prefix):
                return ValidationError(
                    f"Branch isolation: flag '{a}' not allowed "
                    f"(exposes multiple branches)"
                )

    # Check positional ref args (before --), skipping known option values.
    skip_next = False
    for a in sub_args:
        if a == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if a in _REF_READING_VALUE_FLAGS:
            skip_next = True
            continue
        if "=" in a and a.split("=", 1)[0] in _REF_READING_VALUE_FLAGS:
            continue
        if a.startswith("-"):
            continue
        if not _is_allowed_ref(a, sandbox_branch, base_branch):
            return ValidationError(
                f"Branch isolation: ref '{a}' not allowed. "
                f"If this is a file path, use -- to separate paths from refs."
            )

    return None


# ---------------------------------------------------------------------------
# SHA Reachability Enforcement
# ---------------------------------------------------------------------------


def _extract_sha_args(sub_args: List[str]) -> List[str]:
    """Collect SHA-like positional args from a ref-reading command.

    Handles range operators (``..``, ``...``) and strips revision
    suffixes before checking whether a token looks like a SHA.
    Stops at ``--`` (pathspec separator).
    Skips values consumed by known option flags (mirrors
    ``_validate_ref_reading_isolation`` behaviour).
    """
    shas: List[str] = []
    skip_next = False
    for arg in sub_args:
        if arg == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if arg in _REF_READING_VALUE_FLAGS:
            skip_next = True
            continue
        if "=" in arg and arg.split("=", 1)[0] in _REF_READING_VALUE_FLAGS:
            continue
        if arg.startswith("-"):
            continue
        # Expand range operators
        for sep in ("...", ".."):
            if sep in arg:
                parts = arg.split(sep, 1)
                for part in parts:
                    if part:
                        base = _strip_rev_suffixes(part)
                        if _is_sha_like(base):
                            shas.append(base)
                break
        else:
            base = _strip_rev_suffixes(arg)
            if _is_sha_like(base):
                shas.append(base)
    return shas


def _get_allowed_refs(
    bare_repo: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> List[str]:
    """Build the list of fully-qualified refs this sandbox may access.

    Includes the sandbox's own branch, base branch (if any), well-known
    branches (matched via ``for-each-ref``), and all tags.

    Args:
        bare_repo: Path to the bare git repository.
        sandbox_branch: This sandbox's branch name.

    Returns:
        List of fully-qualified ref patterns for ``--stdin`` input.
    """
    refs: List[str] = [f"refs/heads/{sandbox_branch}"]
    if base_branch:
        refs.append(f"refs/heads/{base_branch}")

    # Well-known branches
    for name in WELL_KNOWN_BRANCHES:
        refs.append(f"refs/heads/{name}")

    # Well-known prefixes — enumerate matching refs via for-each-ref
    for prefix in WELL_KNOWN_BRANCH_PREFIXES:
        try:
            result = subprocess.run(
                [GIT_BINARY, "--git-dir", bare_repo,
                 "for-each-ref", "--format=%(refname)",
                 f"refs/heads/{prefix}"],
                capture_output=True, timeout=SHA_CHECK_TIMEOUT,
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.decode().splitlines():
                    line = line.strip()
                    if line:
                        refs.append(line)
        except (subprocess.TimeoutExpired, OSError):
            pass

    # All tags
    refs.append("refs/tags/")

    return refs


def _check_sha_reachability(
    sha: str,
    bare_repo: str,
    allowed_refs: List[str],
    cache: dict,
) -> bool:
    """Check whether *sha* is reachable from any allowed ref.

    Strategy:
      1. Check tag containment first (single ``merge-base --is-ancestor``
         call against all tags is fast because tags share object storage).
      2. Check branch reachability via ``merge-base --is-ancestor`` with
         early exit on first match.

    Results are memoized in *cache* for the duration of a single request.

    Args:
        sha: The SHA hex string to verify.
        bare_repo: Path to the bare git repository.
        allowed_refs: Fully-qualified ref list from ``_get_allowed_refs``.
        cache: Per-request dict for memoization.

    Returns:
        True if reachable, False otherwise.
    """
    if sha in cache:
        return cache[sha]

    # Check each allowed ref (tags prefix handled specially)
    for ref in allowed_refs:
        if ref.endswith("/"):
            # Tag prefix — use for-each-ref --contains with --count=1
            # for early exit after first match (faster than `git tag
            # --contains` which enumerates all matching tags).
            try:
                result = subprocess.run(
                    [GIT_BINARY, "--git-dir", bare_repo,
                     "for-each-ref", f"--contains={sha}",
                     "refs/tags/", "--count=1",
                     "--format=%(refname)"],
                    capture_output=True, timeout=SHA_CHECK_TIMEOUT,
                )
                if result.returncode == 0 and result.stdout.strip():
                    cache[sha] = True
                    return True
            except subprocess.TimeoutExpired:
                logger.warning(
                    "SHA reachability: timeout checking %s against %s",
                    sha, ref,
                )
            except OSError:
                pass
            continue

        # Branch ref — single merge-base check
        try:
            result = subprocess.run(
                [GIT_BINARY, "--git-dir", bare_repo,
                 "merge-base", "--is-ancestor", sha, ref],
                capture_output=True, timeout=SHA_CHECK_TIMEOUT,
            )
            if result.returncode == 0:
                cache[sha] = True
                return True
        except subprocess.TimeoutExpired:
            logger.warning(
                "SHA reachability: timeout checking %s against %s",
                sha, ref,
            )
            continue
        except OSError:
            continue

    cache[sha] = False
    return False


def validate_sha_reachability(
    args: List[str],
    repo_root: str,
    metadata: Optional[dict],
) -> Optional[ValidationError]:
    """Validate that SHA arguments are reachable from allowed branches.

    Only applies to ref-reading commands (log, show, diff, etc.) when
    branch isolation is active.  Skips checks for shallow repos.

    Args:
        args: Git command arguments (without ``git`` prefix).
        repo_root: Server-side repository root path.
        metadata: Container metadata dict (must contain ``sandbox_branch``).

    Returns:
        None if allowed, ValidationError if a SHA is unreachable.
    """
    if not metadata:
        return None
    sandbox_branch = metadata.get("sandbox_branch")
    if not sandbox_branch:
        return None
    base_branch = _normalize_base_branch(metadata.get("from_branch"))

    subcommand, sub_args, _ = get_subcommand_args(args)
    if subcommand is None:
        return None

    # Only check ref-reading commands
    if subcommand not in _REF_READING_CMDS:
        return None

    # Extract SHA-like args
    shas = _extract_sha_args(sub_args)
    if not shas:
        return None

    # Resolve bare repo — fail closed if resolution fails
    bare_repo = resolve_bare_repo_path(repo_root)
    if not bare_repo:
        return ValidationError(
            "Branch isolation: cannot resolve bare repo path for SHA "
            "reachability check"
        )

    # Shallow repo: skip checks (log warning)
    shallow_file = os.path.join(bare_repo, "shallow")
    if os.path.isfile(shallow_file):
        logger.warning(
            "SHA reachability check skipped: shallow repo at %s", bare_repo,
        )
        return None

    # Build allowed refs and check each SHA
    allowed_refs = _get_allowed_refs(bare_repo, sandbox_branch, base_branch)
    cache: dict = {}

    for sha in shas:
        if not _check_sha_reachability(sha, bare_repo, allowed_refs, cache):
            return ValidationError(
                f"Branch isolation: SHA '{sha}' is not reachable from "
                f"allowed branches"
            )

    return None
