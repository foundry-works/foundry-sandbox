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
"""

import logging
import os
import re
import subprocess

# Re-export shared types and constants from branch_types
from .branch_types import (
    GIT_BINARY,
    REF_ENUM_CMDS,
    SHA_CHECK_TIMEOUT,
    ValidationError,
    WELL_KNOWN_BRANCHES,
    WELL_KNOWN_BRANCH_PREFIXES,
    _is_allowed_branch_name,
    _is_sha_like,
    _normalize_base_branch,
    get_subcommand_args,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bare Repo Resolution
# ---------------------------------------------------------------------------


def _is_within_boundary(resolved: str, boundary: str) -> bool:
    """Check that *resolved* is under *boundary* (inclusive).

    Both paths must already be canonicalized via ``os.path.realpath()``.
    Returns True when *resolved* equals *boundary* or is a child path.
    """
    if boundary == os.sep:
        return resolved.startswith(os.sep)
    return resolved == boundary or resolved.startswith(boundary + os.sep)


def resolve_bare_repo_path(repo_root: str) -> str | None:
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
        boundary = os.path.dirname(real_root)
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
                if not _is_within_boundary(resolved, boundary):
                    logger.warning(
                        "commondir escapes repo boundary: %s (boundary: %s)",
                        resolved, boundary,
                    )
                    return None
                return resolved
            # No commondir — .git itself is the git dir
            resolved_git = os.path.realpath(dot_git)
            if not _is_within_boundary(resolved_git, boundary):
                logger.warning(
                    ".git dir escapes repo boundary: %s (boundary: %s)",
                    resolved_git, boundary,
                )
                return None
            return resolved_git

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

        if not _is_within_boundary(bare_path, boundary):
            logger.warning(
                "worktree commondir escapes repo boundary: %s (boundary: %s)",
                bare_path, boundary,
            )
            return None

        return bare_path

    except (OSError, IOError) as exc:
        logger.debug("Could not resolve bare repo path from %s: %s", repo_root, exc)
        return None


# ---------------------------------------------------------------------------
# Branch Isolation Constants (local to this module)
# ---------------------------------------------------------------------------

# Commands that accept ref arguments for reading (not switching branches)
_REF_READING_CMDS: frozenset[str] = frozenset({
    "log", "show", "diff", "blame", "cherry-pick", "merge", "rebase",
    "reset", "rev-list", "diff-tree", "rev-parse", "shortlog", "describe",
    "name-rev", "archive", "format-patch",
    "cat-file", "ls-tree",
})

# Notes sub-subcommands (used in branch isolation for positional arg parsing)
_NOTES_SUBCMDS: frozenset[str] = frozenset({
    "list", "add", "copy", "append", "edit", "show",
    "merge", "remove", "prune",
})

# Flags that implicitly reference all branches/refs
_IMPLICIT_ALL_REF_FLAGS: frozenset[str] = frozenset({
    "--all", "--branches", "--remotes", "--glob",
})

# Flag prefixes that implicitly reference refs with patterns
_IMPLICIT_REF_FLAG_PREFIXES: tuple[str, ...] = (
    "--branches=", "--remotes=", "--glob=",
)

# Ref-reading flags that consume the next argument as a value.
# This prevents option values (e.g. ``-n 5``) from being misclassified as refs.
_REF_READING_VALUE_FLAGS: frozenset[str] = frozenset({
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
_FETCH_VALUE_FLAGS: frozenset[str] = frozenset({
    "--depth", "--deepen", "--shallow-since", "--shallow-exclude",
    "-j", "--jobs", "--negotiation-tip", "--server-option", "-o",
    "--upload-pack", "--refmap", "--recurse-submodules-default",
    "--filter",
})

# checkout/switch flags that consume the next argument as a value
_CHECKOUT_VALUE_FLAGS: frozenset[str] = frozenset({
    "-b", "-B",       # checkout: create branch
    "-c", "-C",       # switch: create branch
    "--orphan",       # checkout: create orphan branch
    "--conflict",     # checkout: conflict style
    "--pathspec-from-file",
})

# checkout/switch flags that indicate branch creation (next arg is new branch name)
_BRANCH_CREATE_FLAGS: frozenset[str] = frozenset({
    "-b", "-B", "-c", "-C", "--orphan",
})

_TAG_VALUE_FLAGS: frozenset[str] = frozenset({
    "-m", "--message", "-F", "--file", "-u", "--local-user",
    "--cleanup", "--sort",
})

# push flags that consume the next argument as a value
_PUSH_VALUE_FLAGS: frozenset[str] = frozenset({
    "--repo", "--receive-pack", "--exec", "--push-option", "-o",
})

# Ref-enumeration flags that either consume the next value or can remove ref
# names from output. Ref names must remain available for output filtering.
_REF_ENUM_VALUE_FLAGS: frozenset[str] = frozenset({
    "--sort", "--count", "--contains", "--no-contains",
    "--merged", "--no-merged", "--points-at", "--exclude",
    "--start-after",
})

_REF_ENUM_FORMAT_FLAGS: frozenset[str] = frozenset({
    "--format",
})

_SHOW_REF_HASH_ONLY_FLAGS: frozenset[str] = frozenset({
    "--hash", "-s",
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
    base_branch: str | None = None,
) -> bool:
    """Check if a ref argument is allowed under branch isolation.

    Allows: HEAD, @{...} forms, own sandbox branch, well-known branches,
    tags, SHA hashes (>= 12 hex chars, with reachability checked later
    for commands that accept commit-ish arguments), range operators
    (checked recursively).
    Blocks: FETCH_HEAD, other sandbox branches, short hex strings.
    """
    # Handle range operators recursively
    for sep in ("...", ".."):
        if sep in ref:
            parts = ref.split(sep, 1)
            return all(
                _is_allowed_ref(p, sandbox_branch, base_branch) for p in parts if p
            )

    # FETCH_HEAD is always blocked (could contain cross-branch data)
    if ref == "FETCH_HEAD":
        return False

    # HEAD and @{} forms are always allowed.
    # Check the original ref BEFORE stripping rev suffixes because
    # @{u}, @{upstream}, @{push} etc. are entirely consumed by the
    # suffix regex, leaving an empty string that would fail all checks.
    # These are safe: config writes are blocked so tracking refs can
    # only point to branches the sandbox already has push access to.
    if ref == "HEAD" or ref.startswith("@{"):
        return True

    # Strip revision suffixes
    base = _strip_rev_suffixes(ref)

    # Post-strip HEAD check (e.g. HEAD~3 → HEAD)
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
            if branch_part and re.fullmatch(r"[A-Za-z0-9_-]+", prefix):
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
    args: list[str],
    metadata: dict | None,
) -> ValidationError | None:
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

    subcommand, sub_args, _, _ = get_subcommand_args(args)
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

    # --- ref enum commands (validated here, output still filtered later) ---
    if subcommand in REF_ENUM_CMDS:
        return _validate_ref_enum_isolation(
            subcommand, sub_args, sandbox_branch, base_branch
        )

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
        positionals: list[str] = []
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
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
    """Validate checkout/switch args for branch isolation."""
    creating_branch = False
    skip_next = False
    positionals: list[str] = []
    start_point: str | None = None

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
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
    """Validate fetch/pull args for branch isolation."""
    skip_next = False
    positionals: list[str] = []

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
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
    """Validate push args for branch isolation.

    Ensures that a sandbox can only push to its own branch and well-known
    branches.  Blocks --all and --mirror (defense-in-depth; also blocked
    by check_push_protected_branches).
    """
    skip_next = False
    positionals: list[str] = []

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
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
    """Validate worktree add args for branch isolation."""
    skip_next = False
    positionals: list[str] = []

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
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
    """Validate tag args for branch isolation.

    ``git tag <tagname> [<commit-ish>]`` -- the commit-ish (if present)
    must be an allowed ref.  We also block ``-d`` on tags we do not own
    (handled elsewhere), but the main concern here is the commit-ish
    argument that lets a sandbox read from another branch.
    """
    skip_next = False
    positionals: list[str] = []

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


def _format_includes_refname(fmt: str) -> bool:
    """Return True when a for-each-ref format keeps a ref field in output."""
    return "%(refname" in fmt or "%(*refname" in fmt


def _validate_ref_enum_isolation(
    subcommand: str,
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
    """Validate commands that enumerate refs before output filtering.

    Output filtering needs ref names to decide which lines to drop.  Formats
    and flags that emit hashes without refs are therefore blocked.
    """
    skip_next = False
    pending_format = False
    positionals: list[str] = []

    for a in sub_args:
        if pending_format:
            pending_format = False
            if not _format_includes_refname(a):
                return ValidationError(
                    "Branch isolation: for-each-ref --format must include %(refname)"
                )
            continue

        if skip_next:
            skip_next = False
            continue

        if subcommand == "for-each-ref" and a == "--stdin":
            return ValidationError(
                "Branch isolation: for-each-ref --stdin is not allowed"
            )

        if subcommand == "show-ref":
            flag_name = a.split("=", 1)[0]
            if flag_name in _SHOW_REF_HASH_ONLY_FLAGS:
                return ValidationError(
                    "Branch isolation: show-ref hash-only output is not allowed"
                )

        if a in _REF_ENUM_FORMAT_FLAGS:
            pending_format = True
            continue
        if a.startswith("--format="):
            fmt = a.split("=", 1)[1]
            if not _format_includes_refname(fmt):
                return ValidationError(
                    "Branch isolation: for-each-ref --format must include %(refname)"
                )
            continue

        if a in _REF_ENUM_VALUE_FLAGS:
            skip_next = True
            continue
        if "=" in a and a.split("=", 1)[0] in _REF_ENUM_VALUE_FLAGS:
            continue

        if a.startswith("-"):
            continue

        positionals.append(a)

    if pending_format:
        return ValidationError("Branch isolation: missing value for --format")

    # ls-remote's first positional is the remote/repository, not a ref pattern.
    ref_patterns = positionals[1:] if subcommand == "ls-remote" else positionals
    for pattern in ref_patterns:
        if not _is_allowed_ref(pattern, sandbox_branch, base_branch):
            return ValidationError(
                f"Branch isolation: ref pattern '{pattern}' not allowed"
            )

    return None


def _validate_ref_reading_isolation(
    sub_args: list[str],
    sandbox_branch: str,
    base_branch: str | None = None,
) -> ValidationError | None:
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
# Pathspec Auto-Expansion
# ---------------------------------------------------------------------------

# File extensions that strongly indicate a path rather than a ref.
# Kept intentionally broad – false positives are harmless (git will just
# report "file not found"), while false negatives produce a confusing
# branch-isolation error.
_PATH_EXTENSION_RE = re.compile(
    r"\.[A-Za-z0-9]{1,10}$"
)


def _looks_like_path(arg: str) -> bool:
    """Heuristic: does *arg* look like a file path rather than a git ref?

    Returns True for arguments that contain a file extension, start with
    ``./`` or ``../``, or contain path separator characters combined with
    an extension-like suffix.  Returns False for range operators (``..``,
    ``...``) and revision suffixes.
    """
    # Range operators are refs, not paths
    if ".." in arg and not arg.startswith(".."):
        return False
    if arg.startswith("./") or arg.startswith("../"):
        return True
    # Contains a file extension (e.g. "docs/foo.md", "README.txt")
    if _PATH_EXTENSION_RE.search(arg):
        return True
    return False


def normalize_pathspec_args(
    args: list[str],
    metadata: dict | None,
) -> tuple[list[str], bool]:
    """Auto-insert ``--`` for ref-reading commands when args look like paths.

    When a user runs ``git diff docs/foo.md`` without a ``--`` separator,
    branch isolation treats ``docs/foo.md`` as a ref and blocks it.  This
    function detects the pattern and rewrites the args to insert ``--``
    before the first path-like positional argument.

    Applies to ref-reading commands (diff, log, show, blame, etc.) and
    checkout/switch (when not in branch-creation mode) when:

    - Branch isolation metadata is present
    - No ``--`` already exists in the subcommand args
    - At least one positional arg fails ref validation AND looks like a path

    Args:
        args: Full git argument list (without the ``git`` binary itself).
        metadata: Container metadata (must contain ``sandbox_branch``).

    Returns:
        ``(args, True)`` if the args were rewritten, ``(args, False)``
        otherwise.  The original *args* list is never mutated.
    """
    if not metadata or not metadata.get("sandbox_branch"):
        return args, False

    sandbox_branch = metadata["sandbox_branch"]
    base_branch = _normalize_base_branch(metadata.get("from_branch"))

    subcommand, sub_args, _, _ = get_subcommand_args(args)
    if subcommand is None:
        return args, False

    # Already has -- separator
    if "--" in sub_args:
        return args, False

    # Determine which value flags to use and whether to skip
    if subcommand in _REF_READING_CMDS:
        value_flags = _REF_READING_VALUE_FLAGS
    elif subcommand in ("checkout", "switch"):
        # Don't expand when creating a branch (-b, -B, -c, -C, --orphan)
        for a in sub_args:
            if a in _BRANCH_CREATE_FLAGS:
                return args, False
            if "=" in a and a.split("=", 1)[0] in _BRANCH_CREATE_FLAGS:
                return args, False
        value_flags = _CHECKOUT_VALUE_FLAGS
    else:
        return args, False

    # Find the index (in the full args list) of the first positional arg
    # that fails ref validation but looks like a file path.
    # We need to walk the full args list to find the correct insertion point.
    sub_start = len(args) - len(sub_args)
    skip_next = False
    insert_idx = None

    for i, a in enumerate(sub_args):
        if skip_next:
            skip_next = False
            continue
        if a in value_flags:
            skip_next = True
            continue
        if "=" in a and a.split("=", 1)[0] in value_flags:
            continue
        if a.startswith("-"):
            continue
        # Positional arg — check if it fails ref validation but looks like a path
        if not _is_allowed_ref(a, sandbox_branch, base_branch) and _looks_like_path(a):
            insert_idx = sub_start + i
            break

    if insert_idx is None:
        return args, False

    # Insert -- before the first path-like positional
    new_args = list(args[:insert_idx]) + ["--"] + list(args[insert_idx:])
    return new_args, True


# ---------------------------------------------------------------------------
# SHA Reachability Enforcement
# ---------------------------------------------------------------------------


def _extract_sha_args(sub_args: list[str]) -> list[str]:
    """Collect SHA-like positional args from a ref-reading command.

    Handles range operators (``..``, ``...``) and strips revision
    suffixes before checking whether a token looks like a SHA.
    Stops at ``--`` (pathspec separator).
    Skips values consumed by known option flags (mirrors
    ``_validate_ref_reading_isolation`` behaviour).
    """
    shas: list[str] = []
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


def _extract_tag_sha_args(sub_args: list[str]) -> list[str]:
    """Collect SHA-like commit-ish args from `git tag <name> [<commit>]`."""
    positionals: list[str] = []
    skip_next = False

    for arg in sub_args:
        if arg == "--":
            break
        if skip_next:
            skip_next = False
            continue
        if arg in _TAG_VALUE_FLAGS:
            skip_next = True
            continue
        if "=" in arg and arg.split("=", 1)[0] in _TAG_VALUE_FLAGS:
            continue
        if arg.startswith("-"):
            continue
        positionals.append(arg)

    if len(positionals) < 2:
        return []

    base = _strip_rev_suffixes(positionals[1])
    return [base] if _is_sha_like(base) else []


def _extract_checkout_sha_args(sub_args: list[str]) -> list[str]:
    """Collect SHA-like targets from checkout/switch commit-ish arguments."""
    creating_branch = False
    skip_next = False
    positionals: list[str] = []

    idx = 0
    while idx < len(sub_args):
        arg = sub_args[idx]
        if arg == "--":
            break
        if skip_next:
            skip_next = False
            idx += 1
            continue

        if arg in _BRANCH_CREATE_FLAGS:
            creating_branch = True
            skip_next = True
            idx += 1
            continue

        if arg in _CHECKOUT_VALUE_FLAGS:
            skip_next = True
            idx += 1
            continue

        flag_name = arg.split("=", 1)[0]
        if flag_name in _CHECKOUT_VALUE_FLAGS:
            if flag_name in _BRANCH_CREATE_FLAGS:
                creating_branch = True
            idx += 1
            continue

        if not arg.startswith("-"):
            positionals.append(arg)

        idx += 1

    if not positionals:
        return []

    target = positionals[-1] if creating_branch else positionals[0]
    base = _strip_rev_suffixes(target)
    return [base] if _is_sha_like(base) else []


def _get_allowed_refs(
    bare_repo: str,
    sandbox_branch: str,
    base_branch: str | None = None,
) -> list[str]:
    """Build the list of fully-qualified refs this sandbox may access.

    Includes the sandbox's own branch, base branch (if any), well-known
    branches (matched via ``for-each-ref``), and all tags.

    Args:
        bare_repo: Path to the bare git repository.
        sandbox_branch: This sandbox's branch name.

    Returns:
        List of fully-qualified ref patterns for ``--stdin`` input.
    """
    refs: list[str] = [f"refs/heads/{sandbox_branch}"]
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
    allowed_refs: list[str],
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
    args: list[str],
    repo_root: str,
    metadata: dict | None,
) -> ValidationError | None:
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

    subcommand, sub_args, _, _ = get_subcommand_args(args)
    if subcommand is None:
        return None

    # Check commands that can dereference raw commit-ish arguments.
    if subcommand == "tag":
        shas = _extract_tag_sha_args(sub_args)
    elif subcommand in ("checkout", "switch"):
        shas = _extract_checkout_sha_args(sub_args)
    elif subcommand in _REF_READING_CMDS:
        shas = _extract_sha_args(sub_args)
    else:
        return None

    if not shas:
        return None

    # Resolve bare repo — fail closed if resolution fails
    bare_repo = resolve_bare_repo_path(repo_root)
    if not bare_repo:
        return ValidationError(
            "Branch isolation: cannot resolve bare repo path for SHA "
            "reachability check"
        )

    # Shallow repo: fail closed (cannot verify reachability)
    shallow_file = os.path.join(bare_repo, "shallow")
    if os.path.isfile(shallow_file):
        return ValidationError(
            "Branch isolation: SHA reachability check cannot be performed on "
            "shallow repo. Deepen the clone or contact an administrator."
        )

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
