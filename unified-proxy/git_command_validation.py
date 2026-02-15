"""Git command validation: allowlists, flag blocklists, and input validators.

Extracted from git_operations.py to reduce module size.  Contains all
constants, dataclasses, and validation functions that run *before*
subprocess execution.
"""

import base64
import os
import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from branch_types import ValidationError, get_subcommand_args

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_STDIN_SIZE = 1 * 1024 * 1024       # 1MB decoded stdin
MAX_RESPONSE_SIZE = 10 * 1024 * 1024   # 10MB response truncation
MAX_REQUEST_BODY_SIZE = 256 * 1024     # 256KB request body
MAX_ARGS_COUNT = 256                    # Max number of args
MAX_ARG_LENGTH = 8 * 1024              # 8KB per arg
MAX_CONCURRENT_PER_SANDBOX = 4         # Max in-flight ops per sandbox
SUBPROCESS_TIMEOUT = 120               # 2 minutes

# ---------------------------------------------------------------------------
# Command Allowlist (deny-by-default)
# ---------------------------------------------------------------------------

# Working tree commands
_WORKING_TREE_CMDS = frozenset({
    "status", "add", "restore", "stash", "clean",
})

# Committing commands
_COMMIT_CMDS = frozenset({
    "commit", "cherry-pick", "merge", "rebase", "revert",
})

# Branching commands
_BRANCH_CMDS = frozenset({
    "branch", "checkout", "switch", "tag",
})

# History commands
_HISTORY_CMDS = frozenset({
    "diff", "show", "log", "blame", "shortlog",
    "describe", "name-rev",
})

# Remote commands
_REMOTE_CMDS = frozenset({
    "fetch", "pull", "push", "remote",
})

# Clone commands
_CLONE_CMDS = frozenset({
    "clone",
})

# Patch commands
_PATCH_CMDS = frozenset({
    "apply", "am", "format-patch",
})

# Notes (read-only enforced separately)
_NOTES_CMDS = frozenset({
    "notes",
})

# Config (restricted subcommands enforced separately)
_CONFIG_CMDS = frozenset({
    "config",
})

# Sparse checkout (read-only subcommands enforced separately)
_SPARSE_CHECKOUT_CMDS = frozenset({
    "sparse-checkout",
})

# Plumbing commands
_PLUMBING_CMDS = frozenset({
    "rev-parse", "symbolic-ref", "for-each-ref", "ls-tree",
    "ls-files", "ls-remote", "cat-file", "rev-list",
    "diff-tree", "diff-files", "diff-index",
})

ALLOWED_COMMANDS: FrozenSet[str] = (
    _WORKING_TREE_CMDS
    | _COMMIT_CMDS
    | _BRANCH_CMDS
    | _HISTORY_CMDS
    | _REMOTE_CMDS
    | _CLONE_CMDS
    | _PATCH_CMDS
    | _NOTES_CMDS
    | _CONFIG_CMDS
    | _SPARSE_CHECKOUT_CMDS
    | _PLUMBING_CMDS
)

# ---------------------------------------------------------------------------
# Flag Blocklist (per-operation)
# ---------------------------------------------------------------------------

GLOBAL_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--git-dir",
    "--work-tree",
    "--exec",
    "--upload-pack",
    "--receive-pack",
})

# Per-command destructive flag blocking
_PUSH_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f", "--force-with-lease", "--force-if-includes",
})

_REBASE_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--interactive", "-i",
})

# Destructive variants for checkout/switch/branch/clean
_CHECKOUT_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f",
})

_SWITCH_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f", "--discard-changes",
})

_BRANCH_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "--force", "-f", "-D",
})

_CLEAN_BLOCKED_FLAGS: FrozenSet[str] = frozenset({
    "-f", "--force", "-fd", "-fx", "-fxd", "-fX",
    "-d", "-x", "-X",
})

# Only --dry-run is allowed for clean
_CLEAN_ALLOWED_FLAGS: FrozenSet[str] = frozenset({
    "--dry-run", "-n",
})

COMMAND_BLOCKED_FLAGS: Dict[str, FrozenSet[str]] = {
    "push": _PUSH_BLOCKED_FLAGS,
    "rebase": _REBASE_BLOCKED_FLAGS,
    "checkout": _CHECKOUT_BLOCKED_FLAGS,
    "switch": _SWITCH_BLOCKED_FLAGS,
    "branch": _BRANCH_BLOCKED_FLAGS,
    "clean": _CLEAN_BLOCKED_FLAGS,
}

# ---------------------------------------------------------------------------
# Remote Subcommand Validation
# ---------------------------------------------------------------------------

REMOTE_ALLOWED_SUBCOMMANDS: FrozenSet[str] = frozenset({
    "-v", "show", "get-url",
})

REMOTE_BLOCKED_SUBCOMMANDS: FrozenSet[str] = frozenset({
    "add", "set-url", "remove", "rename",
})

# ---------------------------------------------------------------------------
# Clone Validation
# ---------------------------------------------------------------------------

# Always-allowed repos for Claude plugin marketplaces (read-only)
# Must match unified-proxy/addons/git_proxy.py
ALLOWED_MARKETPLACES: FrozenSet[str] = frozenset({
    "anthropics/claude-plugins-official",
    "foundry-works/claude-foundry",
})

# Only allow HTTPS GitHub URLs (ensures proxy enforcement)
_GITHUB_HTTPS_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)

# Clone options that consume a value argument.
_CLONE_OPTIONS_WITH_VALUE: FrozenSet[str] = frozenset({
    "-b", "--branch",
    "-o", "--origin",
    "-c", "--config",
    "--depth",
    "--filter",
    "--shallow-since",
    "--shallow-exclude",
    "--reference",
    "--reference-if-able",
    "--separate-git-dir",
    "--template",
    "--upload-pack",
    "-j", "--jobs",
})

# Short options that may embed their value (e.g. -bmain)
_CLONE_SHORT_EMBED_OPTS: Tuple[str, ...] = (
    "-b",
    "-o",
    "-c",
    "-j",
)

# Base64-safe credential pattern (user:pass@) — reject for clone URLs
_CLONE_CRED_RE = re.compile(r"://[^/:@]+:[^/:@]+@")

# ---------------------------------------------------------------------------
# Config Key Validation (-c key=value)
# ---------------------------------------------------------------------------

# Never-allow list: checked FIRST, always rejected
CONFIG_NEVER_ALLOW: Tuple[str, ...] = (
    "alias.",
    "core.sshCommand",
    "core.pager",
    "core.editor",
    "core.hooksPath",
    "core.fsmonitor",
    "core.gitProxy",
    "core.askPass",
    "credential.",
    "http.",
    "remote.*.proxy",      # matched via special logic
    "remote.*.pushurl",    # matched via special logic
    "protocol.*.allow",    # matched via special logic
    "diff.*.textconv",     # matched via special logic
    "diff.*.command",      # matched via special logic
    "filter.",
    "merge.*.driver",      # matched via special logic
    "gpg.",
    "sendemail.",
    "browser.",
    "instaweb.",
    "difftool.*.cmd",      # matched via special logic
    "mergetool.*.cmd",     # matched via special logic
    "sequence.editor",
)

# Permitted prefixes: only checked if not in never-allow
CONFIG_PERMITTED_PREFIXES: Tuple[str, ...] = (
    "user.",
    "color.",
    "core.quotepath",
    "core.autocrlf",
    "core.eol",
    "core.whitespace",
    "core.sparseCheckout",
    "core.sparseCheckoutCone",
    "diff.",
    "merge.",
    "format.",
    "log.",
    "pretty.",
    "column.",
    "pager.",
)

# ---------------------------------------------------------------------------
# Config Subcommand Validation
# ---------------------------------------------------------------------------

CONFIG_ALLOWED_FLAGS: FrozenSet[str] = frozenset({
    "--get", "--list", "--get-regexp",
    "--get-all", "--get-urlmatch",
    "-l",
})

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class GitExecRequest:
    """Request to execute a git command."""

    args: List[str]
    cwd: Optional[str] = None
    stdin_b64: Optional[str] = None


@dataclass
class GitExecResponse:
    """Response from git command execution."""

    exit_code: int
    stdout: str
    stderr: str
    stdout_b64: Optional[str] = None
    truncated: bool = False

    def to_dict(self) -> dict:
        result = {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
        }
        if self.stdout_b64 is not None:
            result["stdout_b64"] = self.stdout_b64
        return result


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------


def validate_request(raw: dict) -> Tuple[Optional[GitExecRequest], Optional[ValidationError]]:
    """Parse and validate a raw request dict.

    Returns (request, None) on success, (None, error) on failure.
    """
    if not isinstance(raw, dict):
        return None, ValidationError("Request must be a JSON object")

    args = raw.get("args")
    if not isinstance(args, list) or len(args) == 0:
        return None, ValidationError("args must be a non-empty array", "args")

    if len(args) > MAX_ARGS_COUNT:
        return None, ValidationError(
            f"Too many arguments: {len(args)} > {MAX_ARGS_COUNT}", "args"
        )

    for i, arg in enumerate(args):
        if not isinstance(arg, str):
            return None, ValidationError(
                f"args[{i}] must be a string", "args"
            )
        if len(arg) > MAX_ARG_LENGTH:
            return None, ValidationError(
                f"args[{i}] exceeds max length: {len(arg)} > {MAX_ARG_LENGTH}",
                "args",
            )

    cwd = raw.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        return None, ValidationError("cwd must be a string or null", "cwd")

    stdin_b64 = raw.get("stdin_b64")
    if stdin_b64 is not None:
        if not isinstance(stdin_b64, str):
            return None, ValidationError(
                "stdin_b64 must be a string or null", "stdin_b64"
            )
        try:
            decoded = base64.b64decode(stdin_b64)
        except Exception:
            return None, ValidationError(
                "stdin_b64 is not valid base64", "stdin_b64"
            )
        if len(decoded) > MAX_STDIN_SIZE:
            return None, ValidationError(
                f"Decoded stdin exceeds limit: {len(decoded)} > {MAX_STDIN_SIZE}",
                "stdin_b64",
            )

    return GitExecRequest(args=args, cwd=cwd, stdin_b64=stdin_b64), None


def validate_command(
    args: List[str],
    extra_allowed: Optional[Set[str]] = None,
) -> Optional[ValidationError]:
    """Validate git command args against allowlist and flag restrictions.

    Args:
        args: The git command arguments (without 'git' prefix).
        extra_allowed: Additional commands allowed per-sandbox from metadata.

    Returns:
        None if valid, ValidationError if blocked.
    """
    if not args:
        return ValidationError("Empty command")

    # Extract subcommand and args using shared helper (needed before flag
    # checking so we can distinguish global options from subcommand args)
    subcommand, subcommand_args, config_pairs = get_subcommand_args(args)

    # Determine pre-subcommand args (true global options)
    if subcommand is not None:
        try:
            sub_idx = args.index(subcommand)
        except ValueError:
            sub_idx = len(args)
        pre_subcommand_args = args[:sub_idx]
    else:
        pre_subcommand_args = args

    # Check global blocked flags in pre-subcommand args (true global options)
    for arg in pre_subcommand_args:
        flag_name = arg.split("=", 1)[0]
        if flag_name in GLOBAL_BLOCKED_FLAGS:
            return ValidationError(f"Blocked flag: {flag_name}")

    # Check global blocked flags in subcommand args too, EXCEPT for
    # rev-parse which legitimately uses --git-dir/--work-tree as query flags
    _REV_PARSE_SAFE_FLAGS = frozenset({"--git-dir", "--work-tree"})
    blocked_in_subargs = GLOBAL_BLOCKED_FLAGS
    if subcommand == "rev-parse":
        blocked_in_subargs = GLOBAL_BLOCKED_FLAGS - _REV_PARSE_SAFE_FLAGS

    for arg in subcommand_args:
        flag_name = arg.split("=", 1)[0]
        if flag_name in blocked_in_subargs:
            return ValidationError(f"Blocked flag: {flag_name}")
    if subcommand is None:
        return ValidationError("No subcommand found")

    # Check subcommand against allowlist
    allowed = ALLOWED_COMMANDS
    if extra_allowed:
        allowed = allowed | frozenset(extra_allowed)

    if subcommand not in allowed:
        return ValidationError(f"Command not allowed: {subcommand}")

    # Validate -c config keys
    for pair in config_pairs:
        err = _validate_config_key(pair)
        if err:
            return err

    # Per-command flag validation
    err = _validate_command_flags(subcommand, subcommand_args)
    if err:
        return err

    # Remote subcommand validation
    if subcommand == "remote":
        err = _validate_remote_subcommand(subcommand_args)
        if err:
            return err

    # Config subcommand validation
    if subcommand == "config":
        err = _validate_config_subcommand(subcommand_args)
        if err:
            return err

    # Notes: only allow read-only operations
    if subcommand == "notes":
        err = _validate_notes_subcommand(subcommand_args)
        if err:
            return err

    # Sparse checkout: only allow 'list'
    if subcommand == "sparse-checkout":
        err = _validate_sparse_checkout_subcommand(subcommand_args)
        if err:
            return err

    # Clean: only allow --dry-run
    if subcommand == "clean":
        err = _validate_clean_flags(subcommand_args)
        if err:
            return err

    return None


def _validate_config_key(pair: str) -> Optional[ValidationError]:
    """Validate a -c key=value config override.

    Never-allow list is checked BEFORE permitted prefixes.
    """
    # Parse key from key=value
    key = pair.split("=", 1)[0] if "=" in pair else pair

    if not key:
        return ValidationError("Empty config key in -c option")

    # Check never-allow list FIRST
    for pattern in CONFIG_NEVER_ALLOW:
        if pattern.endswith("."):
            # Prefix match (e.g., "alias." matches "alias.anything")
            if key.startswith(pattern) or key == pattern.rstrip("."):
                return ValidationError(f"Blocked config key: {key}")
        elif "*" in pattern:
            # Wildcard pattern like "remote.*.proxy"
            if _matches_wildcard_config(key, pattern):
                return ValidationError(f"Blocked config key: {key}")
        else:
            # Exact match
            if key == pattern:
                return ValidationError(f"Blocked config key: {key}")

    # Check permitted prefixes
    for prefix in CONFIG_PERMITTED_PREFIXES:
        if key.startswith(prefix) or key == prefix.rstrip("."):
            return None

    return ValidationError(f"Config key not in permitted list: {key}")


def _matches_wildcard_config(key: str, pattern: str) -> bool:
    """Match a config key against a wildcard pattern like 'remote.*.proxy'.

    The '*' matches exactly one dotted segment.
    """
    parts = pattern.split(".")
    key_parts = key.split(".")

    if len(key_parts) != len(parts):
        return False

    for p, k in zip(parts, key_parts):
        if p == "*":
            continue
        if p != k:
            return False

    return True


def _validate_command_flags(
    subcommand: str, args: List[str]
) -> Optional[ValidationError]:
    """Check per-command blocked flags."""
    blocked = COMMAND_BLOCKED_FLAGS.get(subcommand)
    if not blocked:
        return None

    for arg in args:
        flag_name = arg.split("=", 1)[0]
        if flag_name in blocked:
            return ValidationError(
                f"Blocked flag for {subcommand}: {flag_name}"
            )

    return None


def _validate_remote_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git remote subcommands — explicit enumeration."""
    if not args:
        # bare 'git remote' lists remotes — allowed
        return None

    subcmd = args[0]

    if subcmd in REMOTE_BLOCKED_SUBCOMMANDS:
        return ValidationError(f"Remote subcommand not allowed: {subcmd}")

    if subcmd.startswith("-"):
        # Flags like -v are checked against allowed set
        if subcmd not in REMOTE_ALLOWED_SUBCOMMANDS:
            return ValidationError(f"Remote flag not allowed: {subcmd}")

    # Allow subcommands in the allowed set
    if subcmd in REMOTE_ALLOWED_SUBCOMMANDS:
        return None

    # Unknown subcommands are blocked by default
    return ValidationError(f"Remote subcommand not allowed: {subcmd}")


def _extract_clone_positionals(args: List[str]) -> List[str]:
    """Extract positional args from clone subcommand args.

    Returns [repo, dest] (dest optional) after stripping flags and
    options that consume values.
    """
    positionals: List[str] = []
    idx = 0
    while idx < len(args):
        arg = args[idx]

        # -- terminates options; everything after is positional
        if arg == "--":
            idx += 1
            positionals.extend(args[idx:])
            break

        # Options that consume values (separate arg)
        if arg in _CLONE_OPTIONS_WITH_VALUE:
            idx += 2
            continue

        # --opt=value form
        if any(
            arg.startswith(opt + "=")
            for opt in _CLONE_OPTIONS_WITH_VALUE
            if opt.startswith("--")
        ):
            idx += 1
            continue

        # Short options with embedded value (e.g. -bmain)
        for opt in _CLONE_SHORT_EMBED_OPTS:
            if arg.startswith(opt) and len(arg) > len(opt):
                idx += 1
                break
        else:
            if arg.startswith("-"):
                idx += 1
                continue

            positionals.append(arg)
            idx += 1
            continue

        # Embedded short opt consumed
        continue

    return positionals


def _parse_github_https_repo(url: str) -> Optional[str]:
    """Parse https://github.com/<owner>/<repo>[.git] URLs into owner/repo."""
    if not url:
        return None
    if _CLONE_CRED_RE.search(url):
        return None
    match = _GITHUB_HTTPS_RE.match(url)
    if not match:
        return None
    owner = match.group("owner")
    repo = match.group("repo")
    return f"{owner}/{repo}"


def _get_allowed_repos(metadata: Optional[dict]) -> List[str]:
    """Get allowed repos from container metadata in owner/repo form."""
    if not metadata:
        return []
    allowed_repos = metadata.get("repos", [])
    if not allowed_repos:
        repo = metadata.get("repo")
        if repo:
            allowed_repos = [repo]
    return allowed_repos if isinstance(allowed_repos, list) else []


def validate_clone_args(
    args: List[str],
    metadata: Optional[dict] = None,
) -> Tuple[Optional[List[str]], Optional[ValidationError]]:
    """Validate clone arguments and return extra allowed roots.

    Enforces:
    - HTTPS GitHub URLs only
    - Repo must be in allowed_repos or ALLOWED_MARKETPLACES
    - Disallow embedded credentials in URL

    Returns:
        (extra_allowed_roots, None) if valid, (None, ValidationError) if blocked.
        For non-clone commands, returns (None, None).
    """
    subcommand, sub_args, _ = get_subcommand_args(args)
    if subcommand != "clone":
        return None, None

    positionals = _extract_clone_positionals(sub_args)
    if not positionals:
        return None, ValidationError("Clone requires a repository URL")

    repo_url = positionals[0]
    repo_spec = _parse_github_https_repo(repo_url)
    if not repo_spec:
        return None, ValidationError(
            "Clone URL not allowed: must be https://github.com/<owner>/<repo>[.git]"
        )

    allowed_repos = _get_allowed_repos(metadata)
    if repo_spec not in allowed_repos and repo_spec not in ALLOWED_MARKETPLACES:
        return None, ValidationError(
            f"Clone repository not authorized: {repo_spec}"
        )

    # Allow clone destinations under the Claude plugin dirs.
    # The git API runs as root (HOME=/root) but the dev container user
    # is always ubuntu (HOME=/home/ubuntu).
    client_home = os.environ.get("CONTAINER_HOME", "/home/ubuntu")
    plugin_base = os.path.join(client_home, ".claude", "plugins")
    plugin_cache_root = os.path.join(plugin_base, "cache")
    plugin_marketplaces_root = os.path.join(plugin_base, "marketplaces")
    return [plugin_cache_root, plugin_marketplaces_root], None


def _strip_clone_config_overrides(args: List[str]) -> List[str]:
    """Strip config overrides that are safe to ignore for HTTPS clones.

    Currently drops core.sshCommand when present as a global -c option.
    This avoids blocking marketplace clones that inject sshCommand even
    though HTTPS URLs do not use SSH.
    """
    stripped: List[str] = []
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "-c" and idx + 1 < len(args):
            pair = args[idx + 1]
            key = pair.split("=", 1)[0]
            if key == "core.sshCommand":
                idx += 2
                continue
            stripped.extend([arg, pair])
            idx += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            pair = arg[2:]
            key = pair.split("=", 1)[0]
            if key == "core.sshCommand":
                idx += 1
                continue
            stripped.append(arg)
            idx += 1
            continue
        stripped.append(arg)
        idx += 1
    return stripped


def _validate_config_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git config — only read-only operations allowed."""
    if not args:
        # bare 'git config' shows help — allowed
        return None

    # Check that at least one allowed flag is present
    has_allowed = False
    for arg in args:
        if arg in CONFIG_ALLOWED_FLAGS:
            has_allowed = True
            break

    if not has_allowed:
        return ValidationError(
            "Config command requires --get, --list, or --get-regexp"
        )

    return None


def _validate_notes_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git notes — only read-only operations allowed."""
    write_subcmds = {"add", "append", "copy", "edit", "merge", "remove", "prune"}
    if args and args[0] in write_subcmds:
        return ValidationError(f"Notes subcommand not allowed: {args[0]}")
    return None


def _validate_sparse_checkout_subcommand(args: List[str]) -> Optional[ValidationError]:
    """Validate git sparse-checkout — only read-only 'list' subcommand allowed."""
    if not args:
        # bare 'git sparse-checkout' shows help — allowed
        return None

    subcmd = args[0]
    if subcmd != "list":
        return ValidationError(
            f"Sparse-checkout subcommand not allowed: {subcmd} (only 'list' is permitted)"
        )

    return None


def _validate_clean_flags(args: List[str]) -> Optional[ValidationError]:
    """Validate git clean — only --dry-run is allowed.

    Note: combined short options (e.g. ``-nfd``) are intentionally blocked
    because they don't exactly match ``-n``.  This is conservative by design
    — users must pass ``-n`` as a separate flag.
    """
    for arg in args:
        if arg.startswith("-") and arg not in _CLEAN_ALLOWED_FLAGS:
            return ValidationError(
                f"Clean only allows --dry-run/-n, got: {arg}"
            )
    return None


def validate_path(
    cwd: Optional[str], repo_root: str
) -> Tuple[str, Optional[ValidationError]]:
    """Validate and resolve working directory within repo root.

    Server-side repo root is authoritative. Client cwd is only used
    for relative subdirectory resolution within the repo root.

    Args:
        cwd: Client-requested working directory (relative to repo root).
        repo_root: Server-derived repo root path.

    Returns:
        (resolved_path, None) on success, ("", error) on failure.
    """
    if not repo_root:
        return "", ValidationError("No repo root configured")

    real_root = os.path.realpath(repo_root)

    if cwd is None or cwd in ("", ".", "/"):
        return real_root, None

    # Block path traversal
    if ".." in cwd.split(os.sep):
        return "", ValidationError("Path traversal (..) not allowed")

    # Resolve relative to repo root
    if os.path.isabs(cwd):
        # Absolute paths: must be within repo root
        resolved = os.path.realpath(cwd)
        # Compatibility: wrapper may send /workspace absolute paths while
        # the proxy repo_root is mounted at /git-workspace.
        client_workspace_root = os.path.realpath(
            os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
        )
        if (
            resolved == client_workspace_root
            or resolved.startswith(client_workspace_root + os.sep)
        ):
            rel = os.path.relpath(resolved, client_workspace_root)
            resolved = os.path.realpath(os.path.join(real_root, rel))
    else:
        resolved = os.path.realpath(os.path.join(real_root, cwd))

    if not resolved.startswith(real_root + os.sep) and resolved != real_root:
        return "", ValidationError(
            "Resolved path is outside repo root"
        )

    return resolved, None


def validate_path_args(
    args: List[str],
    repo_root: str,
    extra_allowed_roots: Optional[List[str]] = None,
) -> Optional[ValidationError]:
    """Check that path-like arguments don't contain traversal.

    Allows optional extra roots (absolute paths) for sanctioned operations
    like plugin marketplace clones.
    """
    real_root = os.path.realpath(repo_root)
    allowed_roots = [real_root]
    if extra_allowed_roots:
        for root in extra_allowed_roots:
            try:
                allowed_roots.append(os.path.realpath(root))
            except OSError:
                continue

    # Translate /workspace paths to repo_root (proxy mounts at /git-workspace)
    client_root = os.path.realpath(
        os.environ.get("GIT_CLIENT_WORKSPACE_ROOT", "/workspace")
    )

    for arg in args:
        # Skip flags
        if arg.startswith("-"):
            continue
        # Check for path traversal
        if ".." in arg.split(os.sep):
            return ValidationError(f"Path traversal (..) not allowed in arg: {arg}")
        # If it looks like a path (contains / or \), validate it
        if os.sep in arg or "/" in arg:
            resolved = os.path.realpath(os.path.join(real_root, arg))
            # Translate client workspace paths to server repo root
            if os.path.isabs(arg) and (
                resolved == client_root
                or resolved.startswith(client_root + os.sep)
            ):
                rel = os.path.relpath(resolved, client_root)
                resolved = os.path.realpath(os.path.join(real_root, rel))
            if not any(
                resolved == root or resolved.startswith(root + os.sep)
                for root in allowed_roots
            ):
                return ValidationError(f"Path outside allowed roots: {arg}")

    return None
