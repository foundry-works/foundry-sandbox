"""Push operation validation: protected branches, file restrictions, refspec parsing.

Extracted from operations.py to reduce module size.  Contains all push-specific
validation that runs before subprocess execution.
"""

import logging
import os
import subprocess
import time

from .branch_isolation import resolve_bare_repo_path
from .branch_types import (
    GIT_BINARY,
    SHA_CHECK_TIMEOUT,
    ValidationError,
)
from .config import (
    ConfigError,
    check_file_restrictions,
    get_file_restrictions_config,
)
from .policies import check_protected_branches
from .subprocess_env import build_clean_env

logger = logging.getLogger(__name__)

# TTL cache for default branch detection to avoid subprocess on every push
_DEFAULT_BRANCH_CACHE: dict[str, tuple[str | None, float]] = {}
_DEFAULT_BRANCH_CACHE_TTL = 300.0  # 5 minutes

# SHA used by git_policies to detect creation/deletion operations.
_ZERO_SHA = "0" * 40

# Synthetic SHAs for policy checks where real SHAs are unavailable.
# Any non-zero SHA signals "existing ref" to check_protected_branches.
_SYNTHETIC_OLD_SHA = "1" * 40
_SYNTHETIC_NEW_SHA = "2" * 40

# Push options that consume the following argument.
_PUSH_OPTIONS_WITH_VALUE: frozenset[str] = frozenset({
    "--repo",
    "--receive-pack",
    "--exec",
    "--upload-pack",
    "--push-option",
    "-o",
})


def _has_push_flag(args: list[str], flag: str) -> bool:
    """Check if a push flag is present in args."""
    return any(arg == flag or arg.startswith(flag + "=") for arg in args)


def _is_wildcard_refspec(spec: str) -> bool:
    """Check if a push refspec uses wildcard patterns."""
    if spec.startswith("+"):
        spec = spec[1:]

    parts: list[str]
    if ":" in spec:
        src, dst = spec.split(":", 1)
        parts = [src, dst]
    else:
        parts = [spec]

    wildcard_chars = ("*", "?", "[")
    for part in parts:
        if any(ch in part for ch in wildcard_chars):
            return True
    return False


def _extract_push_positionals(args: list[str]) -> list[str]:
    """Extract positional args from push subcommand args.

    Returns [remote, refspec1, refspec2, ...] after stripping flags
    and options that consume values.
    """
    positionals: list[str] = []
    idx = 0
    while idx < len(args):
        arg = args[idx]

        # -- terminates options; everything after is positional
        if arg == "--":
            idx += 1
            positionals.extend(args[idx:])
            break

        if arg in _PUSH_OPTIONS_WITH_VALUE:
            idx += 2
            continue

        if any(
            arg.startswith(opt + "=")
            for opt in _PUSH_OPTIONS_WITH_VALUE
            if opt.startswith("--")
        ):
            idx += 1
            continue

        if arg.startswith("-o") and arg != "-o":
            idx += 1
            continue

        if arg.startswith("-"):
            idx += 1
            continue

        positionals.append(arg)
        idx += 1

    return positionals


def _parse_push_refspecs(args: list[str]) -> list[str]:
    """Extract target refnames from push command arguments.

    Parses push subcommand args (after 'push') to find refspecs and extracts
    destination refs.

    Returns a list of fully qualified refnames (refs/heads/<branch>).
    """
    refs: list[str] = []

    positionals = _extract_push_positionals(args)
    if len(positionals) <= 1:
        return refs

    for spec in positionals[1:]:
        refs.extend(_parse_single_refspec(spec))

    return refs


def _parse_single_refspec(spec: str) -> list[str]:
    """Parse a single refspec into target refnames.

    Refspec forms:
      "branch"          -> push local branch to refs/heads/branch
      "src:dst"         -> push src to dst
      ":branch"         -> delete remote branch (handled separately)
      "+src:dst"        -> force push (+ prefix ignored, force flag handled elsewhere)
      "refs/heads/main" -> fully qualified ref
    """
    # Strip force prefix
    if spec.startswith("+"):
        spec = spec[1:]

    if ":" in spec:
        src, dst = spec.split(":", 1)
        if not dst:
            return []
        if not src:
            # Deletion refspec — handled separately in check_push_protected_branches
            return []
        return [_qualify_ref(dst)]
    else:
        if not spec:
            return []
        # "HEAD" without explicit destination is ambiguous for policy checks.
        if spec == "HEAD":
            return []
        return [_qualify_ref(spec)]


def _qualify_ref(ref: str) -> str:
    """Ensure a ref is fully qualified (refs/heads/...)."""
    if ref.startswith("refs/"):
        return ref
    return f"refs/heads/{ref}"


def extract_push_args(args: list[str]) -> list[str] | None:
    """Extract push subcommand arguments from a full git args list.

    Skips global flags and -c options to find the subcommand.
    Returns the args after 'push' if the command is a push,
    or None if it's not a push command.
    """
    idx = _find_push_index(args)
    if idx is None:
        return None
    return args[idx + 1:]


def _find_push_index(args: list[str]) -> int | None:
    """Return the index of ``"push"`` in a full git args list, or ``None``.

    Skips global ``-c`` key=value pairs and other global flags to locate
    the subcommand position.  Mirrors the skip logic of
    :func:`extract_push_args` but returns the index instead of the tail.
    """
    idx = 0
    while idx < len(args):
        arg = args[idx]
        # Skip -c key=value pairs
        if arg == "-c" and idx + 1 < len(args):
            idx += 2
            continue
        if arg.startswith("-c") and len(arg) > 2:
            idx += 1
            continue
        # Skip other global flags
        if arg.startswith("-"):
            idx += 1
            continue
        # Found the subcommand
        if arg == "push":
            return idx
        return None
    return None


def strip_credential_config_overrides(
    args: list[str],
) -> tuple[list[str], bool]:
    """Strip ``-c credential.*=...`` config overrides from git args.

    GitHub CLI (``gh``) and other tools inject ``-c credential.helper=...``
    overrides into their internal git commands.  The proxy's
    ``CONFIG_NEVER_ALLOW`` blocklist rejects these, causing the entire
    command to fail.

    Since the proxy manages credentials independently (via
    ``FOUNDRY_PROXY_GIT_TOKEN`` and the credential-helper script installed
    in ``entrypoint.sh``), client-side credential overrides are redundant
    and safe to remove.

    Args:
        args: Full git argument list (without the ``git`` binary itself).

    Returns:
        ``(args, True)`` if any overrides were stripped,
        ``(args, False)`` otherwise.  The original list is never mutated.
    """
    stripped: list[str] = []
    changed = False
    idx = 0
    while idx < len(args):
        arg = args[idx]
        # -c key=value (separate args)
        if arg == "-c" and idx + 1 < len(args):
            pair = args[idx + 1]
            key = pair.split("=", 1)[0] if "=" in pair else pair
            if key.startswith("credential.") or key == "credential":
                idx += 2
                changed = True
                continue
            stripped.extend([arg, pair])
            idx += 2
            continue
        # -ckey=value (combined form)
        if arg.startswith("-c") and len(arg) > 2:
            pair = arg[2:]
            key = pair.split("=", 1)[0] if "=" in pair else pair
            if key.startswith("credential.") or key == "credential":
                idx += 1
                changed = True
                continue
            stripped.append(arg)
            idx += 1
            continue
        stripped.append(arg)
        idx += 1
    return stripped, changed


def normalize_push_args(
    args: list[str], metadata: dict | None,
) -> tuple[list[str], bool]:
    """Auto-expand bare ``git push`` with the sandbox branch as refspec.

    When the sandbox AI runs ``git push`` or ``git push origin`` without a
    refspec, the proxy rejects it because branch isolation requires explicit
    targets.  Since the proxy always knows ``metadata["sandbox_branch"]``,
    we can infer the intended target and append it.

    Args:
        args: Full git argument list (without the ``git`` binary itself).
        metadata: Container metadata containing ``sandbox_branch``.

    Returns:
        ``(args, True)`` if the args were expanded, ``(args, False)``
        otherwise.  The original *args* list is never mutated; a new list
        is returned when expansion occurs.
    """
    if not metadata or not metadata.get("sandbox_branch"):
        return args, False

    push_idx = _find_push_index(args)
    if push_idx is None:
        return args, False

    push_sub_args = args[push_idx + 1:]

    # Don't interfere with broad push modes — existing validation handles them.
    for flag in ("--tags", "--all", "--mirror"):
        if _has_push_flag(push_sub_args, flag):
            return args, False

    positionals = _extract_push_positionals(push_sub_args)
    sandbox_branch = metadata["sandbox_branch"]

    if len(positionals) == 0:
        # git push → git push origin <branch>
        return list(args) + ["origin", sandbox_branch], True
    elif len(positionals) == 1:
        # git push origin → git push origin <branch>
        return list(args) + [sandbox_branch], True
    else:
        # Already has remote + refspec(s)
        return args, False


def _detect_default_branch(bare_repo_path: str) -> str | None:
    """Detect the default branch name from a bare repo's HEAD symref.

    Results are cached for 5 minutes to avoid spawning a subprocess
    on every push request.
    """
    now = time.monotonic()
    cached = _DEFAULT_BRANCH_CACHE.get(bare_repo_path)
    if cached is not None:
        branch, ts = cached
        if now - ts < _DEFAULT_BRANCH_CACHE_TTL:
            return branch

    try:
        result = subprocess.run(
            [GIT_BINARY, "--git-dir", bare_repo_path,
             "symbolic-ref", "HEAD"],
            capture_output=True, timeout=SHA_CHECK_TIMEOUT,
        )
        branch = None
        if result.returncode == 0:
            head_ref = result.stdout.decode("utf-8", errors="replace").strip()
            if head_ref.startswith("refs/heads/"):
                branch = head_ref[len("refs/heads/"):]
        _DEFAULT_BRANCH_CACHE[bare_repo_path] = (branch, now)
        return branch
    except (subprocess.TimeoutExpired, OSError):
        return None


def _inject_default_branch_protection(
    metadata: dict, default_branch: str,
) -> dict:
    """Return a shallow copy of *metadata* with the default branch added to protected patterns.

    Adds ``refs/heads/<default_branch>`` to
    ``metadata["git"]["protected_branches"]["patterns"]`` if not already present.
    Never mutates the caller's metadata dict.
    """
    default_pattern = f"refs/heads/{default_branch}"
    git_config = metadata.get("git", {})
    if not isinstance(git_config, dict):
        git_config = {}
    pb_config = git_config.get("protected_branches", {})
    if not isinstance(pb_config, dict):
        pb_config = {}
    patterns = list(pb_config.get("patterns", []))
    if default_pattern not in patterns:
        patterns.append(default_pattern)
        metadata = dict(metadata)
        metadata["git"] = dict(git_config)
        metadata["git"]["protected_branches"] = dict(pb_config)
        metadata["git"]["protected_branches"]["patterns"] = patterns
    return metadata


def check_push_protected_branches(
    args: list[str],
    repo_root: str,
    metadata: dict | None = None,
) -> ValidationError | None:
    """Check if a push command targets protected branches.

    Parses push CLI arguments to extract target refspecs, then checks
    each against the protected branch policy using the shared validator
    from git_policies.py.

    To avoid bypasses from implicit push targets, this validator requires
    explicit refspecs for branch pushes and blocks broad push modes
    (--all, --mirror).
    """
    bare_repo_path = resolve_bare_repo_path(repo_root)

    # Detect default branch from bare repo HEAD and inject into metadata
    # so that load_branch_policy() protects it.
    if bare_repo_path and metadata is not None:
        default_branch = _detect_default_branch(bare_repo_path)
        if default_branch:
            metadata = _inject_default_branch_protection(metadata, default_branch)

    if _has_push_flag(args, "--all") or _has_push_flag(args, "--mirror"):
        return ValidationError(
            "Push modes --all and --mirror are not allowed; use explicit refspecs"
        )

    positionals = _extract_push_positionals(args)
    if not positionals:
        return ValidationError("Push command must include a remote")

    # Only a remote specified: this relies on implicit/default push targets.
    if len(positionals) == 1:
        if _has_push_flag(args, "--tags"):
            return None
        return ValidationError(
            "Push command must include explicit refspecs for policy enforcement"
        )

    refspecs = positionals[1:]
    for spec in refspecs:
        if _is_wildcard_refspec(spec):
            return ValidationError(
                "Wildcard push refspecs are not allowed; use explicit branch names"
            )

    # --delete mode uses plain ref names after remote.
    if _has_push_flag(args, "--delete"):
        for target in refspecs:
            qualified = _qualify_ref(target)
            block_reason = check_protected_branches(
                refname=qualified,
                old_sha=_SYNTHETIC_OLD_SHA,
                new_sha=_ZERO_SHA,  # Deletion
                bare_repo_path=bare_repo_path,
                metadata=metadata,
            )
            if block_reason:
                return ValidationError(block_reason)
        return None

    # Check regular push refspecs (treated as updates).
    # NOTE: synthetic non-zero SHAs mean check_protected_branches always
    # classifies these as updates, never creations.  The security outcome is
    # correct (protected branches are still blocked), but the bootstrap
    # creation guard in policies.check_protected_branches is only reached
    # via the git-receive-pack hook path.
    refnames = _parse_push_refspecs(args)
    for refname in refnames:
        block_reason = check_protected_branches(
            refname=refname,
            old_sha=_SYNTHETIC_OLD_SHA,   # Non-zero: treat as update
            new_sha=_SYNTHETIC_NEW_SHA,   # Non-zero: treat as update
            bare_repo_path=bare_repo_path,
            metadata=metadata,
        )
        if block_reason:
            return ValidationError(block_reason)

    # Check deletion refspecs (":ref" form)
    saw_deletion = False
    for spec in refspecs:
        if spec.startswith("+"):
            spec = spec[1:]
        if ":" in spec:
            src, dst = spec.split(":", 1)
            if not src and dst:
                saw_deletion = True
                qualified = _qualify_ref(dst)
                block_reason = check_protected_branches(
                    refname=qualified,
                    old_sha=_SYNTHETIC_OLD_SHA,
                    new_sha=_ZERO_SHA,  # Deletion
                    bare_repo_path=bare_repo_path,
                    metadata=metadata,
                )
                if block_reason:
                    return ValidationError(block_reason)

    if not refnames and not saw_deletion and not _has_push_flag(args, "--tags"):
        return ValidationError(
            "Push refspecs could not be resolved; use explicit <src>:<dst> forms"
        )

    return None


def check_push_file_restrictions(
    args: list[str],
    repo_root: str,
    metadata: dict | None = None,
) -> ValidationError | None:
    """Check if a push modifies restricted files.

    Enumerates files changed between the remote branch and HEAD, then
    checks each against the file restriction config (blocked/warned patterns).

    Fails closed: if the config cannot be loaded or the diff cannot be
    computed, returns a ValidationError (blocks the push).
    """
    # Load file restrictions config (fail closed on error)
    try:
        config = get_file_restrictions_config()
    except ConfigError as exc:
        logger.warning("File restrictions config unavailable: %s", exc)
        return ValidationError(
            "File restrictions config unavailable; push blocked (fail-closed)"
        )

    # Parse the push target to determine the remote and branch
    positionals = _extract_push_positionals(args)
    if not positionals:
        return None

    remote = positionals[0]
    refspecs = positionals[1:] if len(positionals) > 1 else []

    # Determine the remote branch to diff against
    target_branch = None
    if refspecs:
        parsed = _parse_push_refspecs(args)
        if parsed:
            ref = parsed[0]
            if ref.startswith("refs/heads/"):
                target_branch = ref[len("refs/heads/"):]

    if not target_branch and metadata:
        target_branch = metadata.get("sandbox_branch")

    if not target_branch:
        return None

    remote_ref = f"{remote}/{target_branch}"

    # Try diffing against the remote tracking branch
    resolved_cwd = os.path.realpath(repo_root)
    env = build_clean_env()
    changed_files = _enumerate_push_changed_files(
        resolved_cwd, env, remote_ref,
    )

    if changed_files is None and metadata:
        from_branch = metadata.get("from_branch")
        if from_branch:
            changed_files = _enumerate_push_changed_files(
                resolved_cwd, env, from_branch,
            )

    if changed_files is None:
        bare_repo_path = resolve_bare_repo_path(repo_root)
        default_branch = None
        if bare_repo_path:
            default_branch = _detect_default_branch(bare_repo_path)
        if default_branch:
            changed_files = _enumerate_push_changed_files(
                resolved_cwd, env, default_branch,
            )

    if changed_files is None:
        return ValidationError(
            "Cannot enumerate changed files for push file validation; "
            "push blocked (fail-closed)"
        )

    if not changed_files:
        return None

    result = check_file_restrictions(changed_files, config)

    if result.blocked:
        return ValidationError(result.reason)

    if result.warned_files:
        logger.warning(
            "Push modifies sensitive files: %s",
            ", ".join(result.warned_files),
        )

    return None


def _enumerate_push_changed_files(
    cwd: str,
    env: dict[str, str],
    base_ref: str,
) -> list[str] | None:
    """Enumerate files changed between base_ref and HEAD.

    Returns:
        List of changed file paths, or None if the diff fails
        (e.g. the base ref doesn't exist).
    """
    try:
        result = subprocess.run(
            [GIT_BINARY, "diff", "--name-only", f"{base_ref}..HEAD", "--"],
            cwd=cwd,
            capture_output=True,
            timeout=SHA_CHECK_TIMEOUT,
            env=env,
        )
        if result.returncode != 0:
            return None
        output = result.stdout.decode("utf-8", errors="replace").strip()
        if not output:
            return []
        return output.splitlines()
    except (subprocess.TimeoutExpired, OSError):
        return None
