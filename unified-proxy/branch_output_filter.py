"""Output filtering for branch isolation in multi-sandbox git proxy.

Strips disallowed branch names from git output (branch listings,
ref enumerations, log decorations, stderr messages).

Extracted from branch_isolation.py to reduce module size.
"""

import logging
import re
from typing import List, Optional

from branch_types import (
    REF_ENUM_CMDS,
    _BRANCH_LINE_RE,
    _CUSTOM_D_RE,
    _DECORATION_LINE_RE,
    _REF_IN_LINE_RE,
    _REMOTE_BRANCH_LINE_RE,
    _STDERR_BARE_BRANCH_RE,
    _STDERR_REF_RE,
    _is_allowed_branch_name,
    _is_sha_like,
    _normalize_base_branch,
    get_subcommand_args,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Branch Listings
# ---------------------------------------------------------------------------


def _filter_branch_output(
    output: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> str:
    """Filter git branch output to hide other sandbox branches.

    Handles plain, verbose (-v/-vv), and remote (-a) branch listing formats.
    Drops lines where the branch is not allowed.
    Preserves current-branch indicator (*).
    Drops unrecognized format lines (fail-closed).

    Args:
        output: Raw stdout from a ``git branch`` command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output with disallowed branches removed.
    """
    if not output:
        return output


    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")

        # Empty lines are kept
        if not stripped:
            filtered_lines.append(line)
            continue

        # Try remote branch pattern first (more specific)
        m = _REMOTE_BRANCH_LINE_RE.match(stripped)
        if m:
            branch_name = m.group("branch")
            rest = m.group("rest")
            # Handle symref format: "HEAD -> origin/main"
            if branch_name == "HEAD" and "->" in rest:
                # Always keep HEAD symref lines
                filtered_lines.append(line)
                continue
            if _is_allowed_branch_name(branch_name, sandbox_branch, base_branch):
                filtered_lines.append(line)
            continue

        # Try local branch pattern
        m = _BRANCH_LINE_RE.match(stripped)
        if m:
            branch_name = m.group("branch")
            if _is_allowed_branch_name(branch_name, sandbox_branch, base_branch):
                filtered_lines.append(line)
            continue

        # Unrecognized format — drop (fail-closed to prevent leaking
        # branch names if git changes its output format)
        logger.debug("branch output filter: dropping unrecognized line: %r", stripped)

    return "".join(filtered_lines)


# ---------------------------------------------------------------------------
# Ref Enumerations
# ---------------------------------------------------------------------------


def _is_allowed_short_ref_token(
    token: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> bool:
    """Check whether a short/custom ref token from ref-enum output is allowed."""

    if not token:
        return True
    if token.startswith("("):
        return True
    if token.startswith("refs/tags/") or token.startswith("tags/"):
        return True
    if token.startswith("refs/heads/"):
        return _is_allowed_branch_name(
            token[len("refs/heads/"):], sandbox_branch, base_branch
        )
    if token.startswith("refs/remotes/"):
        parts = token.split("/", 3)
        if len(parts) >= 4:
            return _is_allowed_branch_name(parts[3], sandbox_branch, base_branch)
        # Incomplete path (e.g. "refs/remotes/origin") — deny
        return False
    # First treat token as a branch name (supports slashed branch names like
    # "sandbox/alice" and "release/1.0").
    if _is_allowed_branch_name(token, sandbox_branch, base_branch):
        return True
    # Then try remote-short form ("origin/main", "upstream/feature").
    if "/" in token:
        remote, _, branch = token.partition("/")
        if remote and branch:
            return _is_allowed_branch_name(branch, sandbox_branch, base_branch)
    return False


def _looks_like_ref_token(token: str) -> bool:
    """Heuristic: return True if *token* plausibly looks like a git ref.

    Used in pass-2 of ``_filter_ref_enum_output`` to avoid applying ref
    filtering to non-ref data (commit messages, dates, etc.) that may
    appear as a second token on SHA-prefixed lines in custom formats.
    """
    if not token or len(token) > 256:
        return False
    # Tokens starting with a digit (but not a SHA) are likely dates, counts
    if token[0].isdigit() and not _is_sha_like(token):
        return False
    # Tokens containing revision traversal operators are not bare ref names
    for ch in ("..", "~", "^", ":"):
        if ch in token:
            return False
    return True


def _filter_ref_enum_output(
    output: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> str:
    """Filter ref enumeration output (for-each-ref, ls-remote, show-ref).

    Two-pass filtering:
      Pass 1: Check refs/heads/<branch> patterns via _REF_IN_LINE_RE.
              Drop if branch not allowed. Tags always kept.
      Pass 2: For lines not matched by pass 1, check first whitespace-
              delimited token as a potential short refname (handles custom
              --format output like %(refname:short)).

    Args:
        output: Raw stdout from a ref enumeration command.
        sandbox_branch: This sandbox's branch name.
        base_branch: Optional base branch to allow.

    Returns:
        Filtered output with disallowed branch refs removed.
    """
    if not output:
        return output


    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")
        if not stripped:
            filtered_lines.append(line)
            continue

        # Pass 1: Check for refs/heads/<branch> or refs/tags/ patterns
        ref_match = _REF_IN_LINE_RE.search(stripped)
        if ref_match:
            branch_name = ref_match.group(1)
            if _is_allowed_branch_name(branch_name, sandbox_branch, base_branch):
                filtered_lines.append(line)
            continue

        # Check for tags — always keep
        if "refs/tags/" in stripped:
            filtered_lines.append(line)
            continue

        # Check for remote refs
        remote_match = re.search(r"refs/remotes/[^/]+/([^\s]+)", stripped)
        if remote_match:
            branch_name = remote_match.group(1)
            if _is_allowed_branch_name(branch_name, sandbox_branch, base_branch):
                filtered_lines.append(line)
            continue

        # Pass 2: Check first token as potential short refname
        # This handles custom --format output like %(refname:short)
        tokens = stripped.split()
        if tokens:
            first_token = tokens[0]
            # If it looks like a SHA (hex, >= 12 chars), check second token
            if _is_sha_like(first_token):
                # SHA-prefixed line with optional ref token (custom format)
                if len(tokens) >= 2:
                    second = tokens[1]
                    if _looks_like_ref_token(second):
                        # Looks like a ref — apply isolation filter
                        if _is_allowed_short_ref_token(
                            second, sandbox_branch, base_branch
                        ):
                            filtered_lines.append(line)
                    else:
                        # Non-ref data (date, commit message, etc.) — keep
                        filtered_lines.append(line)
                else:
                    filtered_lines.append(line)
                continue

            # First token might be a short/custom ref token.
            if _is_allowed_short_ref_token(
                first_token, sandbox_branch, base_branch
            ):
                filtered_lines.append(line)
            continue

        # Unrecognized format — drop (fail-closed to prevent leaking
        # branch names if git changes its output format)
        logger.debug("ref enum output filter: dropping unrecognized line: %r", stripped)

    return "".join(filtered_lines)


# ---------------------------------------------------------------------------
# Log Decorations
# ---------------------------------------------------------------------------


def _is_decoration_ref_allowed(
    ref: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> bool:
    """Check if a single decoration ref should be kept.

    Always keeps: HEAD, HEAD -> branch (if branch allowed), tags,
    detached HEAD annotations.
    """

    ref = ref.strip()
    if not ref:
        return True

    # HEAD is always kept
    if ref == "HEAD":
        return True

    # "HEAD -> branch" form
    if ref.startswith("HEAD -> "):
        branch = ref[len("HEAD -> "):]
        return _is_allowed_branch_name(branch, sandbox_branch, base_branch)

    # Tags are always kept
    if ref.startswith("tag: "):
        return True

    # Remote tracking refs: "origin/branch"
    if "/" in ref:
        parts = ref.split("/", 1)
        if len(parts) == 2:
            # Could be origin/branch
            branch_name = parts[1]
            return _is_allowed_branch_name(branch_name, sandbox_branch, base_branch)

    # Bare branch name
    return _is_allowed_branch_name(ref, sandbox_branch, base_branch)


def _filter_decoration_refs(
    decorations: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> Optional[str]:
    """Filter individual refs within a decoration string.

    Args:
        decorations: Comma-separated decoration refs (without parens).
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered decoration string, or None if all refs were removed.
    """
    refs = [r.strip() for r in decorations.split(",")]
    allowed = [
        r for r in refs if _is_decoration_ref_allowed(r, sandbox_branch, base_branch)
    ]
    if not allowed:
        return None
    return ", ".join(allowed)


def _filter_log_decorations(
    output: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> str:
    """Filter SHA-anchored decoration lines in git log output.

    Handles standard ``git log --decorate`` format where decorations
    appear in parentheses after the commit SHA.

    Args:
        output: Raw stdout from a ``git log`` command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output with disallowed branch refs removed from decorations.
    """
    if not output:
        return output

    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")

        m = _DECORATION_LINE_RE.match(stripped)
        if m:
            prefix = m.group("prefix")
            decorations = m.group("decorations")
            suffix = m.group("suffix")
            filtered = _filter_decoration_refs(
                decorations, sandbox_branch, base_branch
            )
            if filtered:
                filtered_lines.append(
                    prefix + "(" + filtered + ")" + suffix
                    + (line[len(stripped):])  # preserve trailing newline
                )
            else:
                # All decorations removed — emit line without parens
                filtered_lines.append(
                    prefix.rstrip() + suffix
                    + (line[len(stripped):])
                )
            continue

        # Not a decoration line — keep as-is
        filtered_lines.append(line)

    return "".join(filtered_lines)


def _filter_custom_format_decorations(
    output: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
    has_bare_D: bool = True,
) -> str:
    """Filter custom --format=%d/%D decoration output.

    Handles both %d (parenthesized) and %D (bare) formats.

    Args:
        output: Raw stdout from a ``git log --format`` command with %d or %D.
        sandbox_branch: This sandbox's branch name.
        has_bare_D: Whether the format string contains bare %D.  When False,
            the bare (non-parenthesized) heuristic is skipped to avoid
            false-positives on commit messages containing commas or "HEAD".

    Returns:
        Filtered output with disallowed refs removed from decorations.
    """
    if not output:
        return output


    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")
        trailing = line[len(stripped):]

        # Try parenthesized format (%d): " (HEAD -> main, origin/feature)"
        m = _CUSTOM_D_RE.search(stripped)
        if m:
            decorations = m.group("decorations")
            filtered = _filter_decoration_refs(
                decorations, sandbox_branch, base_branch
            )
            if filtered:
                new_line = (
                    stripped[:m.start()]
                    + "(" + filtered + ")"
                    + stripped[m.end():]
                )
                filtered_lines.append(new_line + trailing)
            else:
                # Remove empty decoration entirely
                new_line = stripped[:m.start()] + stripped[m.end():]
                filtered_lines.append(new_line.rstrip() + trailing)
            continue

        # Try bare format (%D): "HEAD -> main, origin/feature"
        # Only apply this heuristic when %D is actually in the format string;
        # %d always produces parenthesized output handled above.
        #
        # Best-effort: input validation is the primary defense; this heuristic
        # catches residual decoration lines.  A majority of comma-separated
        # tokens must look ref-like to trigger filtering, and tokens longer
        # than 256 chars are assumed to be non-ref data (commit messages, etc.).
        if has_bare_D and ("," in stripped or stripped.startswith("HEAD")):
            tokens = [t.strip() for t in stripped.split(",")]
            non_empty = [t for t in tokens if t]
            ref_like_count = sum(
                1 for t in non_empty
                if len(t) <= 256 and (
                    t.startswith("HEAD") or t.startswith("tag: ")
                    or "/" in t or _is_allowed_branch_name(
                        t, sandbox_branch, base_branch
                    )
                )
            )
            total_count = len(non_empty)
            looks_like_refs = total_count > 0 and ref_like_count > total_count // 2
            if looks_like_refs:
                filtered = _filter_decoration_refs(
                    stripped, sandbox_branch, base_branch
                )
                if filtered:
                    filtered_lines.append(filtered + trailing)
                else:
                    filtered_lines.append(trailing)
                continue

        filtered_lines.append(line)

    return "".join(filtered_lines)


def _log_has_custom_decoration_format(args: List[str]) -> bool:
    """Detect if git log args use --format/--pretty with %d or %D."""
    for idx, arg in enumerate(args):
        for prefix in ("--format=", "--pretty=", "--pretty=format:"):
            if arg.startswith(prefix):
                fmt = arg[len(prefix):]
                if "%d" in fmt or "%D" in fmt:
                    return True
        # Also check --format <value> and --pretty <value>
        if arg in ("--format", "--pretty") and idx + 1 < len(args):
            fmt = args[idx + 1]
            if "%d" in fmt or "%D" in fmt:
                return True
    return False


def _log_has_bare_D_format(args: List[str]) -> bool:
    """Detect if git log args use --format/--pretty with bare %D (not %d)."""
    for idx, arg in enumerate(args):
        for prefix in ("--format=", "--pretty=", "--pretty=format:"):
            if arg.startswith(prefix):
                fmt = arg[len(prefix):]
                if "%D" in fmt:
                    return True
        if arg in ("--format", "--pretty") and idx + 1 < len(args):
            fmt = args[idx + 1]
            if "%D" in fmt:
                return True
    return False


def _log_has_source_flag(args: List[str]) -> bool:
    """Detect if git log args include --source."""
    return "--source" in args


def _filter_log_source_refs(
    output: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> str:
    """Redact disallowed branch refs from --source output.

    --source adds a ref name column to log output. Disallowed refs/heads/
    branch names are replaced with [redacted].

    Args:
        output: Raw stdout from a ``git log --source`` command.
        sandbox_branch: This sandbox's branch name.

    Returns:
        Output with disallowed source refs redacted.
    """
    if not output:
        return output


    filtered_lines: List[str] = []
    for line in output.splitlines(True):
        stripped = line.rstrip("\n\r")
        trailing = line[len(stripped):]

        # --source output has ref as a tab-separated column, typically:
        # "abc1234\trefs/heads/branch\trest..."
        # or it appears as a space-separated token after the SHA
        new_stripped = re.sub(
            r"refs/heads/([^\s]+)",
            lambda m: (
                m.group(0)
                if _is_allowed_branch_name(
                    m.group(1), sandbox_branch, base_branch
                )
                else "refs/heads/[redacted]"
            ),
            stripped,
        )
        filtered_lines.append(new_stripped + trailing)

    return "".join(filtered_lines)


# ---------------------------------------------------------------------------
# Stderr Redaction
# ---------------------------------------------------------------------------


def filter_stderr_branch_refs(
    stderr: str,
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> str:
    """Redact disallowed branch names from stderr output.

    Git error messages, hints, and verbose output may contain branch names
    (e.g. ``error: pathspec 'sandbox/other' did not match``).  This function
    replaces disallowed branch ref paths with a generic placeholder.
    """
    if not stderr or not sandbox_branch:
        return stderr
    base_branch = _normalize_base_branch(base_branch)


    def _redact_match(m: re.Match) -> str:
        branch = m.group("branch") or m.group("remote_branch")
        if branch and not _is_allowed_branch_name(branch, sandbox_branch, base_branch):
            # Replace entire match with redacted version
            full = m.group(0)
            return full[:full.rfind(branch)] + "<redacted>"
        return m.group(0)

    result = _STDERR_REF_RE.sub(_redact_match, stderr)

    # Second pass: redact bare branch names in single-quoted contexts
    def _redact_bare_match(m: re.Match) -> str:
        branch = m.group("bare_branch")
        if branch and not _is_allowed_branch_name(branch, sandbox_branch, base_branch):
            return "'<redacted>'"
        return m.group(0)

    return _STDERR_BARE_BRANCH_RE.sub(_redact_bare_match, result)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def filter_ref_listing_output(
    output: str,
    args: List[str],
    sandbox_branch: str,
    base_branch: Optional[str] = None,
) -> str:
    """Dispatch to the appropriate output filter based on git subcommand.

    Called after git command execution for commands that enumerate refs.
    Routes to branch listing, ref enumeration, or log decoration filters.

    Args:
        output: Raw stdout from the git command.
        args: The original git command args (without 'git' prefix).
        sandbox_branch: This sandbox's branch name.

    Returns:
        Filtered output.
    """
    if not output or not sandbox_branch:
        return output
    base_branch = _normalize_base_branch(base_branch)

    subcommand, sub_args, _ = get_subcommand_args(args)
    if subcommand is None:
        return output

    # Branch listing
    if subcommand == "branch":
        return _filter_branch_output(output, sandbox_branch, base_branch)

    # Ref enumeration commands
    if subcommand in REF_ENUM_CMDS:
        return _filter_ref_enum_output(output, sandbox_branch, base_branch)

    # Log with decorations
    if subcommand == "log":
        if _log_has_source_flag(sub_args):
            output = _filter_log_source_refs(output, sandbox_branch, base_branch)
        if _log_has_custom_decoration_format(sub_args):
            return _filter_custom_format_decorations(
                output, sandbox_branch, base_branch,
                has_bare_D=_log_has_bare_D_format(sub_args),
            )
        return _filter_log_decorations(output, sandbox_branch, base_branch)

    return output
