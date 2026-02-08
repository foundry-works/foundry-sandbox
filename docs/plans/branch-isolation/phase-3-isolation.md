# Phase 3: Cross-Sandbox Branch Isolation

## 3A. Add subcommand extraction helper, constants, and validators

**File:** `unified-proxy/git_operations.py`

### Subcommand extraction

Add `_get_subcommand()` helper (reuse the parsing pattern from `validate_command()` at lines 507-540):

```python
def _get_subcommand(args: List[str]) -> Optional[str]:
    """Extract the git subcommand from args, skipping global flags and -c options."""
    sub, _ = _get_subcommand_args(args)
    return sub


def _get_subcommand_args(args: List[str]) -> Tuple[Optional[str], List[str]]:
    """Extract the git subcommand and its args from the full arg list.

    Handles global flags (-c key=val, -C <path>, --git-dir, --work-tree,
    --namespace, etc.) and the '--' global-options terminator
    (e.g., `git -- log` is valid).
    """
    # Global flags that consume the next token as a value
    _GLOBAL_VALUE_FLAGS = frozenset({
        "-c", "-C", "--git-dir", "--work-tree", "--namespace",
    })
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            # '--' terminates global options; next arg is the subcommand
            idx += 1
            if idx < len(args):
                return args[idx], args[idx + 1:]
            return None, []
        # Handle --flag=value (single token) for global flags
        if "=" in arg and arg.split("=", 1)[0] in _GLOBAL_VALUE_FLAGS:
            idx += 1
            continue
        # Handle two-token global flags (e.g., -c key=val, -C /path)
        if arg in _GLOBAL_VALUE_FLAGS and idx + 1 < len(args):
            idx += 2
            continue
        # Handle compact -c form (e.g., -ccore.pager=less)
        if arg.startswith("-c") and len(arg) > 2:
            idx += 1
            continue
        if not arg.startswith("-"):
            return arg, args[idx + 1:]
        idx += 1
    return None, []
```

**Refactoring note:** `validate_command()` (lines 507-540) has the same global-flag/`-c` parsing loop. Refactor it to call `_get_subcommand_args()` internally, eliminating the duplicated logic. This ensures future changes to global flag handling (e.g., adding new two-token flags) are made in one place.

### Constants

```python
# Branches always accessible regardless of sandbox isolation
WELL_KNOWN_BRANCHES: FrozenSet[str] = frozenset({
    "main", "master", "develop", "production",
})

WELL_KNOWN_BRANCH_PREFIXES: Tuple[str, ...] = (
    "release/", "hotfix/",
)

# Commands that take ref arguments subject to isolation
_REF_READING_CMDS: FrozenSet[str] = frozenset({
    "log", "show", "diff", "blame", "cherry-pick", "merge",
    "rebase", "reset", "rev-list", "diff-tree", "rev-parse",
    "shortlog", "describe", "name-rev",
    "archive", "format-patch",
})

# Commands that enumerate refs — output filtering only (3C), not input-blocked
_REF_ENUM_CMDS: FrozenSet[str] = frozenset({
    "for-each-ref", "ls-remote", "show-ref",
})

# Flags that implicitly expand to all refs — blocked on ref-reading commands
_IMPLICIT_ALL_REF_FLAGS: FrozenSet[str] = frozenset({
    "--all", "--branches", "--remotes", "--glob",
})

# Flag prefixes that expand to pattern-matched refs (e.g., --branches=sandbox-*)
_IMPLICIT_REF_FLAG_PREFIXES: Tuple[str, ...] = (
    "--branches=", "--remotes=", "--glob=",
)
```

### Ref validation helpers

```python
import re

_REV_SUFFIX_RE = re.compile(r'([~^]\d*)+$')

def _strip_rev_suffixes(ref: str) -> str:
    """Strip git revision suffixes (~N, ^N, ~, ^) from a ref.

    Examples: main~3 -> main, HEAD^2 -> HEAD, branch~1^2 -> branch.
    These suffixes select ancestors/parents and don't change which
    ref is being accessed.
    """
    return _REV_SUFFIX_RE.sub('', ref)


def _is_allowed_ref(ref: str, sandbox_branch: str) -> bool:
    """Check if a ref is accessible to this sandbox.

    Allows: relative refs, well-known branches, own sandbox branch,
    remote tracking refs for allowed branches, tags, SHA hashes.
    Blocks: other sandboxes' branch names (local or remote).
    """
    # Strip revision suffixes first (main~3 -> main, branch^2 -> branch).
    # This must happen before any other checks so that main~3, develop^2,
    # and FETCH_HEAD~1 are all resolved to their base ref.
    ref = _strip_rev_suffixes(ref)

    # FETCH_HEAD blocked (even with suffixes stripped above)
    if ref == "FETCH_HEAD":
        return False  # FETCH_HEAD can contain commits fetched from any branch
    if ref.startswith("HEAD") or "@{" in ref:
        return True

    # Range operators -- check each side recursively
    for sep in ("...", ".."):
        if sep in ref:
            parts = ref.split(sep)
            return all(
                _is_allowed_ref(p.lstrip("^"), sandbox_branch)
                for p in parts if p
            )

    # Tags are always allowed
    if ref.startswith("refs/tags/") or ref.startswith("tags/"):
        return True

    # Remote tracking refs -- apply same isolation to the branch name part
    if ref.startswith("refs/remotes/"):
        # refs/remotes/origin/branch-name -> extract branch-name
        parts = ref.split("/", 3)  # ['refs', 'remotes', 'origin', 'branch-name']
        if len(parts) >= 4:
            return _is_allowed_branch_name(parts[3], sandbox_branch)
        return True
    if ref.startswith("origin/"):
        bare_ref = ref.removeprefix("origin/")
        return _is_allowed_branch_name(bare_ref, sandbox_branch)

    # Strip refs/heads/ prefix for comparison
    bare_ref = ref.removeprefix("refs/heads/")
    return _is_allowed_branch_name(bare_ref, sandbox_branch)


def _is_allowed_branch_name(name: str, sandbox_branch: str) -> bool:
    """Check if a bare branch name (no refs/heads/ prefix) is allowed."""
    # Well-known branches
    if name in WELL_KNOWN_BRANCHES:
        return True
    if any(name.startswith(p) for p in WELL_KNOWN_BRANCH_PREFIXES):
        return True
    # Own sandbox branch
    if name == sandbox_branch:
        return True
    # SHA hashes -- require 12+ hex chars to avoid matching branch names
    # like "deadbeef" (full SHAs are 40 chars; 12 is git's default abbrev)
    if len(name) >= 12 and re.fullmatch(r'[0-9a-f]+', name):
        return True
    # Everything else is potentially another sandbox's branch
    return False
```

### `validate_branch_isolation()`

```python
def validate_branch_isolation(
    args: List[str],
    metadata: Optional[dict] = None,
) -> Optional[ValidationError]:
    """Block access to other sandboxes' branches.

    Checks input refs for ref-reading commands, checkout/switch targets,
    and branch deletion. Blocks implicit-all flags (--all, --branches,
    --remotes). Output filtering for branch/for-each-ref/ls-remote listing
    is handled separately in 3C.
    """
    if not metadata:
        return None
    sandbox_branch = metadata.get("sandbox_branch", "")
    if not sandbox_branch:
        return None

    subcommand, subcommand_args = _get_subcommand_args(args)
    if subcommand is None:
        return None

    # --- Branch deletion guard ---
    if subcommand == "branch":
        if any(a in ("-d", "-D", "--delete") for a in subcommand_args):
            for arg in subcommand_args:
                if arg.startswith("-"):
                    continue
                if not _is_allowed_ref(arg, sandbox_branch):
                    return ValidationError(
                        f"Cannot delete branch '{arg}': belongs to another sandbox"
                    )
        return None  # branch listing handled by output filtering (3C)

    # --- Ref enumeration commands (for-each-ref, ls-remote) ---
    # Input args are glob patterns (refs/heads/*), not individual refs.
    # Blocking them here would break legitimate usage. Output is filtered
    # in 3C instead. Return early.
    if subcommand in _REF_ENUM_CMDS:
        return None

    # --- Checkout/switch to another sandbox's branch ---
    if subcommand in ("checkout", "switch"):
        _BRANCH_CREATE_FLAGS = {"-b", "-B", "-c", "-C", "--orphan"}
        creating_branch = False
        skip_next = False
        positionals = []

        for arg in subcommand_args:
            if skip_next:
                skip_next = False
                continue
            if arg == "--":
                break  # Pathspecs after --
            if arg in _BRANCH_CREATE_FLAGS:
                creating_branch = True
                skip_next = True  # Next arg is the new branch name (skip it)
                continue
            if arg.startswith("-"):
                continue
            positionals.append(arg)

        if creating_branch:
            # `checkout -b new-branch start-point` or `switch -c new start`
            # positionals[0] is the start-point -- must be isolation-checked
            if positionals and not _is_allowed_ref(positionals[0], sandbox_branch):
                return ValidationError(
                    f"Cannot use start-point '{positionals[0]}': "
                    f"belongs to another sandbox"
                )
        else:
            # `checkout <branch>` -- first positional is the target
            if positionals and not _is_allowed_ref(positionals[0], sandbox_branch):
                return ValidationError(
                    f"Cannot checkout branch '{positionals[0]}': "
                    f"belongs to another sandbox"
                )
        return None

    # --- Fetch refspec isolation ---
    # `git fetch origin other-sandbox-branch` downloads objects and sets
    # FETCH_HEAD, enabling a two-step bypass (fetch + cherry-pick FETCH_HEAD).
    # Block fetch when a refspec resolves to another sandbox's branch.
    if subcommand in ("fetch", "pull"):
        # Fetch/pull flags that consume the next token as a value.
        # Without this, `git fetch --depth 1 origin branch` would
        # miscount positionals (treating "1" as the remote name).
        _FETCH_VALUE_FLAGS = frozenset({
            "-j", "--depth", "--deepen", "--shallow-since",
            "--shallow-exclude", "--jobs", "--refmap",
            "--server-option", "-o", "--upload-pack",
            "--negotiation-tip", "--filter",
        })
        positional_idx = 0
        skip_next = False
        for arg in subcommand_args:
            if skip_next:
                skip_next = False
                continue
            if arg == "--":
                break
            if arg.startswith("-"):
                # Handle --flag=value (single token) vs --flag value (two tokens)
                flag_name = arg.split("=", 1)[0]
                if "=" not in arg and flag_name in _FETCH_VALUE_FLAGS:
                    skip_next = True
                continue
            positional_idx += 1
            if positional_idx == 1:
                continue  # First positional is the remote name (e.g. "origin")
            # Remaining positionals are refspecs
            # Handle explicit refspec format: +src:dst
            src = arg.split(":")[0].lstrip("+") if ":" in arg else arg
            if src and not _is_allowed_ref(src, sandbox_branch):
                return ValidationError(
                    f"Cannot fetch ref '{src}': belongs to another sandbox"
                )
        return None

    # --- Worktree add isolation ---
    # `git worktree add ../path other-sandbox-branch` creates a new worktree
    # from another sandbox's branch, bypassing isolation.
    if subcommand == "worktree":
        if subcommand_args and subcommand_args[0] == "add":
            add_args = subcommand_args[1:]
            positionals = []
            skip_next = False
            for arg in add_args:
                if skip_next:
                    skip_next = False
                    continue
                if arg in ("-b", "-B"):
                    skip_next = True  # Next arg is new branch name
                    continue
                if arg.startswith("-"):
                    continue
                positionals.append(arg)
            # positionals[0] is the path, positionals[1] is the commit-ish
            if len(positionals) >= 2:
                if not _is_allowed_ref(positionals[1], sandbox_branch):
                    return ValidationError(
                        f"Cannot create worktree from '{positionals[1]}': "
                        f"belongs to another sandbox"
                    )
        return None

    # --- Bisect start isolation ---
    # `git bisect start <bad> <good> [<good>...]` accepts ref arguments.
    # Only the `start` sub-subcommand takes refs; other bisect subcommands
    # (good, bad, reset, skip) operate on HEAD or SHAs from the bisect log.
    if subcommand == "bisect":
        if subcommand_args and subcommand_args[0] == "start":
            start_args = subcommand_args[1:]
            for arg in start_args:
                if arg == "--":
                    break  # Remaining args are pathspecs
                if arg.startswith("-"):
                    continue
                if not _is_allowed_ref(arg, sandbox_branch):
                    return ValidationError(
                        f"Cannot bisect with ref '{arg}': "
                        f"belongs to another sandbox"
                    )
        return None

    # --- Ref-reading commands ---
    if subcommand not in _REF_READING_CMDS:
        return None

    # Block flags that implicitly expand to all refs
    for arg in subcommand_args:
        if arg in _IMPLICIT_ALL_REF_FLAGS:
            return ValidationError(
                f"Flag '{arg}' not allowed: exposes branches from other "
                f"sandboxes. Specify refs explicitly instead."
            )
        if any(arg.startswith(p) for p in _IMPLICIT_REF_FLAG_PREFIXES):
            flag_name = arg.split("=", 1)[0]
            return ValidationError(
                f"Flag '{flag_name}' not allowed: exposes branches from other "
                f"sandboxes. Specify refs explicitly instead."
            )

    for arg in subcommand_args:
        if arg.startswith("-"):
            continue
        if arg == "--":
            break  # Everything after -- is pathspecs, not refs
        if _is_allowed_ref(arg, sandbox_branch):
            continue
        return ValidationError(
            f"Access denied: ref '{arg}' belongs to another sandbox. "
            f"If this is a file path, use '--' to separate refs from paths "
            f"(e.g., git log branch -- path)."
        )
    return None
```

## 3B. Wire isolation into `execute_git()`

**File:** `unified-proxy/git_operations.py` — in `execute_git()`, after path args validation (line 1193), before push check (line 1195):

```python
# Check branch isolation
err = validate_branch_isolation(request.args, metadata)
if err:
    audit_log(event="branch_isolation_blocked",
              action=" ".join(request.args[:3]),
              decision="deny", command_args=request.args, reason=err.reason,
              matched_rule="branch_isolation", request_id=req_id)
    return None, err
```

## 3C. Output filtering for ref listings

**File:** `unified-proxy/git_operations.py` — in `execute_git()`, after path translation (line 1278), before constructing the response (line 1280):

```python
# Post-process ref listing output for isolation
if metadata and metadata.get("sandbox_branch"):
    stdout_str = _filter_ref_listing_output(
        request.args, stdout_str, metadata["sandbox_branch"]
    )
```

### Output filtering functions

```python
_BRANCH_LINE_RE = re.compile(r'^([* ] +)(.+)$')
_REMOTE_BRANCH_LINE_RE = re.compile(r'^( +)(remotes/\S+)(.*)$')
_REF_IN_LINE_RE = re.compile(r'refs/heads/(\S+)')
# Matches decoration parentheticals in git log output, anchored to appear
# after a hex SHA (with optional "commit " prefix). This prevents matching
# arbitrary parenthesized text in commit messages (e.g., "Fix bug (see #123)").
# Handles both: "abc1234 (HEAD -> main)" and "commit abc1234 (HEAD -> main)"
_DECORATION_LINE_RE = re.compile(
    r'(\b[0-9a-f]{7,40}\s+)\(([^)]+)\)'
)
_DECORATION_REF_RE = re.compile(r'(?:HEAD -> |tag: )?(\S+)')

def _filter_ref_listing_output(
    args: List[str], stdout: str, sandbox_branch: str,
) -> str:
    """Dispatch to the appropriate output filter based on subcommand."""
    subcommand = _get_subcommand(args)
    if subcommand == "branch":
        return _filter_branch_output(stdout, sandbox_branch)
    if subcommand in _REF_ENUM_CMDS:
        return _filter_ref_enum_output(stdout, sandbox_branch)
    if subcommand == "log":
        result = stdout
        if _log_has_custom_decoration_format(args):
            result = _filter_custom_format_decorations(result, sandbox_branch)
        else:
            result = _filter_log_decorations(result, sandbox_branch)
        if _log_has_source_flag(args):
            result = _filter_log_source_refs(result, sandbox_branch)
        return result
    return stdout


def _filter_branch_output(stdout: str, sandbox_branch: str) -> str:
    """Filter `git branch` output to hide other sandboxes' branches.

    Handles multiple output formats:
    - Plain: "* main" / "  feature"
    - Verbose (-v/-vv): "* main abc1234 commit message"
    - Remote (-a): "  remotes/origin/main"
    """
    lines = stdout.split("\n")
    filtered = []
    for line in lines:
        if not line.strip():
            filtered.append(line)
            continue

        # Try matching remote branch format "  remotes/origin/branch"
        # (check this first -- more specific pattern)
        m = _REMOTE_BRANCH_LINE_RE.match(line)
        if m:
            ref = m.group(2).strip()
            if _is_allowed_ref(ref, sandbox_branch):
                filtered.append(line)
            continue

        # Try matching "* branch" or "  branch" format (local branches)
        # With -v, format is "* branch  abc1234 commit message"
        m = _BRANCH_LINE_RE.match(line)
        if m:
            branch_part = m.group(2).strip()
            # Handle "branch -> origin/branch" symref format (e.g. HEAD)
            if " -> " in branch_part:
                branch_name = branch_part.split(" -> ")[0]
            else:
                # Extract just the branch name (first whitespace-delimited token)
                # This handles both plain ("main") and verbose ("main abc1234 msg")
                branch_name = branch_part.split()[0] if branch_part else ""
            if _is_allowed_ref(branch_name, sandbox_branch):
                filtered.append(line)
            continue

        # Unrecognized format -- keep it (safe default)
        filtered.append(line)

    return "\n".join(filtered)


def _filter_ref_enum_output(stdout: str, sandbox_branch: str) -> str:
    """Filter `git for-each-ref`, `git ls-remote`, and `git show-ref` output.

    Two-pass filtering:
    1. Lines containing refs/heads/<branch> -- drop if branch not allowed.
    2. Lines not matching pass 1 -- scan for short branch names by checking
       the first whitespace-delimited token. Only drop lines where the token
       exactly matches a non-allowed branch pattern. This catches custom
       --format output like "main abc1234 commit msg" where %(refname:short)
       is the first token.
    """
    lines = stdout.split("\n")
    filtered = []
    for line in lines:
        if not line.strip():
            filtered.append(line)
            continue
        # Pass 1: explicit refs/heads/ pattern
        m = _REF_IN_LINE_RE.search(line)
        if m:
            branch_name = m.group(1)
            if not _is_allowed_branch_name(branch_name, sandbox_branch):
                continue  # Drop -- belongs to another sandbox
            filtered.append(line)
            continue
        # Pass 2: check first token as potential short refname
        tokens = line.split()
        if tokens:
            first = tokens[0]
            if re.fullmatch(r'[0-9a-f]{40}', first) and len(tokens) >= 2:
                # SHA-prefixed line (show-ref/ls-remote) -- already handled by pass 1
                filtered.append(line)
            elif not _is_allowed_branch_name(first, sandbox_branch) and \
                 not first.startswith("-") and \
                 re.fullmatch(r'[a-zA-Z0-9/_.\-]+', first):
                # First token looks like a branch name and is not allowed
                continue
            else:
                filtered.append(line)
        else:
            filtered.append(line)
    return "\n".join(filtered)


def _filter_log_decorations(stdout: str, sandbox_branch: str) -> str:
    """Strip other sandboxes' branch names from git log decoration output.

    Decorations appear as "(HEAD -> main, origin/feature, other-sandbox)"
    in git log output (--oneline, --decorate, default). This filter removes
    non-allowed refs from decoration parentheticals. If all refs in a
    decoration are removed, the entire "()" is stripped.

    The regex is anchored to appear after a hex SHA to avoid matching
    arbitrary parenthesized text in commit messages. Custom --format output
    using %d/%D is handled by _filter_custom_format_decorations() instead.

    Note: In detached HEAD state, git outputs "(HEAD detached at abc1234)".
    The regex handles this safely -- "HEAD detached at abc1234" doesn't match
    any branch pattern and is kept as-is.
    """
    def _filter_decoration_refs(inner: str) -> str:
        refs = [r.strip() for r in inner.split(",")]
        kept = []
        for ref_str in refs:
            # Preserve HEAD pointer, tags, and decoration prefixes
            m = _DECORATION_REF_RE.match(ref_str)
            if not m:
                kept.append(ref_str)
                continue
            ref_name = m.group(1)
            # "HEAD -> branch" -- check the branch part
            if ref_str.startswith("HEAD -> "):
                ref_name = ref_str.split("HEAD -> ", 1)[1]
            # "HEAD detached at ..." -- always keep
            if "detached" in ref_str:
                kept.append(ref_str)
                continue
            # "tag: v1.0" -- always keep
            if ref_str.startswith("tag: "):
                kept.append(ref_str)
                continue
            # "HEAD" alone -- always keep
            if ref_name == "HEAD":
                kept.append(ref_str)
                continue
            if _is_allowed_ref(ref_name, sandbox_branch):
                kept.append(ref_str)
        if not kept:
            return ""
        return "(" + ", ".join(kept) + ")"

    def _replace_decoration(match: re.Match) -> str:
        prefix = match.group(1)  # SHA + whitespace
        inner = match.group(2)   # decoration content
        result = _filter_decoration_refs(inner)
        if result:
            return prefix + result
        return prefix.rstrip()

    lines = stdout.split("\n")
    filtered = []
    for line in lines:
        # Replace decoration parentheticals anchored after SHA prefix
        new_line = _DECORATION_LINE_RE.sub(_replace_decoration, line)
        filtered.append(new_line)
    return "\n".join(filtered)


_CUSTOM_DECO_FORMAT_RE = re.compile(r'%[dD]')

def _log_has_custom_decoration_format(args: List[str]) -> bool:
    """Check if git log args include --format/--pretty with %d or %D.

    %d produces " (HEAD -> main, origin/main)" (with parens and leading space).
    %D produces "HEAD -> main, origin/main" (bare, no parens).
    Both bypass the SHA-anchored _DECORATION_LINE_RE regex.
    """
    _, subcommand_args = _get_subcommand_args(args)
    for arg in subcommand_args:
        for prefix in ("--format=", "--pretty=", "--pretty=format:"):
            if arg.startswith(prefix):
                fmt = arg.split("=", 1)[1]
                if _CUSTOM_DECO_FORMAT_RE.search(fmt):
                    return True
    return False


# Matches branch-name-like tokens in decoration output. Handles:
# - "HEAD -> branch", "tag: v1.0", "origin/branch", bare "branch"
# Comma-separated within optional parens.
_BARE_DECORATION_RE = re.compile(
    r'\(([^)]+)\)'  # Parenthesized decorations from %d
)

def _filter_custom_format_decorations(
    stdout: str, sandbox_branch: str,
) -> str:
    """Filter decorations in custom --format=%d/%D output.

    %d output: " (HEAD -> main, origin/feature, other-sandbox)"
    %D output: "HEAD -> main, origin/feature, other-sandbox"

    Strategy: scan each line for comma-separated ref-like tokens.
    For %d (parenthesized), match (ref, ref, ...) groups.
    For %D (bare), the entire line may be a decoration string --
    split on commas and filter each token.

    This is more aggressive than _filter_log_decorations() because
    custom format output has no SHA anchor to distinguish decorations
    from commit message text. The tradeoff is accepted: custom format
    users expect programmatic output, and false-positive redaction of
    commit message text containing branch-name-like tokens is low risk.
    """
    lines = stdout.split("\n")
    filtered = []
    for line in lines:
        # Try parenthesized decorations first (%d format)
        new_line = _BARE_DECORATION_RE.sub(
            lambda m: _redact_decoration_group(m.group(1), sandbox_branch),
            line,
        )
        # If no parens matched but line looks like bare %D output
        # (comma-separated refs with no other content), filter it directly
        if new_line == line and "," in line:
            tokens = [t.strip() for t in line.split(",")]
            if all(_looks_like_decoration_token(t) for t in tokens if t):
                kept = [t for t in tokens if _keep_decoration_token(t, sandbox_branch)]
                new_line = ", ".join(kept) if kept else ""
        filtered.append(new_line)
    return "\n".join(filtered)


def _redact_decoration_group(inner: str, sandbox_branch: str) -> str:
    """Filter a parenthesized decoration group, returning "(kept, refs)" or ""."""
    tokens = [t.strip() for t in inner.split(",")]
    kept = [t for t in tokens if _keep_decoration_token(t, sandbox_branch)]
    if not kept:
        return ""
    return "(" + ", ".join(kept) + ")"


def _keep_decoration_token(token: str, sandbox_branch: str) -> bool:
    """Decide whether to keep a single decoration token."""
    if not token:
        return False
    if token == "HEAD" or token.startswith("HEAD "):
        # "HEAD" alone or "HEAD -> branch" -- check branch part
        if " -> " in token:
            ref = token.split(" -> ", 1)[1]
            return _is_allowed_ref(ref, sandbox_branch)
        return True
    if "detached" in token:
        return True
    if token.startswith("tag: "):
        return True
    return _is_allowed_ref(token, sandbox_branch)


def _looks_like_decoration_token(token: str) -> bool:
    """Heuristic: does this token look like a git decoration ref?

    Used to detect bare %D output lines (no parens). Conservative --
    only matches patterns that look like refs (alphanumeric with
    slashes, dashes, dots, HEAD, tag: prefix).
    """
    token = token.strip()
    if not token:
        return False
    if token in ("HEAD",) or token.startswith("HEAD "):
        return True
    if token.startswith("tag: "):
        return True
    # Ref-like: alphanumeric, slashes, dashes, dots, underscores
    return bool(re.fullmatch(r'[a-zA-Z0-9/_.\-]+', token))
```

**Limitation:** `for-each-ref` with custom `--format` strings could produce output where the ref isn't in `refs/heads/<name>` format (e.g., `%(refname:short)`). The regex won't catch these. This is an accepted gap — custom format output is hard to filter generically, and the branch name leak is low-severity (code access is already blocked by input validation).

## Verification

With two sandboxes on the same repo:

- `git branch -a` from sandbox A should NOT list sandbox B's branch
- `git branch -v` should NOT list sandbox B's branch (verbose format)
- `git log sandbox-B-branch` should be blocked
- `git log origin/sandbox-B-branch` should be blocked (remote ref isolation)
- `git cherry-pick <sandbox-B-commit>` by branch name should be blocked
- `git cherry-pick FETCH_HEAD` should be blocked
- `git branch -d <sandbox-B-branch>` should be blocked
- `git checkout sandbox-B-branch` should be blocked
- `git checkout -b new-branch sandbox-B-branch` should be blocked (start-point)
- `git log --all` should be blocked (implicit ref expansion)
- `git fetch origin sandbox-B-branch` should be blocked (fetch refspec isolation)
- `git fetch --depth 1 origin sandbox-B-branch` should be blocked (two-token flag handling)
- `git pull origin sandbox-B-branch` should be blocked
- `git rev-parse sandbox-B-branch` should be blocked (SHA leak)
- `git worktree add ../path sandbox-B-branch` should be blocked
- `git reset --hard sandbox-B-branch` should be blocked
- `git bisect start sandbox-B-branch main` should be blocked
- `git bisect start my-branch main` should work
- `git for-each-ref refs/heads/` should NOT list sandbox B's branch (output filtered)
- `git log --oneline` decorations should NOT show sandbox B's branch names
- `git checkout --orphan new-branch sandbox-B-branch` should be blocked
- `git name-rev <sha>` with another sandbox's branch name should be blocked
- `git log --glob=refs/heads/*` should be blocked
- `git log --branches=sandbox-*` should be blocked
- `git archive sandbox-B-branch` should be blocked
- `git format-patch sandbox-B-branch..main` should be blocked
- `git show-ref --heads` should NOT list sandbox B's branch (output filtered)
- `git log main`, `git log origin/main`, `git log HEAD~3` should all work
- `git log main~3..my-branch` should work (revision suffixes stripped)
- `git log my-branch^2` should work (revision suffixes stripped)
- `git fetch origin main` should work
- `git fetch origin` (no refspec) should work
- `git log my-branch -- src/file.py` should work (paths after `--` are not ref-checked)
- `git log my-branch src/file.py` should be blocked (no `--` separator)
- `git -C /path log` should correctly identify `log` as the subcommand
