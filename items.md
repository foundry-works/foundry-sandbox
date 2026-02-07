# Remaining Branch Isolation Review Items

Items identified during senior code review. Status tracked below.

## HIGH Severity

### ~~SHA reachability fails open on bare repo resolution failure~~ FIXED
- `_resolve_bare_repo_path` failure now returns `ValidationError` instead of `None`

### ~~Output filter "safe default" keeps unrecognized lines~~ FIXED
- `_filter_branch_output` and `_filter_ref_enum_output` now drop unrecognized lines (fail-closed)
- Empty lines preserved; debug logging added for dropped lines

## MEDIUM Severity

### ~~`fetch --all` not blocked~~ FIXED
- Added `--all` check to `_validate_fetch_isolation`

### ~~Stderr not filtered~~ FIXED
- Added `_filter_stderr_branch_refs` that redacts `refs/heads/` and `refs/remotes/` patterns
- Applied to stderr in `execute_git` alongside stdout filtering

### ~~`_extract_sha_args` doesn't skip value flags~~ FIXED
- Mirrors `_REF_READING_VALUE_FLAGS` skip logic from `_validate_ref_reading_isolation`

### ~~Blocking subprocess/sleep in async context~~ NO CHANGE NEEDED
- `execute_git` (containing `_check_sha_reachability` and `_fetch_lock`) already runs in a thread pool via `execute_git_async`'s `run_in_executor` — blocking calls don't stall the event loop

### ~~`_is_allowed_ref` only handles `origin/` remote~~ FIXED
- Now handles `refs/remotes/<any-remote>/<branch>` generically
- Short form `<remote>/<branch>` also handled for non-origin remotes

### ~~`refs/remotes/` short path returns True for < 4 parts~~ FIXED
- `_is_allowed_short_ref_token` now returns `False` for incomplete remote ref paths

## LOW Severity

### ~~Dead code: `stash@{` check~~ KEPT (defensive)
- Added comment explaining it's defensive against malformed variants

### ~~`notes_args` assigned but never used~~ ALREADY FIXED
- Was already removed in a prior commit

### ~~`_NOTES_SUBCMDS` defined inside function body~~ FIXED
- Moved to module-level constant

### ~~Missing `--` before `$branch` in shell cleanup~~ FIXED
- Changed `git branch -D "$branch"` to `git branch -D -- "$branch"` in `lib/git_worktree.sh`

### File size / modularity
- Not addressed — refactoring deferred to a separate effort

## Test Coverage Gaps — Status

### Added tests for:
- `_extract_sha_args` value flag skipping (9 tests)
- `_filter_stderr_branch_refs` redaction (6 tests)
- `fetch --all` blocking (3 tests)
- Non-origin remote ref validation (7 tests)
- `_is_allowed_short_ref_token` incomplete paths (5 tests)
- Output filter unrecognized line dropping (4 tests)
- `validate_sha_reachability` fail-closed (4 tests)
- `^ref` exclusion prefix behaviour (2 tests)
- `ref@{upstream}` suffix patterns (3 tests)
- `--branches=`/`--remotes=`/`--glob=` value forms (3 tests)
- Reflog expire/delete sub-subcommands (5 tests)
- Bisect sub-subcommands (4 tests, incl. documented gaps)
- ls-remote/show-ref output filtering (2 tests)

### Still untested (deferred):
- `_resolve_bare_repo_path` — worktree gitdir/commondir chain (needs filesystem fixtures)
- `_fetch_lock` — timeout, `os.open` failure, concurrent locking (needs process-level test)
- `_check_sha_reachability` / `_get_allowed_refs` — needs bare repo fixture
- `_filter_log_source_refs` (`--source` output filtering)
- `--stdin` input to rev-list (bypasses all ref argument checking)
- Format specifiers `%gD`, `%S`, `%gs` in log output (not filtered)
- `git branch -a` verbose mode remote output
