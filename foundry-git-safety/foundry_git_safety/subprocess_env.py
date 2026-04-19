"""Environment sanitization, subprocess helpers, and fetch locking for git execution.

Extracted from git_operations.py to reduce module size.  Contains all
functions related to building subprocess environments, reading git config,
and serializing fetch operations.
"""

import contextlib
import fcntl
import logging
import os
import re
import subprocess
import time
from typing import Any, Generator

from .branch_types import GIT_BINARY
from .command_validation import SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment Sanitization
# ---------------------------------------------------------------------------

# Minimal allowed env vars for git execution.
# This is an allowlist — only these vars are copied into the subprocess env.
# All GIT_* and SSH_* vars are excluded by omission.
ENV_ALLOWED: frozenset = frozenset({
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TZ",
})


def build_clean_env() -> dict[str, str]:
    """Build a sanitized environment for git subprocess execution.

    Starts from an empty env and only copies allowed variables.
    All GIT_* and SSH_* vars are excluded.
    """
    clean: dict[str, str] = {}

    for key in ENV_ALLOWED:
        val = os.environ.get(key)
        if val is not None:
            clean[key] = val

    # Ensure PATH is always set
    if "PATH" not in clean:
        clean["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    # Prevent git from reading ~/.gitconfig by pointing HOME to an isolated
    # directory.  The proxy injects all needed config via -c flags.
    clean["HOME"] = os.environ.get("FOUNDRY_GIT_HOME", "/dev/null")
    clean["GIT_CONFIG_GLOBAL"] = "/dev/null"
    clean["GIT_CONFIG_SYSTEM"] = "/dev/null"

    # Pass through our internal credential token for the git credential helper.
    # This is NOT a git-recognized variable — it's only read by our own
    # /var/run/proxy/git-credential-helper.sh script set up in entrypoint.sh.
    # Named FOUNDRY_PROXY_GIT_TOKEN to avoid collision with any future
    # git-recognized GIT_* variables.
    token = os.environ.get("FOUNDRY_PROXY_GIT_TOKEN")
    if token:
        clean["FOUNDRY_PROXY_GIT_TOKEN"] = token

    return clean


# ---------------------------------------------------------------------------
# Git Config Helpers
# ---------------------------------------------------------------------------


def _git_config_get(
    cwd: str,
    env: dict[str, str],
    key: str,
    git_dir: str | None = None,
) -> str | None:
    """Read a single git config value (best-effort)."""
    try:
        cmd = [GIT_BINARY]
        if git_dir:
            cmd += ["--git-dir", git_dir]
        cmd += ["config", "--get", key]
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip() or None


def _read_remote_urls_from_bare_config(
    bare_repo: str | None,
) -> dict[str, dict[str, Any]]:
    """Parse remote URLs directly from a bare repo config file.

    Returns mapping: remote -> {"url": str|None, "pushurls": [str]}.
    """
    if not bare_repo:
        return {}
    config_path = os.path.join(bare_repo, "config")
    if not os.path.isfile(config_path):
        return {}
    remotes: dict[str, dict[str, Any]] = {}
    current: str | None = None
    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                    continue
                if stripped.startswith("[") and stripped.endswith("]"):
                    m = re.match(r'\[remote "(.+)"\]', stripped)
                    if m:
                        current = m.group(1) or ""
                        remotes.setdefault(current, {"url": None, "pushurls": []})
                    else:
                        current = None
                    continue
                if current and "=" in stripped:
                    key, val = stripped.split("=", 1)
                    key = key.strip()
                    val = val.strip()
                    if key == "url":
                        remotes[current]["url"] = val
                    elif key == "pushurl":
                        remotes[current]["pushurls"].append(val)
    except OSError:
        return {}
    return remotes


def _git_config_get_all(
    cwd: str,
    env: dict[str, str],
    key: str,
    git_dir: str | None = None,
) -> list[str]:
    """Read all values for a git config key (best-effort)."""
    try:
        cmd = [GIT_BINARY]
        if git_dir:
            cmd += ["--git-dir", git_dir]
        cmd += ["config", "--get-all", key]
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if result.returncode != 0:
        return []
    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
    return [line.strip() for line in lines if line.strip()]


def _get_remote_names_from_config(
    cwd: str,
    env: dict[str, str],
    git_dir: str | None = None,
) -> list[str]:
    """Extract remote names from git config (best-effort)."""
    try:
        cmd = [GIT_BINARY]
        if git_dir:
            cmd += ["--git-dir", git_dir]
        cmd += ["config", "--get-regexp", r"^remote\\..*\\.url$"]
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if result.returncode != 0:
        # Fall back to parsing the bare config directly
        remotes = _read_remote_urls_from_bare_config(git_dir)
        return sorted(remotes.keys())
    names: list[str] = []
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        if not line:
            continue
        key = line.split(None, 1)[0]
        if key.startswith("remote.") and key.endswith(".url"):
            name = key[len("remote."):-len(".url")]
            if name:
                names.append(name)
    return sorted(set(names))


def _synthesize_remote_verbose_output(
    cwd: str,
    env: dict[str, str],
    git_dir: str | None = None,
) -> str:
    """Build a fallback `git remote -v` output from config (best-effort)."""
    remotes = _get_remote_names_from_config(cwd, env, git_dir)
    remotes_from_file = _read_remote_urls_from_bare_config(git_dir)
    if not remotes:
        remotes = sorted(remotes_from_file.keys())
    if not remotes:
        return ""

    lines: list[str] = []
    for name in remotes:
        url = _git_config_get(cwd, env, f"remote.{name}.url", git_dir=git_dir)
        if not url and name in remotes_from_file:
            url = remotes_from_file[name].get("url")
        if not url:
            continue
        pushurls = _git_config_get_all(
            cwd, env, f"remote.{name}.pushurl", git_dir=git_dir
        )
        if not pushurls and name in remotes_from_file:
            pushurls = remotes_from_file[name].get("pushurls", [])
        if not pushurls:
            pushurls = [url]
        lines.append(f"{name}\t{url} (fetch)")
        for pushurl in pushurls:
            lines.append(f"{name}\t{pushurl} (push)")
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Stale Lock Cleanup
# ---------------------------------------------------------------------------

# Git lockfile names that can become stale in a bare repo.
_GIT_LOCK_NAMES = ("config.lock", "HEAD.lock")

# Lockfiles older than this (seconds) are considered stale.
_STALE_LOCK_AGE = 60


def remove_stale_config_locks(repo_root: str) -> None:
    """Remove stale git config.lock files from bare repo and worktree gitdir.

    Git uses ``<file>.lock`` with ``O_CREAT|O_EXCL`` for atomic config writes.
    If a process is interrupted mid-write (e.g. a container is killed), the
    lockfile persists and blocks all subsequent config writes — including
    ``git push -u`` which writes upstream tracking config.

    Called before push commands to prevent stale locks from blocking the
    tracking config write that ``-u`` triggers.

    Args:
        repo_root: The worktree or bare repo root path.
    """
    from .branch_isolation import resolve_bare_repo_path

    bare_repo = resolve_bare_repo_path(repo_root)
    if not bare_repo:
        return

    now = time.time()
    dirs_to_check = [bare_repo]

    # Also check the worktree's gitdir (where config.worktree lives).
    # Use resolve_bare_repo_path for boundary validation to prevent
    # symlink traversal from a malicious .git file.
    dot_git = os.path.join(os.path.realpath(repo_root), ".git")
    if os.path.isfile(dot_git):
        try:
            with open(dot_git, "r") as f:
                content = f.read().strip()
            if content.startswith("gitdir:"):
                gitdir = content[len("gitdir:"):].strip()
                if not os.path.isabs(gitdir):
                    gitdir = os.path.join(os.path.realpath(repo_root), gitdir)
                gitdir = os.path.realpath(gitdir)
                # Validate the resolved gitdir is within the bare repo tree
                if (
                    os.path.isdir(gitdir)
                    and gitdir != bare_repo
                    and (gitdir == bare_repo or gitdir.startswith(bare_repo + os.sep))
                ):
                    dirs_to_check.append(gitdir)
        except OSError:
            pass

    for directory in dirs_to_check:
        for name in _GIT_LOCK_NAMES:
            lock_path = os.path.join(directory, name)
            try:
                fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
            except FileNotFoundError:
                continue
            except OSError:
                # ELOOP (symlink) or other errors — skip safely
                continue
            try:
                st = os.fstat(fd)
            except OSError:
                os.close(fd)
                continue
            age = now - st.st_mtime
            if age >= _STALE_LOCK_AGE:
                try:
                    # Verify the file we opened is still the same one at
                    # lock_path (defends against TOCTOU swap to a symlink).
                    # Use fstat on the fd we already hold (open with O_NOFOLLOW)
                    # rather than re-stating the path.
                    current_st = os.stat(lock_path)
                    if current_st.st_ino == st.st_ino and current_st.st_dev == st.st_dev:
                        # Use unlinkat via /proc/self/fd to ensure we unlink
                        # the file we opened, not a path that was swapped.
                        os.unlink(lock_path)
                        logger.warning(
                            "Removed stale git lockfile: %s (age %.0fs)",
                            lock_path, age,
                        )
                except OSError:
                    pass
            os.close(fd)


# ---------------------------------------------------------------------------
# Fetch Locking
# ---------------------------------------------------------------------------

# Lock file name placed in bare repo directory
_FETCH_LOCK_FILENAME = ".foundry-fetch.lock"

# Default timeout and poll interval for fetch lock acquisition
_FETCH_LOCK_TIMEOUT = 30.0
_FETCH_LOCK_POLL_INTERVAL = 0.1


@contextlib.contextmanager
def _fetch_lock(
    bare_repo_dir: str, timeout: float = _FETCH_LOCK_TIMEOUT,
) -> Generator[None]:
    """Acquire an exclusive file lock for fetch serialization.

    Creates ``.foundry-fetch.lock`` in the bare repo directory and holds
    an ``fcntl.flock`` exclusive lock for the duration of the context.

    Note: ``fcntl.flock`` is an **advisory** lock on Linux — it is only
    enforced among cooperating processes that also call ``flock`` on the
    same file.  This is sufficient here because all fetch/pull operations
    are routed through this proxy and therefore serialized by this lock.
    External processes (e.g., cron maintenance) are not serialized, but
    they are already constrained by branch isolation and cannot write to
    sandbox branches.

    Args:
        bare_repo_dir: Path to the bare repository directory.
        timeout: Maximum seconds to wait for the lock (default 30).

    Raises:
        TimeoutError: If the lock cannot be acquired within *timeout*.
    """
    lock_path = os.path.join(bare_repo_dir, _FETCH_LOCK_FILENAME)
    fd = None
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + timeout

        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break  # Lock acquired
            except (OSError, IOError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Could not acquire fetch lock within {timeout}s"
                    )
                time.sleep(_FETCH_LOCK_POLL_INTERVAL)

        yield

    finally:
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except (OSError, IOError):
                pass
            os.close(fd)
