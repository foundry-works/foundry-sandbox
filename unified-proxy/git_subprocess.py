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
from typing import Dict, Generator, List, Optional

from branch_types import GIT_BINARY
from git_command_validation import SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment Sanitization
# ---------------------------------------------------------------------------

# Vars to explicitly clear (set to empty string in subprocess env)
ENV_VARS_TO_CLEAR: tuple = (
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EDITOR",
    "GIT_PAGER",
)

# Prefixes to strip from environment
ENV_PREFIX_STRIP: tuple = (
    "GIT_",
    "SSH_",
)

# Minimal allowed env vars for git execution
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


def build_clean_env() -> Dict[str, str]:
    """Build a sanitized environment for git subprocess execution.

    Starts from an empty env and only copies allowed variables.
    All GIT_* and SSH_* vars are excluded.
    """
    clean: Dict[str, str] = {}

    for key in ENV_ALLOWED:
        val = os.environ.get(key)
        if val is not None:
            clean[key] = val

    # Ensure PATH is always set
    if "PATH" not in clean:
        clean["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    # Pass through our internal credential token for the git credential helper.
    # This is NOT a git-recognized variable — it's only read by our own
    # /var/run/proxy/git-credential-helper.sh script set up in entrypoint.sh.
    token = os.environ.get("GIT_CREDENTIAL_TOKEN")
    if token:
        clean["GIT_CREDENTIAL_TOKEN"] = token

    return clean


# ---------------------------------------------------------------------------
# Git Config Helpers
# ---------------------------------------------------------------------------


def _git_config_get(
    cwd: str,
    env: Dict[str, str],
    key: str,
    git_dir: Optional[str] = None,
) -> Optional[str]:
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
    bare_repo: Optional[str],
) -> Dict[str, Dict[str, list]]:
    """Parse remote URLs directly from a bare repo config file.

    Returns mapping: remote -> {"url": str|None, "pushurls": [str]}.
    """
    if not bare_repo:
        return {}
    config_path = os.path.join(bare_repo, "config")
    if not os.path.isfile(config_path):
        return {}
    remotes: Dict[str, Dict[str, list]] = {}
    current: Optional[str] = None
    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                    continue
                if stripped.startswith("[") and stripped.endswith("]"):
                    m = re.match(r'\[remote "(.+)"\]', stripped)
                    if m:
                        current = m.group(1)
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
    env: Dict[str, str],
    key: str,
    git_dir: Optional[str] = None,
) -> List[str]:
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
    env: Dict[str, str],
    git_dir: Optional[str] = None,
) -> List[str]:
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
    names: List[str] = []
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
    env: Dict[str, str],
    git_dir: Optional[str] = None,
) -> str:
    """Build a fallback `git remote -v` output from config (best-effort)."""
    remotes = _get_remote_names_from_config(cwd, env, git_dir)
    remotes_from_file = _read_remote_urls_from_bare_config(git_dir)
    if not remotes:
        remotes = sorted(remotes_from_file.keys())
    if not remotes:
        return ""

    lines: List[str] = []
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
) -> Generator[None, None, None]:
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
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
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
