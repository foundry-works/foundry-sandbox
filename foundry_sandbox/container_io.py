"""Container I/O primitives for foundry-sandbox.

Replaces shell functions from lib/container_config.sh (copy_file_to_container,
copy_dir_to_container, copy_file_to_container_quiet, copy_dir_to_container_quiet)
and adds docker_exec_json / docker_exec_text helpers.

Uses tar piped into ``docker exec`` for reliable host-to-container file transfer
with macOS metadata suppression (COPYFILE_DISABLE, --no-xattrs) and automatic
retry logic.

No Click or Pydantic imports at module level (bridge-callable constraint).
"""

from __future__ import annotations

import functools
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from foundry_sandbox.constants import CONTAINER_READY_ATTEMPTS, CONTAINER_READY_DELAY, CONTAINER_USER, TIMEOUT_DOCKER_EXEC, TIMEOUT_LOCAL_CMD, get_sandbox_verbose
from foundry_sandbox.utils import log_debug, log_error


# ============================================================================
# Tar Feature Detection (cached per process)
# ============================================================================


@functools.lru_cache(maxsize=1)
def _tar_supports_no_xattrs() -> bool:
    """Check if host tar supports --no-xattrs."""
    try:
        result = subprocess.run(
            ["tar", "--no-xattrs", "--version"],
            capture_output=True, check=False, timeout=TIMEOUT_LOCAL_CMD,
        )
        return result.returncode == 0
    except OSError as exc:
        log_debug(f"tar --no-xattrs check failed: {exc}")
        return False


@functools.lru_cache(maxsize=1)
def _tar_supports_transform() -> bool:
    """Check if host tar supports --transform."""
    try:
        result = subprocess.run(
            ["tar", "--help"],
            capture_output=True, text=True, check=False, timeout=TIMEOUT_LOCAL_CMD,
        )
        return "--transform" in result.stdout or "--transform" in result.stderr
    except OSError as exc:
        log_debug(f"tar --transform check failed: {exc}")
        return False


# ============================================================================
# Internal Helpers
# ============================================================================


# Directories that container copy operations should never target.
# These are system paths that, if overwritten, could compromise the container.
_CONTAINER_BLOCKED_PREFIXES = (
    "/etc/", "/proc/", "/sys/", "/dev/",
    "/var/run/", "/run/", "/sbin/", "/bin/",
    "/usr/sbin/", "/usr/bin/",
)


def _validate_container_dst(dst: str) -> None:
    """Reject container destination paths targeting sensitive system directories.

    Raises:
        ValueError: If dst targets a blocked system path.
    """
    normalized = dst.rstrip("/") + "/"
    for prefix in _CONTAINER_BLOCKED_PREFIXES:
        if normalized.startswith(prefix) or dst == prefix.rstrip("/"):
            raise ValueError(
                f"Refusing to copy to container system path: {dst}"
            )


def _build_tar_base_args() -> list[str]:
    """Build base tar arguments including --no-xattrs if supported.

    Returns:
        List of extra tar flags (may be empty).
    """
    args: list[str] = []
    if _tar_supports_no_xattrs():
        args.append("--no-xattrs")
    return args


def _tar_env() -> dict[str, str]:
    """Build environment dict for tar subprocesses.

    Sets COPYFILE_DISABLE=1 to suppress macOS AppleDouble (._) metadata files.

    Returns:
        Copy of os.environ with COPYFILE_DISABLE set.
    """
    return {**os.environ, "COPYFILE_DISABLE": "1"}


def _verbose_trace(cmd_str: str) -> None:
    """Print a verbose trace line to stderr when SANDBOX_VERBOSE is set.

    Args:
        cmd_str: The command string to display.
    """
    if get_sandbox_verbose():
        print(f"+ {cmd_str}", file=sys.stderr)


def _pipe_tar_to_docker(
    tar_cmd: list[str],
    docker_cmd: list[str],
    *,
    quiet: bool = False,
) -> int:
    """Pipe a local tar command into a docker exec tar command.

    Args:
        tar_cmd: Local tar command to produce the archive.
        docker_cmd: Docker exec command to consume the archive.
        quiet: If True, suppress stderr on both subprocesses.

    Returns:
        Exit code of the docker process (0 on success).
    """
    stderr_kwargs: dict[str, Any] = {}
    if quiet:
        stderr_kwargs["stderr"] = subprocess.DEVNULL

    tar_proc = subprocess.Popen(
        tar_cmd, stdout=subprocess.PIPE, env=_tar_env(), **stderr_kwargs,
    )
    try:
        docker_proc = subprocess.Popen(
            docker_cmd, stdin=tar_proc.stdout, **stderr_kwargs,
        )
        tar_proc.stdout.close()  # Allow tar_proc to receive SIGPIPE if docker_proc exits
        try:
            docker_proc.wait(timeout=TIMEOUT_DOCKER_EXEC)
        except subprocess.TimeoutExpired:
            docker_proc.kill()
            docker_proc.wait()
            raise
    finally:
        if tar_proc.stdout and not tar_proc.stdout.closed:
            tar_proc.stdout.close()
        try:
            tar_proc.wait(timeout=TIMEOUT_DOCKER_EXEC)
        except subprocess.TimeoutExpired:
            tar_proc.kill()
            tar_proc.wait()

    # Check both processes — tar failure should not be silently ignored
    if tar_proc.returncode != 0 and docker_proc.returncode == 0:
        return tar_proc.returncode
    return docker_proc.returncode


# ============================================================================
# Copy File to Container
# ============================================================================


def copy_file_to_container(
    container_id: str,
    src: str,
    dst: str,
    *,
    quiet: bool = False,
    mode: str | None = None,
) -> bool:
    """Copy a single file from host to container using tar piped into docker exec.

    Handles basename mismatches via --transform (if supported) or a fallback
    ``docker exec mv`` rename. Retries up to 5 attempts with 0.2s sleep.

    Args:
        container_id: Docker container ID or name.
        src: Source file path on the host.
        dst: Destination file path inside the container.
        quiet: If True, suppress stderr output.
        mode: If set, chmod the file to this mode immediately after copy
              (e.g. "0600"). Eliminates TOCTOU window for sensitive files.

    Returns:
        True on success, False after exhausting retries.

    Raises:
        ValueError: If dst targets a blocked system path.
    """
    _validate_container_dst(dst)

    src_path = Path(src)
    dst_path = Path(dst)
    parent_dir = str(dst_path.parent)
    src_dir = str(src_path.parent)
    src_base = src_path.name
    dst_base = dst_path.name

    base_tar_args = _build_tar_base_args()
    needs_rename = src_base != dst_base

    stderr_kwargs: dict[str, Any] = {}
    if quiet:
        stderr_kwargs["stderr"] = subprocess.DEVNULL

    def _post_copy_chmod() -> bool:
        """Apply chmod immediately after copy to eliminate TOCTOU window."""
        if mode is None:
            return True
        if not re.fullmatch(r"[0-7]{3,4}", mode):
            raise ValueError(f"invalid chmod mode: {mode!r}")
        chmod_cmd = [
            "docker", "exec", "-u", CONTAINER_USER,
            container_id, "chmod", mode, dst,
        ]
        _verbose_trace(" ".join(chmod_cmd))
        return subprocess.run(chmod_cmd, check=False, timeout=TIMEOUT_DOCKER_EXEC, **stderr_kwargs).returncode == 0

    for attempt in range(CONTAINER_READY_ATTEMPTS):
        # Create parent directory inside container
        mkdir_cmd = [
            "docker", "exec", "-u", CONTAINER_USER,
            container_id, "mkdir", "-p", parent_dir,
        ]
        _verbose_trace(" ".join(mkdir_cmd))
        subprocess.run(mkdir_cmd, check=False, timeout=TIMEOUT_DOCKER_EXEC, **stderr_kwargs)

        if not needs_rename:
            # Simple case: basenames match
            tar_cmd = ["tar"] + base_tar_args + ["-C", src_dir, "-cf", "-", src_base]
            docker_cmd = [
                "docker", "exec", "-i", "-u", CONTAINER_USER,
                container_id, "tar", "--warning=no-unknown-keyword",
                "-C", parent_dir, "-xf", "-",
            ]
            _verbose_trace(
                f"COPYFILE_DISABLE=1 tar{' ' + ' '.join(base_tar_args) if base_tar_args else ''}"
                f' -C "{src_dir}" -cf - "{src_base}"'
                f' | docker exec -u "{CONTAINER_USER}" -i "{container_id}"'
                f' tar --warning=no-unknown-keyword -C "{parent_dir}" -xf -'
            )
            rc = _pipe_tar_to_docker(tar_cmd, docker_cmd, quiet=quiet)
            if rc == 0 and _post_copy_chmod():
                return True
        elif _tar_supports_transform():
            # Rename during transfer using --transform
            transform_expr = f"s|^{src_base}$|{dst_base}|"
            tar_cmd = (
                ["tar"] + base_tar_args
                + ["-C", src_dir, f"--transform={transform_expr}", "-cf", "-", src_base]
            )
            docker_cmd = [
                "docker", "exec", "-i", "-u", CONTAINER_USER,
                container_id, "tar", "--warning=no-unknown-keyword",
                "-C", parent_dir, "-xf", "-",
            ]
            _verbose_trace(
                f"COPYFILE_DISABLE=1 tar{' ' + ' '.join(base_tar_args) if base_tar_args else ''}"
                f' -C "{src_dir}" --transform="s|^{src_base}$|{dst_base}|"'
                f' -cf - "{src_base}"'
                f' | docker exec -u "{CONTAINER_USER}" -i "{container_id}"'
                f' tar --warning=no-unknown-keyword -C "{parent_dir}" -xf -'
            )
            rc = _pipe_tar_to_docker(tar_cmd, docker_cmd, quiet=quiet)
            if rc == 0 and _post_copy_chmod():
                return True
        else:
            # Fallback: tar with original name, then mv to rename
            tar_cmd = ["tar"] + base_tar_args + ["-C", src_dir, "-cf", "-", src_base]
            docker_cmd = [
                "docker", "exec", "-i", "-u", CONTAINER_USER,
                container_id, "tar", "--warning=no-unknown-keyword",
                "-C", parent_dir, "-xf", "-",
            ]
            _verbose_trace(
                f"COPYFILE_DISABLE=1 tar{' ' + ' '.join(base_tar_args) if base_tar_args else ''}"
                f' -C "{src_dir}" -cf - "{src_base}"'
                f' | docker exec -u "{CONTAINER_USER}" -i "{container_id}"'
                f' tar --warning=no-unknown-keyword -C "{parent_dir}" -xf -'
            )
            rc = _pipe_tar_to_docker(tar_cmd, docker_cmd, quiet=quiet)
            if rc == 0:
                mv_cmd = [
                    "docker", "exec", "-u", CONTAINER_USER,
                    container_id, "mv", "-f",
                    f"{parent_dir}/{src_base}", dst,
                ]
                _verbose_trace(" ".join(mv_cmd))
                mv_result = subprocess.run(mv_cmd, check=False, timeout=TIMEOUT_DOCKER_EXEC, **stderr_kwargs)
                if mv_result.returncode == 0 and _post_copy_chmod():
                    return True

        if attempt < CONTAINER_READY_ATTEMPTS - 1:
            time.sleep(CONTAINER_READY_DELAY)

    log_error(f"copy_file_to_container failed after {CONTAINER_READY_ATTEMPTS} attempts: {src} -> {dst}")
    return False


# ============================================================================
# Copy Directory to Container
# ============================================================================


def copy_dir_to_container(
    container_id: str,
    src: str,
    dst: str,
    excludes: list[str] | None = None,
    *,
    quiet: bool = False,
) -> bool:
    """Copy an entire directory from host to container using tar piped into docker exec.

    Retries up to 5 attempts with 0.2s sleep between retries.

    Args:
        container_id: Docker container ID or name.
        src: Source directory path on the host.
        dst: Destination directory path inside the container.
        excludes: Optional list of exclude patterns for tar.
        quiet: If True, suppress stderr output.

    Returns:
        True on success, False after exhausting retries.

    Raises:
        ValueError: If dst targets a blocked system path.
    """
    _validate_container_dst(dst)

    base_tar_args = _build_tar_base_args()

    exclude_args: list[str] = []
    if excludes:
        for pattern in excludes:
            exclude_args.append(f"--exclude={pattern}")

    stderr_kwargs: dict[str, Any] = {}
    if quiet:
        stderr_kwargs["stderr"] = subprocess.DEVNULL

    for attempt in range(CONTAINER_READY_ATTEMPTS):
        # Create destination directory inside container
        mkdir_cmd = [
            "docker", "exec", "-u", CONTAINER_USER,
            container_id, "mkdir", "-p", dst,
        ]
        _verbose_trace(" ".join(mkdir_cmd))
        subprocess.run(mkdir_cmd, check=False, timeout=TIMEOUT_DOCKER_EXEC, **stderr_kwargs)

        tar_cmd = ["tar"] + base_tar_args + exclude_args + ["-C", src, "-cf", "-", "."]
        docker_cmd = [
            "docker", "exec", "-i", "-u", CONTAINER_USER,
            container_id, "tar", "--warning=no-unknown-keyword",
            "-C", dst, "-xf", "-",
        ]

        all_tar_flags = base_tar_args + exclude_args
        _verbose_trace(
            f"COPYFILE_DISABLE=1 tar{' ' + ' '.join(all_tar_flags) if all_tar_flags else ''}"
            f' -C "{src}" -cf - .'
            f' | docker exec -u "{CONTAINER_USER}" -i "{container_id}"'
            f' tar --warning=no-unknown-keyword -C "{dst}" -xf -'
        )

        rc = _pipe_tar_to_docker(tar_cmd, docker_cmd, quiet=quiet)
        if rc == 0:
            return True

        if attempt < CONTAINER_READY_ATTEMPTS - 1:
            time.sleep(CONTAINER_READY_DELAY)

    log_error(f"copy_dir_to_container failed after {CONTAINER_READY_ATTEMPTS} attempts: {src} -> {dst}")
    return False


# ============================================================================
# Quiet Variants
# ============================================================================


def copy_file_to_container_quiet(
    container_id: str,
    src: str,
    dst: str,
) -> bool:
    """Copy a single file from host to container, suppressing stderr.

    Same as ``copy_file_to_container`` but passes stderr=subprocess.DEVNULL
    to all subprocess calls.

    Args:
        container_id: Docker container ID or name.
        src: Source file path on the host.
        dst: Destination file path inside the container.

    Returns:
        True on success, False after exhausting retries.
    """
    return copy_file_to_container(container_id, src, dst, quiet=True)


def copy_dir_to_container_quiet(
    container_id: str,
    src: str,
    dst: str,
    excludes: list[str] | None = None,
) -> bool:
    """Copy an entire directory from host to container, suppressing stderr.

    Same as ``copy_dir_to_container`` but passes stderr=subprocess.DEVNULL
    to all subprocess calls.

    Args:
        container_id: Docker container ID or name.
        src: Source directory path on the host.
        dst: Destination directory path inside the container.
        excludes: Optional list of exclude patterns for tar.

    Returns:
        True on success, False after exhausting retries.
    """
    return copy_dir_to_container(container_id, src, dst, excludes=excludes, quiet=True)


# ============================================================================
# Docker Exec Helpers
# ============================================================================


def docker_exec_json(
    container_id: str,
    *args: str,
    user: str = CONTAINER_USER,
) -> Any:
    """Run a command inside a container and parse stdout as JSON.

    Args:
        container_id: Docker container ID or name.
        *args: Command and arguments to run inside the container.
        user: Container user to run as (default: ubuntu).

    Returns:
        Parsed JSON object from command stdout.

    Raises:
        ValueError: If the command output is not valid JSON.
        subprocess.CalledProcessError: If the docker exec command fails.
    """
    cmd = ["docker", "exec", "-u", user, container_id, *args]
    _verbose_trace(" ".join(cmd))

    result = subprocess.run(
        cmd, capture_output=True, text=True, check=True, timeout=TIMEOUT_DOCKER_EXEC,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"docker exec output is not valid JSON: {result.stdout!r}"
        ) from exc


def docker_exec_text(
    container_id: str,
    *args: str,
    user: str = CONTAINER_USER,
) -> str:
    """Run a command inside a container and return stdout as a stripped string.

    Args:
        container_id: Docker container ID or name.
        *args: Command and arguments to run inside the container.
        user: Container user to run as (default: ubuntu).

    Returns:
        Stripped stdout string from the command.

    Raises:
        subprocess.CalledProcessError: If the docker exec command fails.
    """
    cmd = ["docker", "exec", "-u", user, container_id, *args]
    _verbose_trace(" ".join(cmd))

    result = subprocess.run(
        cmd, capture_output=True, text=True, check=True, timeout=TIMEOUT_DOCKER_EXEC,
    )
    return result.stdout.strip()
