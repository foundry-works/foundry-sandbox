#!/usr/bin/env python3
"""Standalone git API server for sbx validation spike.

Minimal version of unified-proxy/git_api.py that runs on the host without
mitmproxy or Docker networking dependencies.

Security:
- HMAC-SHA256 signature on every request
- Replay protection via nonce + clock window
- Per-sandbox rate limiting
- Executes git against a bare repo on the host

Usage:
    python3 git-api-standalone.py --repo /path/to/bare/repo --port 8083

Phase 0 validation only — NOT production hardened.
"""

import argparse
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CLOCK_WINDOW_SECONDS = 300
NONCE_TTL_SECONDS = 600
NONCE_MAX = 1000
RATE_BURST = 300
RATE_SUSTAINED = 120  # per minute
MAX_BODY_SIZE = 256 * 1024

# ---------------------------------------------------------------------------
# HMAC Secret Store
# ---------------------------------------------------------------------------

class SecretStore:
    def __init__(self, secrets_path: str):
        self._path = secrets_path
        self._cache: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def get_secret(self, sandbox_id: str) -> Optional[bytes]:
        with self._lock:
            if sandbox_id in self._cache:
                return self._cache[sandbox_id]

        secret_path = os.path.join(self._path, sandbox_id)
        try:
            with open(secret_path, "rb") as f:
                secret = f.read().rstrip(b"\n")
            if secret:
                with self._lock:
                    self._cache[sandbox_id] = secret
                return secret
        except FileNotFoundError:
            pass
        return None

# ---------------------------------------------------------------------------
# Nonce Store
# ---------------------------------------------------------------------------

class NonceStore:
    def __init__(self):
        self._nonces: Dict[str, OrderedDict] = {}
        self._lock = threading.Lock()

    def check_and_store(self, sandbox_id: str, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            if sandbox_id not in self._nonces:
                self._nonces[sandbox_id] = OrderedDict()

            cache = self._nonces[sandbox_id]

            # Evict expired
            while cache:
                oldest_n, oldest_t = next(iter(cache.items()))
                if now - oldest_t > NONCE_TTL_SECONDS:
                    cache.popitem(last=False)
                else:
                    break

            # Evict if over max
            while len(cache) >= NONCE_MAX:
                cache.popitem(last=False)

            if nonce in cache:
                return False

            cache[nonce] = now
            return True

# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self):
        self._buckets: Dict[str, list] = {}
        self._global_times: list = []
        self._lock = threading.Lock()

    def check(self, sandbox_id: str) -> bool:
        now = time.time()
        with self._lock:
            # Per-sandbox
            if sandbox_id not in self._buckets:
                self._buckets[sandbox_id] = []
            times = self._buckets[sandbox_id]
            times[:] = [t for t in times if now - t < 60]
            if len(times) >= RATE_BURST:
                return False
            times.append(now)

            # Global
            self._global_times[:] = [t for t in self._global_times if now - t < 60]
            return len(self._global_times) < RATE_SUSTAINED * 10

# ---------------------------------------------------------------------------
# Signature Verification
# ---------------------------------------------------------------------------

def verify_signature(method, path, body, timestamp, nonce, provided_sig, secret):
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{method}\n{path}\n{body_hash}\n{timestamp}\n{nonce}"
    expected = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided_sig)

# ---------------------------------------------------------------------------
# Git Execution
# ---------------------------------------------------------------------------

def execute_git(args: list, cwd: str, repo_root: str) -> dict:
    if not args:
        return {"exit_code": 1, "stdout": "", "stderr": "error: no arguments provided"}

    # Validate command is in allowlist (basic check for spike)
    cmd = args[0] if args else ""
    allowed_commands = {
        "status", "add", "rm", "restore", "stash", "clean",
        "commit", "cherry-pick", "merge", "rebase", "revert",
        "branch", "checkout", "switch", "tag",
        "diff", "show", "log", "blame", "shortlog",
        "fetch", "pull", "push", "remote",
        "clone", "rev-parse", "symbolic-ref", "for-each-ref",
        "ls-tree", "ls-files", "ls-remote", "cat-file",
        "rev-list", "diff-tree", "diff-files", "diff-index",
        "apply", "am", "format-patch", "describe", "name-rev",
        "config", "notes", "init", "version",
    }

    subcmd = cmd
    if cmd == "config" and len(args) > 1 and args[1].startswith("-"):
        # Allow git config --get etc (read-only)
        pass
    elif cmd not in allowed_commands:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": f"error: git command '{cmd}' is not allowed",
        }

    # Block dangerous flags (basic)
    blocked_flags = {"--force", "-f", "--force-with-lease", "--mirror", "--all"}
    for arg in args:
        if arg in blocked_flags:
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": f"error: flag '{arg}' is not allowed",
            }

    # Resolve working directory
    work_dir = os.path.join(repo_root, cwd) if cwd != "." else repo_root
    if not os.path.isdir(work_dir):
        work_dir = repo_root

    env = os.environ.copy()
    # Strip credential env vars
    for key in list(env.keys()):
        if key.startswith(("GIT_", "SSH_")) and key not in ("GIT_CONFIG_NOSYSTEM",):
            del env[key]

    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"

    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            cwd=work_dir,
            env=env,
            timeout=30,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "error: git command timed out"}
    except Exception as e:
        return {"exit_code": 1, "stdout": "", "stderr": str(e)}

# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

secrets: Optional[SecretStore] = None
nonces = NonceStore()
limiter = RateLimiter()
repo_root = "."

class GitAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info("%s - %s", self.client_address[0], format % args)

    def _send_json(self, code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/git/exec":
            self._send_json(404, {"error": "Not found"})
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_BODY_SIZE:
            self._send_json(413, {"error": "Request too large"})
            return
        body = self.rfile.read(content_length) if content_length else b""

        # Extract auth headers
        sandbox_id = self.headers.get("X-Sandbox-Id", "")
        signature = self.headers.get("X-Request-Signature", "")
        timestamp = self.headers.get("X-Request-Timestamp", "")
        nonce = self.headers.get("X-Request-Nonce", "")

        if not all([sandbox_id, signature, timestamp, nonce]):
            self._send_json(401, {"error": "Missing authentication headers"})
            return

        # Clock window
        try:
            req_time = float(timestamp)
        except (ValueError, TypeError):
            self._send_json(401, {"error": "Invalid timestamp"})
            return
        if abs(time.time() - req_time) > CLOCK_WINDOW_SECONDS:
            self._send_json(401, {"error": "Timestamp outside clock window"})
            return

        # Get secret
        secret = secrets.get_secret(sandbox_id)
        if secret is None:
            self._send_json(401, {"error": "Unknown sandbox"})
            return

        # Verify HMAC
        if not verify_signature(
            "POST", "/git/exec", body, timestamp, nonce, signature, secret
        ):
            self._send_json(401, {"error": "Invalid signature"})
            return

        # Nonce replay check
        if not nonces.check_and_store(sandbox_id, nonce):
            self._send_json(401, {"error": "Replayed nonce"})
            return

        # Rate limit
        if not limiter.check(sandbox_id):
            self._send_json(429, {"error": "Rate limit exceeded", "retry_after": 5})
            return

        # Parse body
        try:
            req = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Invalid JSON"})
            return

        cwd = req.get("cwd", ".")
        args = req.get("args", [])

        if not isinstance(args, list):
            self._send_json(400, {"error": "args must be a list"})
            return

        # Execute
        result = execute_git(args, cwd, repo_root)
        self._send_json(200, result)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global secrets, repo_root

    parser = argparse.ArgumentParser(description="Standalone git API server for sbx validation")
    parser.add_argument("--repo", required=True, help="Path to git repo (bare or working)")
    parser.add_argument("--port", type=int, default=8083, help="Port to listen on")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    parser.add_argument("--secrets-dir", default="/tmp/phase0-secrets", help="Directory containing HMAC secret files")
    args = parser.parse_args()

    repo_root = os.path.abspath(args.repo)
    if not os.path.isdir(repo_root):
        print(f"error: repo path does not exist: {repo_root}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.secrets_dir, exist_ok=True)
    secrets = SecretStore(args.secrets_dir)

    server = HTTPServer((args.bind, args.port), GitAPIHandler)
    logger.info("Git API server listening on %s:%d", args.bind, args.port)
    logger.info("Repo root: %s", repo_root)
    logger.info("Secrets dir: %s", args.secrets_dir)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.shutdown()

if __name__ == "__main__":
    main()
