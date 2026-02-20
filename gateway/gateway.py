#!/usr/bin/env python3
"""Gateway service for credential-isolated sandbox operations.

Provides HTTP proxy for git operations, holding real credentials
and issuing session tokens to sandboxes.
"""

import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse  # noqa: F401 - used by future proxy routes

import requests
from flask import Flask, Response, request

# Flask app initialization
app = Flask(__name__)

# Headers that should never be logged
SENSITIVE_HEADERS = {
    "Authorization",
    "X-Auth-Token",
    "Cookie",
    "Set-Cookie",
    "X-Session-Token",
}

# Event type constants
EVENT_SESSION_CREATE = "session_create"
EVENT_SESSION_DESTROY = "session_destroy"
EVENT_GIT_ACCESS = "git_access"
EVENT_GIT_DENIED = "git_denied"
EVENT_PROXY_ALLOW = "proxy_allow"
EVENT_PROXY_DENY = "proxy_deny"

# Session configuration
SESSION_TTL_INACTIVITY = 24 * 60 * 60  # 24 hours
SESSION_TTL_ABSOLUTE = 7 * 24 * 60 * 60  # 7 days
SESSION_TOKEN_LENGTH = 32  # bytes, hex encoded = 64 chars
SESSION_SECRET_LENGTH = 32

# Git endpoint allowlist
ALLOWED_GIT_PATHS = {"info/refs", "git-upload-pack", "git-receive-pack"}

# Input validation
OWNER_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$')
REPO_REGEX = re.compile(r'^[a-zA-Z0-9._-]+$')

# Upstream configuration - hard-pinned to github.com
UPSTREAM_HOST = "github.com"
UPSTREAM_BASE = f"https://{UPSTREAM_HOST}"


def scrub_headers(headers: dict) -> dict:
    """Remove sensitive headers from a headers dictionary.

    Args:
        headers: Dictionary of headers to scrub

    Returns:
        Dictionary with sensitive headers removed
    """
    scrubbed = {}
    for key, value in headers.items():
        if key not in SENSITIVE_HEADERS:
            scrubbed[key] = value
    return scrubbed


def scrub_sensitive_fields(data: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive fields in a dictionary.

    Replaces values of fields containing 'token', 'auth', 'secret',
    'credential', or 'password' (case-insensitive) with '***REDACTED***'.

    Args:
        data: Dictionary to scrub

    Returns:
        Dictionary with sensitive fields redacted
    """
    scrubbed = {}
    sensitive_keys = {"token", "auth", "secret", "credential", "password"}

    for key, value in data.items():
        # Check if any sensitive keyword is in the key (case-insensitive)
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            scrubbed[key] = "***REDACTED***"
        else:
            scrubbed[key] = value

    return scrubbed


def get_client_info() -> Dict[str, str]:
    """Extract container_id and IP from Flask request context.

    Returns:
        Dictionary with 'container_id' and 'ip' keys
    """
    # Get IP address from request
    # Check for X-Forwarded-For header first (proxy scenario)
    ip = request.headers.get("X-Forwarded-For")
    if ip:
        # X-Forwarded-For can contain multiple IPs; take the first one
        ip = ip.split(",")[0].strip()
    else:
        ip = request.remote_addr or "unknown"

    # Get container_id from header or default to unknown
    container_id = request.headers.get("X-Container-ID", "unknown")

    return {
        "container_id": container_id,
        "ip": ip,
    }


def audit_log(event_type: str, **kwargs) -> None:
    """Log an audit event as structured JSON to stderr.

    Always includes timestamp (ISO 8601), event type, container_id, and ip.
    Scrubs sensitive fields and headers before logging.

    Args:
        event_type: Type of event (use EVENT_* constants)
        **kwargs: Additional fields to include in the log entry
    """
    # Get current timestamp in ISO 8601 format
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    # Get client info
    client_info = get_client_info()

    # Build the log entry
    log_entry = {
        "timestamp": timestamp,
        "event": event_type,
        "container_id": client_info["container_id"],
        "ip": client_info["ip"],
    }

    # Add additional fields and scrub sensitive data
    for key, value in kwargs.items():
        if key == "headers" and isinstance(value, dict):
            # Scrub headers specially
            log_entry[key] = scrub_headers(value)
        elif isinstance(value, dict):
            # Recursively scrub nested dictionaries
            log_entry[key] = scrub_sensitive_fields(value)
        else:
            # Scrub top-level fields
            scrubbed = scrub_sensitive_fields({key: value})
            log_entry[key] = scrubbed[key]

    # Write as JSON to stderr
    json_str = json.dumps(log_entry, separators=(",", ":"))
    print(json_str, file=sys.stderr)


class SessionStore:
    """Thread-safe in-memory session storage with TTL."""

    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, container_id: str, client_ip: str) -> dict:
        """Create a new session bound to container IP."""
        token = secrets.token_hex(SESSION_TOKEN_LENGTH)
        secret = secrets.token_hex(SESSION_SECRET_LENGTH)
        now = time.time()

        session = {
            "token": token,
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "container_id": container_id,
            "client_ip": client_ip,
            "created_at": now,
            "last_used": now,
        }

        with self._lock:
            self._sessions[token] = session

        return {"token": token, "secret": secret}

    def validate(self, token: str, secret: str, client_ip: str) -> Optional[Dict]:
        """Validate token+secret+IP. Returns session or None."""
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None

            now = time.time()
            # Check TTLs
            if now - session["last_used"] > SESSION_TTL_INACTIVITY:
                del self._sessions[token]
                return None
            if now - session["created_at"] > SESSION_TTL_ABSOLUTE:
                del self._sessions[token]
                return None

            # Verify secret
            secret_hash = hashlib.sha256(secret.encode()).hexdigest()
            if not secrets.compare_digest(secret_hash, session["secret_hash"]):
                return None

            # Verify IP binding
            if session["client_ip"] != client_ip:
                return None

            # Update last used
            session["last_used"] = now
            return session

    def destroy(self, token: str) -> bool:
        """Destroy a session. Returns True if found."""
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def gc(self):
        """Remove expired sessions."""
        now = time.time()
        with self._lock:
            expired = [
                t for t, s in self._sessions.items()
                if now - s["last_used"] > SESSION_TTL_INACTIVITY
                or now - s["created_at"] > SESSION_TTL_ABSOLUTE
            ]
            for t in expired:
                del self._sessions[t]
        return len(expired)


sessions = SessionStore()


@app.before_request
def log_request_start() -> None:
    """Log incoming request before processing."""
    # Store the request start time for latency calculation
    request.start_time = time.time()


@app.after_request
def log_request_end(response):
    """Log request completion after processing."""
    # Calculate request duration
    duration_ms = None
    if hasattr(request, "start_time"):
        duration_ms = int((time.time() - request.start_time) * 1000)

    # Log the request/response
    audit_log(
        "http_request",
        method=request.method,
        path=request.path,
        status=response.status_code,
        duration_ms=duration_ms,
    )

    return response


@app.route("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.route("/session/create", methods=["POST"])
def session_create():
    """Create a new session. Only accessible from Unix socket / internal network."""
    data = request.get_json(silent=True) or {}
    container_id = data.get("container_id", "unknown")
    client_ip = request.remote_addr or "unknown"

    result = sessions.create(container_id, client_ip)

    audit_log(EVENT_SESSION_CREATE, container_id=container_id)
    return {"token": result["token"], "secret": result["secret"]}, 201


@app.route("/session/destroy", methods=["POST"])
def session_destroy():
    """Destroy an existing session."""
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")

    if sessions.destroy(token):
        audit_log(EVENT_SESSION_DESTROY)
        return {"status": "destroyed"}, 200

    return {"error": "session not found"}, 404


@app.route("/session/gc", methods=["POST"])
def session_gc():
    """Run session garbage collection."""
    count = sessions.gc()
    return {"expired": count}, 200


@app.route("/git/<owner>/<repo_name>.git/<path:git_path>", methods=["GET", "POST"])
def git_proxy(owner: str, repo_name: str, git_path: str):
    """Proxy git Smart HTTP requests to upstream."""
    # Validate owner
    if not OWNER_REGEX.match(owner):
        audit_log(EVENT_GIT_DENIED, reason="invalid owner", owner=owner)
        return {"error": "invalid owner"}, 400

    # Validate repo
    if not REPO_REGEX.match(repo_name):
        audit_log(EVENT_GIT_DENIED, reason="invalid repo", repo=repo_name)
        return {"error": "invalid repo name"}, 400

    # Validate git path - only allowed endpoints
    if git_path not in ALLOWED_GIT_PATHS:
        audit_log(EVENT_GIT_DENIED, reason="disallowed path", path=git_path)
        return {"error": "disallowed git endpoint"}, 403

    # Validate session
    token = request.headers.get("X-Session-Token", "")
    secret = request.headers.get("X-Session-Secret", "")
    client_ip = request.remote_addr or "unknown"

    session = sessions.validate(token, secret, client_ip)
    if not session:
        audit_log(EVENT_GIT_DENIED, reason="invalid session", owner=owner, repo=repo_name)
        return {"error": "unauthorized"}, 401

    # Build upstream URL - hard-pinned to github.com
    upstream_url = f"{UPSTREAM_BASE}/{owner}/{repo_name}.git/{git_path}"

    # Forward query string (needed for ?service=git-upload-pack)
    if request.query_string:
        upstream_url += f"?{request.query_string.decode()}"

    # Get GitHub token from environment
    github_token = os.environ.get("GITHUB_TOKEN", "")

    # Proxy the request
    headers = {
        "User-Agent": "foundry-gateway/1.0",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    try:
        resp = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=request.get_data(),
            stream=True,
            allow_redirects=False,  # CRITICAL: disable redirects
            timeout=120,
        )
    except requests.RequestException as e:
        audit_log(EVENT_GIT_DENIED, reason="upstream error", error=str(e))
        return {"error": "upstream unavailable"}, 502

    # Check for redirect (should not happen with github.com, but block it)
    if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
        audit_log(EVENT_GIT_DENIED, reason="redirect blocked",
                  status=resp.status_code, location=resp.headers.get("Location", ""))
        return {"error": "redirects not allowed"}, 502

    audit_log(EVENT_GIT_ACCESS, owner=owner, repo=repo_name, path=git_path,
              upstream_status=resp.status_code)

    # Stream response back
    return Response(
        resp.iter_content(chunk_size=8192),
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type", "application/octet-stream"),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
