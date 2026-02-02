#!/usr/bin/env python3
"""
Gateway service for credential isolation.
Handles GitHub URL rewriting and session token management.
Rejects IP literal requests to enforce DNS resolution.
"""

from flask import Flask, request, Response
import os
import logging
import json
import sys
from datetime import datetime, timedelta
import ipaddress
import secrets
import re
import requests
from urllib.parse import urljoin
import threading
import atexit
import base64
import hmac

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Domain allowlists (loaded from config at startup)
ALLOWLIST_DOMAINS = []  # Exact domain matches (e.g., "github.com")
WILDCARD_DOMAINS = []   # Wildcard patterns (e.g., "*.openai.com")

def load_domain_allowlist():
    """
    Load domain allowlist from firewall-allowlist.generated.

    Parses both ALLOWLIST_DOMAINS (exact matches) and WILDCARD_DOMAINS (patterns)
    from the generated config file. Called at module initialization.
    """
    global ALLOWLIST_DOMAINS, WILDCARD_DOMAINS
    config_path = os.path.join(os.path.dirname(__file__), 'firewall-allowlist.generated')

    if not os.path.exists(config_path):
        logger.warning(f'Domain allowlist config not found: {config_path}')
        return

    try:
        with open(config_path, 'r') as f:
            content = f.read()

        import re

        # Parse ALLOWLIST_DOMAINS array from bash syntax
        # Looking for: "domain.com" entries (non-wildcard)
        allowlist_pattern = r'ALLOWLIST_DOMAINS=\(\s*(.*?)\s*\)'
        allowlist_match = re.search(allowlist_pattern, content, re.DOTALL)
        if allowlist_match:
            # Extract quoted domain strings
            domains = re.findall(r'"([^"*][^"]*)"', allowlist_match.group(1))
            ALLOWLIST_DOMAINS = [d.lower() for d in domains]
            logger.info(f'Loaded {len(ALLOWLIST_DOMAINS)} exact domain patterns')

        # Parse WILDCARD_DOMAINS array from bash syntax
        # Looking for: "*.domain.com" entries
        wildcard_pattern = r'WILDCARD_DOMAINS=\(\s*(.*?)\s*\)'
        wildcard_match = re.search(wildcard_pattern, content, re.DOTALL)
        if wildcard_match:
            wildcards = re.findall(r'"(\*\.[^"]+)"', wildcard_match.group(1))
            WILDCARD_DOMAINS = [w.lower() for w in wildcards]
            logger.info(f'Loaded {len(WILDCARD_DOMAINS)} wildcard domain patterns')

        total = len(ALLOWLIST_DOMAINS) + len(WILDCARD_DOMAINS)
        logger.info(f'Total domain allowlist: {total} entries')

    except Exception as e:
        logger.error(f'Failed to load domain allowlist config: {e}')

def matches_domain_allowlist(hostname: str, allowlist: list = None, wildcards: list = None) -> bool:
    """
    Check if hostname matches the domain allowlist.

    Checks against both exact domain matches and wildcard patterns.

    Supports suffix wildcards: *.example.com matches:
    - foo.example.com
    - bar.baz.example.com
    - example.com (the base domain itself)

    Does NOT match:
    - notexample.com (different domain)
    - exampleXcom (no dot separator)

    Args:
        hostname: The hostname to check (e.g., "api.example.com")
        allowlist: Optional list of exact domains. Uses ALLOWLIST_DOMAINS if None.
        wildcards: Optional list of wildcard patterns. Uses WILDCARD_DOMAINS if None.

    Returns:
        bool: True if hostname matches any pattern in the allowlist, False otherwise
    """
    if allowlist is None:
        allowlist = ALLOWLIST_DOMAINS
    if wildcards is None:
        wildcards = WILDCARD_DOMAINS

    # SECURITY: If no allowlist is configured, deny all (fail-safe)
    if not allowlist and not wildcards:
        logger.warning('No domain allowlist configured - denying all hostnames')
        return False

    hostname = hostname.lower().rstrip('.')

    # Check exact domain matches first (fast path)
    if hostname in allowlist:
        return True

    # Check wildcard patterns
    for pattern in wildcards:
        pattern = pattern.lower().rstrip('.')
        if pattern.startswith('*.'):
            # Wildcard pattern: *.example.com
            suffix = pattern[2:]  # "example.com"
            if hostname == suffix or hostname.endswith('.' + suffix):
                return True
        elif hostname == pattern:
            # Exact match (shouldn't happen if wildcards list is correct)
            return True

    return False

# Load domain allowlist at module initialization
load_domain_allowlist()

app = Flask(__name__)

# Configuration
GATEWAY_PORT = int(os.environ.get('GATEWAY_PORT', 8080))
GATEWAY_HOST = os.environ.get('GATEWAY_HOST', '0.0.0.0')

# Upstream request timeouts (in seconds)
UPSTREAM_CONNECT_TIMEOUT = int(os.environ.get('GATEWAY_CONNECT_TIMEOUT', 30))
UPSTREAM_READ_TIMEOUT = int(os.environ.get('GATEWAY_READ_TIMEOUT', 600))

# Session management
# NOTE: In-memory session store requires single Gunicorn worker (--workers 1)
# to maintain consistency. Each worker has its own SESSIONS dict, so multi-worker
# deployments would fail session validation. For horizontal scaling, replace
# this dict with a Redis-backed session store.
SESSIONS = {}  # {token: {'secret': secret, 'container_id': id, 'container_ip': ip, 'repos': [], 'created': datetime, 'last_accessed': datetime, 'expires_at': datetime}}

# Session management API key (for TCP-based session management from host)
# Required when session management is done via TCP instead of Unix socket
SESSION_MGMT_KEY = os.environ.get('GATEWAY_SESSION_MGMT_KEY', '')
SESSIONS_LOCK = threading.Lock()  # Protects SESSIONS dict from concurrent access by GC thread
SESSION_TTL_INACTIVITY = timedelta(hours=24)  # 24 hour inactivity timeout
SESSION_TTL_ABSOLUTE = timedelta(days=7)  # 7 day absolute timeout
SESSION_GC_INTERVAL = timedelta(minutes=5)  # Run garbage collection every 5 minutes

# Session limit (memory bound / sanity check)
MAX_SESSIONS = int(os.environ.get('GATEWAY_MAX_SESSIONS', 100))

# Garbage collection state
_gc_timer = None
_gc_initialized = False

# Validation regex patterns
OWNER_REGEX = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'
REPO_REGEX = r'^[a-zA-Z0-9._-]+$'

# Allowed git endpoints
ALLOWED_GIT_PATHS = {'info/refs', 'git-upload-pack', 'git-receive-pack'}

# LFS endpoint patterns (not supported)
LFS_PATTERNS = [
    r'^objects/batch$',           # LFS batch API
    r'^lfs/',                     # LFS namespace
    r'^\.git/lfs/',               # .git/lfs paths
    r'^info/lfs/',                # LFS info endpoints
]

# Upstream configuration
UPSTREAM_HOST = 'github.com'
UPSTREAM_PROTOCOL = 'https'

# Zero SHA for detecting branch creation/deletion
ZERO_SHA = '0' * 40


def parse_pktline(data: bytes) -> list:
    """
    Parse git pkt-line format from git-receive-pack request body.

    Git uses pkt-line format for protocol communication. Each line starts with
    a 4-character hex length prefix (including the 4 bytes of the length itself).
    A length of '0000' indicates a flush packet (end of section).

    For push operations, the format is:
    <old-sha> <new-sha> <refname>\0<capabilities>
    or for subsequent lines:
    <old-sha> <new-sha> <refname>

    Args:
        data: Raw bytes from git-receive-pack request body

    Returns:
        list: List of tuples (old_sha, new_sha, refname, capabilities)
              capabilities is a string for the first ref, empty string for others
    """
    updates = []
    pos = 0

    while pos < len(data):
        # Read 4-byte length prefix
        if pos + 4 > len(data):
            break

        try:
            length_hex = data[pos:pos + 4].decode('ascii')
            length = int(length_hex, 16)
        except (ValueError, UnicodeDecodeError):
            break

        # Flush packet (0000) marks end of section
        if length == 0:
            pos += 4
            continue

        # Length includes the 4-byte prefix itself
        if length < 4 or pos + length > len(data):
            break

        # Extract line content (excluding length prefix)
        line_data = data[pos + 4:pos + length]
        pos += length

        # Skip empty lines
        if not line_data:
            continue

        # Try to decode as UTF-8
        try:
            line = line_data.decode('utf-8').rstrip('\n')
        except UnicodeDecodeError:
            continue

        # Parse ref update line: <old-sha> <new-sha> <refname>[\0<capabilities>]
        # First line may have capabilities after null byte
        capabilities = ''
        if '\0' in line:
            line, capabilities = line.split('\0', 1)

        parts = line.split(' ', 2)
        if len(parts) >= 3:
            old_sha, new_sha, refname = parts[0], parts[1], parts[2]
            # Validate SHA format (40 hex characters)
            if len(old_sha) == 40 and len(new_sha) == 40:
                updates.append((old_sha, new_sha, refname, capabilities))

    return updates


def is_fast_forward(old_sha: str, new_sha: str, owner: str, repo: str) -> bool:
    """
    Check if a ref update is a fast-forward (new_sha is descendant of old_sha).

    Uses GitHub API compare endpoint to determine ancestry. A fast-forward
    update means the new commit is reachable from the old commit by following
    parent links - i.e., no history is being rewritten.

    Args:
        old_sha: Current SHA of the ref on remote
        new_sha: New SHA being pushed
        owner: Repository owner
        repo: Repository name

    Returns:
        bool: True if fast-forward (safe), False if force push (history rewrite)
    """
    # If old_sha is zero, this is a new branch creation (always allowed)
    if old_sha == ZERO_SHA:
        return True

    # If new_sha is zero, this is a branch deletion (handled separately)
    if new_sha == ZERO_SHA:
        return True  # Let deletion check handle this

    try:
        github_token = get_github_token()
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json',
        }

        # Use GitHub compare API: GET /repos/{owner}/{repo}/compare/{base}...{head}
        # If head is ahead of base with 0 behind, it's a fast-forward
        compare_url = f'https://api.github.com/repos/{owner}/{repo}/compare/{old_sha}...{new_sha}'

        response = requests.get(
            compare_url,
            headers=headers,
            timeout=(10, 30)  # 10s connect, 30s read
        )

        if response.status_code == 200:
            data = response.json()
            # Fast-forward: new commit is ahead, old commit is not behind
            # "behind_by" = 0 means old_sha is an ancestor of new_sha
            behind_by = data.get('behind_by', -1)
            if behind_by == 0:
                return True
            else:
                # Non-zero behind_by means old_sha has commits not in new_sha
                # This is a history rewrite (force push)
                logger.warning(f'Non-fast-forward detected: {old_sha[:8]}..{new_sha[:8]} (behind_by={behind_by})')
                return False

        elif response.status_code == 404:
            # Commits not found - could be new commits not yet on GitHub
            # Be conservative: block to prevent potential history rewrite
            logger.warning(f'Compare API returned 404 for {old_sha[:8]}..{new_sha[:8]} - blocking as precaution')
            return False

        else:
            # API error - be conservative and block
            logger.error(f'GitHub compare API error: {response.status_code}')
            return False

    except Exception as e:
        # On error, be conservative and block
        logger.error(f'Error checking fast-forward: {e}')
        return False


def check_ref_updates(request_body: bytes, owner: str, repo: str) -> tuple:
    """
    Check git-receive-pack request for disallowed ref changes.

    Blocks:
    - Branch/tag deletion (new_sha = 0000...)
    - Force push / history rewrite (non-fast-forward updates)
    - All variants: --force, --force-with-lease, --force-if-includes, +refspec

    Args:
        request_body: Raw bytes from git-receive-pack POST body
        owner: Repository owner
        repo: Repository name

    Returns:
        tuple: (blocked_updates, details) where:
               blocked_updates is a list of blocked ref update dicts
               details is a human-readable summary string
    """
    updates = parse_pktline(request_body)
    blocked = []

    for old_sha, new_sha, refname, capabilities in updates:
        # Check for branch/tag deletion
        if new_sha == ZERO_SHA:
            blocked.append({
                'ref': refname,
                'reason': 'deletion_blocked',
                'message': f'Deleting refs is not allowed: {refname}',
                'old_sha': old_sha[:8],
                'new_sha': '(delete)',
            })
            continue

        # Check for force push (non-fast-forward)
        # Skip if this is a new branch creation
        if old_sha != ZERO_SHA:
            if not is_fast_forward(old_sha, new_sha, owner, repo):
                blocked.append({
                    'ref': refname,
                    'reason': 'force_push_blocked',
                    'message': f'Force push not allowed (history rewrite detected): {refname}',
                    'old_sha': old_sha[:8],
                    'new_sha': new_sha[:8],
                })
                continue

    if blocked:
        refs = [b['ref'] for b in blocked]
        details = f"Blocked {len(blocked)} ref update(s): {', '.join(refs)}"
    else:
        details = None

    return blocked, details

# Default policy hook allows all operations
def get_github_token():
    """
    Get the real GitHub token for upstream authentication.

    Returns:
        str: GitHub token from environment

    Raises:
        RuntimeError: If GITHUB_TOKEN is not set
    """
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        return token

    # Log error and raise - silent fallback causes confusing auth errors
    logger.error('GITHUB_TOKEN environment variable is not set - git operations will fail')
    raise RuntimeError('GITHUB_TOKEN environment variable is required but not set')

def default_policy_hook(owner, repo, operation):
    """
    Default policy hook that denies all operations (defense-in-depth).

    SECURITY NOTE: This default denies all access to enforce the principle
    that repository access should be explicitly authorized via session
    repo scoping. Sessions without a repos list will be denied by default.

    This implements THREAT_MODEL.md Priority 2: "Gateway validates all
    repository access against session scope."

    To allow unrestricted access for specific use cases, override this
    hook via environment or configuration.

    Args:
        owner: Repository owner
        repo: Repository name
        operation: 'read' or 'write'

    Returns:
        bool: True if operation is allowed, False otherwise
    """
    # Deny by default - sessions must have explicit repo authorization
    # Repo scoping at lines 755-768 handles sessions with repos lists.
    # This hook catches sessions without repos lists (legacy/misconfigured).
    return False

POLICY_HOOK = default_policy_hook

def generate_session_token():
    """
    Generate a secure random session token.

    Returns:
        str: A secure token string
    """
    return secrets.token_urlsafe(32)

def generate_session_secret():
    """
    Generate a secure random session secret.

    Returns:
        str: A secure secret string
    """
    return secrets.token_urlsafe(32)

def create_session(container_ip, container_id=None, repos=None):
    """
    Create a new session with token and secret, bound to a container IP.

    Args:
        container_ip: IP address of the container
        container_id: Container identifier (optional)
        repos: List of authorized repositories for this session (optional)

    Returns:
        dict: {'token': token, 'secret': secret}

    Raises:
        ValueError: If session limit is exceeded
    """
    token = generate_session_token()
    secret = generate_session_secret()
    now = datetime.utcnow()
    expires_at = now + SESSION_TTL_ABSOLUTE

    with SESSIONS_LOCK:
        # Check global session limit (memory bound / sanity check)
        if len(SESSIONS) >= MAX_SESSIONS:
            raise ValueError(f'Maximum session limit ({MAX_SESSIONS}) exceeded')

        SESSIONS[token] = {
            'secret': secret,
            'container_id': container_id,
            'container_ip': container_ip,
            'repos': repos if repos else [],
            'created': now,
            'last_accessed': now,
            'expires_at': expires_at
        }

    return {'token': token, 'secret': secret}

def validate_session(token, secret, client_ip):
    """
    Validate a session token and secret against the client IP.
    Checks both 24h inactivity TTL and 7d absolute expiry.

    Args:
        token: Session token
        secret: Session secret (can be None for Basic auth flow)
        client_ip: Client IP address from request

    Returns:
        dict: A copy of the validated session if valid, None otherwise.
              Returning a copy ensures consistent data for authorization
              decisions, even if GC deletes the original session after
              this function returns.
    """
    with SESSIONS_LOCK:
        if token not in SESSIONS:
            return None

        session = SESSIONS[token]

        # Check secret matches (if provided)
        # Basic auth flow doesn't carry the secret, so we skip this check when secret is None
        # Security note: Basic auth relies on IP binding for additional security
        # Use constant-time comparison to prevent timing attacks
        if secret is not None and not hmac.compare_digest(session['secret'], secret):
            return None

        # Check IP binding (use constant-time comparison for consistency)
        if not hmac.compare_digest(session['container_ip'], client_ip):
            return None

        now = datetime.utcnow()

        # Check inactivity timeout (24 hours)
        if now - session['last_accessed'] > SESSION_TTL_INACTIVITY:
            logger.info(f'Session {token} expired due to inactivity')
            del SESSIONS[token]
            return None

        # Check absolute expiry (7 days from creation)
        if now > session['expires_at']:
            logger.info(f'Session {token} expired due to absolute TTL')
            del SESSIONS[token]
            return None

        # Update last accessed time
        session['last_accessed'] = now

        # Return a copy of the session to prevent modifications outside the lock
        return dict(session)

def garbage_collect_sessions():
    """
    Remove expired sessions from the session store.
    Checks both inactivity TTL (24h) and absolute expiry (7d).
    Scheduled to run every 5 minutes.
    """
    global _gc_timer
    now = datetime.utcnow()
    expired_tokens = []

    with SESSIONS_LOCK:
        for token, session in list(SESSIONS.items()):
            # Check inactivity timeout
            if now - session['last_accessed'] > SESSION_TTL_INACTIVITY:
                logger.info(f'GC: Removing session {token} (inactivity timeout)')
                expired_tokens.append(token)
                continue

            # Check absolute expiry
            if now > session['expires_at']:
                logger.info(f'GC: Removing session {token} (absolute expiry)')
                expired_tokens.append(token)
                continue

        # Remove expired sessions
        for token in expired_tokens:
            del SESSIONS[token]

    if expired_tokens:
        logger.info(f'Garbage collection completed: removed {len(expired_tokens)} expired sessions')

    # Schedule next garbage collection
    _gc_timer = threading.Timer(SESSION_GC_INTERVAL.total_seconds(), garbage_collect_sessions)
    _gc_timer.daemon = True
    _gc_timer.start()

def start_garbage_collection():
    """
    Start the background garbage collection timer.
    Runs every 5 minutes to clean up expired sessions.
    Safe to call multiple times - will only start once.
    """
    global _gc_timer, _gc_initialized
    if _gc_initialized:
        return  # Already started
    _gc_initialized = True
    logger.info('Starting session garbage collection (interval: 5 minutes)')
    _gc_timer = threading.Timer(SESSION_GC_INTERVAL.total_seconds(), garbage_collect_sessions)
    _gc_timer.daemon = True
    _gc_timer.start()

def stop_garbage_collection():
    """
    Stop the background garbage collection timer.
    Called on application shutdown.
    """
    global _gc_timer, _gc_initialized
    if _gc_timer:
        logger.info('Stopping session garbage collection')
        _gc_timer.cancel()
        _gc_timer = None
    _gc_initialized = False


def _delayed_gc_init():
    """
    Start GC after brief delay to allow app initialization.
    Called at module load time to ensure GC runs under Gunicorn.
    """
    start_garbage_collection()


# Initialize garbage collection when module loads (works under Gunicorn)
# Uses a delayed timer to allow app initialization to complete first
# The __main__ block also calls start_garbage_collection for direct execution
_gc_init_timer = threading.Timer(2.0, _delayed_gc_init)
_gc_init_timer.daemon = True
_gc_init_timer.start()

# Register cleanup on module unload
atexit.register(stop_garbage_collection)

def destroy_session(token):
    """
    Destroy a session by token.

    Args:
        token: Session token

    Returns:
        bool: True if session was destroyed, False if not found
    """
    with SESSIONS_LOCK:
        if token in SESSIONS:
            del SESSIONS[token]
            return True
        return False

def validate_owner(owner):
    """
    Validate repository owner name against regex pattern.

    Args:
        owner: Owner name

    Returns:
        bool: True if valid, False otherwise
    """
    if not owner:
        return False
    return re.match(OWNER_REGEX, owner) is not None

def validate_repo(repo):
    """
    Validate repository name against regex pattern.

    Args:
        repo: Repository name

    Returns:
        bool: True if valid, False otherwise
    """
    if not repo:
        return False
    return re.match(REPO_REGEX, repo) is not None

def validate_git_path(path):
    """
    Validate git endpoint path against allowlist.

    Args:
        path: Git endpoint path

    Returns:
        bool: True if path is allowed, False otherwise
    """
    if not path:
        return False
    return path in ALLOWED_GIT_PATHS


def is_lfs_endpoint(path):
    """
    Check if the given path is a Git LFS endpoint.
    LFS is not supported by this gateway.

    Args:
        path: Git endpoint path

    Returns:
        bool: True if path is an LFS endpoint, False otherwise
    """
    if not path:
        return False
    for pattern in LFS_PATTERNS:
        if re.match(pattern, path):
            return True
    return False

def is_ip_literal(host):
    """
    Check if the given host is an IP address literal.
    Returns True if host is an IPv4 or IPv6 address, False otherwise.

    Args:
        host: The hostname/IP string to check (may include port)

    Returns:
        bool: True if host is an IP literal, False otherwise
    """
    if not host:
        return False

    # Handle IPv6 addresses in brackets (e.g., "[::1]" or "[2001:db8::1]:443")
    if host.startswith('['):
        # Extract IPv6 address from brackets
        bracket_end = host.find(']')
        if bracket_end > 0:
            host_only = host[1:bracket_end]
        else:
            return False  # Malformed bracket notation
    else:
        # IPv4: Remove port if present (e.g., "1.2.3.4:8080" -> "1.2.3.4")
        host_only = host.split(':')[0]

    try:
        ipaddress.ip_address(host_only)
        return True
    except ValueError:
        return False

def check_ip_literal_request():
    """
    Check if the current request is to an IP literal.
    If it is, log and reject the request.

    Returns:
        tuple: (is_ip_literal, response) where response is a Flask Response if IP literal, None otherwise
    """
    host = request.host
    if is_ip_literal(host):
        logger.warning(f'Rejecting request to IP literal: {host} from {request.remote_addr}')
        audit_log('proxy_deny', extra_data={
            'reason': 'ip_literal_rejected',
            'target_host': host,
            'method': request.method,
            'path': request.path
        })
        error_response = {
            'error': 'IP literal requests are not allowed',
            'message': 'All requests must be made to DNS-resolvable domain names, not IP addresses',
            'target': host
        }
        return True, Response(json.dumps(error_response), status=403, mimetype='application/json')
    return False, None

def scrub_credentials(value):
    """
    Scrub potential credentials from a string value.

    Removes or masks patterns that could contain sensitive data:
    - Bearer tokens
    - Basic auth credentials
    - API keys in URLs
    - OAuth tokens

    Args:
        value: String value to scrub

    Returns:
        str: Scrubbed string with credentials removed/masked
    """
    if not isinstance(value, str):
        return value

    # Patterns to scrub (order matters - more specific patterns first)
    patterns = [
        # Bearer tokens: "Bearer xxx" -> "Bearer [REDACTED]"
        (r'Bearer\s+[A-Za-z0-9_\-\.=]+', 'Bearer [REDACTED]'),
        # Basic auth: "Basic xxx" -> "Basic [REDACTED]"
        (r'Basic\s+[A-Za-z0-9+/=]+', 'Basic [REDACTED]'),
        # URL credentials: "://user:pass@" -> "://[REDACTED]@"
        (r'://[^@\s]+@', '://[REDACTED]@'),
        # GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_ prefixed (before generic patterns)
        (r'\bgh[pousr]_[A-Za-z0-9_]+\b', '[GITHUB_TOKEN_REDACTED]'),
        # Session tokens (our format): 43-char base64url (before generic patterns)
        (r'\b[A-Za-z0-9_-]{43}\b', '[TOKEN_REDACTED]'),
        # Generic API keys: key=xxx, api_key=xxx, apikey=xxx (last to not override specific patterns)
        (r'(?i)(api[_-]?key|secret|password|auth)[=:]\s*[^\s&]+', r'\1=[REDACTED]'),
    ]

    result = value
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)

    return result


def audit_log(event_type, container_id=None, ip=None, **extra_data):
    """
    Log structured audit events as JSON to stderr.

    Args:
        event_type: Type of event (session_create, session_destroy, git_access,
                   git_denied, proxy_allow, proxy_deny)
        container_id: Container identifier
        ip: IP address of the requester
        **extra_data: Additional event-specific data (sanitized)
    """
    # Get container_id from environment if not provided
    if container_id is None:
        container_id = os.environ.get('CONTAINER_ID', 'unknown')

    # Get IP from request if not provided
    if ip is None:
        ip = request.remote_addr if request else 'unknown'

    # Build the audit log entry
    audit_entry = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'event_type': event_type,
        'container_id': container_id,
        'ip': ip,
    }

    # Add any extra data, but ensure no sensitive data is included
    for key, value in extra_data.items():
        # Skip sensitive fields entirely
        if key.lower() in ('token', 'authorization', 'password', 'secret', 'auth'):
            continue
        # Scrub credential patterns from string values (e.g., error messages)
        if isinstance(value, str):
            value = scrub_credentials(value)
        audit_entry[key] = value

    # Write to stderr as JSON with error handling
    # If disk is full or stderr is unavailable, log to logger and continue
    try:
        json.dump(audit_entry, sys.stderr)
        sys.stderr.write('\n')
        sys.stderr.flush()
    except (IOError, OSError) as e:
        # Fallback to logger if stderr write fails (e.g., disk full)
        logger.error(f'Audit log write failed ({e}): {event_type} - {audit_entry}')

@app.route('/health')
def health():
    """Health check endpoint."""
    logger.info('Health check requested')
    return {'status': 'healthy'}, 200

def is_localhost(addr):
    """
    Check if an address is a localhost address (IPv4 or IPv6).

    Args:
        addr: IP address string

    Returns:
        bool: True if localhost, False otherwise
    """
    if not addr:
        return False
    # IPv4 localhost
    if addr == '127.0.0.1':
        return True
    # IPv6 localhost variants
    if addr in ('::1', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1'):
        return True
    return False


def check_session_mgmt_auth():
    """
    Check if the request is authorized for session management.

    Allows requests from:
    1. Localhost (127.0.0.1, ::1) - traditional Unix socket / local TCP
    2. Requests with valid X-Session-Mgmt-Key header matching GATEWAY_SESSION_MGMT_KEY

    Returns:
        tuple: (is_authorized, error_response) where error_response is None if authorized
    """
    # Allow localhost requests (Unix socket or local TCP)
    if is_localhost(request.remote_addr):
        return True, None

    # Check for session management API key (for TCP from Docker host)
    if SESSION_MGMT_KEY:
        provided_key = request.headers.get('X-Session-Mgmt-Key', '')
        if provided_key and hmac.compare_digest(SESSION_MGMT_KEY, provided_key):
            return True, None

    audit_log('session_mgmt_denied', extra_data={
        'reason': 'unauthorized',
        'remote_addr': request.remote_addr,
        'has_key': bool(request.headers.get('X-Session-Mgmt-Key'))
    })
    return False, ({'error': 'Session management not authorized'}, 403)


@app.route('/session/create', methods=['POST'])
def session_create_endpoint():
    """
    Create a new session with token and secret binding to container IP.
    Requires localhost or valid session management API key.
    """
    # Check authorization
    authorized, error_response = check_session_mgmt_auth()
    if not authorized:
        return error_response

    try:
        data = request.json if request.json else {}
        container_id = data.get('container_id')
        container_ip = data.get('container_ip')
        repos = data.get('repos', [])

        if not container_ip:
            audit_log('session_create_denied', extra_data={'reason': 'missing_container_ip'})
            return {'error': 'container_ip is required'}, 400

        # Validate container_ip is a valid IP address
        try:
            ipaddress.ip_address(container_ip)
        except ValueError:
            audit_log('session_create_denied', extra_data={'reason': 'invalid_container_ip', 'container_ip': container_ip})
            return {'error': 'container_ip must be a valid IP address'}, 400

        # Validate container_id format if provided (Docker container IDs are 64 hex chars, short form is 12)
        if container_id is not None:
            if not isinstance(container_id, str) or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$', container_id):
                audit_log('session_create_denied', extra_data={'reason': 'invalid_container_id'})
                return {'error': 'container_id must be alphanumeric with optional _.- separators'}, 400

        # Validate repos list format (must be list of owner/repo strings)
        if repos:
            if not isinstance(repos, list):
                audit_log('session_create_denied', extra_data={'reason': 'repos_not_list'})
                return {'error': 'repos must be a list'}, 400
            for repo_entry in repos:
                if not isinstance(repo_entry, str) or '/' not in repo_entry:
                    audit_log('session_create_denied', extra_data={'reason': 'invalid_repo_format', 'repo': repo_entry})
                    return {'error': 'Each repo must be in owner/repo format'}, 400
                parts = repo_entry.split('/', 1)
                if not validate_owner(parts[0]) or not validate_repo(parts[1]):
                    audit_log('session_create_denied', extra_data={'reason': 'invalid_repo_format', 'repo': repo_entry})
                    return {'error': f'Invalid repo format: {repo_entry}'}, 400

        # Create session (may raise ValueError if limit exceeded)
        session_data = create_session(container_ip, container_id=container_id, repos=repos)

        audit_log('session_create', container_id=container_id, extra_data={'container_ip': container_ip})

        return {
            'token': session_data['token'],
            'secret': session_data['secret'],
            'ttl_inactivity_hours': 24,
            'ttl_absolute_days': 7
        }, 201

    except ValueError as e:
        # Session limit exceeded
        logger.warning(f'Session creation denied: {e}')
        audit_log('session_create_denied', extra_data={'reason': 'limit_exceeded', 'error': str(e)})
        return {'error': str(e)}, 503

    except Exception as e:
        logger.error(f'Session creation error: {e}')
        audit_log('session_create_error', extra_data={'error': str(e)})
        return {'error': 'Internal server error'}, 500

@app.route('/session/<session_token>', methods=['DELETE'])
def session_destroy_endpoint(session_token):
    """
    Destroy a session by token.
    Requires localhost or valid session management API key.
    """
    # Check authorization
    authorized, error_response = check_session_mgmt_auth()
    if not authorized:
        return error_response

    if destroy_session(session_token):
        audit_log('session_destroy', extra_data={'token': session_token})
        return {'status': 'destroyed'}, 200
    else:
        audit_log('session_destroy_not_found', extra_data={'token': session_token})
        return {'error': 'Session not found'}, 404

def stream_response_generator(response, chunk_size=8192):
    """
    Generator function for streaming response data.
    Memory-bounded streaming without buffering entire response.

    Args:
        response: requests.Response object with stream=True
        chunk_size: Size of chunks to read (default 8192 bytes)

    Yields:
        bytes: Response data chunks
    """
    try:
        for chunk in response.iter_content(chunk_size=chunk_size):
            if chunk:  # filter out keep-alive new chunks
                yield chunk
    except Exception as e:
        logger.error(f'Error streaming response: {e}')
        yield b'Gateway error: streaming failed'

@app.route('/git/<owner>/<repo>.git/<path:git_path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def git_proxy(owner, repo, git_path):
    """
    Proxy endpoint for Git Smart HTTP operations with streaming support.
    Validates token+secret+IP, owner/repo, git endpoints, and applies policy.
    Hard-pins upstream to github.com with redirects disabled.

    Features:
    - Streaming request/response handling (no buffering)
    - Chunked transfer encoding support
    - Header forwarding (Content-Type, Expect: 100-continue)
    - Authorization header replacement (session token -> GitHub token)
    - Timeouts: 30s connect, 600s transfer
    - Memory-bounded streaming with 8KB chunks
    - Explicitly allows receive-pack (push) operations
    """
    logger.info(f'Git proxy request: {request.method} /git/{owner}/{repo}.git/{git_path}')

    # Check for IP literal requests
    is_ip, error_response = check_ip_literal_request()
    if is_ip:
        return error_response

    # Validate owner and repo format
    if not validate_owner(owner):
        audit_log('git_denied', extra_data={
            'reason': 'invalid_owner',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        return Response('Invalid owner format', status=400)

    if not validate_repo(repo):
        audit_log('git_denied', extra_data={
            'reason': 'invalid_repo',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        return Response('Invalid repo format', status=400)

    # Check for LFS endpoints (not supported)
    if is_lfs_endpoint(git_path):
        audit_log('git_denied', extra_data={
            'reason': 'lfs_not_supported',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        error_response = {
            'error': 'Git LFS is not supported',
            'message': 'This gateway does not support Git Large File Storage (LFS). Please use standard Git operations only.',
            'path': git_path
        }
        return Response(json.dumps(error_response), status=501, mimetype='application/json')

    # Validate git endpoint path
    if not validate_git_path(git_path):
        audit_log('git_denied', extra_data={
            'reason': 'invalid_git_path',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        return Response('Invalid git endpoint', status=400)

    # Extract and validate session token and secret
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        audit_log('git_denied', extra_data={
            'reason': 'no_authorization',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        return Response('Unauthorized', status=401)

    # Parse authorization header (supports both Bearer and Basic formats)
    # - Bearer format: "Bearer token:secret" (direct API calls)
    # - Basic format: "Basic base64(username:password)" (git credential helper)
    #   The credential helper puts the token in the password field
    token = None
    secret = None

    if auth_header.startswith('Bearer '):
        # Bearer format: "Bearer token:secret"
        try:
            token_secret = auth_header[7:]  # Remove "Bearer " prefix
            if ':' not in token_secret:
                raise ValueError('Missing token:secret separator')
            token, secret = token_secret.split(':', 1)
        except Exception as e:
            audit_log('git_denied', extra_data={
                'reason': 'malformed_bearer_credentials',
                'owner': owner,
                'repo': repo,
                'path': git_path,
                'error': str(e)
            })
            return Response('Malformed Bearer credentials', status=401)
    elif auth_header.startswith('Basic '):
        # Basic format: base64(username:password)
        # The credential helper puts the session token in the password field
        # Format from credential helper: "x-gateway-token:token_value"
        try:
            encoded = auth_header[6:]  # Remove "Basic " prefix
            decoded = base64.b64decode(encoded).decode('utf-8')
            if ':' not in decoded:
                raise ValueError('Missing username:password separator')
            username, password = decoded.split(':', 1)
            # Token is in the password field (from credential helper)
            token = password
            # Basic auth doesn't carry the secret - will need to validate without it
            secret = None
        except Exception as e:
            audit_log('git_denied', extra_data={
                'reason': 'malformed_basic_credentials',
                'owner': owner,
                'repo': repo,
                'path': git_path,
                'error': str(e)
            })
            return Response('Malformed Basic credentials', status=401)
    else:
        audit_log('git_denied', extra_data={
            'reason': 'invalid_auth_format',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        return Response('Invalid authorization format (expected Bearer or Basic)', status=401)

    # Validate session - returns the validated session object to prevent race conditions
    client_ip = request.remote_addr
    session = validate_session(token, secret, client_ip)
    if session is None:
        audit_log('git_denied', extra_data={
            'reason': 'invalid_session',
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'client_ip': client_ip
        })
        return Response('Invalid or expired session', status=401)

    # Enforce repo scoping if session has a repos list
    # Track whether repo scoping was enforced for policy hook decision
    repo_scoping_enforced = False
    if session.get('repos'):
        repo_scoping_enforced = True
        requested_repo = f"{owner}/{repo}"
        if requested_repo not in session['repos']:
            audit_log('git_denied', extra_data={
                'reason': 'repo_not_authorized',
                'owner': owner,
                'repo': repo,
                'path': git_path,
                'requested_repo': requested_repo,
                'authorized_repos': session['repos']
            })
            logger.warning(f"Repo {requested_repo} not in authorized list for session")
            return Response('Repository not authorized for this session', status=403)

    # Determine operation type
    if git_path == 'info/refs':
        operation = 'read'
    elif git_path == 'git-upload-pack':
        operation = 'read'
    elif git_path == 'git-receive-pack':
        # Explicitly allow receive-pack (push) operations
        operation = 'write'
    else:
        operation = 'unknown'

    # Apply policy hook (only when repo scoping was NOT enforced)
    # When session has repos list, repo scoping already validated access.
    # Policy hook is for sessions without repos list (legacy/misconfigured).
    if not repo_scoping_enforced and not POLICY_HOOK(owner, repo, operation):
        audit_log('git_denied', extra_data={
            'reason': 'policy_denied',
            'owner': owner,
            'repo': repo,
            'operation': operation
        })
        return Response('Access denied by policy', status=403)

    # Get GitHub token first - fail fast if not configured
    try:
        github_token = get_github_token()
    except RuntimeError as e:
        audit_log('git_proxy_error', extra_data={
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'error': 'github_token_missing',
            'error_details': str(e)
        })
        return Response('Gateway configuration error: GitHub token not available', status=503)

    # For git-receive-pack (push), check for force push / history rewriting operations
    # This requires buffering the request body to parse pkt-line format
    request_body_bytes = None
    if git_path == 'git-receive-pack' and request.method == 'POST':
        # Read request body for force push detection
        # Note: This buffers the body in memory, but push request bodies are typically small
        # (they contain ref updates, not the actual pack data which comes later)
        request_body_bytes = request.get_data()

        # Check for blocked ref updates (force push, deletion, etc.)
        blocked_updates, block_details = check_ref_updates(request_body_bytes, owner, repo)

        if blocked_updates:
            audit_log('git_denied', extra_data={
                'reason': 'history_protection',
                'owner': owner,
                'repo': repo,
                'path': git_path,
                'blocked_updates': blocked_updates,
                'details': block_details
            })

            # Return detailed error response
            error_response = {
                'error': 'History protection: operation blocked',
                'message': 'This operation would rewrite git history, which is not allowed.',
                'blocked_refs': [b['ref'] for b in blocked_updates],
                'details': [b['message'] for b in blocked_updates],
                'hint': 'Committed history is immutable. Use git revert to undo changes instead of rewriting history.'
            }
            return Response(
                json.dumps(error_response, indent=2),
                status=403,
                mimetype='application/json',
                headers={'X-Sandbox-Blocked': 'true'}
            )

    # Proxy to GitHub with streaming support
    # Initialize proxied_request before try block for reliable cleanup
    proxied_request = None
    try:
        # Construct upstream URL
        upstream_url = f'{UPSTREAM_PROTOCOL}://{UPSTREAM_HOST}/{owner}/{repo}.git/{git_path}'

        # Forward headers with selective inclusion
        headers = {}

        # Forward Content-Type header for POST/PUT requests
        if request.method in ['POST', 'PUT']:
            content_type = request.headers.get('Content-Type')
            if content_type:
                headers['Content-Type'] = content_type
            else:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'

        # Forward Expect header if present (for 100-continue support)
        expect_header = request.headers.get('Expect')
        if expect_header:
            headers['Expect'] = expect_header

        # Replace Authorization header with GitHub token
        headers['Authorization'] = f'token {github_token}'

        # Determine request body for upstream
        # If we already read the body for force push detection, use that
        # Otherwise, stream it for memory efficiency
        request_body = None
        if request.method in ['POST', 'PUT']:
            if request_body_bytes is not None:
                # Use buffered body from force push check
                request_body = request_body_bytes
            else:
                # Use streaming to avoid loading entire request into memory
                request_body = request.stream

        # Make streaming request with configurable timeouts
        proxied_request = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=request_body,
            params=request.args,
            allow_redirects=False,  # Disable redirects per spec
            timeout=(UPSTREAM_CONNECT_TIMEOUT, UPSTREAM_READ_TIMEOUT),
            stream=True  # Enable streaming response
        )

        # Log successful git access
        audit_log('git_access', extra_data={
            'owner': owner,
            'repo': repo,
            'operation': operation,
            'upstream_status': proxied_request.status_code
        })

        # Build response headers, forwarding relevant ones
        response_headers = {}

        # Forward Content-Type header
        if 'Content-Type' in proxied_request.headers:
            response_headers['Content-Type'] = proxied_request.headers['Content-Type']

        # Forward Transfer-Encoding if present (chunked support)
        if 'Transfer-Encoding' in proxied_request.headers:
            response_headers['Transfer-Encoding'] = proxied_request.headers['Transfer-Encoding']

        # Forward Content-Length if present and chunked encoding not used
        if 'Content-Length' in proxied_request.headers and 'Transfer-Encoding' not in proxied_request.headers:
            response_headers['Content-Length'] = proxied_request.headers['Content-Length']

        # Forward other important headers
        for header in ['Cache-Control', 'Pragma', 'Connection']:
            if header in proxied_request.headers:
                response_headers[header] = proxied_request.headers[header]

        # Return streamed response with memory-bounded generator (8KB chunks)
        return Response(
            stream_response_generator(proxied_request, chunk_size=8192),
            status=proxied_request.status_code,
            headers=response_headers
        )

    except requests.exceptions.Timeout as e:
        logger.error(f'Git proxy timeout: {e}')
        audit_log('git_proxy_error', extra_data={
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'error': 'timeout',
            'error_details': str(e)
        })
        # Close the response if it was partially created
        if proxied_request is not None:
            try:
                proxied_request.close()
            except Exception:
                pass
        return Response('Gateway timeout', status=504)

    except Exception as e:
        logger.error(f'Git proxy error: {e}')
        audit_log('git_proxy_error', extra_data={
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'error': str(e)
        })
        # Close the response if it was partially created to prevent connection leaks
        if proxied_request is not None:
            try:
                proxied_request.close()
            except Exception:
                pass
        return Response('Gateway error', status=502)

@app.route('/')
def index():
    """Root endpoint."""
    return {'service': 'credential-isolation-gateway', 'version': '1.0.0'}, 200

def check_hostname_allowlist(hostname: str) -> tuple:
    """
    Check if hostname is allowed by the wildcard domain allowlist.

    Args:
        hostname: The target hostname to validate

    Returns:
        tuple: (is_allowed, response) where response is a Flask Response if denied, None if allowed
    """
    if not WILDCARD_DOMAINS:
        # No wildcards configured - allow (legacy behavior, exact domains handled elsewhere)
        return True, None

    if not matches_domain_allowlist(hostname):
        logger.warning(f'Rejecting request to non-allowlisted hostname: {hostname} from {request.remote_addr}')
        audit_log('proxy_deny', extra_data={
            'reason': 'hostname_not_allowlisted',
            'target_host': hostname,
            'method': request.method,
            'path': request.path
        })
        error_response = {
            'error': 'Hostname not in allowlist',
            'message': 'The requested hostname does not match any allowed domain pattern',
            'target': hostname
        }
        return False, Response(json.dumps(error_response), status=403, mimetype='application/json')

    return True, None


@app.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    """
    General proxy endpoint.
    Logs allow/deny decisions for audit purposes.
    Rejects IP literal requests.
    Validates hostname against wildcard domain allowlist.
    """
    # Check for IP literal requests and reject if found
    is_ip, error_response = check_ip_literal_request()
    if is_ip:
        return error_response

    # Validate hostname against wildcard allowlist
    target_host = request.headers.get('Host', request.host)
    # Strip port if present
    if ':' in target_host and not target_host.startswith('['):
        target_host = target_host.split(':')[0]

    is_allowed, error_response = check_hostname_allowlist(target_host)
    if not is_allowed:
        return error_response

    # Check if request is allowed (placeholder logic)
    auth_header = request.headers.get('Authorization')
    if auth_header:
        audit_log('proxy_allow', extra_data={'path': path, 'method': request.method, 'target_host': target_host})
        # Placeholder for proxy logic
        return Response('Not implemented', status=501)
    else:
        audit_log('proxy_deny', extra_data={'path': path, 'method': request.method, 'reason': 'no_authorization'})
        return Response('Forbidden', status=403)

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return {'error': 'Not found'}, 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f'Internal server error: {error}')
    return {'error': 'Internal server error'}, 500

if __name__ == '__main__':
    logger.info(f'Starting credential isolation gateway on {GATEWAY_HOST}:{GATEWAY_PORT}')

    # GC is already started by module-level initialization
    # atexit handler is already registered at module level

    app.run(host=GATEWAY_HOST, port=GATEWAY_PORT, debug=False)
