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
    Default policy hook that allows all operations.
    Can be overridden via environment or configuration.

    Args:
        owner: Repository owner
        repo: Repository name
        operation: 'read' or 'write'

    Returns:
        bool: True if operation is allowed, False otherwise
    """
    return True

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
        dict: The validated session object if valid, None otherwise.
              Returning the session object prevents race conditions where
              GC could delete the session between validation and usage.
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

        # Check IP binding
        if session['container_ip'] != client_ip:
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
        # Skip sensitive fields
        if key.lower() in ('token', 'authorization', 'password', 'secret', 'auth'):
            continue
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

@app.route('/session/create', methods=['POST'])
def session_create_endpoint():
    """
    Create a new session with token and secret binding to container IP.
    Unix socket only (trusted orchestrator).
    """
    # Check if request comes from Unix socket (local)
    # Note: 'localhost' would be resolved to '127.0.0.1' by the time it reaches here
    if request.remote_addr != '127.0.0.1':
        audit_log('session_create_denied', extra_data={'reason': 'not_unix_socket'})
        return {'error': 'Session creation only allowed from Unix socket'}, 403

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
    Unix socket only.
    """
    # Check if request comes from Unix socket (local)
    # Note: 'localhost' would be resolved to '127.0.0.1' by the time it reaches here
    if request.remote_addr != '127.0.0.1':
        audit_log('session_destroy_denied', extra_data={'reason': 'not_unix_socket', 'token': session_token})
        return {'error': 'Session destruction only allowed from Unix socket'}, 403

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
    if session.get('repos'):
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

    # Apply policy hook
    if not POLICY_HOOK(owner, repo, operation):
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

        # Stream request body to avoid buffering large payloads (e.g., git push)
        # Use request.stream for memory-bounded streaming instead of request.get_data()
        request_body = None
        if request.method in ['POST', 'PUT']:
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

@app.route('/proxy/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    """
    General proxy endpoint.
    Logs allow/deny decisions for audit purposes.
    Rejects IP literal requests.
    """
    # Check for IP literal requests and reject if found
    is_ip, error_response = check_ip_literal_request()
    if is_ip:
        return error_response

    # Check if request is allowed (placeholder logic)
    auth_header = request.headers.get('Authorization')
    if auth_header:
        audit_log('proxy_allow', extra_data={'path': path, 'method': request.method})
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
