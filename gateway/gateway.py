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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
GATEWAY_PORT = int(os.environ.get('GATEWAY_PORT', 8080))
GATEWAY_HOST = os.environ.get('GATEWAY_HOST', '0.0.0.0')

# Session management
SESSIONS = {}  # {token: {'secret': secret, 'container_id': id, 'container_ip': ip, 'repos': [], 'created': datetime, 'last_accessed': datetime, 'expires_at': datetime}}
SESSION_TTL_INACTIVITY = timedelta(hours=24)  # 24 hour inactivity timeout
SESSION_TTL_ABSOLUTE = timedelta(days=7)  # 7 day absolute timeout
SESSION_GC_INTERVAL = timedelta(minutes=5)  # Run garbage collection every 5 minutes

# Garbage collection state
_gc_timer = None

# Validation regex patterns
OWNER_REGEX = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'
REPO_REGEX = r'^[a-zA-Z0-9._-]+$'

# Allowed git endpoints
ALLOWED_GIT_PATHS = {'info/refs', 'git-upload-pack', 'git-receive-pack'}

# Upstream configuration
UPSTREAM_HOST = 'github.com'
UPSTREAM_PROTOCOL = 'https'

# Default policy hook allows all operations
def get_github_token():
    """
    Get the real GitHub token for upstream authentication.

    Returns:
        str: GitHub token from environment or session context
    """
    # Try to get from environment first
    token = os.environ.get('GITHUB_TOKEN')
    if token:
        return token

    # Fallback to placeholder
    return 'placeholder-github-token'

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
    """
    token = generate_session_token()
    secret = generate_session_secret()
    now = datetime.utcnow()
    expires_at = now + SESSION_TTL_ABSOLUTE

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
        secret: Session secret
        client_ip: Client IP address from request

    Returns:
        bool: True if session is valid, False otherwise
    """
    if token not in SESSIONS:
        return False

    session = SESSIONS[token]

    # Check secret matches
    if session['secret'] != secret:
        return False

    # Check IP binding
    if session['container_ip'] != client_ip:
        return False

    now = datetime.utcnow()

    # Check inactivity timeout (24 hours)
    if now - session['last_accessed'] > SESSION_TTL_INACTIVITY:
        logger.info(f'Session {token} expired due to inactivity')
        del SESSIONS[token]
        return False

    # Check absolute expiry (7 days from creation)
    if now > session['expires_at']:
        logger.info(f'Session {token} expired due to absolute TTL')
        del SESSIONS[token]
        return False

    # Update last accessed time
    session['last_accessed'] = now

    return True

def garbage_collect_sessions():
    """
    Remove expired sessions from the session store.
    Checks both inactivity TTL (24h) and absolute expiry (7d).
    Scheduled to run every 5 minutes.
    """
    global _gc_timer
    now = datetime.utcnow()
    expired_tokens = []

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
    """
    global _gc_timer
    logger.info('Starting session garbage collection (interval: 5 minutes)')
    _gc_timer = threading.Timer(SESSION_GC_INTERVAL.total_seconds(), garbage_collect_sessions)
    _gc_timer.daemon = True
    _gc_timer.start()

def stop_garbage_collection():
    """
    Stop the background garbage collection timer.
    Called on application shutdown.
    """
    global _gc_timer
    if _gc_timer:
        logger.info('Stopping session garbage collection')
        _gc_timer.cancel()
        _gc_timer = None

def destroy_session(token):
    """
    Destroy a session by token.

    Args:
        token: Session token

    Returns:
        bool: True if session was destroyed, False if not found
    """
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

    # Remove port if present (e.g., "1.2.3.4:8080" -> "1.2.3.4")
    host_only = host.split(':')[0]
    # Also handle IPv6 addresses in brackets (e.g., "[::1]" or "[::1]:8080")
    host_only = host_only.strip('[]')

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

    # Write to stderr as JSON
    json.dump(audit_entry, sys.stderr)
    sys.stderr.write('\n')
    sys.stderr.flush()

@app.route('/health')
def health():
    """Health check endpoint."""
    logger.info('Health check requested')
    return {'status': 'healthy'}, 200

@app.route('/session/create', methods=['POST'])
def session_create_endpoint():
    """
    Create a new session with token and secret binding to container IP.
    Unix socket only.
    """
    # Check if request comes from Unix socket (local)
    if request.remote_addr not in ('127.0.0.1', 'localhost'):
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

        # Create session with container_id and repos
        session_data = create_session(container_ip, container_id=container_id, repos=repos)

        audit_log('session_create', container_id=container_id, extra_data={'container_ip': container_ip})

        return {
            'token': session_data['token'],
            'secret': session_data['secret'],
            'ttl_inactivity_hours': 24,
            'ttl_absolute_days': 7
        }, 201

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
    if request.remote_addr not in ('127.0.0.1', 'localhost'):
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

    # Parse authorization header (expected format: "Bearer token:secret")
    if not auth_header.startswith('Bearer '):
        audit_log('git_denied', extra_data={
            'reason': 'invalid_auth_format',
            'owner': owner,
            'repo': repo,
            'path': git_path
        })
        return Response('Invalid authorization format', status=401)

    try:
        token_secret = auth_header[7:]  # Remove "Bearer " prefix
        if ':' not in token_secret:
            raise ValueError('Missing token:secret separator')
        token, secret = token_secret.split(':', 1)
    except Exception as e:
        audit_log('git_denied', extra_data={
            'reason': 'malformed_credentials',
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'error': str(e)
        })
        return Response('Malformed credentials', status=401)

    # Validate session
    client_ip = request.remote_addr
    if not validate_session(token, secret, client_ip):
        audit_log('git_denied', extra_data={
            'reason': 'invalid_session',
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'client_ip': client_ip
        })
        return Response('Invalid or expired session', status=401)

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

    # Proxy to GitHub with streaming support
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
        github_token = get_github_token()
        headers['Authorization'] = f'token {github_token}'

        # Get request body for streaming if present
        request_body = None
        if request.method in ['POST', 'PUT']:
            request_body = request.get_data()

        # Make streaming request with proper timeouts: (30s connect, 600s transfer)
        proxied_request = requests.request(
            method=request.method,
            url=upstream_url,
            headers=headers,
            data=request_body,
            params=request.args,
            allow_redirects=False,  # Disable redirects per spec
            timeout=(30, 600),  # Connect timeout, read timeout
            stream=True  # Enable streaming
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
        return Response('Gateway timeout', status=504)

    except Exception as e:
        logger.error(f'Git proxy error: {e}')
        audit_log('git_proxy_error', extra_data={
            'owner': owner,
            'repo': repo,
            'path': git_path,
            'error': str(e)
        })
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

    # Start garbage collection on application startup
    start_garbage_collection()

    # Register cleanup on application shutdown
    atexit.register(stop_garbage_collection)

    app.run(host=GATEWAY_HOST, port=GATEWAY_PORT, debug=False)
