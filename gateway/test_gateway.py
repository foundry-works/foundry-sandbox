#!/usr/bin/env python3
"""
Pytest test suite for the credential isolation gateway.

Tests cover:
- Session management (create, validate, destroy, TTL, IP binding, repo scoping)
- Input validation (owner/repo regex, IP literal detection, git paths, LFS)
- Authentication parsing (Bearer and Basic formats)
- Garbage collection
- Audit logging
"""

import pytest
import base64
import json
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Import the gateway module
import gateway


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def clean_sessions():
    """Clear session store before and after each test."""
    gateway.SESSIONS.clear()
    yield
    gateway.SESSIONS.clear()


@pytest.fixture
def app():
    """Create Flask test client."""
    gateway.app.config['TESTING'] = True
    return gateway.app


@pytest.fixture
def client(app):
    """Create Flask test client."""
    return app.test_client()


@pytest.fixture
def session_data():
    """Create a valid session and return token/secret."""
    result = gateway.create_session(
        container_ip='10.0.0.1',
        container_id='test-container',
        repos=['owner/repo']
    )
    return result


# =============================================================================
# Token Generation Tests
# =============================================================================

class TestTokenGeneration:
    """Tests for secure token and secret generation."""

    def test_generate_session_token_returns_string(self):
        """Token generation returns a string."""
        token = gateway.generate_session_token()
        assert isinstance(token, str)

    def test_generate_session_token_length(self):
        """Token has sufficient length (43 chars for 32 bytes urlsafe)."""
        token = gateway.generate_session_token()
        assert len(token) >= 40

    def test_generate_session_token_uniqueness(self):
        """Each generated token is unique."""
        tokens = [gateway.generate_session_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_generate_session_secret_returns_string(self):
        """Secret generation returns a string."""
        secret = gateway.generate_session_secret()
        assert isinstance(secret, str)

    def test_generate_session_secret_uniqueness(self):
        """Each generated secret is unique."""
        secrets = [gateway.generate_session_secret() for _ in range(100)]
        assert len(set(secrets)) == 100


# =============================================================================
# Session Management Tests
# =============================================================================

class TestSessionCreate:
    """Tests for session creation."""

    def test_create_session_returns_token_and_secret(self):
        """Session creation returns both token and secret."""
        result = gateway.create_session('10.0.0.1')
        assert 'token' in result
        assert 'secret' in result
        assert len(result['token']) > 0
        assert len(result['secret']) > 0

    def test_create_session_stores_in_sessions(self):
        """Created session is stored in SESSIONS dict."""
        result = gateway.create_session('10.0.0.1', container_id='test')
        assert result['token'] in gateway.SESSIONS

    def test_create_session_stores_container_info(self):
        """Session stores container IP and ID."""
        result = gateway.create_session('10.0.0.1', container_id='test-123')
        session = gateway.SESSIONS[result['token']]
        assert session['container_ip'] == '10.0.0.1'
        assert session['container_id'] == 'test-123'

    def test_create_session_stores_repos(self):
        """Session stores authorized repos list."""
        repos = ['owner1/repo1', 'owner2/repo2']
        result = gateway.create_session('10.0.0.1', repos=repos)
        session = gateway.SESSIONS[result['token']]
        assert session['repos'] == repos

    def test_create_session_empty_repos_default(self):
        """Session has empty repos list by default."""
        result = gateway.create_session('10.0.0.1')
        session = gateway.SESSIONS[result['token']]
        assert session['repos'] == []

    def test_create_session_sets_timestamps(self):
        """Session has created, last_accessed, and expires_at timestamps."""
        result = gateway.create_session('10.0.0.1')
        session = gateway.SESSIONS[result['token']]
        assert 'created' in session
        assert 'last_accessed' in session
        assert 'expires_at' in session
        assert isinstance(session['created'], datetime)

    def test_create_session_limit_exceeded(self):
        """Raises ValueError when session limit is exceeded."""
        original_max = gateway.MAX_SESSIONS
        gateway.MAX_SESSIONS = 2
        try:
            gateway.create_session('10.0.0.1')
            gateway.create_session('10.0.0.2')
            with pytest.raises(ValueError, match='Maximum session limit'):
                gateway.create_session('10.0.0.3')
        finally:
            gateway.MAX_SESSIONS = original_max


class TestSessionValidate:
    """Tests for session validation."""

    def test_validate_session_valid(self, session_data):
        """Valid session with correct token, secret, and IP passes."""
        assert gateway.validate_session(
            session_data['token'],
            session_data['secret'],
            '10.0.0.1'
        )

    def test_validate_session_invalid_token(self, session_data):
        """Invalid token fails validation."""
        assert not gateway.validate_session(
            'invalid-token',
            session_data['secret'],
            '10.0.0.1'
        )

    def test_validate_session_invalid_secret(self, session_data):
        """Invalid secret fails validation."""
        assert not gateway.validate_session(
            session_data['token'],
            'invalid-secret',
            '10.0.0.1'
        )

    def test_validate_session_none_secret_allowed(self, session_data):
        """None secret (Basic auth flow) passes if IP matches."""
        assert gateway.validate_session(
            session_data['token'],
            None,
            '10.0.0.1'
        )

    def test_validate_session_wrong_ip(self, session_data):
        """Wrong IP fails validation."""
        assert not gateway.validate_session(
            session_data['token'],
            session_data['secret'],
            '10.0.0.99'
        )

    def test_validate_session_updates_last_accessed(self, session_data):
        """Validation updates last_accessed timestamp."""
        old_accessed = gateway.SESSIONS[session_data['token']]['last_accessed']
        time.sleep(0.01)
        gateway.validate_session(session_data['token'], session_data['secret'], '10.0.0.1')
        new_accessed = gateway.SESSIONS[session_data['token']]['last_accessed']
        assert new_accessed > old_accessed

    def test_validate_session_inactivity_expired(self, session_data):
        """Session expired by inactivity fails validation."""
        token = session_data['token']
        # Set last_accessed to 25 hours ago
        gateway.SESSIONS[token]['last_accessed'] = datetime.utcnow() - timedelta(hours=25)
        assert not gateway.validate_session(token, session_data['secret'], '10.0.0.1')
        # Session should be removed
        assert token not in gateway.SESSIONS

    def test_validate_session_absolute_expired(self, session_data):
        """Session expired by absolute TTL fails validation."""
        token = session_data['token']
        # Set expires_at to past
        gateway.SESSIONS[token]['expires_at'] = datetime.utcnow() - timedelta(hours=1)
        assert not gateway.validate_session(token, session_data['secret'], '10.0.0.1')
        # Session should be removed
        assert token not in gateway.SESSIONS


class TestSessionDestroy:
    """Tests for session destruction."""

    def test_destroy_session_existing(self, session_data):
        """Destroying existing session returns True."""
        assert gateway.destroy_session(session_data['token'])
        assert session_data['token'] not in gateway.SESSIONS

    def test_destroy_session_nonexistent(self):
        """Destroying nonexistent session returns False."""
        assert not gateway.destroy_session('nonexistent-token')


# =============================================================================
# Input Validation Tests
# =============================================================================

class TestValidateOwner:
    """Tests for repository owner validation."""

    @pytest.mark.parametrize('owner', [
        'validowner',
        'Valid-Owner',
        'owner123',
        'a',
        'a1',
        'abc-def',
    ])
    def test_valid_owners(self, owner):
        """Valid owner names pass validation."""
        assert gateway.validate_owner(owner)

    @pytest.mark.parametrize('owner', [
        '',
        None,
        '-startwithdash',
        'endwithdash-',
        'invalid/slash',
        'invalid.dot',
        'invalid_underscore',
        'has space',
    ])
    def test_invalid_owners(self, owner):
        """Invalid owner names fail validation."""
        assert not gateway.validate_owner(owner)


class TestValidateRepo:
    """Tests for repository name validation."""

    @pytest.mark.parametrize('repo', [
        'repo',
        'my-repo',
        'my_repo',
        'my.repo',
        'MyRepo123',
    ])
    def test_valid_repos(self, repo):
        """Valid repo names pass validation."""
        assert gateway.validate_repo(repo)

    @pytest.mark.parametrize('repo', [
        '',
        None,
        'has space',
        'has/slash',
        'has:colon',
    ])
    def test_invalid_repos(self, repo):
        """Invalid repo names fail validation."""
        assert not gateway.validate_repo(repo)


class TestValidateGitPath:
    """Tests for git endpoint path validation."""

    @pytest.mark.parametrize('path', [
        'info/refs',
        'git-upload-pack',
        'git-receive-pack',
    ])
    def test_allowed_paths(self, path):
        """Allowed git paths pass validation."""
        assert gateway.validate_git_path(path)

    @pytest.mark.parametrize('path', [
        '',
        None,
        'objects/pack/123.pack',
        'HEAD',
        'config',
        '../../../etc/passwd',
    ])
    def test_disallowed_paths(self, path):
        """Disallowed paths fail validation."""
        assert not gateway.validate_git_path(path)


class TestIsLfsEndpoint:
    """Tests for LFS endpoint detection."""

    @pytest.mark.parametrize('path', [
        'objects/batch',
        'lfs/objects/batch',
        '.git/lfs/objects',
        'info/lfs/locks',
    ])
    def test_lfs_endpoints_detected(self, path):
        """LFS endpoints are detected."""
        assert gateway.is_lfs_endpoint(path)

    @pytest.mark.parametrize('path', [
        'info/refs',
        'git-upload-pack',
        'git-receive-pack',
        '',
        None,
    ])
    def test_non_lfs_endpoints(self, path):
        """Non-LFS endpoints are not flagged."""
        assert not gateway.is_lfs_endpoint(path)


class TestIsIpLiteral:
    """Tests for IP literal detection."""

    @pytest.mark.parametrize('host', [
        '127.0.0.1',
        '192.168.1.1',
        '10.0.0.1:8080',
        '8.8.8.8',
    ])
    def test_ipv4_literals_detected(self, host):
        """IPv4 literal hosts are detected."""
        assert gateway.is_ip_literal(host)

    @pytest.mark.parametrize('host', [
        '[::1]',
        '[::1]:8080',
        '[2001:db8::1]',
        '[2001:db8::1]:443',
    ])
    def test_ipv6_bracketed_literals_detected(self, host):
        """IPv6 bracketed literals (standard HTTP Host format) are detected."""
        assert gateway.is_ip_literal(host)

    @pytest.mark.parametrize('host', [
        '::1',           # Bare IPv6 - not valid HTTP Host format
        '2001:db8::1',   # Bare IPv6 - not valid HTTP Host format
    ])
    def test_bare_ipv6_not_detected(self, host):
        """Bare IPv6 addresses (without brackets) are not detected.

        This is acceptable because HTTP Host headers with IPv6 always use
        bracket notation per RFC 3986. Bare IPv6 addresses would never
        appear in a valid HTTP request Host header.
        """
        # Bare IPv6 splits on ':' and yields invalid result - acceptable
        assert not gateway.is_ip_literal(host)

    @pytest.mark.parametrize('host', [
        'github.com',
        'api.github.com',
        'example.com:443',
        'localhost',
        '',
        None,
    ])
    def test_hostnames_not_flagged(self, host):
        """Hostnames are not flagged as IP literals."""
        assert not gateway.is_ip_literal(host)


# =============================================================================
# Authentication Parsing Tests
# =============================================================================

class TestBearerAuthParsing:
    """Tests for Bearer auth header parsing via git_proxy endpoint."""

    def test_bearer_auth_format(self, client, session_data):
        """Bearer token:secret format is parsed correctly."""
        token = session_data['token']
        secret = session_data['secret']
        auth_header = f"Bearer {token}:{secret}"

        with patch.object(gateway, 'get_github_token', return_value='fake-token'):
            with patch('gateway.requests.request') as mock_request:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'application/x-git-upload-pack-result'}
                mock_response.iter_content = MagicMock(return_value=[b'test'])
                mock_request.return_value = mock_response

                response = client.get(
                    '/git/owner/repo.git/info/refs',
                    headers={'Authorization': auth_header},
                    environ_base={'REMOTE_ADDR': '10.0.0.1'}
                )
                # Should reach upstream (we mocked it)
                assert response.status_code == 200

    def test_bearer_auth_missing_secret(self, client, session_data):
        """Bearer without secret delimiter fails."""
        auth_header = f"Bearer {session_data['token']}"
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={'Authorization': auth_header},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 401


class TestBasicAuthParsing:
    """Tests for Basic auth header parsing."""

    def test_basic_auth_format(self, client, session_data):
        """Basic auth with token in password field is parsed correctly."""
        token = session_data['token']
        # Format: base64(username:token)
        credentials = base64.b64encode(f"x-gateway-token:{token}".encode()).decode()
        auth_header = f"Basic {credentials}"

        with patch.object(gateway, 'get_github_token', return_value='fake-token'):
            with patch('gateway.requests.request') as mock_request:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.headers = {'Content-Type': 'application/x-git-upload-pack-result'}
                mock_response.iter_content = MagicMock(return_value=[b'test'])
                mock_request.return_value = mock_response

                response = client.get(
                    '/git/owner/repo.git/info/refs',
                    headers={'Authorization': auth_header},
                    environ_base={'REMOTE_ADDR': '10.0.0.1'}
                )
                assert response.status_code == 200

    def test_basic_auth_malformed(self, client):
        """Malformed Basic auth fails."""
        # Invalid base64
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={'Authorization': 'Basic not-valid-base64!!!'},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 401


# =============================================================================
# Repo Scoping Tests
# =============================================================================

class TestRepoScoping:
    """Tests for repository authorization scoping."""

    def test_repo_scoping_allowed(self, client):
        """Request to authorized repo succeeds."""
        session = gateway.create_session(
            '10.0.0.1',
            repos=['owner/repo']
        )
        token = session['token']
        secret = session['secret']

        with patch.object(gateway, 'get_github_token', return_value='fake-token'):
            with patch('gateway.requests.request') as mock_request:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.headers = {}
                mock_response.iter_content = MagicMock(return_value=[])
                mock_request.return_value = mock_response

                response = client.get(
                    '/git/owner/repo.git/info/refs',
                    headers={'Authorization': f'Bearer {token}:{secret}'},
                    environ_base={'REMOTE_ADDR': '10.0.0.1'}
                )
                assert response.status_code == 200

    def test_repo_scoping_denied(self, client):
        """Request to unauthorized repo fails."""
        session = gateway.create_session(
            '10.0.0.1',
            repos=['owner/allowed-repo']
        )
        token = session['token']
        secret = session['secret']

        response = client.get(
            '/git/owner/denied-repo.git/info/refs',
            headers={'Authorization': f'Bearer {token}:{secret}'},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 403
        assert b'not authorized' in response.data

    def test_repo_scoping_empty_list_denied_by_default(self, client):
        """Empty repos list is denied by default policy (defense-in-depth).

        SECURITY: Sessions without explicit repo authorization are denied.
        This prevents legacy/misconfigured sessions from having unrestricted access.
        """
        session = gateway.create_session('10.0.0.1', repos=[])
        token = session['token']
        secret = session['secret']

        response = client.get(
            '/git/any/repo.git/info/refs',
            headers={'Authorization': f'Bearer {token}:{secret}'},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        # Should be denied by default policy hook
        assert response.status_code == 403
        assert b'policy' in response.data.lower()


# =============================================================================
# Garbage Collection Tests
# =============================================================================

class TestGarbageCollection:
    """Tests for session garbage collection."""

    def test_gc_removes_inactive_sessions(self):
        """GC removes sessions inactive for > 24 hours."""
        session = gateway.create_session('10.0.0.1')
        token = session['token']

        # Set last_accessed to 25 hours ago
        gateway.SESSIONS[token]['last_accessed'] = datetime.utcnow() - timedelta(hours=25)

        gateway.garbage_collect_sessions()
        # Stop the timer that GC schedules
        if gateway._gc_timer:
            gateway._gc_timer.cancel()

        assert token not in gateway.SESSIONS

    def test_gc_removes_expired_sessions(self):
        """GC removes sessions past absolute expiry."""
        session = gateway.create_session('10.0.0.1')
        token = session['token']

        # Set expires_at to past
        gateway.SESSIONS[token]['expires_at'] = datetime.utcnow() - timedelta(hours=1)

        gateway.garbage_collect_sessions()
        if gateway._gc_timer:
            gateway._gc_timer.cancel()

        assert token not in gateway.SESSIONS

    def test_gc_keeps_valid_sessions(self):
        """GC keeps sessions that are still valid."""
        session = gateway.create_session('10.0.0.1')
        token = session['token']

        gateway.garbage_collect_sessions()
        if gateway._gc_timer:
            gateway._gc_timer.cancel()

        assert token in gateway.SESSIONS


# =============================================================================
# API Endpoint Tests
# =============================================================================

class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_returns_200(self, client):
        """Health endpoint returns 200 OK."""
        response = client.get('/health')
        assert response.status_code == 200

    def test_health_returns_healthy_status(self, client):
        """Health endpoint returns healthy status."""
        response = client.get('/health')
        data = json.loads(response.data)
        assert data['status'] == 'healthy'


class TestSessionCreateEndpoint:
    """Tests for session creation endpoint."""

    def test_session_create_from_localhost(self, client):
        """Session creation from localhost succeeds."""
        response = client.post(
            '/session/create',
            json={'container_ip': '10.0.0.5', 'container_id': 'test'},
            environ_base={'REMOTE_ADDR': '127.0.0.1'}
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'token' in data
        assert 'secret' in data

    def test_session_create_from_ipv6_localhost(self, client):
        """Session creation from IPv6 localhost (::1) succeeds."""
        response = client.post(
            '/session/create',
            json={'container_ip': '10.0.0.5', 'container_id': 'test-ipv6'},
            environ_base={'REMOTE_ADDR': '::1'}
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'token' in data
        assert 'secret' in data

    def test_session_create_from_ipv4_mapped_ipv6(self, client):
        """Session creation from IPv4-mapped IPv6 (::ffff:127.0.0.1) succeeds."""
        response = client.post(
            '/session/create',
            json={'container_ip': '10.0.0.5', 'container_id': 'test-mapped'},
            environ_base={'REMOTE_ADDR': '::ffff:127.0.0.1'}
        )
        assert response.status_code == 201

    def test_session_create_from_external_denied(self, client):
        """Session creation from external IP is denied."""
        response = client.post(
            '/session/create',
            json={'container_ip': '10.0.0.5'},
            environ_base={'REMOTE_ADDR': '192.168.1.100'}
        )
        assert response.status_code == 403

    def test_session_create_missing_ip(self, client):
        """Session creation without container_ip fails."""
        response = client.post(
            '/session/create',
            json={},
            environ_base={'REMOTE_ADDR': '127.0.0.1'}
        )
        assert response.status_code == 400


class TestSessionDestroyEndpoint:
    """Tests for session destruction endpoint."""

    def test_session_destroy_success(self, client, session_data):
        """Destroying existing session succeeds."""
        response = client.delete(
            f"/session/{session_data['token']}",
            environ_base={'REMOTE_ADDR': '127.0.0.1'}
        )
        assert response.status_code == 200
        assert session_data['token'] not in gateway.SESSIONS

    def test_session_destroy_not_found(self, client):
        """Destroying nonexistent session returns 404."""
        response = client.delete(
            '/session/nonexistent-token',
            environ_base={'REMOTE_ADDR': '127.0.0.1'}
        )
        assert response.status_code == 404

    def test_session_destroy_external_denied(self, client, session_data):
        """Destroying session from external IP is denied."""
        response = client.delete(
            f"/session/{session_data['token']}",
            environ_base={'REMOTE_ADDR': '192.168.1.100'}
        )
        assert response.status_code == 403


class TestGitProxyEndpoint:
    """Tests for git proxy endpoint."""

    def test_git_proxy_invalid_owner(self, client, session_data):
        """Invalid owner format returns 400."""
        response = client.get(
            '/git/-invalid/repo.git/info/refs',
            headers={'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 400

    def test_git_proxy_invalid_repo(self, client, session_data):
        """Invalid repo format returns 400."""
        response = client.get(
            '/git/owner/invalid:repo.git/info/refs',
            headers={'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 400

    def test_git_proxy_invalid_path(self, client, session_data):
        """Invalid git path returns 400."""
        response = client.get(
            '/git/owner/repo.git/invalid/path',
            headers={'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 400

    def test_git_proxy_lfs_rejected(self, client, session_data):
        """LFS endpoint returns 501."""
        response = client.get(
            '/git/owner/repo.git/objects/batch',
            headers={'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 501
        data = json.loads(response.data)
        assert 'LFS' in data['error']

    def test_git_proxy_no_auth(self, client):
        """Request without auth returns 401."""
        response = client.get('/git/owner/repo.git/info/refs')
        assert response.status_code == 401

    def test_git_proxy_invalid_session(self, client):
        """Request with invalid session returns 401."""
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={'Authorization': 'Bearer invalid:token'},
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 401


class TestIndexEndpoint:
    """Tests for root endpoint."""

    def test_index_returns_service_info(self, client):
        """Root endpoint returns service info."""
        response = client.get('/')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['service'] == 'credential-isolation-gateway'
        assert 'version' in data


# =============================================================================
# Audit Logging Tests
# =============================================================================

class TestAuditLog:
    """Tests for audit logging."""

    def test_audit_log_filters_sensitive_fields(self, capsys):
        """Audit log filters out sensitive fields."""
        # Use **kwargs to pass extra_data fields directly
        gateway.audit_log(
            'test_event',
            container_id='test',
            ip='10.0.0.1',
            safe_field='visible',
            token='should-be-filtered',
            secret='should-be-filtered',
            authorization='should-be-filtered',
            password='should-be-filtered',
        )
        captured = capsys.readouterr()
        assert 'should-be-filtered' not in captured.err
        assert 'visible' in captured.err

    def test_audit_log_includes_timestamp(self, capsys):
        """Audit log includes timestamp."""
        gateway.audit_log('test_event', container_id='test', ip='10.0.0.1')
        captured = capsys.readouterr()
        log_entry = json.loads(captured.err.strip())
        assert 'timestamp' in log_entry
        assert log_entry['timestamp'].endswith('Z')

    def test_audit_log_scrubs_credentials_in_error_messages(self, capsys):
        """Audit log scrubs credential patterns from error message strings."""
        # Test various credential patterns that might appear in error messages
        gateway.audit_log(
            'test_event',
            container_id='test',
            ip='10.0.0.1',
            error='Failed with Bearer abc123token',
            details='URL was https://user:pass@github.com/repo',
        )
        captured = capsys.readouterr()
        log_entry = json.loads(captured.err.strip())
        # Bearer token should be redacted
        assert 'abc123token' not in log_entry['error']
        assert '[REDACTED]' in log_entry['error']
        # URL credentials should be redacted
        assert 'user:pass' not in log_entry['details']
        assert '[REDACTED]' in log_entry['details']


class TestCredentialScrubbing:
    """Tests for the scrub_credentials function."""

    def test_scrub_bearer_token(self):
        """Bearer tokens are scrubbed."""
        result = gateway.scrub_credentials('Error: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 failed')
        assert 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' not in result
        assert 'Bearer [REDACTED]' in result

    def test_scrub_basic_auth(self):
        """Basic auth tokens are scrubbed."""
        result = gateway.scrub_credentials('Auth header: Basic dXNlcjpwYXNz')
        assert 'dXNlcjpwYXNz' not in result
        assert 'Basic [REDACTED]' in result

    def test_scrub_url_credentials(self):
        """URL-embedded credentials are scrubbed."""
        result = gateway.scrub_credentials('URL: https://user:password123@github.com/repo')
        assert 'user:password123' not in result
        assert '://[REDACTED]@' in result

    def test_scrub_github_token(self):
        """GitHub tokens (ghp_, gho_, etc.) are scrubbed."""
        result = gateway.scrub_credentials('Found token ghp_1234567890abcdefghij in response')
        assert 'ghp_1234567890abcdefghij' not in result
        assert '[GITHUB_TOKEN_REDACTED]' in result

    def test_scrub_api_key_pattern(self):
        """API key patterns are scrubbed."""
        result = gateway.scrub_credentials('Config: api_key=supersecret123')
        assert 'supersecret123' not in result
        assert 'api_key=[REDACTED]' in result

    def test_scrub_session_token_pattern(self):
        """Session tokens (43-char base64url) are scrubbed."""
        # Our tokens are 43-char base64url strings (secrets.token_urlsafe(32))
        token_43_chars = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'  # exactly 43 chars
        result = gateway.scrub_credentials(f'Session {token_43_chars} expired')
        assert token_43_chars not in result
        assert '[TOKEN_REDACTED]' in result

    def test_scrub_non_string_passthrough(self):
        """Non-string values pass through unchanged."""
        assert gateway.scrub_credentials(123) == 123
        assert gateway.scrub_credentials(None) is None
        assert gateway.scrub_credentials(['a', 'b']) == ['a', 'b']

    def test_scrub_safe_content_unchanged(self):
        """Safe content without credentials is unchanged."""
        safe = 'Normal error message without secrets'
        assert gateway.scrub_credentials(safe) == safe


# =============================================================================
# IP Literal Request Tests
# =============================================================================

class TestIpLiteralRequests:
    """Tests for IP literal request rejection."""

    def test_check_ip_literal_request_with_app_context(self, app):
        """IP literal requests are rejected."""
        with app.test_request_context('/', headers={'Host': '192.168.1.1:8080'}):
            is_ip, response = gateway.check_ip_literal_request()
            assert is_ip
            assert response.status_code == 403

    def test_check_ip_literal_request_hostname_allowed(self, app):
        """Hostname requests are allowed."""
        with app.test_request_context('/', headers={'Host': 'gateway.example.com'}):
            is_ip, response = gateway.check_ip_literal_request()
            assert not is_ip
            assert response is None


# =============================================================================
# DNS Bypass Prevention Tests
# =============================================================================

class TestDnsBypassPrevention:
    """
    Tests verifying that DNS-based bypass attempts are blocked.

    These tests ensure that the gateway rejects requests that attempt to
    bypass credential injection by using IP addresses directly instead of
    DNS-resolved hostnames.

    Security context: Without DNS routing through the gateway, sandboxes
    could bypass the gateway by:
    1. Using hardcoded GitHub IPs (e.g., 140.82.112.4)
    2. Using alternative DNS resolvers to get real GitHub IPs
    3. Making direct IP requests that skip credential injection

    The gateway rejects IP literal requests to enforce that all traffic
    must go through DNS resolution (which the gateway controls via dnsmasq).
    """

    def test_ipv4_literal_git_request_blocked(self, client, session_data):
        """Git request to IPv4 literal is blocked."""
        # Simulate request to GitHub IP directly (bypass attempt)
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={
                'Host': '140.82.112.4',  # GitHub's actual IP
                'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
            },
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 403
        data = json.loads(response.data)
        assert 'IP literal' in data['error']

    def test_ipv4_with_port_git_request_blocked(self, client, session_data):
        """Git request to IPv4:port literal is blocked."""
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={
                'Host': '140.82.112.4:443',
                'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
            },
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 403

    def test_ipv6_literal_git_request_blocked(self, client, session_data):
        """Git request to IPv6 literal is blocked."""
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={
                'Host': '[2001:db8::1]',
                'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
            },
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 403

    def test_ipv6_with_port_git_request_blocked(self, client, session_data):
        """Git request to [IPv6]:port literal is blocked."""
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={
                'Host': '[2001:db8::1]:443',
                'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
            },
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 403

    def test_localhost_ipv4_blocked(self, client, session_data):
        """Git request to 127.x.x.x is blocked (localhost bypass attempt)."""
        response = client.get(
            '/git/owner/repo.git/info/refs',
            headers={
                'Host': '127.0.0.1',
                'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
            },
            environ_base={'REMOTE_ADDR': '10.0.0.1'}
        )
        assert response.status_code == 403

    def test_private_network_ip_blocked(self, client, session_data):
        """Git request to private network IP is blocked."""
        # These could be used to probe internal services
        for ip in ['10.0.0.100', '172.16.0.1', '192.168.1.1']:
            response = client.get(
                '/git/owner/repo.git/info/refs',
                headers={
                    'Host': ip,
                    'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
                },
                environ_base={'REMOTE_ADDR': '10.0.0.1'}
            )
            assert response.status_code == 403, f"Expected 403 for IP {ip}"

    def test_hostname_request_allowed(self, client, session_data):
        """Git request to hostname (not IP) proceeds to validation."""
        # This should pass IP literal check but may fail on other validation
        # (e.g., upstream connection) - the key is it's NOT blocked as IP literal
        with patch('gateway.requests.request') as mock_request:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {'Content-Type': 'application/x-git-upload-pack-advertisement'}
            mock_response.iter_content = MagicMock(return_value=[b'test'])
            mock_request.return_value = mock_response

            with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token'}):
                response = client.get(
                    '/git/owner/repo.git/info/refs',
                    headers={
                        'Host': 'github.com',  # Hostname, not IP
                        'Authorization': f"Bearer {session_data['token']}:{session_data['secret']}"
                    },
                    environ_base={'REMOTE_ADDR': '10.0.0.1'}
                )
                # Should NOT be 403 (IP literal rejection)
                assert response.status_code != 403 or 'IP literal' not in response.data.decode()

    def test_proxy_endpoint_ip_literal_blocked(self, client):
        """General proxy endpoint also blocks IP literals."""
        response = client.get(
            '/proxy/some/path',
            headers={
                'Host': '8.8.8.8',
                'Authorization': 'Bearer some-token'
            }
        )
        assert response.status_code == 403
        data = json.loads(response.data)
        assert 'IP literal' in data['error']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
