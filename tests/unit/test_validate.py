"""Unit tests for foundry_sandbox validation, Docker, and API keys modules.

Tests cover:
- foundry_sandbox.validate: sandbox names, git URLs, SSH modes, mount paths,
  command checking, Docker status, git remote credentials
- foundry_sandbox.docker: subnet generation, credential placeholders, compose commands
- foundry_sandbox.api_keys: AI/search key detection, auth conflicts, status reporting
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, mock_open, patch


from foundry_sandbox import api_keys, docker, validate


# ============================================================================
# validate.py Tests
# ============================================================================


class TestSandboxNameValidation:
    """Tests for validate_sandbox_name()."""

    def test_empty_name_rejected(self):
        """Empty sandbox name should be rejected."""
        valid, msg = validate.validate_sandbox_name("")
        assert valid is False
        assert msg == "Sandbox name required"

    def test_valid_name_accepted(self):
        """Non-empty sandbox name should be accepted."""
        valid, msg = validate.validate_sandbox_name("my-sandbox")
        assert valid is True
        assert msg == ""

    def test_valid_name_variants_accepted(self):
        """Safe sandbox names should be accepted."""
        for name in ["a", "123", "test_name", "valid-sandbox-123", "a.b-c_d"]:
            valid, msg = validate.validate_sandbox_name(name)
            assert valid is True
            assert msg == ""

    def test_rejects_path_separators(self):
        for name in ["../x", "a/b", r"a\\b"]:
            valid, _ = validate.validate_sandbox_name(name)
            assert valid is False

    def test_rejects_whitespace(self):
        for name in ["has space", "tab\tname", "line\nname"]:
            valid, _ = validate.validate_sandbox_name(name)
            assert valid is False


class TestExistingSandboxNameValidation:
    """Tests for validate_existing_sandbox_name()."""

    def test_allows_legacy_name_with_space(self):
        valid, msg = validate.validate_existing_sandbox_name("legacy sandbox name")
        assert valid is True
        assert msg == ""

    def test_rejects_path_separators(self):
        for name in ["../x", "a/b", r"a\\b"]:
            valid, _ = validate.validate_existing_sandbox_name(name)
            assert valid is False

    def test_rejects_control_characters(self):
        for name in ["name\nx", "name\tx", "name\rx", "name\x7fx"]:
            valid, _ = validate.validate_existing_sandbox_name(name)
            assert valid is False


class TestGitUrlValidation:
    """Tests for validate_git_url()."""

    def test_empty_url_rejected(self):
        """Empty URL should be rejected."""
        valid, msg = validate.validate_git_url("")
        assert valid is False
        assert msg == "Repository URL required"

    def test_https_url_accepted(self):
        """HTTPS URLs should be accepted."""
        valid, msg = validate.validate_git_url("https://github.com/user/repo.git")
        assert valid is True
        assert msg == ""

    def test_http_url_accepted(self):
        """HTTP URLs should be accepted."""
        valid, msg = validate.validate_git_url("http://github.com/user/repo.git")
        assert valid is True
        assert msg == ""

    def test_git_ssh_url_accepted(self):
        """Git SSH URLs should be accepted."""
        valid, msg = validate.validate_git_url("git@github.com:user/repo.git")
        assert valid is True
        assert msg == ""

    def test_org_repo_shorthand_accepted(self):
        """Org/repo shorthand should be accepted (contains /)."""
        valid, msg = validate.validate_git_url("foundry-works/foundry-sandbox")
        assert valid is True
        assert msg == ""

    def test_invalid_url_rejected(self):
        """URLs without http/git@/slash should be rejected."""
        valid, msg = validate.validate_git_url("invalid-url")
        assert valid is False
        assert "Invalid repository URL" in msg
        assert "invalid-url" in msg

    def test_http_embedded_credentials_rejected(self):
        """HTTP URLs with embedded credentials should be rejected."""
        valid, msg = validate.validate_git_url("https://user:pass@github.com/repo")
        assert valid is False
        assert "embedded credentials" in msg

    def test_http_semicolon_in_host_rejected(self):
        """HTTP URLs with semicolons in netloc should be rejected."""
        valid, msg = validate.validate_git_url("http://evil.com;@legit.com/repo")
        assert valid is False

    def test_http_missing_host_rejected(self):
        """HTTP URLs without a host should be rejected."""
        valid, msg = validate.validate_git_url("https:///path")
        assert valid is False
        assert "missing host" in msg

    def test_http_missing_path_rejected(self):
        """HTTP URLs without a repo path should be rejected."""
        valid, msg = validate.validate_git_url("https://github.com")
        assert valid is False
        assert "missing path" in msg

    def test_ssh_empty_host_rejected(self):
        """SSH URLs with empty host should be rejected."""
        valid, msg = validate.validate_git_url("git@:path")
        assert valid is False
        assert "missing host" in msg

    def test_ssh_invalid_host_rejected(self):
        """SSH URLs with invalid host characters should be rejected."""
        valid, msg = validate.validate_git_url("git@host with spaces:repo")
        assert valid is False
        assert "invalid host" in msg

    def test_ssh_absolute_path_rejected(self):
        """SSH URLs with absolute paths after colon should be rejected."""
        valid, msg = validate.validate_git_url("git@github.com:/absolute/path")
        assert valid is False
        assert "absolute path" in msg

    def test_sensitive_path_etc_rejected(self):
        """Paths to /etc should be rejected."""
        valid, msg = validate.validate_git_url("/etc/passwd")
        assert valid is False
        assert "sensitive location" in msg

    def test_sensitive_path_proc_rejected(self):
        """Paths to /proc should be rejected."""
        valid, msg = validate.validate_git_url("/proc/self")
        assert valid is False
        assert "sensitive location" in msg

    def test_local_path_accepted(self):
        """Valid local paths should be accepted."""
        valid, msg = validate.validate_git_url("/home/user/repos/myrepo")
        assert valid is True

    def test_relative_path_accepted(self):
        """Relative paths should be accepted."""
        valid, msg = validate.validate_git_url("./my-repo")
        assert valid is True

    def test_path_traversal_rejected(self):
        """Path traversal attempts should be rejected."""
        valid, msg = validate.validate_git_url("https://example.com/../../etc/passwd")
        assert valid is False
        assert "path traversal" in msg


class TestSshModeValidation:
    """Tests for validate_ssh_mode()."""

    def test_valid_modes(self):
        """Valid SSH modes should be accepted."""
        for mode in ["init", "always", "disabled"]:
            valid, msg = validate.validate_ssh_mode(mode)
            assert valid is True
            assert msg == ""

    def test_invalid_mode(self):
        """Invalid SSH modes should be rejected."""
        valid, msg = validate.validate_ssh_mode("invalid")
        assert valid is False
        assert "Invalid SSH mode" in msg
        assert "invalid" in msg


class TestMountPathValidation:
    """Tests for validate_mount_path()."""

    def test_safe_path_accepted(self, tmp_path):
        """Safe paths should be accepted and return resolved canonical path."""
        valid, canonical = validate.validate_mount_path(str(tmp_path))
        assert valid is True
        # On success, the second element is the resolved canonical path
        assert canonical == str(Path(tmp_path).resolve())

    def test_ssh_dir_rejected(self):
        """~/.ssh directory should be rejected."""
        ssh_path = str(Path.home() / ".ssh")
        valid, msg = validate.validate_mount_path(ssh_path)
        assert valid is False
        assert "credential" in msg.lower() or "does not exist" in msg.lower()

    def test_aws_dir_rejected(self):
        """~/.aws directory should be rejected."""
        aws_path = str(Path.home() / ".aws")
        valid, msg = validate.validate_mount_path(aws_path)
        assert valid is False
        assert "credential" in msg.lower() or "does not exist" in msg.lower()

    def test_docker_sock_rejected(self):
        """Docker socket paths should be rejected."""
        for sock in ["/var/run/docker.sock", "/run/docker.sock"]:
            valid, msg = validate.validate_mount_path(sock)
            assert valid is False
            assert "credential" in msg.lower() or "does not exist" in msg.lower()

    def test_parent_of_dangerous_rejected(self, tmp_path):
        """Parent directory of dangerous path should be rejected."""
        # Create ~/.ssh-like structure under tmp_path to test parent detection
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        fake_ssh = fake_home / ".ssh"
        fake_ssh.mkdir()

        # Patch Path.home() and _dangerous_paths to use our test structure
        with patch("foundry_sandbox.validate.Path.home", return_value=fake_home):
            # Mounting the parent (fake_home) should be rejected as it would expose .ssh
            valid, msg = validate.validate_mount_path(str(fake_home))
            assert valid is False
            assert "expose credential directory" in msg.lower()

    def test_child_of_dangerous_rejected(self, tmp_path):
        """Child directory of dangerous path should be rejected."""
        # Create ~/.ssh-like structure
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        fake_ssh = fake_home / ".ssh"
        fake_ssh.mkdir()
        fake_ssh_subdir = fake_ssh / "keys"
        fake_ssh_subdir.mkdir()

        # Patch Path.home() and _dangerous_paths to use our test structure
        with patch("foundry_sandbox.validate.Path.home", return_value=fake_home):
            # Mounting a child of .ssh should be rejected
            valid, msg = validate.validate_mount_path(str(fake_ssh_subdir))
            assert valid is False
            assert "inside credential directory" in msg.lower()


class TestRequireCommand:
    """Tests for require_command()."""

    def test_existing_command(self):
        """Commands that exist should be found."""
        with patch("shutil.which", return_value="/usr/bin/git"):
            valid, msg = validate.require_command("git")
            assert valid is True
            assert msg == ""

    def test_missing_command(self):
        """Commands that don't exist should be reported missing."""
        with patch("shutil.which", return_value=None):
            valid, msg = validate.require_command("nonexistent-cmd")
            assert valid is False
            assert "Missing required command" in msg
            assert "nonexistent-cmd" in msg


class TestGitRemoteValidation:
    """Tests for validate_git_remotes()."""

    def test_clean_config(self, tmp_path):
        """Clean git config without credentials should pass."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        config = git_dir / "config"
        config.write_text(
            "[remote \"origin\"]\n"
            "    url = https://github.com/user/repo.git\n"
            "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
        )

        valid, msg = validate.validate_git_remotes(str(git_dir))
        assert valid is True
        assert msg == ""

    def test_embedded_credentials_detected(self, tmp_path):
        """Embedded credentials in git config should be detected."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        config = git_dir / "config"
        config.write_text(
            "[remote \"origin\"]\n"
            "    url = https://user:password@github.com/user/repo.git\n"
            "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
        )

        valid, msg = validate.validate_git_remotes(str(git_dir))
        assert valid is False
        assert "Embedded credentials detected" in msg
        assert "user:***@" in msg  # Password should be redacted

    def test_missing_config_is_clean(self, tmp_path):
        """Missing git config file should be considered clean."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        # Don't create config file

        valid, msg = validate.validate_git_remotes(str(git_dir))
        assert valid is True
        assert msg == ""

    def test_unreadable_config_is_clean(self, tmp_path):
        """Unreadable git config should be considered clean."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        config = git_dir / "config"
        config.write_text("content")

        # Mock OSError on read
        with patch.object(Path, "read_text", side_effect=OSError):
            valid, msg = validate.validate_git_remotes(str(git_dir))
            assert valid is True
            assert msg == ""


class TestCheckDockerRunning:
    """Tests for check_docker_running()."""

    def test_docker_running(self):
        """Docker running should return success."""
        mock_result = Mock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            valid, msg = validate.check_docker_running()
            assert valid is True
            assert msg == ""
            mock_run.assert_called_once()
            assert mock_run.call_args[0][0] == ["docker", "info"]

    def test_docker_not_running(self):
        """Docker not running should return error."""
        mock_result = Mock()
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            valid, msg = validate.check_docker_running()
            assert valid is False
            assert "Docker is not running" in msg

    def test_docker_command_fails(self):
        """Docker command error (OSError) should be handled."""
        with patch("subprocess.run", side_effect=OSError):
            valid, msg = validate.check_docker_running()
            assert valid is False
            assert "Docker is not running" in msg


# ============================================================================
# docker.py Tests
# ============================================================================


class TestSubnetGeneration:
    """Tests for generate_sandbox_subnet()."""

    def test_deterministic(self):
        """Same project name should produce same subnet."""
        subnet1, ip1 = docker.generate_sandbox_subnet("test-project")
        subnet2, ip2 = docker.generate_sandbox_subnet("test-project")

        assert subnet1 == subnet2
        assert ip1 == ip2

    def test_valid_range(self):
        """Generated subnets should be in valid 10.x.x.0/24 range."""
        for project in ["proj1", "proj2", "test", "sandbox", "a" * 50]:
            subnet, proxy_ip = docker.generate_sandbox_subnet(project)

            # Check subnet format
            assert subnet.startswith("10.")
            assert subnet.endswith(".0/24")

            # Extract bytes
            parts = subnet.replace("/24", "").split(".")
            assert len(parts) == 4
            byte1, byte2 = int(parts[1]), int(parts[2])

            # Check range (1-254)
            assert 1 <= byte1 <= 254
            assert 1 <= byte2 <= 254

            # Check proxy IP matches subnet
            assert proxy_ip == f"10.{byte1}.{byte2}.2"

    def test_different_projects_different_subnets(self):
        """Different project names should (usually) produce different subnets."""
        subnet1, _ = docker.generate_sandbox_subnet("project-alpha")
        subnet2, _ = docker.generate_sandbox_subnet("project-beta")

        # High probability they differ (hash collision unlikely)
        assert subnet1 != subnet2

    def test_zero_byte_handling(self):
        """Bytes that hash to 0 should be clamped to 1."""
        # We test by checking many projects - at least one should trigger the clamp
        subnets = [docker.generate_sandbox_subnet(f"p{i}")[0] for i in range(100)]

        for subnet in subnets:
            parts = subnet.replace("/24", "").split(".")
            byte1, byte2 = int(parts[1]), int(parts[2])
            assert byte1 >= 1
            assert byte2 >= 1

    def test_high_byte_handling(self):
        """Bytes that hash > 254 should be clamped to 254."""
        # Generate many subnets and verify all bytes are <= 254
        for i in range(100):
            subnet, _ = docker.generate_sandbox_subnet(f"test-{i}-{'x' * i}")
            parts = subnet.replace("/24", "").split(".")
            byte1, byte2 = int(parts[1]), int(parts[2])
            assert byte1 <= 254
            assert byte2 <= 254


class TestCredentialPlaceholders:
    """Tests for setup_credential_placeholders()."""

    def test_oauth_mode(self, monkeypatch):
        """OAuth token set should use per-sandbox random placeholder."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        # Mock Gemini settings file
        with patch.object(Path, "is_file", return_value=False):
            env = docker.setup_credential_placeholders().to_env_dict()

            assert env["SANDBOX_ANTHROPIC_API_KEY"] == ""
            assert env["SANDBOX_CLAUDE_OAUTH"].startswith("CRED_PROXY_")
            assert env["SANDBOX_GEMINI_API_KEY"].startswith("CRED_PROXY_")
            assert env["SANDBOX_ENABLE_TAVILY"] == "0"
            # Each placeholder should be unique
            assert env["SANDBOX_CLAUDE_OAUTH"] != env["SANDBOX_GEMINI_API_KEY"]

    def test_api_key_mode(self, monkeypatch):
        """No OAuth token should use per-sandbox random placeholder."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch.object(Path, "is_file", return_value=False):
            env = docker.setup_credential_placeholders().to_env_dict()

            assert env["SANDBOX_ANTHROPIC_API_KEY"].startswith("CRED_PROXY_")
            assert env["SANDBOX_CLAUDE_OAUTH"] == ""

    def test_opencode_enabled(self, monkeypatch):
        """OpenCode enabled should set per-sandbox random placeholder."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "1")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch.object(Path, "is_file", return_value=False):
            env = docker.setup_credential_placeholders().to_env_dict()

            assert env["SANDBOX_ZHIPU_API_KEY"].startswith("CRED_PROXY_")

    def test_opencode_disabled(self, monkeypatch):
        """OpenCode disabled should not set Zhipu placeholder."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        with patch.object(Path, "is_file", return_value=False):
            env = docker.setup_credential_placeholders().to_env_dict()

            assert env["SANDBOX_ZHIPU_API_KEY"] == ""

    def test_tavily_available(self, monkeypatch):
        """Tavily API key should enable Tavily flag."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch.object(Path, "is_file", return_value=False):
            env = docker.setup_credential_placeholders().to_env_dict()

            assert env["SANDBOX_ENABLE_TAVILY"] == "1"

    def test_gemini_oauth_mode(self, monkeypatch):
        """Gemini OAuth should not set API key placeholder."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch("foundry_sandbox.docker.Path.home") as mock_home:
            mock_home.return_value = Path("/fake/home")
            m = mock_open(read_data='{"selectedType": "oauth-personal"}')
            with patch("builtins.open", m):
                env = docker.setup_credential_placeholders().to_env_dict()
                assert env["SANDBOX_GEMINI_API_KEY"] == ""


class TestComposeCommand:
    """Tests for get_compose_command()."""

    def test_basic_command(self):
        """Basic compose command without isolation or override."""
        cmd = docker.get_compose_command()

        assert cmd[0] == "docker"
        assert cmd[1] == "compose"
        assert "-f" in cmd
        assert any("docker-compose.yml" in arg for arg in cmd)

    def test_with_credential_isolation(self):
        """Credential isolation should add isolation compose file."""
        cmd = docker.get_compose_command(isolate_credentials=True)

        assert "-f" in cmd
        assert any("docker-compose.yml" in arg for arg in cmd)
        assert any("credential-isolation.yml" in arg for arg in cmd)

    def test_with_override_file(self, tmp_path):
        """Override file should be included if it exists."""
        override = tmp_path / "override.yml"
        override.write_text("version: '3'")

        cmd = docker.get_compose_command(override_file=str(override))

        assert str(override) in cmd

    def test_nonexistent_override_ignored(self):
        """Non-existent override file should be ignored."""
        cmd = docker.get_compose_command(override_file="/nonexistent/file.yml")

        assert "/nonexistent/file.yml" not in cmd

    def test_all_options_combined(self, tmp_path):
        """All options should work together."""
        override = tmp_path / "override.yml"
        override.write_text("version: '3'")

        cmd = docker.get_compose_command(
            override_file=str(override),
            isolate_credentials=True
        )

        assert "docker" in cmd
        assert "compose" in cmd
        assert any("docker-compose.yml" in arg for arg in cmd)
        assert any("credential-isolation.yml" in arg for arg in cmd)
        assert str(override) in cmd


# ============================================================================
# api_keys.py Tests
# ============================================================================


class TestAiKeyDetection:
    """Tests for AI provider key detection."""

    def test_no_keys(self, monkeypatch):
        """No AI keys should return False."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        assert api_keys.check_any_ai_key() is False
        assert api_keys.has_claude_key() is False

    def test_oauth_only(self, monkeypatch):
        """OAuth token only should be detected."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        assert api_keys.check_any_ai_key() is True
        assert api_keys.has_claude_key() is True

    def test_api_key_only(self, monkeypatch):
        """API key only should be detected."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        assert api_keys.check_any_ai_key() is True
        assert api_keys.has_claude_key() is True

    def test_both_present(self, monkeypatch):
        """Both OAuth and API key should be detected."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        assert api_keys.check_any_ai_key() is True
        assert api_keys.has_claude_key() is True


class TestGeminiKey:
    """Tests for Gemini key detection."""

    def test_oauth_file_detected(self, monkeypatch, tmp_path):
        """Gemini OAuth credentials file should be detected."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

        # Create a fake home with Gemini OAuth file
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        gemini_dir = fake_home / ".gemini"
        gemini_dir.mkdir()
        oauth_file = gemini_dir / "oauth_creds.json"
        oauth_file.write_text("{}")

        with patch("foundry_sandbox.api_keys.Path.home", return_value=fake_home):
            assert api_keys.has_gemini_key() is True

    def test_api_key_detected(self, monkeypatch):
        """Gemini API key env var should be detected."""
        monkeypatch.setenv("GEMINI_API_KEY", "real-api-key")

        with patch.object(Path, "is_file", return_value=False):
            assert api_keys.has_gemini_key() is True

    def test_placeholder_rejected(self, monkeypatch):
        """Placeholder API key should be rejected."""
        monkeypatch.setenv("GEMINI_API_KEY", "CREDENTIAL_PROXY_PLACEHOLDER")

        with patch.object(Path, "is_file", return_value=False):
            assert api_keys.has_gemini_key() is False

    def test_no_gemini_key(self, monkeypatch):
        """No Gemini credentials should return False."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)

        with patch.object(Path, "is_file", return_value=False):
            assert api_keys.has_gemini_key() is False


class TestOpencodeKey:
    """Tests for OpenCode key detection."""

    def test_auth_file_exists(self, tmp_path):
        """OpenCode auth file existence should be detected."""
        # Create a fake home with OpenCode auth file
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        opencode_dir = fake_home / ".local" / "share" / "opencode"
        opencode_dir.mkdir(parents=True)
        auth_file = opencode_dir / "auth.json"
        auth_file.write_text("{}")

        with patch("foundry_sandbox.api_keys.Path.home", return_value=fake_home):
            assert api_keys.has_opencode_key() is True

    def test_auth_file_missing(self):
        """Missing OpenCode auth file should return False."""
        with patch.object(Path, "is_file", return_value=False):
            assert api_keys.has_opencode_key() is False

    def test_opencode_enabled_check(self, monkeypatch):
        """opencode_enabled() should check both env var and auth file."""
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "1")

        with patch("foundry_sandbox.api_keys.has_opencode_key", return_value=True):
            assert api_keys.opencode_enabled() is True

        with patch("foundry_sandbox.api_keys.has_opencode_key", return_value=False):
            assert api_keys.opencode_enabled() is False

    def test_opencode_disabled_env(self, monkeypatch):
        """opencode_enabled() should return False if env var is 0."""
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch("foundry_sandbox.api_keys.has_opencode_key", return_value=True):
            assert api_keys.opencode_enabled() is False


class TestCodexKey:
    """Tests for Codex key detection."""

    def test_auth_file_detected(self, tmp_path):
        """Codex auth file should be detected."""
        # Create a fake home with Codex auth file
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        codex_dir = fake_home / ".codex"
        codex_dir.mkdir()
        auth_file = codex_dir / "auth.json"
        auth_file.write_text("{}")

        with patch("foundry_sandbox.api_keys.Path.home", return_value=fake_home):
            assert api_keys.has_codex_key() is True

    def test_openai_api_key_detected(self, monkeypatch):
        """OPENAI_API_KEY env var should be detected."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")

        with patch.object(Path, "is_file", return_value=False):
            assert api_keys.has_codex_key() is True

    def test_no_codex_key(self, monkeypatch):
        """No Codex credentials should return False."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        with patch.object(Path, "is_file", return_value=False):
            assert api_keys.has_codex_key() is False


class TestZaiKey:
    """Tests for ZAI/Zhipu key detection."""

    def test_real_key_detected(self, monkeypatch):
        """Real ZHIPU_API_KEY should be detected."""
        monkeypatch.setenv("ZHIPU_API_KEY", "real-api-key-12345")

        assert api_keys.has_zai_key() is True

    def test_placeholder_rejected(self, monkeypatch):
        """CREDENTIAL_PROXY_PLACEHOLDER should be rejected."""
        monkeypatch.setenv("ZHIPU_API_KEY", "CREDENTIAL_PROXY_PLACEHOLDER")

        assert api_keys.has_zai_key() is False

    def test_proxy_placeholder_rejected(self, monkeypatch):
        """PROXY_PLACEHOLDER_OPENCODE should be rejected."""
        monkeypatch.setenv("ZHIPU_API_KEY", "PROXY_PLACEHOLDER_OPENCODE")

        assert api_keys.has_zai_key() is False

    def test_empty_key_rejected(self, monkeypatch):
        """Empty ZHIPU_API_KEY should return False."""
        monkeypatch.setenv("ZHIPU_API_KEY", "")

        assert api_keys.has_zai_key() is False

    def test_no_key_rejected(self, monkeypatch):
        """Missing ZHIPU_API_KEY should return False."""
        monkeypatch.delenv("ZHIPU_API_KEY", raising=False)

        assert api_keys.has_zai_key() is False


class TestSearchKeyDetection:
    """Tests for search provider key detection."""

    def test_tavily_only(self, monkeypatch):
        """Tavily key only should be detected."""
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        assert api_keys.check_any_search_key() is True

    def test_perplexity_only(self, monkeypatch):
        """Perplexity key only should be detected."""
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.setenv("PERPLEXITY_API_KEY", "test-key")

        assert api_keys.check_any_search_key() is True

    def test_both_search_keys(self, monkeypatch):
        """Both search keys should be detected."""
        monkeypatch.setenv("TAVILY_API_KEY", "test-key-1")
        monkeypatch.setenv("PERPLEXITY_API_KEY", "test-key-2")

        assert api_keys.check_any_search_key() is True

    def test_no_search_keys(self, monkeypatch):
        """No search keys should return False."""
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        assert api_keys.check_any_search_key() is False


class TestAuthConflict:
    """Tests for Claude auth conflict detection."""

    def test_no_conflict_oauth_only(self, monkeypatch):
        """OAuth only should not produce conflict warning."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        assert api_keys.warn_claude_auth_conflict() == ""

    def test_no_conflict_api_key_only(self, monkeypatch):
        """API key only should not produce conflict warning."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        assert api_keys.warn_claude_auth_conflict() == ""

    def test_conflict_detected(self, monkeypatch):
        """Both OAuth and API key should produce conflict warning."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        warning = api_keys.warn_claude_auth_conflict()
        assert warning != ""
        assert "Both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY" in warning


class TestClaudeKeyRequired:
    """Tests for check_claude_key_required()."""

    def test_no_claude_key_error(self, monkeypatch):
        """Missing Claude key should return error."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        has_key, msg = api_keys.check_claude_key_required()
        assert has_key is False
        assert "Error: Claude Code requires authentication" in msg

    def test_claude_key_present_no_conflict(self, monkeypatch):
        """Claude key present without conflict should succeed."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        has_key, msg = api_keys.check_claude_key_required()
        assert has_key is True
        assert msg == ""

    def test_claude_key_present_with_conflict(self, monkeypatch):
        """Claude key present with conflict should return warning."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        has_key, msg = api_keys.check_claude_key_required()
        assert has_key is True
        assert "Both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY" in msg


class TestApiKeysStatus:
    """Tests for check_api_keys_status()."""

    def test_full_status_structure(self, monkeypatch):
        """check_api_keys_status should return complete status dict."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        status = api_keys.check_api_keys_status()

        assert isinstance(status, dict)
        assert "has_ai_key" in status
        assert "has_search_key" in status
        assert "conflict_warning" in status
        assert "missing_warning" in status
        assert "can_proceed" in status

        assert status["has_ai_key"] is True
        assert status["has_search_key"] is True
        assert status["conflict_warning"] == ""
        assert status["can_proceed"] is True

    def test_missing_keys_status(self, monkeypatch):
        """Missing keys should be reflected in status."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        status = api_keys.check_api_keys_status()

        assert status["has_ai_key"] is False
        assert status["has_search_key"] is False
        assert status["can_proceed"] is False
        assert status["missing_warning"] != ""

    def test_conflict_in_status(self, monkeypatch):
        """Conflict should be included in status."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        status = api_keys.check_api_keys_status()

        assert status["has_ai_key"] is True
        assert status["conflict_warning"] != ""


class TestCliStatus:
    """Tests for get_cli_status()."""

    def test_cli_status_format(self, monkeypatch):
        """get_cli_status should return list of status strings."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        with patch.object(Path, "is_file", return_value=False):
            with patch("shutil.which", return_value=None):
                status_lines = api_keys.get_cli_status()

                assert isinstance(status_lines, list)
                assert len(status_lines) > 0
                assert any("Claude" in line for line in status_lines)
                assert any("GitHub CLI" in line for line in status_lines)
                assert any("Gemini" in line for line in status_lines)
                assert any("Codex" in line for line in status_lines)
                assert any("Search" in line for line in status_lines)

    def test_github_cli_configured(self, monkeypatch):
        """GitHub CLI configured should be detected."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        mock_result = Mock()
        mock_result.returncode = 0

        with patch.object(Path, "is_file", return_value=False):
            with patch("shutil.which", return_value="/usr/bin/gh"):
                with patch("subprocess.run", return_value=mock_result):
                    status_lines = api_keys.get_cli_status()

                    gh_line = [line for line in status_lines if "GitHub CLI" in line][0]
                    assert "configured" in gh_line

    def test_github_cli_not_configured(self, monkeypatch):
        """GitHub CLI not configured should be detected."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")

        with patch.object(Path, "is_file", return_value=False):
            with patch("shutil.which", return_value=None):
                status_lines = api_keys.get_cli_status()

                gh_line = [line for line in status_lines if "GitHub CLI" in line][0]
                assert "not configured" in gh_line


class TestGithubTokenExport:
    """Tests for export_gh_token()."""

    def test_existing_env_var(self, monkeypatch):
        """Existing GITHUB_TOKEN should be returned."""
        monkeypatch.setenv("GITHUB_TOKEN", "test-token-123")

        token = api_keys.export_gh_token()
        assert token == "test-token-123"

    def test_gh_token_env_var(self, monkeypatch):
        """Existing GH_TOKEN should be returned."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GH_TOKEN", "test-gh-token")

        token = api_keys.export_gh_token()
        assert token == "test-gh-token"

    def test_gh_cli_extraction(self, monkeypatch):
        """Token should be extracted from gh CLI."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)

        mock_status = Mock()
        mock_status.returncode = 0

        mock_token = Mock()
        mock_token.stdout = "extracted-token-456\n"

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run", side_effect=[mock_status, mock_token]):
                token = api_keys.export_gh_token()
                assert token == "extracted-token-456"

    def test_gh_not_available(self, monkeypatch):
        """Empty string should be returned if gh is not available."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)

        with patch("shutil.which", return_value=None):
            token = api_keys.export_gh_token()
            assert token == ""

    def test_gh_not_authenticated(self, monkeypatch):
        """Empty string should be returned if gh is not authenticated."""
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)

        mock_status = Mock()
        mock_status.returncode = 1

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run", return_value=mock_status):
                token = api_keys.export_gh_token()
                assert token == ""


class TestMissingKeysWarning:
    """Tests for get_missing_keys_warning()."""

    def test_all_keys_present(self, monkeypatch):
        """No warning should be returned if all keys present."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        warning = api_keys.get_missing_keys_warning()
        assert warning == ""

    def test_missing_ai_key(self, monkeypatch):
        """Warning should mention missing AI key."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        warning = api_keys.get_missing_keys_warning()
        assert "Claude authentication not found" in warning

    def test_missing_search_key(self, monkeypatch):
        """Warning should mention missing search key."""
        monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "test-token")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        warning = api_keys.get_missing_keys_warning()
        assert "No search provider API keys found" in warning

    def test_missing_both(self, monkeypatch):
        """Warning should mention both missing keys."""
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)

        warning = api_keys.get_missing_keys_warning()
        assert "Claude authentication not found" in warning
        assert "No search provider API keys found" in warning


class TestOptionalCliWarnings:
    """Tests for get_optional_cli_warnings()."""

    def test_all_configured(self, monkeypatch):
        """No warnings if all optional CLIs are configured."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch.object(Path, "is_file", return_value=True):
            warnings = api_keys.get_optional_cli_warnings()
            assert len(warnings) == 0

    def test_gemini_not_configured(self, monkeypatch):
        """Warning should be returned for Gemini."""
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch.object(Path, "is_file", return_value=False):
            warnings = api_keys.get_optional_cli_warnings()
            assert any("Gemini" in w for w in warnings)

    def test_codex_not_configured(self, monkeypatch):
        """Warning should be returned for Codex."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "0")

        with patch.object(Path, "is_file", return_value=False):
            warnings = api_keys.get_optional_cli_warnings()
            assert any("Codex" in w for w in warnings)

    def test_opencode_enabled_not_configured(self, monkeypatch):
        """Warning should be returned for OpenCode if enabled but not configured."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("SANDBOX_ENABLE_OPENCODE", "1")

        with patch.object(Path, "is_file", return_value=False):
            warnings = api_keys.get_optional_cli_warnings()
            assert any("OpenCode" in w for w in warnings)
