"""Integration tests for user-defined services across all modules.

Tests: CredentialPlaceholders.to_env_dict(), placeholder generation in docker.py,
compose override generation, api_keys status, credential_injector provider_map,
domain conflict detection, MITM domain extension, and allowlist synthesis.
"""
from __future__ import annotations

import logging
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
import yaml

from tests.mocks import MockHeaders


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user_services_yaml(tmp_path, services):
    """Write a user-services.yaml and return its path string."""
    content = {"version": "1", "services": services}
    path = tmp_path / "user-services.yaml"
    path.write_text(yaml.dump(content))
    return str(path)


OPENROUTER_SERVICE = {
    "name": "OpenRouter",
    "env_var": "OPENROUTER_API_KEY",
    "domain": "openrouter.ai",
    "header": "Authorization",
    "format": "bearer",
}

CUSTOM_SERVICE = {
    "name": "CustomService",
    "env_var": "CUSTOM_API_KEY",
    "domain": "api.custom.example",
    "header": "X-Api-Key",
    "format": "value",
}


# ---------------------------------------------------------------------------
# CredentialPlaceholders.to_env_dict — user_service_placeholders
# ---------------------------------------------------------------------------


class TestCredentialPlaceholdersUserServices:
    """to_env_dict() emits SANDBOX_{env_var} entries from user_service_placeholders."""

    def test_user_service_placeholders_in_env_dict(self):
        from foundry_sandbox.models import CredentialPlaceholders

        creds = CredentialPlaceholders(
            user_service_placeholders={
                "OPENROUTER_API_KEY": "CRED_PROXY_abc123",
                "CUSTOM_API_KEY": "CRED_PROXY_def456",
            }
        )
        env = creds.to_env_dict()
        assert env["SANDBOX_OPENROUTER_API_KEY"] == "CRED_PROXY_abc123"
        assert env["SANDBOX_CUSTOM_API_KEY"] == "CRED_PROXY_def456"

    def test_empty_user_service_placeholders(self):
        from foundry_sandbox.models import CredentialPlaceholders

        creds = CredentialPlaceholders()
        env = creds.to_env_dict()
        # Should have standard keys but no extra user service keys
        assert "SANDBOX_ANTHROPIC_API_KEY" in env
        assert len([k for k in env if k.startswith("SANDBOX_OPENROUTER")]) == 0

    def test_user_service_placeholders_coexist_with_standard(self):
        from foundry_sandbox.models import CredentialPlaceholders

        creds = CredentialPlaceholders(
            sandbox_anthropic_api_key="CRED_PROXY_std",
            user_service_placeholders={"MY_KEY": "CRED_PROXY_user"},
        )
        env = creds.to_env_dict()
        assert env["SANDBOX_ANTHROPIC_API_KEY"] == "CRED_PROXY_std"
        assert env["SANDBOX_MY_KEY"] == "CRED_PROXY_user"

    def test_model_dump_includes_user_service_placeholders(self):
        from foundry_sandbox.models import CredentialPlaceholders

        creds = CredentialPlaceholders(
            user_service_placeholders={"KEY_A": "CRED_PROXY_a"},
        )
        data = creds.model_dump()
        assert data["user_service_placeholders"] == {"KEY_A": "CRED_PROXY_a"}

    def test_json_roundtrip_with_user_service_placeholders(self):
        from foundry_sandbox.models import CredentialPlaceholders

        creds = CredentialPlaceholders(
            user_service_placeholders={"KEY_A": "CRED_PROXY_a"},
        )
        json_str = creds.model_dump_json()
        restored = CredentialPlaceholders.model_validate_json(json_str)
        assert restored.user_service_placeholders == {"KEY_A": "CRED_PROXY_a"}


# ---------------------------------------------------------------------------
# setup_credential_placeholders — user services
# ---------------------------------------------------------------------------


class TestSetupCredentialPlaceholdersUserServices:
    """Placeholder generation for user-defined services in docker.py."""

    @patch("foundry_sandbox.user_services.load_user_services")
    def test_generates_placeholder_when_env_set(self, mock_load, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.docker import setup_credential_placeholders

        mock_load.return_value = [
            UserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            )
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", "real-key-123")
        # Ensure Claude auth is present
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

        creds = setup_credential_placeholders()
        assert "OPENROUTER_API_KEY" in creds.user_service_placeholders
        placeholder = creds.user_service_placeholders["OPENROUTER_API_KEY"]
        assert placeholder.startswith("CRED_PROXY_")
        assert len(placeholder) > len("CRED_PROXY_")

    @patch("foundry_sandbox.user_services.load_user_services")
    def test_no_placeholder_when_env_not_set(self, mock_load, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.docker import setup_credential_placeholders

        mock_load.return_value = [
            UserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            )
        ]
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

        creds = setup_credential_placeholders()
        assert "OPENROUTER_API_KEY" not in creds.user_service_placeholders

    @patch("foundry_sandbox.user_services.load_user_services")
    def test_multiple_services_generate_unique_placeholders(self, mock_load, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.docker import setup_credential_placeholders

        mock_load.return_value = [
            UserService(
                name="A", env_var="KEY_A",
                domain="a.com", header="Authorization", format="bearer",
            ),
            UserService(
                name="B", env_var="KEY_B",
                domain="b.com", header="X-Api-Key", format="value",
            ),
        ]
        monkeypatch.setenv("KEY_A", "real-a")
        monkeypatch.setenv("KEY_B", "real-b")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

        creds = setup_credential_placeholders()
        assert len(creds.user_service_placeholders) == 2
        # Placeholders should be unique
        values = list(creds.user_service_placeholders.values())
        assert values[0] != values[1]

    @patch("foundry_sandbox.user_services.load_user_services")
    def test_placeholder_never_contains_real_key(self, mock_load, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.docker import setup_credential_placeholders

        real_key = "sk-or-real-secret-key-12345"
        mock_load.return_value = [
            UserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            )
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", real_key)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)

        creds = setup_credential_placeholders()
        placeholder = creds.user_service_placeholders["OPENROUTER_API_KEY"]
        assert real_key not in placeholder


# ---------------------------------------------------------------------------
# _prepare_user_services_override
# ---------------------------------------------------------------------------


class TestPrepareUserServicesOverride:
    """Compose override generation for user services."""

    def test_returns_none_when_no_isolation(self):
        from foundry_sandbox.docker import _prepare_user_services_override

        result_path, result_extras = _prepare_user_services_override(
            isolate_credentials=False, compose_extras=None,
        )
        assert result_path is None

    @patch("foundry_sandbox.user_services.load_user_services", return_value=[])
    def test_returns_none_when_no_services(self, mock_load):
        from foundry_sandbox.docker import _prepare_user_services_override

        result_path, result_extras = _prepare_user_services_override(
            isolate_credentials=True, compose_extras=None,
        )
        assert result_path is None

    @patch("foundry_sandbox.user_services.find_user_services_path")
    @patch("foundry_sandbox.user_services.load_user_services")
    def test_creates_override_with_mount_and_env(self, mock_load, mock_find, tmp_path, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.docker import _prepare_user_services_override

        config_path = str(tmp_path / "user-services.yaml")
        (tmp_path / "user-services.yaml").write_text("version: '1'\nservices: []")
        mock_find.return_value = config_path
        mock_load.return_value = [
            UserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            ),
        ]
        # Host env var must be set for dev container env to be generated
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")

        try:
            result_path, result_extras = _prepare_user_services_override(
                isolate_credentials=True, compose_extras=None,
            )
            assert result_path is not None
            assert os.path.isfile(result_path)

            # Parse the generated override YAML
            with open(result_path) as f:
                override = yaml.safe_load(f)

            # Verify mount
            proxy_volumes = override["services"]["unified-proxy"]["volumes"]
            assert any("/etc/unified-proxy/user-services.yaml:ro" in v for v in proxy_volumes)

            # Verify proxy env
            proxy_env = override["services"]["unified-proxy"]["environment"]
            assert "OPENROUTER_API_KEY" in proxy_env

            # Verify dev env — only present when host env var is set
            dev_env = override["services"]["dev"]["environment"]
            assert any("OPENROUTER_API_KEY" in e for e in dev_env)
            assert any("${SANDBOX_OPENROUTER_API_KEY}" in e for e in dev_env)

            # Verify compose_extras updated
            assert result_extras is not None
            assert result_path in result_extras
        finally:
            if result_path and os.path.exists(result_path):
                os.unlink(result_path)

    @patch("foundry_sandbox.user_services.find_user_services_path")
    @patch("foundry_sandbox.user_services.load_user_services")
    def test_override_appended_to_existing_extras(self, mock_load, mock_find, tmp_path):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.docker import _prepare_user_services_override

        config_path = str(tmp_path / "user-services.yaml")
        (tmp_path / "user-services.yaml").write_text("version: '1'\nservices: []")
        mock_find.return_value = config_path
        mock_load.return_value = [
            UserService(
                name="Svc", env_var="SVC_KEY",
                domain="svc.example", header="H", format="bearer",
            ),
        ]

        existing = ["/some/existing/extra.yml"]
        try:
            result_path, result_extras = _prepare_user_services_override(
                isolate_credentials=True, compose_extras=list(existing),
            )
            assert result_extras is not None
            assert "/some/existing/extra.yml" in result_extras
            assert result_path in result_extras
            assert len(result_extras) == 2
        finally:
            if result_path and os.path.exists(result_path):
                os.unlink(result_path)

    @patch("foundry_sandbox.user_services.load_user_services", return_value=[])
    def test_returns_none_when_no_config_file(self, mock_load):
        """No config file → load_user_services returns [] → no override."""
        from foundry_sandbox.docker import _prepare_user_services_override

        result_path, result_extras = _prepare_user_services_override(
            isolate_credentials=True, compose_extras=None,
        )
        assert result_path is None


# ---------------------------------------------------------------------------
# get_cli_status — user services
# ---------------------------------------------------------------------------


class TestGetCliStatusUserServices:
    """api_keys.get_cli_status() includes user-defined service status."""

    @patch("foundry_sandbox.user_services.load_user_services")
    def test_configured_service_shown(self, mock_load, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.api_keys import get_cli_status

        mock_load.return_value = [
            UserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            ),
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", "real-key")

        lines = get_cli_status()
        assert any("OpenRouter: configured" in line for line in lines)

    @patch("foundry_sandbox.user_services.load_user_services")
    def test_unconfigured_service_shown(self, mock_load, monkeypatch):
        from foundry_sandbox.user_services import UserService
        from foundry_sandbox.api_keys import get_cli_status

        mock_load.return_value = [
            UserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            ),
        ]
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

        lines = get_cli_status()
        assert any("OpenRouter: not configured" in line for line in lines)

    @patch("foundry_sandbox.user_services.load_user_services", side_effect=Exception("bad config"))
    def test_malformed_config_does_not_break_status(self, mock_load):
        from foundry_sandbox.api_keys import get_cli_status

        # Should not raise — gracefully handles config errors
        lines = get_cli_status()
        assert any("Claude" in line for line in lines)  # Standard lines still present


# ---------------------------------------------------------------------------
# CredentialInjector — _load_user_services / provider_map
# ---------------------------------------------------------------------------


class TestCredentialInjectorUserServices:
    """Credential injector loads user services into instance provider_map."""

    def _make_proxy_service(self, name, env_var, domain, header, fmt):
        from user_services import ProxyUserService
        return ProxyUserService(
            name=name, env_var=env_var, domain=domain,
            header=header, format=fmt,
        )

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_user_service_added_to_provider_map(self, mock_load, monkeypatch):
        from addons.credential_injector import CredentialInjector

        mock_load.return_value = [
            self._make_proxy_service(
                "OpenRouter", "OPENROUTER_API_KEY",
                "openrouter.ai", "Authorization", "bearer",
            ),
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", "real-key")

        injector = CredentialInjector()
        assert "openrouter.ai" in injector.provider_map
        config = injector.provider_map["openrouter.ai"]
        assert config["header"] == "Authorization"
        assert config["env_var"] == "OPENROUTER_API_KEY"
        assert config["format"] == "bearer"

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_instance_provider_map_does_not_mutate_module_level(self, mock_load, monkeypatch):
        from addons.credential_injector import CredentialInjector, PROVIDER_MAP

        mock_load.return_value = [
            self._make_proxy_service(
                "OpenRouter", "OPENROUTER_API_KEY",
                "openrouter.ai", "Authorization", "bearer",
            ),
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", "real-key")

        injector = CredentialInjector()
        # Instance map has the user service
        assert "openrouter.ai" in injector.provider_map
        # Module-level PROVIDER_MAP does NOT have it
        assert "openrouter.ai" not in PROVIDER_MAP

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_builtin_domain_conflict_skipped(self, mock_load, caplog):
        """User service with domain matching a built-in provider is skipped."""
        from addons.credential_injector import CredentialInjector, PROVIDER_MAP

        conflicting_domain = "api.openai.com"
        assert conflicting_domain in PROVIDER_MAP

        mock_load.return_value = [
            self._make_proxy_service(
                "ConflictSvc", "CONFLICT_KEY",
                conflicting_domain, "Authorization", "bearer",
            ),
        ]

        with caplog.at_level(logging.WARNING):
            injector = CredentialInjector()

        # Should still have the built-in config, not the user one
        assert injector.provider_map[conflicting_domain]["env_var"] == PROVIDER_MAP[conflicting_domain]["env_var"]
        assert any("conflicts with built-in" in r.message for r in caplog.records)

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_user_service_credential_loaded_into_cache(self, mock_load, monkeypatch):
        """Credentials for user services are loaded into credentials_cache."""
        from addons.credential_injector import CredentialInjector

        mock_load.return_value = [
            self._make_proxy_service(
                "OpenRouter", "OPENROUTER_API_KEY",
                "openrouter.ai", "Authorization", "bearer",
            ),
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test123")

        injector = CredentialInjector()
        assert "openrouter.ai" in injector.credentials_cache
        assert injector.credentials_cache["openrouter.ai"]["value"] == "Bearer sk-or-test123"
        assert injector.credentials_cache["openrouter.ai"]["header"] == "Authorization"

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_value_format_credential_no_bearer_prefix(self, mock_load, monkeypatch):
        """Value-format credentials are cached without Bearer prefix."""
        from addons.credential_injector import CredentialInjector

        mock_load.return_value = [
            self._make_proxy_service(
                "Custom", "CUSTOM_KEY",
                "api.custom.example", "X-Api-Key", "value",
            ),
        ]
        monkeypatch.setenv("CUSTOM_KEY", "raw-key-123")

        injector = CredentialInjector()
        assert "api.custom.example" in injector.credentials_cache
        assert injector.credentials_cache["api.custom.example"]["value"] == "raw-key-123"

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_user_service_without_env_var_not_cached(self, mock_load, monkeypatch):
        """User service whose env var is not set does not get cached."""
        from addons.credential_injector import CredentialInjector

        mock_load.return_value = [
            self._make_proxy_service(
                "Unconfigured", "MISSING_KEY",
                "unconfigured.example", "Authorization", "bearer",
            ),
        ]
        monkeypatch.delenv("MISSING_KEY", raising=False)

        injector = CredentialInjector()
        assert "unconfigured.example" not in injector.credentials_cache

    @patch("addons.credential_injector.load_proxy_user_services")
    def test_request_injects_user_service_credential(self, mock_load, monkeypatch):
        """Request to user service domain gets credential injected."""
        from addons.credential_injector import CredentialInjector

        mock_load.return_value = [
            self._make_proxy_service(
                "OpenRouter", "OPENROUTER_API_KEY",
                "openrouter.ai", "Authorization", "bearer",
            ),
        ]
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-real-key")

        injector = CredentialInjector()

        # Build mock flow
        flow = MagicMock()
        flow.request.host = "openrouter.ai"
        flow.request.path = "/api/v1/chat/completions"
        flow.request.headers = MockHeaders({})
        flow.response = None
        flow.metadata = {}

        injector.request(flow)
        assert flow.request.headers.get("Authorization") == "Bearer sk-or-real-key"


# ---------------------------------------------------------------------------
# generate_squid_config — _load_user_mitm_domains
# ---------------------------------------------------------------------------


class TestSquidConfigUserMitmDomains:
    """MITM domain extension with user-defined services."""

    @patch("generate_squid_config.load_proxy_user_services")
    @patch("generate_squid_config.load_allowlist_config")
    def test_user_domains_added_to_mitm_list(self, mock_allowlist, mock_load):
        from generate_squid_config import generate_squid_config
        from user_services import ProxyUserService

        mock_load.return_value = [
            ProxyUserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            ),
        ]
        mock_config = MagicMock()
        mock_config.domains = ["api.github.com"]
        mock_allowlist.return_value = mock_config

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_squid_config(output_dir=tmpdir)

            with open(os.path.join(tmpdir, "mitm_domains.txt")) as f:
                mitm_domains = f.read().splitlines()

            assert "openrouter.ai" in mitm_domains

    @patch("generate_squid_config.load_proxy_user_services")
    @patch("generate_squid_config.load_allowlist_config")
    def test_user_mitm_domains_also_in_allowed_list(self, mock_allowlist, mock_load):
        from generate_squid_config import generate_squid_config
        from user_services import ProxyUserService

        mock_load.return_value = [
            ProxyUserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            ),
        ]
        mock_config = MagicMock()
        mock_config.domains = []
        mock_allowlist.return_value = mock_config

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_squid_config(output_dir=tmpdir)

            with open(os.path.join(tmpdir, "allowed_domains.txt")) as f:
                allowed_domains = f.read().splitlines()

            assert "openrouter.ai" in allowed_domains

    @patch("generate_squid_config.load_proxy_user_services", return_value=[])
    @patch("generate_squid_config.load_allowlist_config")
    def test_no_user_services_no_extra_mitm(self, mock_allowlist, mock_load):
        from generate_squid_config import generate_squid_config

        mock_config = MagicMock()
        mock_config.domains = []
        mock_allowlist.return_value = mock_config

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_squid_config(output_dir=tmpdir)

            with open(os.path.join(tmpdir, "mitm_domains.txt")) as f:
                mitm_domains = f.read().splitlines()

            # Only built-in MITM domains should be present
            assert len(mitm_domains) == len(set(mitm_domains))  # No dupes

    @patch("generate_squid_config.load_proxy_user_services")
    @patch("generate_squid_config.load_allowlist_config")
    def test_user_domain_deduplicated_with_builtin(self, mock_allowlist, mock_load):
        """User domain that matches a built-in MITM domain is deduplicated."""
        from generate_squid_config import generate_squid_config, MITM_DOMAINS
        from user_services import ProxyUserService

        # Pick a domain that's already in MITM_DOMAINS
        existing_domain = MITM_DOMAINS[0]
        mock_load.return_value = [
            ProxyUserService(
                name="Conflict", env_var="CONFLICT_KEY",
                domain=existing_domain, header="H", format="bearer",
            ),
        ]
        mock_config = MagicMock()
        mock_config.domains = []
        mock_allowlist.return_value = mock_config

        with tempfile.TemporaryDirectory() as tmpdir:
            generate_squid_config(output_dir=tmpdir)

            with open(os.path.join(tmpdir, "mitm_domains.txt")) as f:
                mitm_domains = f.read().splitlines()

            # Domain should only appear once (deduplication)
            assert mitm_domains.count(existing_domain) == 1


# ---------------------------------------------------------------------------
# config.py — _synthesize_allowlist_from_user_services
# ---------------------------------------------------------------------------


class TestSynthesizeAllowlistFromUserServices:
    """Allowlist synthesis from user-defined services."""

    def test_empty_services_returns_none(self):
        from config import _synthesize_allowlist_from_user_services

        result = _synthesize_allowlist_from_user_services([])
        assert result is None

    def test_single_service_creates_domain_and_endpoint(self):
        from config import _synthesize_allowlist_from_user_services
        from user_services import ProxyUserService

        services = [
            ProxyUserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
                methods=["GET", "POST"], paths=["/api/**"],
            ),
        ]
        result = _synthesize_allowlist_from_user_services(services)
        assert result is not None
        assert "openrouter.ai" in result.domains
        assert len(result.http_endpoints) == 1
        ep = result.http_endpoints[0]
        assert ep.host == "openrouter.ai"
        assert ep.methods == ["GET", "POST"]
        assert ep.paths == ["/api/**"]

    def test_multiple_services(self):
        from config import _synthesize_allowlist_from_user_services
        from user_services import ProxyUserService

        services = [
            ProxyUserService(
                name="A", env_var="A_KEY", domain="a.example.com",
                header="H", format="bearer",
            ),
            ProxyUserService(
                name="B", env_var="B_KEY", domain="b.example.com",
                header="X-Key", format="value",
                methods=["POST"], paths=["/v1/**"],
            ),
        ]
        result = _synthesize_allowlist_from_user_services(services)
        assert result is not None
        assert len(result.domains) == 2
        assert "a.example.com" in result.domains
        assert "b.example.com" in result.domains
        assert len(result.http_endpoints) == 2

    def test_default_methods_and_paths_in_endpoint(self):
        from config import _synthesize_allowlist_from_user_services
        from user_services import ProxyUserService

        services = [
            ProxyUserService(
                name="Svc", env_var="KEY", domain="svc.example",
                header="H", format="bearer",
            ),
        ]
        result = _synthesize_allowlist_from_user_services(services)
        ep = result.http_endpoints[0]
        expected_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        assert ep.methods == expected_methods
        assert ep.paths == ["/**"]

    def test_partial_config_bypasses_validation(self):
        """Synthesized config uses _partial() and doesn't trigger __post_init__ validation."""
        from config import _synthesize_allowlist_from_user_services, AllowlistConfig
        from user_services import ProxyUserService

        # A config with a single domain and endpoint should work via _partial
        # even though AllowlistConfig.__post_init__ requires non-empty domains/endpoints
        services = [
            ProxyUserService(
                name="Svc", env_var="KEY", domain="svc.example",
                header="H", format="bearer",
            ),
        ]
        result = _synthesize_allowlist_from_user_services(services)
        # Should not raise — _partial() bypasses __post_init__
        assert isinstance(result, AllowlistConfig)
        assert result.version == "1"


# ---------------------------------------------------------------------------
# load_allowlist_config — user services merge integration
# ---------------------------------------------------------------------------


class TestLoadAllowlistConfigUserServicesMerge:
    """User services are merged into the loaded allowlist config."""

    @patch("config.load_proxy_user_services")
    @patch("config._load_yaml_file")
    def test_user_services_merged_into_config(self, mock_yaml, mock_user_svc, monkeypatch):
        from config import load_allowlist_config
        from user_services import ProxyUserService

        # Mock base config YAML
        mock_yaml.return_value = {
            "version": "1",
            "domains": ["api.github.com"],
            "http_endpoints": [{
                "host": "api.github.com",
                "methods": ["GET", "POST"],
                "paths": ["/**"],
            }],
        }
        # Mock user services
        mock_user_svc.return_value = [
            ProxyUserService(
                name="OpenRouter", env_var="OPENROUTER_API_KEY",
                domain="openrouter.ai", header="Authorization", format="bearer",
            ),
        ]
        monkeypatch.delenv("PROXY_ALLOWLIST_EXTRA_PATH", raising=False)

        config = load_allowlist_config(path="/fake/allowlist.yaml", extra_path="")
        assert "openrouter.ai" in config.domains

    @patch("config.load_proxy_user_services", return_value=[])
    @patch("config._load_yaml_file")
    def test_no_user_services_config_unchanged(self, mock_yaml, mock_user_svc, monkeypatch):
        from config import load_allowlist_config

        mock_yaml.return_value = {
            "version": "1",
            "domains": ["api.github.com"],
            "http_endpoints": [{
                "host": "api.github.com",
                "methods": ["GET"],
                "paths": ["/**"],
            }],
        }
        monkeypatch.delenv("PROXY_ALLOWLIST_EXTRA_PATH", raising=False)

        config = load_allowlist_config(path="/fake/allowlist.yaml", extra_path="")
        assert config.domains == ["api.github.com"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
