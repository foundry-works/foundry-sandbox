"""Unit tests for foundry_sandbox/user_services.py (CLI-side config loader).

Tests: config file resolution, YAML parsing, service entry validation,
default values, error handling, and search order logging.
"""
from __future__ import annotations

import pytest
import yaml

from foundry_sandbox.user_services import (
    UserService,
    UserServiceConfigError,
    find_user_services_path,
    load_user_services,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_yaml(tmp_path):
    """Write a minimal valid user-services.yaml and return its path."""
    content = {
        "version": "1",
        "services": [
            {
                "name": "OpenRouter",
                "env_var": "OPENROUTER_API_KEY",
                "domain": "openrouter.ai",
                "header": "Authorization",
                "format": "bearer",
            }
        ],
    }
    path = tmp_path / "user-services.yaml"
    path.write_text(yaml.dump(content))
    return str(path)


@pytest.fixture
def multi_service_yaml(tmp_path):
    """Write a YAML with multiple services including optional fields."""
    content = {
        "version": "1",
        "services": [
            {
                "name": "OpenRouter",
                "env_var": "OPENROUTER_API_KEY",
                "domain": "openrouter.ai",
                "header": "Authorization",
                "format": "bearer",
                "methods": ["GET", "POST"],
                "paths": ["/api/**"],
            },
            {
                "name": "CustomService",
                "env_var": "CUSTOM_API_KEY",
                "domain": "api.custom.example",
                "header": "X-Api-Key",
                "format": "value",
            },
        ],
    }
    path = tmp_path / "user-services.yaml"
    path.write_text(yaml.dump(content))
    return str(path)


# ---------------------------------------------------------------------------
# find_user_services_path
# ---------------------------------------------------------------------------


class TestFindUserServicesPath:
    """Tests for find_user_services_path() search order."""

    def test_env_var_takes_priority(self, valid_yaml, monkeypatch):
        """FOUNDRY_USER_SERVICES_PATH env var is used first."""
        monkeypatch.setenv("FOUNDRY_USER_SERVICES_PATH", valid_yaml)
        assert find_user_services_path() == valid_yaml

    def test_env_var_nonexistent_returns_none(self, monkeypatch):
        """Nonexistent FOUNDRY_USER_SERVICES_PATH returns None."""
        monkeypatch.setenv("FOUNDRY_USER_SERVICES_PATH", "/nonexistent/file.yaml")
        assert find_user_services_path() is None

    def test_default_path_found(self, tmp_path, monkeypatch):
        """config/user-services.yaml relative to project root is found when no env var set."""
        monkeypatch.delenv("FOUNDRY_USER_SERVICES_PATH", raising=False)
        # Create config/user-services.yaml under a fake project root
        project_root = tmp_path / "project"
        project_root.mkdir()
        config_dir = project_root / "config"
        config_dir.mkdir()
        cfg_file = config_dir / "user-services.yaml"
        cfg_file.write_text(yaml.dump({"version": "1", "services": []}))
        # Simulate __file__ being at project_root/foundry_sandbox/user_services.py
        fake_file = project_root / "foundry_sandbox" / "user_services.py"
        fake_file.parent.mkdir(parents=True, exist_ok=True)
        fake_file.touch()
        import foundry_sandbox.user_services as _mod
        monkeypatch.setattr(_mod, "__file__", str(fake_file))
        result = find_user_services_path()
        assert result is not None
        assert result.endswith("user-services.yaml")

    def test_no_file_returns_none(self, tmp_path, monkeypatch):
        """Returns None when no config file exists."""
        monkeypatch.delenv("FOUNDRY_USER_SERVICES_PATH", raising=False)
        # Point __file__ to a temp dir with no config/
        fake_file = tmp_path / "foundry_sandbox" / "user_services.py"
        fake_file.parent.mkdir(parents=True, exist_ok=True)
        fake_file.touch()
        import foundry_sandbox.user_services as _mod
        monkeypatch.setattr(_mod, "__file__", str(fake_file))
        assert find_user_services_path() is None


# ---------------------------------------------------------------------------
# load_user_services — happy paths
# ---------------------------------------------------------------------------


class TestLoadUserServicesValid:
    """Tests for load_user_services() with valid configuration."""

    def test_loads_single_service(self, valid_yaml):
        """Single valid service entry loads correctly."""
        services = load_user_services(path=valid_yaml)
        assert len(services) == 1
        svc = services[0]
        assert svc.name == "OpenRouter"
        assert svc.env_var == "OPENROUTER_API_KEY"
        assert svc.domain == "openrouter.ai"
        assert svc.header == "Authorization"
        assert svc.format == "bearer"

    def test_loads_multiple_services(self, multi_service_yaml):
        """Multiple service entries load correctly."""
        services = load_user_services(path=multi_service_yaml)
        assert len(services) == 2
        assert services[0].name == "OpenRouter"
        assert services[1].name == "CustomService"

    def test_custom_methods_and_paths(self, multi_service_yaml):
        """Custom methods and paths are loaded from YAML."""
        services = load_user_services(path=multi_service_yaml)
        svc = services[0]
        assert svc.methods == ["GET", "POST"]
        assert svc.paths == ["/api/**"]

    def test_default_methods(self, valid_yaml):
        """Default methods are all 7 HTTP methods when omitted."""
        services = load_user_services(path=valid_yaml)
        expected = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        assert services[0].methods == expected

    def test_default_paths(self, valid_yaml):
        """Default paths is ['/**'] when omitted."""
        services = load_user_services(path=valid_yaml)
        assert services[0].paths == ["/**"]

    def test_value_format(self, multi_service_yaml):
        """Value format service loads correctly."""
        services = load_user_services(path=multi_service_yaml)
        custom = services[1]
        assert custom.format == "value"
        assert custom.header == "X-Api-Key"

    def test_no_file_returns_empty_list(self, monkeypatch, tmp_path):
        """Returns empty list when no config file is found."""
        monkeypatch.delenv("FOUNDRY_USER_SERVICES_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        services = load_user_services()
        assert services == []

    def test_explicit_none_path_uses_search(self, monkeypatch, tmp_path):
        """Passing path=None triggers find_user_services_path()."""
        monkeypatch.delenv("FOUNDRY_USER_SERVICES_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        assert load_user_services(path=None) == []

    def test_methods_case_insensitive(self, tmp_path):
        """Methods are uppercased regardless of input case."""
        content = {
            "version": "1",
            "services": [
                {
                    "name": "Svc",
                    "env_var": "SVC_KEY",
                    "domain": "svc.example",
                    "header": "Authorization",
                    "format": "bearer",
                    "methods": ["get", "Post"],
                }
            ],
        }
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump(content))
        services = load_user_services(path=str(path))
        assert services[0].methods == ["GET", "POST"]


# ---------------------------------------------------------------------------
# load_user_services — validation errors
# ---------------------------------------------------------------------------


class TestLoadUserServicesValidation:
    """Tests for load_user_services() validation and error handling."""

    def _write_yaml(self, tmp_path, data):
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump(data))
        return str(path)

    def test_missing_services_key(self, tmp_path):
        """Raises UserServiceConfigError when 'services' key is missing."""
        path = self._write_yaml(tmp_path, {"version": "1"})
        with pytest.raises(UserServiceConfigError, match="Missing 'services' key"):
            load_user_services(path=path)

    def test_services_not_a_list(self, tmp_path):
        """Raises when 'services' is not a list."""
        path = self._write_yaml(tmp_path, {"version": "1", "services": "not-a-list"})
        with pytest.raises(UserServiceConfigError, match="must be a list"):
            load_user_services(path=path)

    def test_service_entry_not_a_dict(self, tmp_path):
        """Raises when a service entry is not a mapping."""
        path = self._write_yaml(tmp_path, {"version": "1", "services": ["not-a-dict"]})
        with pytest.raises(UserServiceConfigError, match="must be a mapping"):
            load_user_services(path=path)

    def test_missing_required_field_name(self, tmp_path):
        """Raises when 'name' field is missing."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="missing required field 'name'"):
            load_user_services(path=path)

    def test_missing_required_field_env_var(self, tmp_path):
        """Raises when 'env_var' field is missing."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="missing required field 'env_var'"):
            load_user_services(path=path)

    def test_invalid_env_var_lowercase(self, tmp_path):
        """Raises when env_var contains lowercase letters."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "lowercase_key",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="env_var.*must match"):
            load_user_services(path=path)

    def test_invalid_env_var_starts_with_digit(self, tmp_path):
        """Raises when env_var starts with a digit."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "1INVALID",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="env_var.*must match"):
            load_user_services(path=path)

    def test_valid_env_var_with_underscore_prefix(self, tmp_path):
        """Env var starting with underscore is valid."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "_MY_KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
            }],
        })
        services = load_user_services(path=path)
        assert services[0].env_var == "_MY_KEY"

    def test_empty_domain(self, tmp_path):
        """Raises when domain is empty."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="domain.*cannot be empty"):
            load_user_services(path=path)

    def test_domain_with_scheme_rejected(self, tmp_path):
        """Raises when domain contains a scheme prefix."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "https://openrouter.ai",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="bare hostname"):
            load_user_services(path=path)

    def test_domain_with_path_rejected(self, tmp_path):
        """Raises when domain contains a path component."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "openrouter.ai/api",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="bare hostname"):
            load_user_services(path=path)

    def test_domain_with_whitespace_rejected(self, tmp_path):
        """Raises when domain contains whitespace."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "open router.ai",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="bare hostname"):
            load_user_services(path=path)

    def test_empty_header(self, tmp_path):
        """Raises when header is empty."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="header.*cannot be empty"):
            load_user_services(path=path)

    def test_invalid_format(self, tmp_path):
        """Raises when format is not 'bearer' or 'value'."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "token",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="format.*must be 'bearer' or 'value'"):
            load_user_services(path=path)

    def test_invalid_http_method(self, tmp_path):
        """Raises when methods list contains an invalid HTTP method."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
                "methods": ["GET", "INVALID"],
            }],
        })
        with pytest.raises(UserServiceConfigError, match="invalid HTTP method"):
            load_user_services(path=path)

    def test_empty_methods_list(self, tmp_path):
        """Raises when methods is an empty list."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
                "methods": [],
            }],
        })
        with pytest.raises(UserServiceConfigError, match="methods.*must be a non-empty list"):
            load_user_services(path=path)

    def test_empty_paths_list(self, tmp_path):
        """Raises when paths is an empty list."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
                "paths": [],
            }],
        })
        with pytest.raises(UserServiceConfigError, match="paths.*must be a non-empty list"):
            load_user_services(path=path)

    def test_empty_path_entry(self, tmp_path):
        """Raises when a path entry is an empty string."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
                "paths": ["/api/**", ""],
            }],
        })
        with pytest.raises(UserServiceConfigError, match="path entries cannot be empty"):
            load_user_services(path=path)

    def test_malformed_yaml(self, tmp_path):
        """Raises on invalid YAML syntax."""
        path = tmp_path / "user-services.yaml"
        path.write_text("{{invalid yaml")
        with pytest.raises(UserServiceConfigError, match="Failed to parse"):
            load_user_services(path=str(path))

    def test_yaml_not_a_dict(self, tmp_path):
        """Raises when YAML root is not a dict."""
        path = tmp_path / "user-services.yaml"
        path.write_text("- just a list")
        with pytest.raises(UserServiceConfigError, match="Expected YAML dict"):
            load_user_services(path=str(path))

    def test_file_not_readable(self, tmp_path):
        """Raises when file cannot be read."""
        path = tmp_path / "user-services.yaml"
        path.write_text("version: '1'")
        path.chmod(0o000)
        try:
            with pytest.raises(UserServiceConfigError, match="Failed to read"):
                load_user_services(path=str(path))
        finally:
            path.chmod(0o644)

    def test_empty_name(self, tmp_path):
        """Raises when name is empty."""
        path = self._write_yaml(tmp_path, {
            "version": "1",
            "services": [{
                "name": "",
                "env_var": "KEY",
                "domain": "d.com",
                "header": "H",
                "format": "bearer",
            }],
        })
        with pytest.raises(UserServiceConfigError, match="name.*cannot be empty"):
            load_user_services(path=path)


# ---------------------------------------------------------------------------
# UserService dataclass
# ---------------------------------------------------------------------------


class TestUserServiceDataclass:
    """Tests for UserService dataclass defaults and construction."""

    def test_default_methods(self):
        """Default methods list includes all 7 HTTP methods."""
        svc = UserService(
            name="Svc", env_var="KEY", domain="d.com",
            header="H", format="bearer",
        )
        expected = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        assert svc.methods == expected

    def test_default_paths(self):
        """Default paths is ['/**']."""
        svc = UserService(
            name="Svc", env_var="KEY", domain="d.com",
            header="H", format="bearer",
        )
        assert svc.paths == ["/**"]

    def test_custom_construction(self):
        """Full custom construction works."""
        svc = UserService(
            name="Svc",
            env_var="MY_KEY",
            domain="api.example.com",
            header="X-Api-Key",
            format="value",
            methods=["GET"],
            paths=["/v1/**"],
        )
        assert svc.name == "Svc"
        assert svc.methods == ["GET"]
        assert svc.paths == ["/v1/**"]

    def test_defaults_are_independent_copies(self):
        """Each instance gets its own copy of default lists."""
        svc1 = UserService(
            name="A", env_var="A", domain="a.com",
            header="H", format="bearer",
        )
        svc2 = UserService(
            name="B", env_var="B", domain="b.com",
            header="H", format="bearer",
        )
        svc1.methods.append("EXTRA")
        assert "EXTRA" not in svc2.methods


# ---------------------------------------------------------------------------
# Schema consistency between CLI-side and proxy-side loaders
# ---------------------------------------------------------------------------


class TestSchemaConsistency:
    """Ensure foundry_sandbox.user_services and unified-proxy/user_services stay in sync."""

    def test_env_var_regex_matches(self):
        """_ENV_VAR_RE pattern is identical in both modules."""
        from foundry_sandbox.user_services import _ENV_VAR_RE as cli_re
        import user_services as proxy_mod

        assert cli_re.pattern == proxy_mod._ENV_VAR_RE.pattern

    def test_domain_regex_matches(self):
        """_DOMAIN_RE pattern is identical in both modules."""
        from foundry_sandbox.user_services import _DOMAIN_RE as cli_re
        import user_services as proxy_mod

        assert cli_re.pattern == proxy_mod._DOMAIN_RE.pattern

    def test_valid_http_methods_match(self):
        """_VALID_HTTP_METHODS is identical in both modules."""
        from foundry_sandbox.user_services import _VALID_HTTP_METHODS as cli_methods
        import user_services as proxy_mod

        assert cli_methods == proxy_mod._VALID_HTTP_METHODS

    def test_default_methods_match(self):
        """_DEFAULT_METHODS is identical in both modules."""
        from foundry_sandbox.user_services import _DEFAULT_METHODS as cli_defaults
        import user_services as proxy_mod

        assert cli_defaults == proxy_mod._DEFAULT_METHODS

    def test_default_paths_match(self):
        """_DEFAULT_PATHS is identical in both modules."""
        from foundry_sandbox.user_services import _DEFAULT_PATHS as cli_paths
        import user_services as proxy_mod

        assert cli_paths == proxy_mod._DEFAULT_PATHS

    def test_dataclass_fields_match(self):
        """UserService and ProxyUserService have the same field names."""
        import dataclasses

        from foundry_sandbox.user_services import UserService
        import user_services as proxy_mod

        cli_names = [f.name for f in dataclasses.fields(UserService)]
        proxy_names = [f.name for f in dataclasses.fields(proxy_mod.ProxyUserService)]
        assert cli_names == proxy_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
