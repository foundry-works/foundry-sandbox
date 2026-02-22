"""Unit tests for unified-proxy/user_services.py (proxy-side config loader).

Tests: YAML loading, default path, validation, error handling with logging,
and ProxyUserService dataclass behavior.

Proxy-side loader is lenient: returns empty list on errors instead of raising.
"""
from __future__ import annotations

import logging

import pytest
import yaml

from user_services import (
    ProxyUserService,
    load_proxy_user_services,
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
    """Write a YAML with two services."""
    content = {
        "version": "1",
        "services": [
            {
                "name": "ServiceA",
                "env_var": "SVC_A_KEY",
                "domain": "a.example.com",
                "header": "Authorization",
                "format": "bearer",
                "methods": ["GET", "POST"],
                "paths": ["/api/**"],
            },
            {
                "name": "ServiceB",
                "env_var": "SVC_B_KEY",
                "domain": "b.example.com",
                "header": "X-Api-Key",
                "format": "value",
            },
        ],
    }
    path = tmp_path / "user-services.yaml"
    path.write_text(yaml.dump(content))
    return str(path)


# ---------------------------------------------------------------------------
# load_proxy_user_services — happy paths
# ---------------------------------------------------------------------------


class TestLoadProxyUserServicesValid:
    """Tests for load_proxy_user_services() with valid configuration."""

    def test_loads_single_service(self, valid_yaml):
        services = load_proxy_user_services(path=valid_yaml)
        assert len(services) == 1
        svc = services[0]
        assert svc.name == "OpenRouter"
        assert svc.env_var == "OPENROUTER_API_KEY"
        assert svc.domain == "openrouter.ai"
        assert svc.header == "Authorization"
        assert svc.format == "bearer"

    def test_loads_multiple_services(self, multi_service_yaml):
        services = load_proxy_user_services(path=multi_service_yaml)
        assert len(services) == 2
        assert services[0].name == "ServiceA"
        assert services[1].name == "ServiceB"

    def test_custom_methods_and_paths(self, multi_service_yaml):
        services = load_proxy_user_services(path=multi_service_yaml)
        assert services[0].methods == ["GET", "POST"]
        assert services[0].paths == ["/api/**"]

    def test_default_methods(self, valid_yaml):
        services = load_proxy_user_services(path=valid_yaml)
        expected = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        assert services[0].methods == expected

    def test_default_paths(self, valid_yaml):
        services = load_proxy_user_services(path=valid_yaml)
        assert services[0].paths == ["/**"]

    def test_methods_case_insensitive(self, tmp_path):
        content = {
            "version": "1",
            "services": [{
                "name": "Svc",
                "env_var": "SVC_KEY",
                "domain": "svc.example",
                "header": "Authorization",
                "format": "bearer",
                "methods": ["get", "Post"],
            }],
        }
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump(content))
        services = load_proxy_user_services(path=str(path))
        assert services[0].methods == ["GET", "POST"]


# ---------------------------------------------------------------------------
# load_proxy_user_services — graceful error handling
# ---------------------------------------------------------------------------


class TestLoadProxyUserServicesErrors:
    """Proxy loader returns empty list on errors (no exceptions)."""

    def test_file_not_found_returns_empty(self, caplog):
        """Missing file returns empty list and logs info."""
        with caplog.at_level(logging.INFO, logger="user_services"):
            result = load_proxy_user_services(path="/nonexistent/file.yaml")
        assert result == []
        assert any("no config" in r.message for r in caplog.records)

    def test_malformed_yaml_returns_empty(self, tmp_path, caplog):
        """Invalid YAML returns empty list and logs warning."""
        path = tmp_path / "user-services.yaml"
        path.write_text("{{invalid yaml")
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=str(path))
        assert result == []
        assert any("failed to read" in r.message for r in caplog.records)

    def test_yaml_not_dict_returns_empty(self, tmp_path, caplog):
        """YAML root that is not a dict returns empty list."""
        path = tmp_path / "user-services.yaml"
        path.write_text("- just a list")
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=str(path))
        assert result == []
        assert any("expected dict" in r.message for r in caplog.records)

    def test_missing_services_key_returns_empty(self, tmp_path, caplog):
        """Missing 'services' key returns empty list."""
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump({"version": "1"}))
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=str(path))
        assert result == []
        assert any("missing or invalid 'services' key" in r.message for r in caplog.records)

    def test_services_not_list_returns_empty(self, tmp_path, caplog):
        """Non-list 'services' value returns empty list."""
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump({"version": "1", "services": "bad"}))
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=str(path))
        assert result == []

    def test_invalid_entry_skipped_with_warning(self, tmp_path, caplog):
        """Invalid entry is skipped; valid entries still loaded."""
        content = {
            "version": "1",
            "services": [
                {"name": "Bad"},  # Missing required fields
                {
                    "name": "Good",
                    "env_var": "GOOD_KEY",
                    "domain": "good.example",
                    "header": "Authorization",
                    "format": "bearer",
                },
            ],
        }
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump(content))
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=str(path))
        assert len(result) == 1
        assert result[0].name == "Good"
        assert any("missing" in r.message for r in caplog.records)

    def test_entry_not_a_dict_skipped(self, tmp_path, caplog):
        """Non-dict entry is skipped with warning."""
        content = {
            "version": "1",
            "services": ["not-a-dict"],
        }
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump(content))
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=str(path))
        assert result == []
        assert any("must be a mapping" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Validation edge cases
# ---------------------------------------------------------------------------


class TestProxyLoaderValidation:
    """Per-entry validation in the proxy loader."""

    def _write_service(self, tmp_path, service_dict):
        content = {"version": "1", "services": [service_dict]}
        path = tmp_path / "user-services.yaml"
        path.write_text(yaml.dump(content))
        return str(path)

    def test_domain_with_scheme_skipped(self, tmp_path, caplog):
        """Domain with scheme prefix is skipped."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "https://openrouter.ai",
            "header": "H",
            "format": "bearer",
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("invalid domain" in r.message for r in caplog.records)

    def test_domain_with_path_skipped(self, tmp_path, caplog):
        """Domain with path component is skipped."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "openrouter.ai/api",
            "header": "H",
            "format": "bearer",
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("invalid domain" in r.message for r in caplog.records)

    def test_invalid_env_var_skipped(self, tmp_path, caplog):
        """Invalid env_var format skips entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "lowercase",
            "domain": "d.com",
            "header": "H",
            "format": "bearer",
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("invalid env_var" in r.message for r in caplog.records)

    def test_invalid_format_skipped(self, tmp_path, caplog):
        """Invalid format skips entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "d.com",
            "header": "H",
            "format": "token",
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("format must be" in r.message for r in caplog.records)

    def test_empty_required_field_skipped(self, tmp_path, caplog):
        """Empty required field (domain) skips entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "",
            "header": "H",
            "format": "bearer",
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("empty required field" in r.message for r in caplog.records)

    def test_invalid_method_skipped(self, tmp_path, caplog):
        """Invalid HTTP method in methods list skips entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "d.com",
            "header": "H",
            "format": "bearer",
            "methods": ["GET", "INVALID"],
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("invalid method" in r.message for r in caplog.records)

    def test_empty_methods_list_skipped(self, tmp_path, caplog):
        """Empty methods list skips entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "d.com",
            "header": "H",
            "format": "bearer",
            "methods": [],
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []

    def test_empty_paths_list_skipped(self, tmp_path, caplog):
        """Empty paths list skips entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "d.com",
            "header": "H",
            "format": "bearer",
            "paths": [],
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []

    def test_empty_path_entry_skipped(self, tmp_path, caplog):
        """Empty path entry in list skips the entire service entry."""
        path = self._write_service(tmp_path, {
            "name": "Svc",
            "env_var": "KEY",
            "domain": "d.com",
            "header": "H",
            "format": "bearer",
            "paths": ["/api/**", ""],
        })
        with caplog.at_level(logging.WARNING, logger="user_services"):
            result = load_proxy_user_services(path=path)
        assert result == []
        assert any("empty path" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# ProxyUserService dataclass
# ---------------------------------------------------------------------------


class TestProxyUserServiceDataclass:
    """Tests for ProxyUserService dataclass."""

    def test_default_methods(self):
        svc = ProxyUserService(
            name="Svc", env_var="KEY", domain="d.com",
            header="H", format="bearer",
        )
        expected = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        assert svc.methods == expected

    def test_default_paths(self):
        svc = ProxyUserService(
            name="Svc", env_var="KEY", domain="d.com",
            header="H", format="bearer",
        )
        assert svc.paths == ["/**"]

    def test_defaults_are_independent_copies(self):
        """Each instance gets independent default lists."""
        svc1 = ProxyUserService(
            name="A", env_var="A", domain="a.com",
            header="H", format="bearer",
        )
        svc2 = ProxyUserService(
            name="B", env_var="B", domain="b.com",
            header="H", format="bearer",
        )
        svc1.methods.append("EXTRA")
        assert "EXTRA" not in svc2.methods


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
