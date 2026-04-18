"""Unit tests for allowlist merge logic.

Tests merge_allowlist_configs(), _parse_extra_allowlist(), and the extra_path
parameter on load_allowlist_config().
"""

import os
import tempfile

import pytest
import yaml

from config import (
    AllowlistConfig,
    BlockedPathConfig,
    ConfigError,
    HttpEndpointConfig,
    load_allowlist_config,
    merge_allowlist_configs,
)


def _write_yaml(data: dict) -> str:
    """Write data to a temporary YAML file and return the path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    yaml.dump(data, f)
    f.close()
    return f.name


def _base_yaml() -> dict:
    return {
        "version": "1.0",
        "domains": ["api.github.com", "example.com"],
        "http_endpoints": [
            {
                "host": "api.github.com",
                "methods": ["GET", "POST"],
                "paths": ["/repos", "/users"],
            }
        ],
    }


def _base_config() -> AllowlistConfig:
    return AllowlistConfig(
        version="1.0",
        domains=["api.github.com", "example.com"],
        http_endpoints=[
            HttpEndpointConfig(
                host="api.github.com",
                methods=["GET", "POST"],
                paths=["/repos", "/users"],
            )
        ],
    )


def _extra_config(
    domains=None, http_endpoints=None, blocked_paths=None
) -> AllowlistConfig:
    """Build a partial AllowlistConfig bypassing __post_init__."""
    cfg = object.__new__(AllowlistConfig)
    cfg.version = "2.0"
    cfg.domains = domains or []
    cfg.http_endpoints = http_endpoints or []
    cfg.blocked_paths = blocked_paths or []
    return cfg


class TestMergeAllowlistConfigs:
    def test_valid_merge_produces_combined_config(self):
        base = _base_config()
        extra = _extra_config(
            domains=["new.com"],
            http_endpoints=[
                HttpEndpointConfig(
                    host="new-api.com", methods=["GET"], paths=["/data"]
                )
            ],
        )
        result = merge_allowlist_configs(base, extra)

        assert result.version == "1.0"
        assert result.domains == ["api.github.com", "example.com", "new.com"]
        assert len(result.http_endpoints) == 2
        assert result.http_endpoints[1].host == "new-api.com"

    def test_domain_dedup_preserves_base_ordering(self):
        base = AllowlistConfig(
            version="1.0",
            domains=["a.com", "b.com", "c.com"],
            http_endpoints=[
                HttpEndpointConfig(host="a.com", methods=["GET"], paths=["/"])
            ],
        )
        extra = _extra_config(domains=["d.com", "b.com", "e.com"])
        result = merge_allowlist_configs(base, extra)
        assert result.domains == ["a.com", "b.com", "c.com", "d.com", "e.com"]

    def test_duplicate_domain_in_extra_not_repeated(self):
        base = _base_config()
        extra = _extra_config(domains=["api.github.com", "example.com"])
        result = merge_allowlist_configs(base, extra)
        assert result.domains == ["api.github.com", "example.com"]

    def test_same_host_endpoint_union_merges_methods_and_paths(self):
        base = _base_config()
        extra = _extra_config(
            http_endpoints=[
                HttpEndpointConfig(
                    host="api.github.com",
                    methods=["post", "PUT"],
                    paths=["/repos", "/orgs"],
                )
            ]
        )
        result = merge_allowlist_configs(base, extra)

        gh_ep = [
            ep for ep in result.http_endpoints if ep.host == "api.github.com"
        ][0]
        assert gh_ep.methods == ["GET", "POST", "PUT"]
        assert gh_ep.paths == ["/repos", "/users", "/orgs"]

    def test_blocked_path_append_ordering(self):
        base = AllowlistConfig(
            version="1.0",
            domains=["a.com"],
            http_endpoints=[
                HttpEndpointConfig(host="a.com", methods=["GET"], paths=["/"])
            ],
            blocked_paths=[
                BlockedPathConfig(host="a.com", patterns=["/admin/*"])
            ],
        )
        extra = _extra_config(
            blocked_paths=[
                BlockedPathConfig(host="b.com", patterns=["/secret/*"])
            ]
        )
        result = merge_allowlist_configs(base, extra)

        assert len(result.blocked_paths) == 2
        assert result.blocked_paths[0].host == "a.com"
        assert result.blocked_paths[1].host == "b.com"

    def test_same_host_blocked_paths_appended_not_merged(self):
        base = AllowlistConfig(
            version="1.0",
            domains=["a.com"],
            http_endpoints=[
                HttpEndpointConfig(host="a.com", methods=["GET"], paths=["/"])
            ],
            blocked_paths=[
                BlockedPathConfig(host="a.com", patterns=["/admin/*"])
            ],
        )
        extra = _extra_config(
            blocked_paths=[
                BlockedPathConfig(host="a.com", patterns=["/secret/*"])
            ]
        )
        result = merge_allowlist_configs(base, extra)

        assert len(result.blocked_paths) == 2
        assert result.blocked_paths[0].host == "a.com"
        assert result.blocked_paths[0].patterns == ["/admin/*"]
        assert result.blocked_paths[1].host == "a.com"
        assert result.blocked_paths[1].patterns == ["/secret/*"]

    def test_version_mismatch_uses_base_version(self):
        base = _base_config()
        extra = _extra_config(domains=["new.com"])
        extra.version = "99.0"
        result = merge_allowlist_configs(base, extra)
        assert result.version == "1.0"


class TestLoadAllowlistConfigExtraPath:
    def test_missing_extra_file_raises_config_error(self):
        base_path = _write_yaml(_base_yaml())
        try:
            with pytest.raises(ConfigError):
                load_allowlist_config(
                    path=base_path, extra_path="/nonexistent/extra.yaml"
                )
        finally:
            os.unlink(base_path)

    def test_invalid_extra_schema_raises_config_error(self):
        base_path = _write_yaml(_base_yaml())
        extra_path = _write_yaml({"version": "1.0", "http_endpoints": "bad"})
        try:
            with pytest.raises(ConfigError):
                load_allowlist_config(path=base_path, extra_path=extra_path)
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)

    def test_extra_file_with_only_http_endpoints_is_valid(self):
        base_path = _write_yaml(_base_yaml())
        extra_path = _write_yaml(
            {
                "version": "2.0",
                "http_endpoints": [
                    {"host": "new.com", "methods": ["GET"], "paths": ["/api"]}
                ],
            }
        )
        try:
            result = load_allowlist_config(
                path=base_path, extra_path=extra_path
            )
            assert len(result.http_endpoints) == 2
            assert result.http_endpoints[1].host == "new.com"
            assert result.domains == ["api.github.com", "example.com"]
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)

    def test_explicit_extra_path_overrides_env_var(self, monkeypatch):
        base_path = _write_yaml(_base_yaml())
        env_extra_path = _write_yaml(
            {"version": "2.0", "domains": ["env.com"]}
        )
        arg_extra_path = _write_yaml(
            {"version": "2.0", "domains": ["arg.com"]}
        )
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", env_extra_path)
        try:
            result = load_allowlist_config(
                path=base_path, extra_path=arg_extra_path
            )
            assert "arg.com" in result.domains
            assert "env.com" not in result.domains
        finally:
            os.unlink(base_path)
            os.unlink(env_extra_path)
            os.unlink(arg_extra_path)

    def test_env_var_fallback_when_extra_path_is_none(self, monkeypatch):
        base_path = _write_yaml(_base_yaml())
        env_extra_path = _write_yaml(
            {"version": "2.0", "domains": ["env.com"]}
        )
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", env_extra_path)
        try:
            result = load_allowlist_config(path=base_path, extra_path=None)
            assert "env.com" in result.domains
        finally:
            os.unlink(base_path)
            os.unlink(env_extra_path)

    def test_explicit_empty_string_extra_path_means_no_extra(
        self, monkeypatch
    ):
        base_path = _write_yaml(_base_yaml())
        env_extra_path = _write_yaml(
            {"version": "2.0", "domains": ["env.com"]}
        )
        monkeypatch.setenv("PROXY_ALLOWLIST_EXTRA_PATH", env_extra_path)
        try:
            result = load_allowlist_config(path=base_path, extra_path="")
            assert result.domains == ["api.github.com", "example.com"]
            assert "env.com" not in result.domains
        finally:
            os.unlink(base_path)
            os.unlink(env_extra_path)

    def test_extra_file_missing_version_raises_config_error(self):
        base_path = _write_yaml(_base_yaml())
        extra_path = _write_yaml({"domains": ["extra.com"]})
        try:
            with pytest.raises(ConfigError, match="version"):
                load_allowlist_config(path=base_path, extra_path=extra_path)
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)

    def test_extra_file_malformed_yaml_raises_config_error(self):
        base_path = _write_yaml(_base_yaml())
        # Write raw invalid YAML content
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        f.write(": :\n  - :\n    bad: [unterminated")
        f.close()
        extra_path = f.name
        try:
            with pytest.raises(ConfigError):
                load_allowlist_config(path=base_path, extra_path=extra_path)
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)

    def test_extra_file_version_only_is_valid(self):
        base_path = _write_yaml(_base_yaml())
        extra_path = _write_yaml({"version": "2.0"})
        try:
            result = load_allowlist_config(
                path=base_path, extra_path=extra_path
            )
            # Merged result should equal base since extra adds nothing
            assert result.version == "1.0"
            assert result.domains == ["api.github.com", "example.com"]
            assert len(result.http_endpoints) == 1
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)

    def test_extra_file_empty_patterns_raises_config_error(self):
        """blocked_paths with patterns: [] must be rejected at parse time."""
        base_path = _write_yaml(_base_yaml())
        extra_path = _write_yaml({
            "version": "2.0",
            "blocked_paths": [
                {"host": "evil.com", "patterns": []},
            ],
        })
        try:
            with pytest.raises(ConfigError, match="patterns must not be empty"):
                load_allowlist_config(path=base_path, extra_path=extra_path)
        finally:
            os.unlink(base_path)
            os.unlink(extra_path)
