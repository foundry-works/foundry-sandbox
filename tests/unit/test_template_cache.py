"""Tests for managed template caching."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from foundry_sandbox.template_cache import (
    TemplateCacheEntry,
    _managed_tag,
    _sanitize_env_for_hash,
    _serialize_packages,
    invalidate_cached_template,
    is_cache_stale,
    list_cached_templates,
    lookup_cached_template,
)


# ============================================================================
# Helpers
# ============================================================================


def _make_profile(
    *,
    pip_requirements: str | None = None,
    packages: dict | None = None,
    tooling: list[str] | None = None,
    agent: str | None = None,
    ide: str | None = None,
    wd: str | None = None,
    template: str | None = None,
) -> MagicMock:
    """Create a mock DevProfile-like object."""
    prof = MagicMock()
    prof.pip_requirements = pip_requirements
    prof.tooling = tooling or []
    prof.agent = agent
    prof.ide = ide
    prof.wd = wd
    prof.template = template

    if packages:
        from foundry_sandbox.foundry_config import PackageBootstrap
        prof.packages = PackageBootstrap(**packages)
    else:
        prof.packages = None

    return prof


def _make_config(
    *,
    bundles: dict | None = None,
) -> MagicMock:
    """Create a mock FoundryConfig-like object."""
    config = MagicMock()
    config.tooling_bundles = bundles or {}
    return config


# ============================================================================
# _sanitize_env_for_hash
# ============================================================================


class TestSanitizeEnv:
    def test_strips_from_host(self):
        env = {"KEY": "prefix-${from_host:SECRET}/suffix"}
        result = _sanitize_env_for_hash(env)
        assert result == {"KEY": "prefix-__LATE_BOUND__/suffix"}

    def test_preserves_plain_values(self):
        env = {"KEY": "plain-value"}
        assert _sanitize_env_for_hash(env) == {"KEY": "plain-value"}

    def test_empty_returns_empty(self):
        assert _sanitize_env_for_hash({}) == {}
        assert _sanitize_env_for_hash(None) == {}


# ============================================================================
# _serialize_packages
# ============================================================================


class TestSerializePackages:
    def test_with_packages_field(self):
        prof = _make_profile(packages={"pip": ["ruff"], "apt": ["jq"]})
        result = _serialize_packages(prof)
        assert result["pip"] == ["ruff"]
        assert result["apt"] == ["jq"]

    def test_with_pip_requirements_fallback(self):
        prof = _make_profile(pip_requirements="requirements.txt")
        result = _serialize_packages(prof)
        assert result["pip"] == "requirements.txt"

    def test_packages_takes_precedence(self):
        prof = _make_profile(
            pip_requirements="requirements.txt",
            packages={"pip": ["ruff"]},
        )
        result = _serialize_packages(prof)
        assert result["pip"] == ["ruff"]

    def test_empty_profile(self):
        prof = _make_profile()
        assert _serialize_packages(prof) == {}


# ============================================================================
# _managed_tag
# ============================================================================


class TestManagedTag:
    def test_simple_name(self):
        tag = _managed_tag("work", "a1b2c3d4e5f67890")
        assert tag == "profile-work-a1b2c3d4e5f67890:latest"

    def test_name_with_spaces(self):
        tag = _managed_tag("my setup", "a1b2c3d4e5f67890")
        assert tag == "profile-my-setup-a1b2c3d4e5f67890:latest"

    def test_name_with_special_chars(self):
        tag = _managed_tag("hello@world", "abc123")
        assert tag == "profile-hello-world-abc123:latest"

    def test_invalid_name_raises(self):
        with pytest.raises(ValueError, match="Cannot derive"):
            _managed_tag("", "abc123")


# ============================================================================
# derive_cache_key — patches target source module (lazy import)
# ============================================================================


class TestDeriveCacheKey:
    @patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1")
    @patch("foundry_sandbox.__version__", "1.5.0")
    def test_deterministic(self, mock_ver):
        from foundry_sandbox.template_cache import derive_cache_key
        prof = _make_profile(packages={"pip": ["ruff"]})
        config = _make_config()
        key1 = derive_cache_key("work", prof, config, "foundry-git-wrapper:latest")
        key2 = derive_cache_key("work", prof, config, "foundry-git-wrapper:latest")
        assert key1 == key2
        assert len(key1) == 16

    @patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1")
    @patch("foundry_sandbox.__version__", "1.5.0")
    def test_packages_change_key(self, mock_ver):
        from foundry_sandbox.template_cache import derive_cache_key
        prof1 = _make_profile(packages={"pip": ["ruff"]})
        prof2 = _make_profile(packages={"pip": ["mypy"]})
        config = _make_config()
        key1 = derive_cache_key("work", prof1, config, "foundry-git-wrapper:latest")
        key2 = derive_cache_key("work", prof2, config, "foundry-git-wrapper:latest")
        assert key1 != key2

    @patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1")
    @patch("foundry_sandbox.__version__", "1.5.0")
    def test_agent_does_not_change_key(self, mock_ver):
        from foundry_sandbox.template_cache import derive_cache_key
        prof1 = _make_profile(agent="claude", packages={"pip": ["ruff"]})
        prof2 = _make_profile(agent="codex", packages={"pip": ["ruff"]})
        config = _make_config()
        key1 = derive_cache_key("work", prof1, config, "foundry-git-wrapper:latest")
        key2 = derive_cache_key("work", prof2, config, "foundry-git-wrapper:latest")
        assert key1 == key2

    @patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1")
    @patch("foundry_sandbox.__version__", "1.5.0")
    def test_ide_does_not_change_key(self, mock_ver):
        from foundry_sandbox.template_cache import derive_cache_key
        prof1 = _make_profile(ide="cursor", packages={"pip": ["ruff"]})
        prof2 = _make_profile(ide="vscode", packages={"pip": ["ruff"]})
        config = _make_config()
        key1 = derive_cache_key("work", prof1, config, "foundry-git-wrapper:latest")
        key2 = derive_cache_key("work", prof2, config, "foundry-git-wrapper:latest")
        assert key1 == key2

    @patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1")
    @patch("foundry_sandbox.__version__", "1.5.0")
    def test_base_template_changes_key(self, mock_ver):
        from foundry_sandbox.template_cache import derive_cache_key
        prof = _make_profile(packages={"pip": ["ruff"]})
        config = _make_config()
        key1 = derive_cache_key("work", prof, config, "foundry-git-wrapper:latest")
        key2 = derive_cache_key("work", prof, config, "custom:latest")
        assert key1 != key2


# ============================================================================
# lookup_cached_template
# ============================================================================


class TestLookupCachedTemplate:
    @patch("foundry_sandbox.sbx.sbx_template_ls")
    def test_hit(self, mock_ls, tmp_path):
        mock_ls.return_value = ["profile-work-abc123:latest"]
        entry = TemplateCacheEntry(
            profile_name="work",
            cache_key="abc123",
            template_tag="profile-work-abc123:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-01T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
        )
        cache_dir = tmp_path / ".foundry" / "template-cache"
        cache_dir.mkdir(parents=True)
        (cache_dir / "work.json").write_text(entry.model_dump_json())

        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = cache_dir / "work.json"
            result = lookup_cached_template("work")
        assert result == "profile-work-abc123:latest"

    def test_miss_no_file(self, tmp_path):
        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = tmp_path / "missing.json"
            result = lookup_cached_template("work")
        assert result is None

    @patch("foundry_sandbox.sbx.sbx_template_ls")
    def test_stale_template_removed(self, mock_ls, tmp_path):
        mock_ls.return_value = []  # template gone from sbx
        entry = TemplateCacheEntry(
            profile_name="work",
            cache_key="abc123",
            template_tag="profile-work-abc123:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-01T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
        )
        cache_dir = tmp_path / ".foundry" / "template-cache"
        cache_dir.mkdir(parents=True)
        (cache_dir / "work.json").write_text(entry.model_dump_json())

        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = cache_dir / "work.json"
            result = lookup_cached_template("work")
        assert result is None


# ============================================================================
# is_cache_stale
# ============================================================================


class TestIsCacheStale:
    @patch("foundry_sandbox.sbx.get_sbx_version", return_value="0.26.1")
    @patch("foundry_sandbox.__version__", "1.5.0")
    def test_fresh(self, mock_ver, tmp_path):
        from foundry_sandbox.template_cache import derive_cache_key
        prof = _make_profile(packages={"pip": ["ruff"]})
        config = _make_config()
        key = derive_cache_key("work", prof, config, "foundry-git-wrapper:latest")
        entry = TemplateCacheEntry(
            profile_name="work",
            cache_key=key,
            template_tag=f"profile-work-{key}:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-01T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
        )
        cache_dir = tmp_path / ".foundry" / "template-cache"
        cache_dir.mkdir(parents=True)
        (cache_dir / "work.json").write_text(entry.model_dump_json())

        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = cache_dir / "work.json"
            assert is_cache_stale("work", prof, config, "foundry-git-wrapper:latest") is False

    def test_no_cache_file(self, tmp_path):
        prof = _make_profile()
        config = _make_config()
        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = tmp_path / "missing.json"
            assert is_cache_stale("work", prof, config, "foundry-git-wrapper:latest") is True


# ============================================================================
# list_cached_templates
# ============================================================================


class TestListCachedTemplates:
    def test_empty(self, tmp_path):
        with patch("foundry_sandbox.template_cache.path_template_cache_dir") as mock_dir:
            mock_dir.return_value = tmp_path / "nonexistent"
            assert list_cached_templates() == []

    def test_lists_entries(self, tmp_path):
        cache_dir = tmp_path / "template-cache"
        cache_dir.mkdir()
        entry1 = TemplateCacheEntry(
            profile_name="work",
            cache_key="abc123",
            template_tag="profile-work-abc123:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-01T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
        )
        entry2 = TemplateCacheEntry(
            profile_name="python",
            cache_key="def456",
            template_tag="profile-python-def456:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-02T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
        )
        (cache_dir / "work.json").write_text(entry1.model_dump_json())
        (cache_dir / "python.json").write_text(entry2.model_dump_json())

        with patch("foundry_sandbox.template_cache.path_template_cache_dir") as mock_dir:
            mock_dir.return_value = cache_dir
            entries = list_cached_templates()
        assert len(entries) == 2
        assert entries[0].profile_name == "python"
        assert entries[1].profile_name == "work"


# ============================================================================
# invalidate_cached_template
# ============================================================================


class TestInvalidateCachedTemplate:
    @patch("foundry_sandbox.sbx.sbx_template_rm")
    def test_removes_template_and_file(self, mock_rm, tmp_path):
        entry = TemplateCacheEntry(
            profile_name="work",
            cache_key="abc123",
            template_tag="profile-work-abc123:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-01T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
        )
        cache_file = tmp_path / "work.json"
        cache_file.write_text(entry.model_dump_json())

        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = cache_file
            result = invalidate_cached_template("work")

        assert result is True
        mock_rm.assert_called_once_with("profile-work-abc123:latest")
        assert not cache_file.exists()

    def test_nothing_to_remove(self, tmp_path):
        with patch("foundry_sandbox.template_cache.path_template_cache_file") as mock_path:
            mock_path.return_value = tmp_path / "missing.json"
            result = invalidate_cached_template("work")
        assert result is False


# ============================================================================
# TemplateCacheEntry serialization
# ============================================================================


class TestTemplateCacheEntryRoundTrip:
    def test_round_trip(self):
        entry = TemplateCacheEntry(
            profile_name="work",
            cache_key="abc123",
            template_tag="profile-work-abc123:latest",
            base_template="foundry-git-wrapper:latest",
            built_at="2026-01-01T00:00:00Z",
            sbx_version="0.26.1",
            cast_version="1.5.0",
            bakeable_inputs={"packages": {"pip": ["ruff"]}, "tooling": ["github"]},
        )
        json_str = entry.model_dump_json()
        restored = TemplateCacheEntry.model_validate_json(json_str)
        assert restored == entry
