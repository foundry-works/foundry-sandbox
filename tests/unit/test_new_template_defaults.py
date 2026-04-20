"""Tests for template precedence in cast new --preset / --last."""

from __future__ import annotations

from unittest.mock import patch

from foundry_sandbox.commands.new import NewDefaults, _apply_saved_new_defaults


class TestTemplatePrecedence:
    """Verify explicit --template wins over preset/last template."""

    def _defaults(self, **overrides):
        kwargs = dict(
            repo="org/repo",
            branch="",
            from_branch="",
            copies=(),
            agent="claude",
            with_opencode=False,
            with_zai=False,
            wd="",
            pip_requirements="",
            allow_pr=False,
            template="foundry-git-wrapper:latest",
            template_managed=False,
        )
        kwargs.update(overrides)
        return kwargs

    def test_preset_template_overrides_click_default(self):
        saved = {"template": "preset-mysetup:latest", "template_managed": True}
        result = _apply_saved_new_defaults(
            saved, explicit_params=set(), **self._defaults()
        )
        assert result.template == "preset-mysetup:latest"
        assert result.template_managed is True

    def test_explicit_template_overrides_preset(self):
        saved = {"template": "preset-mysetup:latest", "template_managed": True}
        result = _apply_saved_new_defaults(
            saved, explicit_params={"template"}, **self._defaults(template="custom:tag")
        )
        assert result.template == "custom:tag"
        assert result.template_managed is False

    def test_no_saved_template_uses_click_default(self):
        saved = {}
        result = _apply_saved_new_defaults(
            saved, explicit_params=set(), **self._defaults()
        )
        assert result.template == "foundry-git-wrapper:latest"

    def test_last_template_managed_carries_through(self):
        saved = {"template": "preset-old:latest", "template_managed": True}
        result = _apply_saved_new_defaults(
            saved, explicit_params=set(), **self._defaults()
        )
        assert result.template == "preset-old:latest"
        assert result.template_managed is True


class TestNewDefaultsDataclass:
    def test_template_fields_present(self):
        d = NewDefaults(
            repo="r", branch="b", from_branch="", copies=(), agent="claude",
            with_opencode=False, with_zai=False, wd="", pip_requirements="",
            allow_pr=False, template="my-tag:latest", template_managed=True,
        )
        assert d.template == "my-tag:latest"
        assert d.template_managed is True


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
