"""Assert that all default config assets are bundled in the wheel.

These tests fail at import time if the package is installed from a wheel
that was built without the default_config assets.
"""

from __future__ import annotations


class TestDefaultConfigAssetPresence:
    """Verify each default config YAML asset is resolvable from the installed package."""

    def test_push_file_restrictions_yaml(self):
        from importlib.resources import files

        resource = files("foundry_git_safety.default_config").joinpath(
            "push-file-restrictions.yaml"
        )
        assert resource.is_file(), (
            "push-file-restrictions.yaml not found in "
            "foundry_git_safety.default_config. Check pyproject.toml "
            "[tool.hatch.build.targets.wheel] artifacts."
        )

    def test_deep_policy_github_yaml(self):
        from importlib.resources import files

        resource = files("foundry_git_safety.default_config").joinpath(
            "deep-policy-github.yaml"
        )
        assert resource.is_file(), (
            "deep-policy-github.yaml not found in "
            "foundry_git_safety.default_config. Check pyproject.toml "
            "[tool.hatch.build.targets.wheel] artifacts."
        )

    def test_foundry_yaml_example(self):
        from importlib.resources import files

        resource = files("foundry_git_safety.default_config").joinpath(
            "foundry.yaml.example"
        )
        assert resource.is_file(), (
            "foundry.yaml.example not found in "
            "foundry_git_safety.default_config. Check pyproject.toml "
            "[tool.hatch.build.targets.wheel] artifacts."
        )
