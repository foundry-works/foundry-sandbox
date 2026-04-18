"""Tests that moved functions are importable from their canonical locations
and that backward-compatible re-exports from _helpers still work."""

import pytest


class TestCanonicalPathImports:
    """Functions moved to foundry_sandbox.paths."""

    def test_repo_url_to_bare_path(self):
        from foundry_sandbox.paths import repo_url_to_bare_path
        assert callable(repo_url_to_bare_path)

    def test_sandbox_name(self):
        from foundry_sandbox.paths import sandbox_name
        assert callable(sandbox_name)

    def test_find_next_sandbox_name(self):
        from foundry_sandbox.paths import find_next_sandbox_name
        assert callable(find_next_sandbox_name)

    def test_strip_github_url(self):
        from foundry_sandbox.paths import strip_github_url
        assert callable(strip_github_url)

    def test_resolve_ssh_agent_sock(self):
        from foundry_sandbox.paths import resolve_ssh_agent_sock
        assert callable(resolve_ssh_agent_sock)


class TestCanonicalDockerImports:
    """Functions moved to foundry_sandbox.docker."""

    def test_uses_credential_isolation(self):
        from foundry_sandbox.docker import uses_credential_isolation
        assert callable(uses_credential_isolation)

    def test_apply_network_restrictions(self):
        from foundry_sandbox.docker import apply_network_restrictions
        assert callable(apply_network_restrictions)

    def test_cleanup_orphaned_networks(self):
        from foundry_sandbox.docker import cleanup_orphaned_networks
        assert callable(cleanup_orphaned_networks)

    def test_proxy_cleanup(self):
        from foundry_sandbox.docker import proxy_cleanup
        assert callable(proxy_cleanup)

    def test_remove_sandbox_networks(self):
        from foundry_sandbox.docker import remove_sandbox_networks
        assert callable(remove_sandbox_networks)


class TestCanonicalUtilsImports:
    """Functions moved to foundry_sandbox.utils."""

    def test_generate_sandbox_id(self):
        from foundry_sandbox.utils import generate_sandbox_id
        assert callable(generate_sandbox_id)

    def test_environment_scope(self):
        from foundry_sandbox.utils import environment_scope
        assert callable(environment_scope)


class TestCanonicalTmuxImports:
    """Functions moved to foundry_sandbox.tmux."""

    def test_tmux_session_name(self):
        from foundry_sandbox.tmux import tmux_session_name
        assert callable(tmux_session_name)


class TestBackwardCompatReExports:
    """All moved functions should still be importable from _helpers."""

    @pytest.mark.parametrize("name", [
        "repo_url_to_bare_path",
        "sandbox_name",
        "find_next_sandbox_name",
        "strip_github_url",
        "resolve_ssh_agent_sock",
        "uses_credential_isolation",
        "apply_network_restrictions",
        "cleanup_orphaned_networks",
        "proxy_cleanup",
        "remove_sandbox_networks",
        "generate_sandbox_id",
        "flag_enabled",
        "tmux_session_name",
    ])
    def test_reexport_from_helpers(self, name):
        import foundry_sandbox.commands._helpers as helpers
        assert hasattr(helpers, name), f"_helpers missing re-export: {name}"


class TestRemoveSandboxNetworks:
    """Unit test for the new remove_sandbox_networks() function."""

    def test_calls_inspect_and_rm(self, monkeypatch):
        """Should inspect+rm for both credential-isolation and proxy-egress."""
        from unittest.mock import MagicMock
        from foundry_sandbox import docker

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            result = MagicMock()
            result.returncode = 0
            return result

        monkeypatch.setattr(docker.subprocess, "run", fake_run)

        docker.remove_sandbox_networks("sandbox-test")

        # Should have 4 calls: inspect+rm for each network suffix
        network_names = [c[3] for c in calls if "inspect" in c]
        assert "sandbox-test_credential-isolation" in network_names
        assert "sandbox-test_proxy-egress" in network_names
        rm_names = [c[3] for c in calls if c[1] == "network" and c[2] == "rm"]
        assert "sandbox-test_credential-isolation" in rm_names
        assert "sandbox-test_proxy-egress" in rm_names

    def test_ignores_failures(self, monkeypatch):
        """Should not raise on subprocess errors."""
        from foundry_sandbox import docker

        def fail_run(cmd, **kwargs):
            raise OSError("docker not found")

        monkeypatch.setattr(docker.subprocess, "run", fail_run)

        # Should not raise
        docker.remove_sandbox_networks("sandbox-test")
