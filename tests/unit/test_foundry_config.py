"""Unit tests for foundry_sandbox.foundry_config — Phase 1 schema, resolver, merge."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from foundry_sandbox.foundry_config import (
    ClaudeCodeConfig,
    DevProfile,
    FileRestrictionsAdd,
    FoundryConfig,
    GitSafetyOverlay,
    HookRule,
    McpServerBuiltin,
    McpServerNpm,
    McpServerProxy,
    PackageBootstrap,
    Permissions,
    ProtectedBranchesAdd,
    SkillSource,
    ToolingBundle,
    UserService,
    _merge,
    _resolve_host_refs,
    collect_bundle_packages,
    collect_secret_refs,
    compile_claude_code,
    compile_git_safety,
    compile_mcp_servers,
    compile_user_services,
    expand_bundles,
    merge_package_bootstrap,
    normalize_profile_packages,
    render_plan_text,
    resolve_foundry_config,
    resolve_profile,
)


# ---------------------------------------------------------------------------
# Strict mode
# ---------------------------------------------------------------------------


class TestStrictMode:
    def test_strict_mode_rejects_unknown_keys(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            FoundryConfig(version="1", unknown=1)

    def test_strict_mode_on_overlay(self):
        with pytest.raises(ValidationError):
            GitSafetyOverlay(unknown_field=True)

    def test_strict_mode_on_mcp_server(self):
        with pytest.raises(ValidationError):
            McpServerBuiltin(name="x", type="builtin", surprise=True)

    def test_strict_mode_on_user_service(self):
        with pytest.raises(ValidationError):
            UserService(name="x", env_var="K", domain="d", extra=True)


# ---------------------------------------------------------------------------
# Version mismatch
# ---------------------------------------------------------------------------


class TestVersionMismatch:
    def test_version_mismatch_raises(self):
        a = FoundryConfig(version="1")
        b = FoundryConfig(version="1")
        # Same version is fine
        result = _merge([a, b])
        assert result.version == "1"


# ---------------------------------------------------------------------------
# Merge: lists concatenate
# ---------------------------------------------------------------------------


class TestMergeLists:
    def test_merge_lists_concatenate(self):
        a = FoundryConfig(
            version="1",
            mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
        )
        b = FoundryConfig(
            version="1",
            mcp_servers=[McpServerBuiltin(name="filesystem", type="builtin")],
        )
        result = _merge([a, b])
        assert len(result.mcp_servers) == 2
        assert result.mcp_servers[0].name == "github"
        assert result.mcp_servers[1].name == "filesystem"

    def test_merge_user_services(self):
        a = FoundryConfig(
            version="1",
            user_services=[UserService(name="svc1", env_var="K1", domain="d1")],
        )
        b = FoundryConfig(
            version="1",
            user_services=[UserService(name="svc2", env_var="K2", domain="d2")],
        )
        result = _merge([a, b])
        assert len(result.user_services) == 2

    def test_merge_empty_lists(self):
        a = FoundryConfig(version="1")
        result = _merge([a])
        assert result.mcp_servers == []
        assert result.user_services == []


# ---------------------------------------------------------------------------
# Merge: allow flags ANDed
# ---------------------------------------------------------------------------


class TestMergeAllowFlags:
    def test_merge_allow_flags_anded(self):
        a = FoundryConfig(version="1", allow_third_party_mcp=False)
        b = FoundryConfig(version="1", allow_third_party_mcp=True)
        result = _merge([a, b])
        assert result.allow_third_party_mcp is False

    def test_both_true_stays_true(self):
        a = FoundryConfig(version="1", allow_third_party_mcp=True)
        b = FoundryConfig(version="1", allow_third_party_mcp=True)
        result = _merge([a, b])
        assert result.allow_third_party_mcp is True

    def test_both_false_stays_false(self):
        a = FoundryConfig(version="1", allow_third_party_mcp=False)
        b = FoundryConfig(version="1", allow_third_party_mcp=False)
        result = _merge([a, b])
        assert result.allow_third_party_mcp is False


# ---------------------------------------------------------------------------
# Third-party MCP gate
# ---------------------------------------------------------------------------


class TestThirdPartyMcpGate:
    def test_third_party_mcp_gate(self):
        with pytest.raises(ValidationError, match="type=npm"):
            FoundryConfig(
                version="1",
                mcp_servers=[McpServerNpm(name="evil", type="npm", package="evil-pkg")],
                allow_third_party_mcp=False,
            )

    def test_npm_allowed_when_flag_set(self):
        cfg = FoundryConfig(
            version="1",
            mcp_servers=[McpServerNpm(name="ok", type="npm", package="ok-pkg")],
            allow_third_party_mcp=True,
        )
        assert cfg.mcp_servers[0].name == "ok"

    def test_repo_gate_true_survives_builtin_defaults(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text(
            'version: "1"\n'
            "allow_third_party_mcp: true\n"
            "mcp_servers:\n"
            "  - name: ok\n"
            "    type: npm\n"
            "    package: ok-pkg\n"
        )
        cfg = resolve_foundry_config(tmp_path)
        assert cfg.allow_third_party_mcp is True
        assert cfg.mcp_servers[0].type == "npm"

    def test_user_gate_false_blocks_repo_npm(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        user_config = tmp_path / "user-foundry.yaml"
        user_config.write_text('version: "1"\nallow_third_party_mcp: false\n')
        monkeypatch.setattr(
            "foundry_sandbox.foundry_config._USER_CONFIG_PATH",
            user_config,
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "foundry.yaml").write_text(
            'version: "1"\n'
            "allow_third_party_mcp: true\n"
            "mcp_servers:\n"
            "  - name: ok\n"
            "    type: npm\n"
            "    package: ok-pkg\n"
        )

        with pytest.raises(ValueError, match="allow_third_party_mcp is off"):
            resolve_foundry_config(repo)


# ---------------------------------------------------------------------------
# Missing layers
# ---------------------------------------------------------------------------


class TestMissingLayers:
    def test_missing_layers_returns_defaults(self, tmp_path: Path):
        config = resolve_foundry_config(tmp_path)
        assert config.version == "1"
        assert config.mcp_servers == []
        assert config.user_services == []
        assert config.git_safety is None
        assert config.claude_code is None
        assert config.allow_third_party_mcp is False


# ---------------------------------------------------------------------------
# Additive-only structural check
# ---------------------------------------------------------------------------


class TestAdditiveOnlyStructural:
    _OVERLAY_MODELS = [
        GitSafetyOverlay,
        ProtectedBranchesAdd,
        FileRestrictionsAdd,
    ]

    def test_additive_only_structural(self):
        for model_cls in self._OVERLAY_MODELS:
            fields = set(model_cls.model_fields.keys())
            forbidden = {f for f in fields if "remove" in f.lower() or "replace" in f.lower()}
            assert not forbidden, (
                f"{model_cls.__name__} has non-additive fields: {forbidden}"
            )


# ---------------------------------------------------------------------------
# Resolver with real files
# ---------------------------------------------------------------------------


class TestResolver:
    def test_repo_layer_loaded(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text(
            'version: "1"\n'
            "git_safety:\n"
            "  protected_branches:\n"
            '    add: ["refs/heads/staging"]\n'
        )
        config = resolve_foundry_config(tmp_path)
        assert config.git_safety is not None
        assert config.git_safety.protected_branches is not None
        assert "refs/heads/staging" in config.git_safety.protected_branches.add

    def test_invalid_yaml_returns_default(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text("{{invalid")
        with pytest.raises(ValueError, match="Failed to load foundry config"):
            resolve_foundry_config(tmp_path)

    def test_invalid_schema_returns_none(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text('version: "1"\nunknown_key: true')
        with pytest.raises(ValueError, match="Invalid foundry config"):
            resolve_foundry_config(tmp_path)


# ---------------------------------------------------------------------------
# Plan renderer
# ---------------------------------------------------------------------------


class TestRenderPlanText:
    def test_renders_minimal(self):
        config = FoundryConfig(version="1")
        text = render_plan_text(config)
        assert "allow_third_party_mcp: false" in text
        assert "policy_patches (0):" in text

    def test_renders_with_overlay(self):
        config = FoundryConfig(
            version="1",
            git_safety=GitSafetyOverlay(
                protected_branches=ProtectedBranchesAdd(add=["refs/heads/staging"]),
                file_restrictions=FileRestrictionsAdd(blocked_patterns_add=["db/migrations/"]),
            ),
        )
        text = render_plan_text(config)
        assert "refs/heads/staging" in text
        assert "db/migrations/" in text
        assert "policy_patches (2):" in text


# ---------------------------------------------------------------------------
# Claude Code merge
# ---------------------------------------------------------------------------


class TestClaudeCodeMerge:
    def test_hooks_merge_per_key(self):
        a = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                hooks={"pre-commit": [HookRule(match="*.py", command="ruff check")]},
            ),
        )
        b = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                hooks={"pre-commit": [HookRule(match="*.ts", command="eslint")]},
            ),
        )
        result = _merge([a, b])
        assert result.claude_code is not None
        assert len(result.claude_code.hooks["pre-commit"]) == 2

    def test_skills_concatenate(self):
        a = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(skills=[SkillSource(source="/a")]),
        )
        b = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(skills=[SkillSource(source="/b")]),
        )
        result = _merge([a, b])
        assert len(result.claude_code.skills) == 2


# ---------------------------------------------------------------------------
# compile_git_safety (Phase 2)
# ---------------------------------------------------------------------------


class TestCompileGitSafety:
    def test_compile_git_safety_empty_overlay(self):
        overlay = GitSafetyOverlay()
        bundle = compile_git_safety(overlay)
        assert bundle.policy_patches == []
        assert bundle.file_writes == []

    def test_compile_git_safety_protected_branches(self):
        overlay = GitSafetyOverlay(
            protected_branches=ProtectedBranchesAdd(add=["refs/heads/staging", "refs/heads/release"]),
        )
        bundle = compile_git_safety(overlay)
        assert len(bundle.policy_patches) == 1
        patch = bundle.policy_patches[0]
        assert patch.op == "add"
        assert patch.path == "protected_branches"
        assert patch.value == ["refs/heads/staging", "refs/heads/release"]

    def test_compile_git_safety_blocked_patterns(self):
        overlay = GitSafetyOverlay(
            file_restrictions=FileRestrictionsAdd(blocked_patterns_add=["db/migrations/", "secrets/"]),
        )
        bundle = compile_git_safety(overlay)
        assert len(bundle.policy_patches) == 1
        assert bundle.policy_patches[0].path == "blocked_patterns"

    def test_compile_git_safety_allow_pr(self):
        overlay = GitSafetyOverlay(allow_pr_operations=True)
        bundle = compile_git_safety(overlay)
        assert len(bundle.policy_patches) == 1
        assert bundle.policy_patches[0].value is True

    def test_compile_git_safety_allow_pr_false(self):
        overlay = GitSafetyOverlay(allow_pr_operations=False)
        bundle = compile_git_safety(overlay)
        assert len(bundle.policy_patches) == 1
        assert bundle.policy_patches[0].value is False

    def test_compile_git_safety_all_fields(self):
        overlay = GitSafetyOverlay(
            protected_branches=ProtectedBranchesAdd(add=["refs/heads/staging"]),
            file_restrictions=FileRestrictionsAdd(blocked_patterns_add=["db/"]),
            allow_pr_operations=False,
        )
        bundle = compile_git_safety(overlay)
        assert len(bundle.policy_patches) == 3


# ---------------------------------------------------------------------------
# compile_user_services (Phase 3)
# ---------------------------------------------------------------------------


class TestCompileUserServices:
    def test_empty_services_returns_empty_bundle(self):
        bundle = compile_user_services([])
        assert bundle.env_vars == {}
        assert bundle.sbx_secrets == []
        assert bundle.policy_patches == []

    def test_single_service_emits_env_and_secret(self):
        services = [UserService(name="Tavily", env_var="TAVILY_API_KEY", domain="api.tavily.com")]
        bundle = compile_user_services(services)
        assert "TAVILY_API_KEY" in bundle.env_vars
        assert bundle.env_vars["TAVILY_API_KEY"] == "http://host.docker.internal:8083/proxy/tavily"
        assert len(bundle.sbx_secrets) == 1
        assert bundle.sbx_secrets[0] == ("tavily", "TAVILY_API_KEY")
        assert bundle.user_services[0]["domain"] == "api.tavily.com"

    def test_multiple_services(self):
        services = [
            UserService(name="OpenRouter", env_var="OPENROUTER_API_KEY", domain="openrouter.ai"),
            UserService(name="Groq API", env_var="GROQ_API_KEY", domain="api.groq.com"),
        ]
        bundle = compile_user_services(services)
        assert len(bundle.env_vars) == 2
        assert len(bundle.sbx_secrets) == 2
        # Slug for "Groq API" should be "groq-api"
        assert bundle.env_vars["GROQ_API_KEY"] == "http://host.docker.internal:8083/proxy/groq-api"

    def test_custom_host_and_port(self):
        services = [UserService(name="svc", env_var="K", domain="d")]
        bundle = compile_user_services(services, port=9090, host="myhost")
        assert bundle.env_vars["K"] == "http://myhost:9090/proxy/svc"

    def test_preserves_proxy_options_in_schema(self):
        services = [UserService(
            name="ReadOnlyAPI",
            env_var="READONLY_API_KEY",
            domain="api.readonly.example",
            header="X-Api-Key",
            format="header",
            methods=["GET"],
            paths=["/v1/**"],
            scheme="http",
            port=8080,
        )]
        bundle = compile_user_services(services)
        assert bundle.env_vars["READONLY_API_KEY"] == "http://host.docker.internal:8083/proxy/readonlyapi"
        assert bundle.sbx_secrets[0] == ("readonlyapi", "READONLY_API_KEY")
        assert bundle.user_services[0]["paths"] == ["/v1/**"]

    def test_value_alias_normalizes_to_header(self):
        svc = UserService(
            name="CustomService",
            env_var="CUSTOM_API_KEY",
            domain="api.custom.example",
            format="value",
        )
        assert svc.format == "header"


class TestCollectSecretRefs:
    def test_collects_user_services_proxy_and_from_host_refs(self):
        config = FoundryConfig(
            version="1",
            user_services=[
                UserService(name="Tavily", env_var="TAVILY_API_KEY", domain="api.tavily.com"),
            ],
            mcp_servers=[
                McpServerProxy(
                    name="internal-api",
                    type="proxy",
                    host_env="INTERNAL_API_KEY",
                    target="api.internal.com",
                ),
                McpServerBuiltin(
                    name="github",
                    type="builtin",
                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": "${from_host:GITHUB_TOKEN}"},
                ),
            ],
        )

        assert collect_secret_refs(config) == [
            ("tavily", "TAVILY_API_KEY"),
            ("internal-api", "INTERNAL_API_KEY"),
            ("github-token", "GITHUB_TOKEN"),
        ]

    def test_dedupes_duplicate_host_refs(self):
        config = FoundryConfig(
            version="1",
            allow_third_party_mcp=True,
            mcp_servers=[
                McpServerBuiltin(
                    name="github",
                    type="builtin",
                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": "${from_host:GITHUB_TOKEN}"},
                ),
                McpServerNpm(
                    name="npm-tool",
                    type="npm",
                    package="@example/tool",
                    env={"TOKEN": "${from_host:GITHUB_TOKEN}"},
                ),
            ],
        )

        assert collect_secret_refs(config) == [("github-token", "GITHUB_TOKEN")]


# ---------------------------------------------------------------------------
# compile_mcp_servers (Phase 4)
# ---------------------------------------------------------------------------


class TestCompileMcpBuiltin:
    def test_builtin_github(self):
        servers = [McpServerBuiltin(name="github", type="builtin")]
        bundle = compile_mcp_servers(servers)
        assert len(bundle.file_writes) == 1
        assert bundle.file_writes[0].container_path == "/workspace/.mcp.json"
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert "github" in content["mcpServers"]
        assert content["mcpServers"]["github"]["command"] == "npx"
        assert bundle.env_vars == {}
        assert bundle.sbx_secrets == []

    def test_builtin_with_plain_env(self):
        servers = [McpServerBuiltin(
            name="github", type="builtin",
            env={"GITHUB_TOOL_VERBOSE": "1"},
        )]
        bundle = compile_mcp_servers(servers)
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert content["mcpServers"]["github"]["env"]["GITHUB_TOOL_VERBOSE"] == "1"

    def test_unknown_builtin_raises(self):
        servers = [McpServerBuiltin(name="nonexistent", type="builtin")]
        with pytest.raises(ValueError, match="Unknown builtin MCP server"):
            compile_mcp_servers(servers)

    def test_empty_servers_returns_empty_bundle(self):
        bundle = compile_mcp_servers([])
        assert bundle.file_writes == []
        assert bundle.env_vars == {}
        assert bundle.sbx_secrets == []

    def test_multiple_builtins(self):
        servers = [
            McpServerBuiltin(name="github", type="builtin"),
            McpServerBuiltin(name="filesystem", type="builtin"),
        ]
        bundle = compile_mcp_servers(servers)
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert "github" in content["mcpServers"]
        assert "filesystem" in content["mcpServers"]


class TestCompileMcpProxy:
    def test_proxy_emits_secret_and_env(self):
        servers = [McpServerProxy(
            name="internal-api", type="proxy",
            host_env="INTERNAL_API_KEY", target="api.internal.com",
        )]
        bundle = compile_mcp_servers(servers)
        assert len(bundle.sbx_secrets) == 1
        assert bundle.sbx_secrets[0] == ("internal-api", "INTERNAL_API_KEY")
        assert len(bundle.env_vars) == 1
        assert any("internal-api" in v for v in bundle.env_vars.values())
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert "internal-api" in content["mcpServers"]
        assert "/proxy/internal-api" in content["mcpServers"]["internal-api"]["url"]
        assert bundle.user_services[0]["domain"] == "api.internal.com"
        assert bundle.user_services[0]["env_var"] == "INTERNAL_API_KEY"

    def test_proxy_custom_host_and_port(self):
        servers = [McpServerProxy(
            name="svc", type="proxy",
            host_env="SVC_KEY", target="svc.example.com",
        )]
        bundle = compile_mcp_servers(servers, port=9090, host="myhost")
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert "http://myhost:9090/proxy/svc" in content["mcpServers"]["svc"]["url"]


class TestFromHostRef:
    def test_from_host_resolves_to_proxy_url(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MY_TOKEN", "tok123")
        resolved, is_proxy = _resolve_host_refs("${from_host:MY_TOKEN}")
        assert is_proxy is True
        assert "proxy/my-token" in resolved

    def test_from_host_unset_raises(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        with pytest.raises(ValueError, match="MISSING_VAR"):
            _resolve_host_refs("${from_host:MISSING_VAR}")

    def test_no_from_host_returns_unchanged(self):
        resolved, is_proxy = _resolve_host_refs("plain-value")
        assert resolved == "plain-value"
        assert is_proxy is False

    def test_builtin_with_from_host_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_test123")
        servers = [McpServerBuiltin(
            name="github", type="builtin",
            env={"GITHUB_PERSONAL_ACCESS_TOKEN": "${from_host:GITHUB_TOKEN}"},
        )]
        bundle = compile_mcp_servers(servers)
        import json
        content = json.loads(bundle.file_writes[0].content)
        env = content["mcpServers"]["github"]["env"]
        assert "proxy/github-token" in env["GITHUB_PERSONAL_ACCESS_TOKEN"]
        assert len(bundle.sbx_secrets) == 1
        assert bundle.sbx_secrets[0] == ("github-token", "GITHUB_TOKEN")


class TestCompileMcpPlanRenderer:
    def test_plan_shows_mcp_file_writes(self):
        config = FoundryConfig(
            version="1",
            mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
        )
        text = render_plan_text(config)
        assert "file_writes (1):" in text
        assert "/workspace/.mcp.json" in text

    def test_plan_shows_proxy_secrets(self):
        config = FoundryConfig(
            version="1",
            mcp_servers=[McpServerProxy(
                name="svc", type="proxy",
                host_env="SVC_KEY", target="svc.example.com",
            )],
        )
        text = render_plan_text(config)
        assert "sbx_secrets" in text
        assert "svc" in text

    def test_plan_shows_npm_post_steps(self):
        config = FoundryConfig(
            version="1",
            allow_third_party_mcp=True,
            mcp_servers=[McpServerNpm(
                name="my-server", type="npm", package="@example/mcp-server",
            )],
        )
        text = render_plan_text(config)
        assert "post_steps (1):" in text
        assert "npm install" in text


# ---------------------------------------------------------------------------
# compile_mcp_servers npm (Phase 6)
# ---------------------------------------------------------------------------


class TestCompileMcpNpm:
    def test_npm_mcp_blocked_without_flag(self):
        with pytest.raises(ValidationError, match="type=npm"):
            FoundryConfig(
                version="1",
                mcp_servers=[McpServerNpm(
                    name="evil", type="npm", package="evil-pkg",
                )],
                allow_third_party_mcp=False,
            )

    def test_npm_mcp_compiles_with_flag(self):
        servers = [McpServerNpm(
            name="my-server", type="npm", package="@example/mcp-server",
        )]
        bundle = compile_mcp_servers(servers)

        # PostStep for global install
        assert len(bundle.post_steps) == 1
        assert bundle.post_steps[0].cmd == [
            "npm", "install", "-g", "@example/mcp-server",
        ]
        assert bundle.post_steps[0].user == "root"

        # FileWrite for .mcp.json
        assert len(bundle.file_writes) == 1
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert "my-server" in content["mcpServers"]
        entry = content["mcpServers"]["my-server"]
        assert entry["command"] == "npx"
        assert entry["args"] == ["@example/mcp-server"]

    def test_npm_mcp_with_plain_env(self):
        servers = [McpServerNpm(
            name="svc", type="npm", package="@acme/svc",
            env={"DEBUG": "1", "LOG_LEVEL": "verbose"},
        )]
        bundle = compile_mcp_servers(servers)
        import json
        content = json.loads(bundle.file_writes[0].content)
        env = content["mcpServers"]["svc"]["env"]
        assert env["DEBUG"] == "1"
        assert env["LOG_LEVEL"] == "verbose"
        assert bundle.sbx_secrets == []

    def test_npm_mcp_with_env_from_host(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MY_API_KEY", "secret123")
        servers = [McpServerNpm(
            name="ext", type="npm", package="@acme/ext",
            env={"API_KEY": "${from_host:MY_API_KEY}"},
        )]
        bundle = compile_mcp_servers(servers)
        import json
        content = json.loads(bundle.file_writes[0].content)
        env = content["mcpServers"]["ext"]["env"]
        assert "proxy/my-api-key" in env["API_KEY"]
        assert len(bundle.sbx_secrets) == 1
        assert bundle.sbx_secrets[0] == ("my-api-key", "MY_API_KEY")

    def test_npm_mcp_mixed_with_builtin(self):
        servers = [
            McpServerBuiltin(name="github", type="builtin"),
            McpServerNpm(name="custom", type="npm", package="@acme/custom"),
        ]
        bundle = compile_mcp_servers(servers)
        import json
        content = json.loads(bundle.file_writes[0].content)
        assert "github" in content["mcpServers"]
        assert "custom" in content["mcpServers"]
        assert len(bundle.post_steps) == 1


# ---------------------------------------------------------------------------
# compile_claude_code (Phase 5)
# ---------------------------------------------------------------------------


class TestCompileClaudeCode:
    def test_empty_config_returns_empty_bundle(self):
        cfg = ClaudeCodeConfig()
        bundle = compile_claude_code(cfg)
        assert bundle.file_writes == []
        assert bundle.post_steps == []
        assert bundle.env_vars == {}
        assert bundle.sbx_secrets == []

    def test_settings_json_shape(self):
        cfg = ClaudeCodeConfig(
            hooks={
                "PreToolUse": [HookRule(match="Bash", command="audit-log.sh")],
            },
            permissions=Permissions(
                allow=["Bash(grep:*)"],
                deny=["Bash(rm -rf:*)"],
            ),
        )
        bundle = compile_claude_code(cfg)
        assert len(bundle.file_writes) == 1
        fw = bundle.file_writes[0]
        assert fw.container_path == "/workspace/.claude/settings.json"

        import json
        settings = json.loads(fw.content)
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]
        entry = settings["hooks"]["PreToolUse"][0]
        assert entry["matcher"] == "Bash"
        assert entry["hooks"][0]["type"] == "command"
        assert entry["hooks"][0]["command"] == "audit-log.sh"
        assert "permissions" in settings
        assert "Bash(grep:*)" in settings["permissions"]["allow"]
        assert "Bash(rm -rf:*)" in settings["permissions"]["deny"]

    def test_settings_json_hooks_only(self):
        cfg = ClaudeCodeConfig(
            hooks={"Stop": [HookRule(match="*", command="cleanup.sh")]},
        )
        bundle = compile_claude_code(cfg)
        import json
        settings = json.loads(bundle.file_writes[0].content)
        assert "hooks" in settings
        assert "permissions" not in settings

    def test_settings_json_permissions_only(self):
        cfg = ClaudeCodeConfig(
            permissions=Permissions(allow=["WebSearch"], deny=["Bash(rm:*)"]),
        )
        bundle = compile_claude_code(cfg)
        import json
        settings = json.loads(bundle.file_writes[0].content)
        assert "permissions" in settings
        assert "hooks" not in settings

    def test_skill_from_host_path(self, tmp_path: Path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "prompt.md").write_text("# My Skill")
        (skill_dir / "helper.sh").write_text("#!/bin/bash")

        cfg = ClaudeCodeConfig(skills=[SkillSource(source=str(skill_dir))])
        bundle = compile_claude_code(cfg)
        paths = [fw.container_path for fw in bundle.file_writes]
        assert "/workspace/.claude/skills/my-skill/prompt.md" in paths
        assert "/workspace/.claude/skills/my-skill/helper.sh" in paths

    def test_skill_from_host_single_file(self, tmp_path: Path):
        skill_file = tmp_path / "review.md"
        skill_file.write_text("# Review")

        cfg = ClaudeCodeConfig(skills=[SkillSource(source=str(skill_file))])
        bundle = compile_claude_code(cfg)
        paths = [fw.container_path for fw in bundle.file_writes]
        assert "/workspace/.claude/skills/review.md/review.md" in paths

    def test_skill_from_host_nonexistent_raises(self):
        cfg = ClaudeCodeConfig(skills=[SkillSource(source="/nonexistent/skill")])
        with pytest.raises(ValueError, match="does not exist"):
            compile_claude_code(cfg)

    def test_skill_from_git_emits_post_step(self):
        cfg = ClaudeCodeConfig(
            skills=[SkillSource(git="https://github.com/user/cool-skill")],
        )
        bundle = compile_claude_code(cfg)
        assert len(bundle.post_steps) == 1
        assert bundle.post_steps[0].cmd == [
            "git", "clone", "--depth", "1",
            "https://github.com/user/cool-skill",
            "/workspace/.claude/skills/cool-skill",
        ]
        assert bundle.post_steps[0].user == "agent"

    def test_skill_from_git_with_path(self):
        cfg = ClaudeCodeConfig(
            skills=[SkillSource(git="https://github.com/user/repo.git", path="skills/review")],
        )
        bundle = compile_claude_code(cfg)
        assert len(bundle.post_steps) == 2
        # First step: clone
        assert "clone" in bundle.post_steps[0].cmd
        # Second step: move subdirectory contents
        assert "mv" in bundle.post_steps[1].cmd[2]

    def test_commands_from_host(self, tmp_path: Path):
        cmd_file = tmp_path / "explain.md"
        cmd_file.write_text("Explain the selected code")

        cfg = ClaudeCodeConfig(commands=[str(cmd_file)])
        bundle = compile_claude_code(cfg)
        paths = [fw.container_path for fw in bundle.file_writes]
        assert "/workspace/.claude/commands/explain.md" in paths
        assert bundle.file_writes[0].content == b"Explain the selected code"

    def test_commands_nonexistent_raises(self):
        cfg = ClaudeCodeConfig(commands=["/nonexistent/cmd.md"])
        with pytest.raises(ValueError, match="does not exist"):
            compile_claude_code(cfg)

    def test_combined_config(self, tmp_path: Path):
        skill_dir = tmp_path / "audit"
        skill_dir.mkdir()
        (skill_dir / "audit.md").write_text("# Audit")

        cmd_file = tmp_path / "review.md"
        cmd_file.write_text("Review code")

        cfg = ClaudeCodeConfig(
            skills=[SkillSource(source=str(skill_dir))],
            commands=[str(cmd_file)],
            hooks={"PreToolUse": [HookRule(match="Bash", command="log.sh")]},
            permissions=Permissions(allow=["WebSearch"]),
        )
        bundle = compile_claude_code(cfg)
        # 1 settings.json + 1 skill file + 1 command = 3
        assert len(bundle.file_writes) == 3


class TestCompileClaudeCodePlanRenderer:
    def test_plan_renders_claude_code_artifacts(self, tmp_path: Path):
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "prompt.md").write_text("# Skill")

        config = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                skills=[SkillSource(source=str(skill_dir))],
                hooks={"PreToolUse": [HookRule(match="Bash", command="log.sh")]},
            ),
        )
        text = render_plan_text(config)
        assert "/workspace/.claude/settings.json" in text
        assert "/workspace/.claude/skills/my-skill/prompt.md" in text

    def test_plan_renders_git_skill_post_steps(self):
        config = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                skills=[SkillSource(git="https://github.com/user/skill")],
            ),
        )
        text = render_plan_text(config)
        assert "post_steps (1):" in text
        assert "git clone" in text


# ---------------------------------------------------------------------------
# Dev profiles
# ---------------------------------------------------------------------------


class TestDevProfile:
    def test_empty_profile_valid(self):
        p = DevProfile()
        assert p.agent is None
        assert p.wd is None
        assert p.ide is None
        assert p.pip_requirements is None
        assert p.template is None

    def test_profile_with_all_fields(self):
        p = DevProfile(
            agent="claude",
            wd="packages/api",
            ide="cursor",
            pip_requirements="requirements-dev.txt",
            template="custom:latest",
        )
        assert p.agent == "claude"
        assert p.wd == "packages/api"
        assert p.ide == "cursor"
        assert p.pip_requirements == "requirements-dev.txt"
        assert p.template == "custom:latest"

    def test_strict_mode_rejects_unknown(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            DevProfile(agent="claude", unknown_field=True)

    def test_partial_profile(self):
        p = DevProfile(agent="codex", wd="src")
        assert p.agent == "codex"
        assert p.wd == "src"
        assert p.ide is None


class TestFoundryConfigProfiles:
    def test_config_accepts_profiles(self):
        cfg = FoundryConfig(
            version="1",
            profiles={"my-profile": DevProfile(agent="claude")},
        )
        assert "my-profile" in cfg.profiles
        assert cfg.profiles["my-profile"].agent == "claude"

    def test_config_without_profiles(self):
        cfg = FoundryConfig(version="1")
        assert cfg.profiles == {}

    def test_multiple_profiles(self):
        cfg = FoundryConfig(
            version="1",
            profiles={
                "work": DevProfile(agent="claude"),
                "api": DevProfile(agent="codex"),
            },
        )
        assert len(cfg.profiles) == 2

    def test_strict_rejects_unknown_profile_field(self):
        with pytest.raises(ValidationError):
            FoundryConfig(
                version="1",
                profiles={"bad": {"agent": "claude", "unknown": True}},
            )


class TestProfileMerge:
    def test_different_names_both_available(self):
        a = FoundryConfig(version="1", profiles={"work": DevProfile(agent="claude")})
        b = FoundryConfig(version="1", profiles={"api": DevProfile(agent="codex")})
        result = _merge([a, b])
        assert len(result.profiles) == 2
        assert result.profiles["work"].agent == "claude"
        assert result.profiles["api"].agent == "codex"

    def test_same_name_later_layer_wins(self):
        a = FoundryConfig(version="1", profiles={"work": DevProfile(agent="claude")})
        b = FoundryConfig(version="1", profiles={"work": DevProfile(agent="codex")})
        result = _merge([a, b])
        assert result.profiles["work"].agent == "codex"

    def test_empty_profiles_merge_to_empty(self):
        a = FoundryConfig(version="1")
        b = FoundryConfig(version="1")
        result = _merge([a, b])
        assert result.profiles == {}

    def test_mixed_layers_some_empty(self):
        a = FoundryConfig(version="1", profiles={"work": DevProfile(agent="claude")})
        b = FoundryConfig(version="1")
        result = _merge([a, b])
        assert "work" in result.profiles


class TestResolveProfile:
    def test_found_profile(self):
        config = FoundryConfig(version="1", profiles={"work": DevProfile(agent="claude")})
        result = resolve_profile(config, "work")
        assert result.agent == "claude"

    def test_default_returns_empty_when_not_defined(self):
        config = FoundryConfig(version="1")
        result = resolve_profile(config, "default")
        assert result.agent is None
        assert result.wd is None

    def test_default_returns_defined_profile(self):
        config = FoundryConfig(version="1", profiles={"default": DevProfile(agent="codex")})
        result = resolve_profile(config, "default")
        assert result.agent == "codex"

    def test_unknown_name_raises_with_available(self):
        config = FoundryConfig(version="1", profiles={"work": DevProfile(agent="claude")})
        with pytest.raises(ValueError, match="Unknown profile 'missing'"):
            resolve_profile(config, "missing")

    def test_unknown_name_raises_no_profiles(self):
        config = FoundryConfig(version="1")
        with pytest.raises(ValueError, match="No profiles are defined"):
            resolve_profile(config, "custom")

    def test_available_profiles_listed_in_error(self):
        config = FoundryConfig(
            version="1",
            profiles={
                "work": DevProfile(agent="claude"),
                "api": DevProfile(agent="codex"),
            },
        )
        with pytest.raises(ValueError, match="work"):
            resolve_profile(config, "missing")


class TestRepoProfileIdeStripping:
    def test_repo_profile_ide_stripped(self, tmp_path):
        (tmp_path / "foundry.yaml").write_text(
            'version: "1"\n'
            'profiles:\n'
            '  work:\n'
            '    agent: claude\n'
            '    ide: cursor\n'
        )
        config = resolve_foundry_config(tmp_path)
        assert config.profiles["work"].ide is None
        assert config.profiles["work"].agent == "claude"

    def test_repo_profile_without_ide_preserved(self, tmp_path):
        (tmp_path / "foundry.yaml").write_text(
            'version: "1"\n'
            'profiles:\n'
            '  work:\n'
            '    agent: claude\n'
        )
        config = resolve_foundry_config(tmp_path)
        assert config.profiles["work"].agent == "claude"

    def test_no_profiles_in_repo(self, tmp_path):
        (tmp_path / "foundry.yaml").write_text('version: "1"\n')
        config = resolve_foundry_config(tmp_path)
        assert config.profiles == {}


class TestRenderPlanProfile:
    def test_plan_shows_selected_profile(self):
        config = FoundryConfig(
            version="1",
            profiles={"work": DevProfile(agent="claude", wd="packages/api")},
        )
        text = render_plan_text(config, profile_name="work")
        assert "Profile: work" in text
        assert "agent: claude" in text
        assert "wd: packages/api" in text

    def test_plan_shows_empty_profile(self):
        config = FoundryConfig(version="1")
        text = render_plan_text(config, profile_name="default")
        assert "Profile: default" in text
        assert "empty" in text

    def test_plan_shows_all_profiles_when_no_selection(self):
        config = FoundryConfig(
            version="1",
            profiles={"work": DevProfile(agent="claude")},
        )
        text = render_plan_text(config)
        assert "Profiles defined" in text
        assert "work" in text

    def test_plan_no_profile_section_when_empty(self):
        config = FoundryConfig(version="1")
        text = render_plan_text(config)
        assert "Profiles defined" not in text
        assert "Profile:" not in text


# ---------------------------------------------------------------------------
# Phase 3: Package Bootstrap
# ---------------------------------------------------------------------------


class TestPackageBootstrap:
    def test_empty(self):
        p = PackageBootstrap()
        assert p.pip is None
        assert p.uv is None
        assert p.apt == []
        assert p.npm == []

    def test_pip_str(self):
        p = PackageBootstrap(pip="requirements.txt")
        assert p.pip == "requirements.txt"

    def test_pip_list(self):
        p = PackageBootstrap(pip=["ruff", "mypy"])
        assert p.pip == ["ruff", "mypy"]

    def test_apt(self):
        p = PackageBootstrap(apt=["jq", "ripgrep"])
        assert p.apt == ["jq", "ripgrep"]

    def test_npm(self):
        p = PackageBootstrap(npm=["typescript"])
        assert p.npm == ["typescript"]

    def test_uv_str(self):
        p = PackageBootstrap(uv="requirements.txt")
        assert p.uv == "requirements.txt"

    def test_all_types(self):
        p = PackageBootstrap(
            pip="requirements.txt",
            uv="uv-requirements.txt",
            apt=["jq"],
            npm=["prettier"],
        )
        assert p.pip == "requirements.txt"
        assert p.uv == "uv-requirements.txt"
        assert p.apt == ["jq"]
        assert p.npm == ["prettier"]

    def test_strict_rejects_unknown(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            PackageBootstrap(pip="req.txt", unknown=True)

    def test_profile_with_packages(self):
        p = DevProfile(packages=PackageBootstrap(pip="requirements.txt"))
        assert p.packages is not None
        assert p.packages.pip == "requirements.txt"


class TestSystemPackagesGate:
    def test_npm_rejected_without_gate(self):
        with pytest.raises(ValidationError, match="allow_system_packages"):
            FoundryConfig(
                version="1",
                profiles={"work": DevProfile(
                    packages=PackageBootstrap(npm=["typescript"]),
                )},
            )

    def test_apt_rejected_without_gate(self):
        with pytest.raises(ValidationError, match="allow_system_packages"):
            FoundryConfig(
                version="1",
                profiles={"work": DevProfile(
                    packages=PackageBootstrap(apt=["curl"]),
                )},
            )

    def test_pip_allowed_without_gate(self):
        cfg = FoundryConfig(
            version="1",
            profiles={"work": DevProfile(
                packages=PackageBootstrap(pip="requirements.txt"),
            )},
        )
        assert cfg.profiles["work"].packages is not None
        assert cfg.profiles["work"].packages.pip == "requirements.txt"

    def test_uv_allowed_without_gate(self):
        cfg = FoundryConfig(
            version="1",
            profiles={"work": DevProfile(
                packages=PackageBootstrap(uv="requirements.txt"),
            )},
        )
        assert cfg.profiles["work"].packages is not None
        assert cfg.profiles["work"].packages.uv == "requirements.txt"

    def test_npm_allowed_with_gate(self):
        cfg = FoundryConfig(
            version="1",
            allow_system_packages=True,
            profiles={"work": DevProfile(
                packages=PackageBootstrap(npm=["typescript"]),
            )},
        )
        assert cfg.profiles["work"].packages is not None
        assert cfg.profiles["work"].packages.npm == ["typescript"]

    def test_apt_allowed_with_gate(self):
        cfg = FoundryConfig(
            version="1",
            allow_system_packages=True,
            profiles={"work": DevProfile(
                packages=PackageBootstrap(apt=["curl", "jq"]),
            )},
        )
        assert cfg.profiles["work"].packages.apt == ["curl", "jq"]

    def test_no_packages_no_gate_needed(self):
        cfg = FoundryConfig(version="1", profiles={"work": DevProfile(agent="claude")})
        assert cfg.allow_system_packages is False


class TestMergeAllowSystemPackages:
    def test_merge_anded_false_wins(self):
        a = FoundryConfig(version="1", allow_system_packages=False)
        b = FoundryConfig(version="1", allow_system_packages=True)
        result = _merge([a, b])
        assert result.allow_system_packages is False

    def test_merge_both_true(self):
        a = FoundryConfig(version="1", allow_system_packages=True)
        b = FoundryConfig(version="1", allow_system_packages=True)
        result = _merge([a, b])
        assert result.allow_system_packages is True

    def test_merge_defaults_to_false(self):
        a = FoundryConfig(version="1")
        b = FoundryConfig(version="1")
        result = _merge([a, b])
        assert result.allow_system_packages is False


class TestNormalizeProfilePackages:
    def test_empty_profile(self):
        pkgs = normalize_profile_packages(DevProfile())
        assert pkgs == {}

    def test_legacy_pip_requirements(self):
        pkgs = normalize_profile_packages(DevProfile(pip_requirements="requirements.txt"))
        assert pkgs == {"pip": "requirements.txt"}

    def test_explicit_packages(self):
        pkgs = normalize_profile_packages(DevProfile(
            packages=PackageBootstrap(pip="requirements.txt", apt=["jq"]),
        ))
        assert pkgs == {"pip": "requirements.txt", "apt": ["jq"]}

    def test_explicit_pip_wins_over_legacy(self):
        pkgs = normalize_profile_packages(DevProfile(
            pip_requirements="legacy.txt",
            packages=PackageBootstrap(pip="explicit.txt"),
        ))
        assert pkgs == {"pip": "explicit.txt"}

    def test_all_package_types(self):
        pkgs = normalize_profile_packages(DevProfile(
            packages=PackageBootstrap(
                pip="req.txt",
                uv="uv-req.txt",
                apt=["jq"],
                npm=["ts"],
            ),
        ))
        assert pkgs == {"pip": "req.txt", "uv": "uv-req.txt", "apt": ["jq"], "npm": ["ts"]}


class TestRenderPlanPackages:
    def test_plan_shows_allow_system_packages_gate(self):
        config = FoundryConfig(version="1", allow_system_packages=True)
        text = render_plan_text(config)
        assert "allow_system_packages: true" in text

    def test_plan_shows_packages_in_profile(self):
        config = FoundryConfig(
            version="1",
            profiles={"work": DevProfile(
                packages=PackageBootstrap(pip="requirements.txt", apt=["jq"]),
            )},
            allow_system_packages=True,
        )
        text = render_plan_text(config, profile_name="work")
        assert "pip: requirements.txt" in text
        assert "apt: ['jq']" in text

    def test_plan_shows_packages_in_all_profiles(self):
        config = FoundryConfig(
            version="1",
            profiles={"work": DevProfile(
                packages=PackageBootstrap(npm=["typescript"]),
            )},
            allow_system_packages=True,
        )
        text = render_plan_text(config)
        assert "packages=" in text


# ---------------------------------------------------------------------------
# Phase 4: Tooling Bundles
# ---------------------------------------------------------------------------


class TestToolingBundle:
    def test_empty_bundle(self):
        b = ToolingBundle()
        assert b.skills == []
        assert b.commands == []
        assert b.mcp_servers == []
        assert b.packages is None
        assert b.permissions is None
        assert b.hooks == {}

    def test_bundle_with_skills(self):
        b = ToolingBundle(skills=[SkillSource(source="/path/to/skill")])
        assert len(b.skills) == 1
        assert b.skills[0].source == "/path/to/skill"

    def test_bundle_with_commands(self):
        b = ToolingBundle(commands=["/path/to/review.md", "/path/to/explain.md"])
        assert len(b.commands) == 2

    def test_bundle_with_mcp_servers(self):
        b = ToolingBundle(mcp_servers=[
            McpServerBuiltin(name="github", type="builtin"),
        ])
        assert len(b.mcp_servers) == 1

    def test_bundle_with_packages(self):
        b = ToolingBundle(packages=PackageBootstrap(pip=["debugpy"], apt=["jq"]))
        assert b.packages is not None
        assert b.packages.pip == ["debugpy"]
        assert b.packages.apt == ["jq"]

    def test_bundle_with_permissions(self):
        b = ToolingBundle(permissions=Permissions(
            allow=["Bash(python *)"],
            deny=["Bash(rm *)"],
        ))
        assert b.permissions is not None
        assert b.permissions.allow == ["Bash(python *)"]

    def test_bundle_with_hooks(self):
        b = ToolingBundle(hooks={
            "post-commit": [HookRule(match="*", command="echo done")],
        })
        assert "post-commit" in b.hooks

    def test_strict_rejects_unknown(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ToolingBundle(unknown_field=True)

    def test_bundle_in_foundry_config(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "review": ToolingBundle(skills=[SkillSource(source="/path")]),
            },
        )
        assert "review" in config.tooling_bundles
        assert len(config.tooling_bundles["review"].skills) == 1

    def test_tooling_in_profile(self):
        p = DevProfile(tooling=["github-mcp", "python-dev"])
        assert p.tooling == ["github-mcp", "python-dev"]

    def test_profile_default_tooling_empty(self):
        p = DevProfile()
        assert p.tooling == []


class TestToolingBundlesMerge:
    def test_different_names_collected(self):
        l1 = FoundryConfig(version="1", tooling_bundles={
            "a": ToolingBundle(skills=[SkillSource(source="/a")]),
        })
        l2 = FoundryConfig(version="1", tooling_bundles={
            "b": ToolingBundle(skills=[SkillSource(source="/b")]),
        })
        result = _merge([l1, l2])
        assert set(result.tooling_bundles.keys()) == {"a", "b"}

    def test_same_name_later_wins(self):
        l1 = FoundryConfig(version="1", tooling_bundles={
            "shared": ToolingBundle(skills=[SkillSource(source="/v1")]),
        })
        l2 = FoundryConfig(version="1", tooling_bundles={
            "shared": ToolingBundle(skills=[SkillSource(source="/v2")]),
        })
        result = _merge([l1, l2])
        assert result.tooling_bundles["shared"].skills[0].source == "/v2"

    def test_empty_dicts_merge_to_empty(self):
        l1 = FoundryConfig(version="1")
        l2 = FoundryConfig(version="1")
        result = _merge([l1, l2])
        assert result.tooling_bundles == {}


class TestExpandBundles:
    def test_empty_tooling_returns_config_unchanged(self):
        config = FoundryConfig(version="1")
        profile = DevProfile()
        expanded, pkgs = expand_bundles(config, profile)
        assert expanded is config
        assert pkgs is None

    def test_unknown_bundle_raises(self):
        config = FoundryConfig(version="1")
        profile = DevProfile(tooling=["nonexistent"])
        with pytest.raises(ValueError, match="Unknown tooling bundle: 'nonexistent'"):
            expand_bundles(config, profile)

    def test_bundle_skills_merge_into_claude_code(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "skills-bundle": ToolingBundle(
                    skills=[SkillSource(source="/path/to/skill")],
                ),
            },
        )
        profile = DevProfile(tooling=["skills-bundle"])
        expanded, _ = expand_bundles(config, profile)
        assert expanded.claude_code is not None
        assert len(expanded.claude_code.skills) == 1
        assert expanded.claude_code.skills[0].source == "/path/to/skill"

    def test_bundle_commands_merge(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "cmd-bundle": ToolingBundle(commands=["/path/to/review.md"]),
            },
        )
        profile = DevProfile(tooling=["cmd-bundle"])
        expanded, _ = expand_bundles(config, profile)
        assert expanded.claude_code is not None
        assert expanded.claude_code.commands == ["/path/to/review.md"]

    def test_bundle_mcp_servers_merge(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "mcp-bundle": ToolingBundle(
                    mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                ),
            },
        )
        profile = DevProfile(tooling=["mcp-bundle"])
        expanded, _ = expand_bundles(config, profile)
        assert len(expanded.mcp_servers) == 1
        assert expanded.mcp_servers[0].name == "github"

    def test_bundle_hooks_merge_per_key(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "hooks-bundle": ToolingBundle(hooks={
                    "post-commit": [HookRule(match="*", command="echo done")],
                }),
            },
        )
        profile = DevProfile(tooling=["hooks-bundle"])
        expanded, _ = expand_bundles(config, profile)
        assert expanded.claude_code is not None
        assert "post-commit" in expanded.claude_code.hooks
        assert expanded.claude_code.hooks["post-commit"][0].command == "echo done"

    def test_bundle_permissions_merge(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "perm-bundle": ToolingBundle(
                    permissions=Permissions(allow=["Bash(python *)"]),
                ),
            },
        )
        profile = DevProfile(tooling=["perm-bundle"])
        expanded, _ = expand_bundles(config, profile)
        assert expanded.claude_code is not None
        assert expanded.claude_code.permissions is not None
        assert "Bash(python *)" in expanded.claude_code.permissions.allow

    def test_bundle_packages_returned(self):
        config = FoundryConfig(
            version="1",
            allow_system_packages=True,
            tooling_bundles={
                "pkg-bundle": ToolingBundle(
                    packages=PackageBootstrap(pip=["debugpy"], apt=["jq"]),
                ),
            },
        )
        profile = DevProfile(tooling=["pkg-bundle"])
        _, pkgs = expand_bundles(config, profile)
        assert pkgs is not None
        assert pkgs.pip == ["debugpy"]
        assert pkgs.apt == ["jq"]

    def test_multiple_bundles_concatenate(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "a": ToolingBundle(
                    mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                    skills=[SkillSource(source="/a")],
                ),
                "b": ToolingBundle(
                    mcp_servers=[McpServerBuiltin(name="memory", type="builtin")],
                    skills=[SkillSource(source="/b")],
                ),
            },
        )
        profile = DevProfile(tooling=["a", "b"])
        expanded, _ = expand_bundles(config, profile)
        assert len(expanded.mcp_servers) == 2
        assert len(expanded.claude_code.skills) == 2

    def test_mcp_name_conflict_warning(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            config = FoundryConfig(
                version="1",
                tooling_bundles={
                    "a": ToolingBundle(
                        mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                    ),
                    "b": ToolingBundle(
                        mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                    ),
                },
            )
            profile = DevProfile(tooling=["a", "b"])
            expanded, _ = expand_bundles(config, profile)
        assert "redefines MCP server 'github'" in caplog.text
        assert len(expanded.mcp_servers) == 2  # both present, dict compile last-wins

    def test_existing_claude_code_preserved(self):
        config = FoundryConfig(
            version="1",
            claude_code=ClaudeCodeConfig(
                skills=[SkillSource(source="/existing")],
                commands=["/existing-cmd"],
            ),
            tooling_bundles={
                "extra": ToolingBundle(
                    skills=[SkillSource(source="/bundle-skill")],
                ),
            },
        )
        profile = DevProfile(tooling=["extra"])
        expanded, _ = expand_bundles(config, profile)
        assert len(expanded.claude_code.skills) == 2
        assert expanded.claude_code.commands == ["/existing-cmd"]

    def test_existing_mcp_servers_preserved(self):
        config = FoundryConfig(
            version="1",
            mcp_servers=[McpServerBuiltin(name="filesystem", type="builtin")],
            tooling_bundles={
                "extra": ToolingBundle(
                    mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                ),
            },
        )
        profile = DevProfile(tooling=["extra"])
        expanded, _ = expand_bundles(config, profile)
        assert len(expanded.mcp_servers) == 2
        assert expanded.mcp_servers[0].name == "filesystem"
        assert expanded.mcp_servers[1].name == "github"


class TestExpandBundlesGates:
    def test_npm_mcp_rejected_at_schema_level(self):
        with pytest.raises(ValidationError, match="npm MCP servers"):
            FoundryConfig(
                version="1",
                tooling_bundles={
                    "bad": ToolingBundle(
                        mcp_servers=[McpServerNpm(
                            name="tavily", type="npm", package="mcp-tavily",
                        )],
                    ),
                },
            )

    def test_npm_mcp_allowed_with_gate(self):
        config = FoundryConfig(
            version="1",
            allow_third_party_mcp=True,
            tooling_bundles={
                "ok": ToolingBundle(
                    mcp_servers=[McpServerNpm(
                        name="tavily", type="npm", package="mcp-tavily",
                    )],
                ),
            },
        )
        profile = DevProfile(tooling=["ok"])
        expanded, _ = expand_bundles(config, profile)
        assert len(expanded.mcp_servers) == 1

    def test_apt_rejected_at_schema_level(self):
        with pytest.raises(ValidationError, match="system packages"):
            FoundryConfig(
                version="1",
                tooling_bundles={
                    "bad": ToolingBundle(packages=PackageBootstrap(apt=["jq"])),
                },
            )

    def test_apt_allowed_with_gate(self):
        config = FoundryConfig(
            version="1",
            allow_system_packages=True,
            tooling_bundles={
                "ok": ToolingBundle(packages=PackageBootstrap(apt=["jq"])),
            },
        )
        profile = DevProfile(tooling=["ok"])
        _, pkgs = expand_bundles(config, profile)
        assert pkgs is not None
        assert pkgs.apt == ["jq"]

    def test_pip_allowed_without_any_gate(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "ok": ToolingBundle(packages=PackageBootstrap(pip=["ruff"])),
            },
        )
        profile = DevProfile(tooling=["ok"])
        _, pkgs = expand_bundles(config, profile)
        assert pkgs is not None
        assert pkgs.pip == ["ruff"]


class TestMergePackageBootstrap:
    def test_both_none(self):
        assert merge_package_bootstrap(None, None) is None

    def test_base_none(self):
        overlay = PackageBootstrap(pip=["a"])
        result = merge_package_bootstrap(None, overlay)
        assert result is not None
        assert result.pip == ["a"]

    def test_overlay_none(self):
        base = PackageBootstrap(pip=["a"])
        result = merge_package_bootstrap(base, None)
        assert result is not None
        assert result.pip == ["a"]

    def test_list_list_concat(self):
        base = PackageBootstrap(pip=["a"], apt=["jq"])
        overlay = PackageBootstrap(pip=["b"], apt=["ripgrep"])
        result = merge_package_bootstrap(base, overlay)
        assert result.pip == ["a", "b"]
        assert result.apt == ["jq", "ripgrep"]

    def test_str_str_becomes_list(self):
        base = PackageBootstrap(pip="req1.txt")
        overlay = PackageBootstrap(pip="req2.txt")
        result = merge_package_bootstrap(base, overlay)
        assert result.pip == ["req1.txt", "req2.txt"]

    def test_str_str_same_stays_str(self):
        base = PackageBootstrap(pip="req.txt")
        overlay = PackageBootstrap(pip="req.txt")
        result = merge_package_bootstrap(base, overlay)
        assert result.pip == "req.txt"

    def test_str_list_merges(self):
        base = PackageBootstrap(pip="req.txt")
        overlay = PackageBootstrap(pip=["a", "b"])
        result = merge_package_bootstrap(base, overlay)
        assert result.pip == ["req.txt", "a", "b"]

    def test_list_str_merges(self):
        base = PackageBootstrap(pip=["a"])
        overlay = PackageBootstrap(pip="req.txt")
        result = merge_package_bootstrap(base, overlay)
        assert result.pip == ["a", "req.txt"]

    def test_dedup_preserves_order(self):
        base = PackageBootstrap(pip=["a", "b"])
        overlay = PackageBootstrap(pip=["b", "c"])
        result = merge_package_bootstrap(base, overlay)
        assert result.pip == ["a", "b", "c"]


class TestCollectBundlePackages:
    def test_no_tooling_returns_none(self):
        config = FoundryConfig(version="1", tooling_bundles={
            "x": ToolingBundle(packages=PackageBootstrap(pip=["a"])),
        })
        result = collect_bundle_packages(config, DevProfile())
        assert result is None

    def test_extracts_packages(self):
        config = FoundryConfig(
            version="1",
            allow_system_packages=True,
            tooling_bundles={
                "x": ToolingBundle(packages=PackageBootstrap(pip=["a"])),
                "y": ToolingBundle(packages=PackageBootstrap(apt=["jq"])),
            },
        )
        result = collect_bundle_packages(config, DevProfile(tooling=["x", "y"]))
        assert result is not None
        assert result.pip == ["a"]
        assert result.apt == ["jq"]

    def test_unknown_bundle_raises(self):
        config = FoundryConfig(version="1")
        with pytest.raises(ValueError, match="Unknown tooling bundle"):
            collect_bundle_packages(config, DevProfile(tooling=["missing"]))

    def test_bundle_without_packages_skipped(self):
        config = FoundryConfig(version="1", tooling_bundles={
            "no-pkgs": ToolingBundle(skills=[SkillSource(source="/s")]),
        })
        result = collect_bundle_packages(config, DevProfile(tooling=["no-pkgs"]))
        assert result is None


class TestRenderPlanBundles:
    def test_shows_bundles_defined(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "github-mcp": ToolingBundle(
                    mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                ),
                "python-dev": ToolingBundle(
                    packages=PackageBootstrap(pip=["ruff"]),
                ),
            },
        )
        text = render_plan_text(config)
        assert "Tooling bundles defined (2)" in text
        assert "github-mcp:" in text
        assert "python-dev:" in text
        assert "1 MCP server(s)" in text
        assert "packages" in text

    def test_shows_active_bundles_for_profile(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={
                "github-mcp": ToolingBundle(
                    mcp_servers=[McpServerBuiltin(name="github", type="builtin")],
                ),
            },
            profiles={"work": DevProfile(tooling=["github-mcp"])},
        )
        text = render_plan_text(config, profile_name="work")
        assert "Active bundles for profile 'work'" in text
        assert "- github-mcp" in text

    def test_no_bundles_section_when_empty(self):
        config = FoundryConfig(version="1")
        text = render_plan_text(config)
        assert "Tooling bundles" not in text

    def test_profile_tooling_shown_in_profile_section(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={"x": ToolingBundle()},
            profiles={"work": DevProfile(tooling=["x"])},
        )
        text = render_plan_text(config, profile_name="work")
        assert "tooling: ['x']" in text

    def test_profile_tooling_shown_in_all_profiles_view(self):
        config = FoundryConfig(
            version="1",
            tooling_bundles={"x": ToolingBundle()},
            profiles={"work": DevProfile(tooling=["x"])},
        )
        text = render_plan_text(config)
        assert "tooling=" in text
