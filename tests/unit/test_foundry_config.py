"""Unit tests for foundry_sandbox.foundry_config — Phase 1 schema, resolver, merge."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from foundry_sandbox.foundry_config import (
    ClaudeCodeConfig,
    FileRestrictionsAdd,
    FoundryConfig,
    GitSafetyOverlay,
    HookRule,
    McpServerBuiltin,
    McpServerNpm,
    McpServerProxy,
    Permissions,
    ProtectedBranchesAdd,
    SkillSource,
    UserService,
    _merge,
    _resolve_host_refs,
    collect_secret_refs,
    compile_claude_code,
    compile_git_safety,
    compile_mcp_servers,
    compile_user_services,
    render_plan_text,
    resolve_foundry_config,
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
        config = resolve_foundry_config(tmp_path)
        assert config.version == "1"
        assert config.git_safety is None

    def test_invalid_schema_returns_none(self, tmp_path: Path):
        (tmp_path / "foundry.yaml").write_text('version: "1"\nunknown_key: true')
        config = resolve_foundry_config(tmp_path)
        assert config.version == "1"


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
