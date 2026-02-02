# Install Tavily MCP in Sandbox

## Mission

Install and configure the Tavily MCP server for all four AI coding tools (Claude Code, OpenCode, Codex CLI, Gemini CLI) in the sandbox environment.

## Objective

Install the Tavily MCP server into the sandbox environment and configure it for all four AI coding tools, enabling web search and content extraction capabilities for AI agents.

## Background

**Tavily MCP Requirements** (from [docs.tavily.com](https://docs.tavily.com/documentation/mcp)):
- Node.js package: `tavily-mcp` (latest: 0.1.3)
- Requires `TAVILY_API_KEY` environment variable
- Provides web search and extraction tools for AI agents

**Current Sandbox Status**:
- `TAVILY_API_KEY` is already passed to containers (docker-compose.yml:61)
- foundry-mcp is already configured for Claude Code and OpenCode

**MCP Support by Tool**:
| Tool | MCP Support | Config Location | Format |
|------|-------------|-----------------|--------|
| Claude Code | Yes | `~/.claude.json` | JSON: `mcpServers` |
| OpenCode | Yes | `~/.config/opencode/opencode.json` | JSON: `mcp` |
| Codex CLI | Yes | `~/.codex/config.toml` | TOML: `[mcp_servers.*]` |
| Gemini CLI | Yes | `~/.gemini/settings.json` | JSON: `mcpServers` |

## Scope

### In Scope
- Install tavily-mcp npm package globally in Docker image
- Configure tavily-mcp for Claude Code (both config files + permissions)
- Configure tavily-mcp for OpenCode (post-merge patch)
- Configure tavily-mcp for Codex CLI (TOML config)
- Configure tavily-mcp for Gemini CLI (JSON config)
- Add auto-approval permissions for tavily-mcp tools

### Out of Scope
- Changes to TAVILY_API_KEY environment variable handling (already working)
- Modifications to foundry-mcp research provider configuration
- Testing on actual Tavily API (requires valid API key)

## Phases

### Phase 1: Install tavily-mcp Package

**Purpose**: Add the tavily-mcp npm package to the Docker image so it's available globally in containers.

**Tasks**:
1. Modify Dockerfile to add `tavily-mcp` to the global npm install block (alongside claude-code, gemini-cli, etc.)

**File Changes**:
- `Dockerfile`: Add `&& npm install -g tavily-mcp` to the npm install block

**Verification**:
- Build image successfully
- `which tavily-mcp` returns `/usr/local/bin/tavily-mcp` in container

### Phase 2: Configure Claude Code Integration

**Purpose**: Register tavily-mcp as an MCP server for Claude Code and add auto-approval permissions.

**Tasks**:
1. Update `ensure_foundry_mcp_config()` in `lib/container_config.sh` to add tavily-mcp to mcpServers
2. Update `ensure_claude_foundry_mcp()` in `lib/container_config.sh` to handle tavily-mcp registration in both `~/.claude.json` and `~/.claude/.claude.json`
3. Add tavily-mcp tool pattern to allowlist in `lib/permissions.sh`

**Configuration Format** (Claude Code):
```json
{
  "mcpServers": {
    "tavily-mcp": {
      "command": "tavily-mcp",
      "args": []
    }
  }
}
```

**Permissions Pattern**:
```
"mcp__tavily-mcp__*"
```

**File Changes**:
- `lib/container_config.sh`: Update `ensure_foundry_mcp_config()` and related functions
- `lib/permissions.sh`: Add Tavily MCP tool pattern to FOUNDRY_ALLOW list

**Verification**:
- `cat ~/.claude.json | jq '.mcpServers["tavily-mcp"]'` shows config
- `cat ~/.claude/.claude.json | jq '.mcpServers["tavily-mcp"]'` shows config
- Permissions include tavily pattern

### Phase 3: Configure OpenCode Integration

**Purpose**: Add tavily-mcp to OpenCode's MCP configuration via post-merge patch.

**Tasks**:
1. Add post-merge patch step after `sync_opencode_foundry()` in `lib/container_config.sh` to inject tavily-mcp into OpenCode config
2. Ensure patch runs in both normal and quiet container setup flows

**Configuration Format** (OpenCode - note array format for command):
```json
{
  "mcp": {
    "tavily-mcp": {
      "command": ["tavily-mcp"]
    }
  }
}
```

**File Changes**:
- `lib/container_config.sh`: Add patch function after `sync_opencode_foundry()` calls

**Verification**:
- `cat ~/.config/opencode/opencode.json | jq '.mcp["tavily-mcp"]'` shows config

### Phase 4: Configure Codex CLI Integration

**Purpose**: Add tavily-mcp to Codex CLI's TOML configuration.

**Tasks**:
1. Extend `ensure_codex_config()` in `lib/container_config.sh` to add `[mcp_servers.tavily-mcp]` TOML section

**Configuration Format** (Codex CLI - TOML):
```toml
[mcp_servers.tavily-mcp]
command = "tavily-mcp"
args = []
```

**File Changes**:
- `lib/container_config.sh`: Update `ensure_codex_config()` Python block

**Verification**:
- `grep -A2 '\[mcp_servers.tavily-mcp\]' ~/.codex/config.toml` shows config

### Phase 5: Configure Gemini CLI Integration

**Purpose**: Add tavily-mcp to Gemini CLI's settings.

**Tasks**:
1. Modify `ensure_gemini_settings()` in `lib/container_config.sh` to add tavily-mcp to mcpServers

**Configuration Format** (Gemini CLI):
```json
{
  "mcpServers": {
    "tavily-mcp": {
      "command": "tavily-mcp",
      "args": []
    }
  }
}
```

**File Changes**:
- `lib/container_config.sh`: Update `ensure_gemini_settings()` Python block

**Verification**:
- `cat ~/.gemini/settings.json | jq '.mcpServers["tavily-mcp"]'` shows config

### Phase 6: Integration Verification

**Purpose**: Verify all configurations work end-to-end.

**Tasks**:
1. Build the updated Docker image
2. Create a test sandbox
3. Verify tavily-mcp binary is installed
4. Verify all four tool configurations are correct
5. Document verification commands

**Verification**:
```bash
# Build and create sandbox
./sandbox.sh build
./sandbox.sh new test-tavily

# Verify installation
which tavily-mcp  # /usr/local/bin/tavily-mcp

# Verify Claude Code
cat ~/.claude.json | jq '.mcpServers["tavily-mcp"]'
cat ~/.claude/.claude.json | jq '.mcpServers["tavily-mcp"]'

# Verify OpenCode
cat ~/.config/opencode/opencode.json | jq '.mcp["tavily-mcp"]'

# Verify Codex CLI
grep -A2 '\[mcp_servers.tavily-mcp\]' ~/.codex/config.toml

# Verify Gemini CLI
cat ~/.gemini/settings.json | jq '.mcpServers["tavily-mcp"]'
```

## Files to Modify Summary

| File | Changes |
|------|---------|
| `Dockerfile` | Add `tavily-mcp` to the global npm install block |
| `lib/container_config.sh` | Update `ensure_foundry_mcp_config()`, `ensure_claude_foundry_mcp()`, add OpenCode post-merge patch, update `ensure_codex_config()`, update `ensure_gemini_settings()` |
| `lib/permissions.sh` | Add Tavily MCP tool pattern to FOUNDRY_ALLOW list |

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| tavily-mcp package name differs from expected | Medium | Verify exact package name from npm registry before implementation |
| Config format incompatibilities | Medium | Test each tool individually after configuration |
| Permission pattern format incorrect | Low | Follow existing foundry-mcp pattern exactly |
| OpenCode command array format causes issues | Low | Test OpenCode specifically, as it differs from other tools |

## Assumptions

- `TAVILY_API_KEY` environment variable handling is already working (docker-compose.yml:61)
- The npm package name is `tavily-mcp` (verify from docs.tavily.com)
- All four AI tools support the standard MCP server protocol
- Container has network access to npm registry during build

## Success Criteria

- [ ] tavily-mcp package is installed globally in Docker image
- [ ] Claude Code can discover and use tavily-mcp tools
- [ ] OpenCode can discover and use tavily-mcp tools
- [ ] Codex CLI can discover and use tavily-mcp tools
- [ ] Gemini CLI can discover and use tavily-mcp tools
- [ ] Tavily tools are auto-approved (no permission prompts) in Claude Code
- [ ] All verification commands pass in a fresh sandbox

## Sources

- [Tavily MCP Documentation](https://docs.tavily.com/documentation/mcp)
- [OpenAI Codex MCP Configuration](https://developers.openai.com/codex/mcp/)
- [Gemini CLI MCP Servers](https://geminicli.com/docs/tools/mcp-server/)
