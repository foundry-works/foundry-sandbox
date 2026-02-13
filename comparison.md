# foundry-sandbox vs egg

## Common Ground

- Both isolate an untrusted agent container from real credentials using a trusted proxy/gateway.
- Both enforce network and git policy controls in infrastructure, not only through prompts.
- Both are Docker + Python heavy and include strong security/integration test coverage.

## Key Differences

### Primary goal

- `foundry-sandbox`: secure, ephemeral local coding workspaces for day-to-day AI-assisted development.
- `egg`: structurally enforced issue-to-PR SDLC pipeline with mandatory human gates.

### Control model

- `foundry-sandbox`: emphasizes environment hardening (read-only root, allowlist egress, worktree/branch isolation, git safety).
- `egg`: adds process governance (phase permissions, role-based contract mutations, blocked self-merge path).

### Runtime topology

- `foundry-sandbox`: single `dev` container, optional `unified-proxy` in credential-isolation mode.
- `egg`: `gateway` + `orchestrator` services by default, with sandbox containers managed around pipeline state.

### Workflow style

- `foundry-sandbox`: operator-driven loop (`cast new`, attach, develop, push, optional PR).
- `egg`: GitHub-driven phased automation (refine -> plan -> implement -> human merge), with HITL checkpoints.

### Defaults and modes

- `foundry-sandbox`: credential isolation enabled by default; network modes tuned for sandbox safety.
- `egg`: public mode is default, private mode is opt-in for stricter network lockdown.

### Tooling focus

- `foundry-sandbox`: multi-tool AI runtime (Claude, Gemini, Codex, OpenCode).
- `egg`: SDLC contract/checkpoint + orchestration features centered on autonomous delivery workflows.

## Major Security Feature Gaps (Both Directions)

### Security/process features in `egg` that are not core in `foundry-sandbox`

- Phase-gated operation enforcement by SDLC stage (`refine`, `plan`, `implement`, `pr`) with policy blocks per phase.
- Role-based contract mutation with field-level ownership (`implementer`, `reviewer`, `human`).
- Formal HITL approval/decision workflow that gates phase transitions.
- Contract-centric SDLC state plus checkpoint/audit workflow tied to issue progression.

### Environment-hardening features in `foundry-sandbox` that are not core in `egg`

- Read-only root filesystem as a default hard boundary for the dev container.
- Explicit capability dropping (`NET_RAW`) on sandbox/proxy containers as a first-class control.
- Strong branch isolation model in credential-isolation mode with deny-by-default ref validation.
- SHA reachability checks to prevent access to commits outside allowed branches.
- Ref/output filtering that hides unauthorized branches.
- Fail-closed behavior when branch identity metadata is missing.

### Not a gap: present in both

- Self-merge prevention is enforced in both systems.
- `egg` blocks this by having no merge endpoint in gateway policy.
- `foundry-sandbox` blocks GitHub merge and auto-merge endpoints in proxy policy.

## Practical Fit

- Choose `foundry-sandbox` when you want a hardened local AI coding sandbox with fast ephemeral branches.
- Choose `egg` when you want governed autonomous delivery with explicit phase enforcement, role separation, and auditability.
