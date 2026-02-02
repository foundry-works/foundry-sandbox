
<foundry-instructions>

# Foundry

Spec-driven development (SDD) toolkit. Plan before code, verify against spec.

## Workflow

```
foundry-spec → foundry-implement → [CODE] → foundry-review → foundry-test → foundry-pr
```

**Supporting skill:** foundry-refactor (LSP-powered refactoring)

## Skill Selection

### Core Workflow

| Skill | Invoke When | Skip If |
|-------|-------------|---------|
| `foundry-spec` | New feature, multi-file refactor, API integration, architecture change | Single-file edit, trivial fix, exploratory spike |
| `foundry-implement` | Spec active, need next task, resume work, track progress | No spec, need to plan new work (use spec first) |
| `foundry-review` | Phase complete, before PR, audit task compliance | Need to run tests (use test), finding tasks (use implement) |
| `foundry-test` | Test failure unclear, need AI diagnosis, systematic debugging | Simple test run, tests pass, obvious failure |
| `foundry-pr` | Spec complete, comprehensive PR needed | Quick change, no spec (use `gh` directly) |
| `foundry-refactor` | Rename/extract/move across files, cleanup unused code | Single-file edit, new code, formatting |

### Supporting

| Skill | Invoke When | Skip If |
|-------|-------------|---------|
| `foundry-note` | User asks to capture/list/dismiss ideas | Autonomous capture during impl (use authoring tool) |
| `foundry-setup` | First foundry use, setup environment | Already configured |
| `foundry-research` | Need AI consultation, multiple perspectives, investigation | Simple questions, no research needed |

### Research (`foundry-research`)

| Signal | Workflow |
|--------|----------|
| Follow-up, iteration | `chat` |
| Multiple perspectives needed | `consensus` |
| Complex investigation | `thinkdeep` |
| Brainstorming | `ideate` |
| Web research, multiple sources, deep research | `deep` |

## Key Patterns

**MCP-First**: All skills use Foundry MCP tools exclusively. No CLI fallbacks.

**Human-in-Loop**: Skills prompt for key decisions. Don't assume - ask.

**Task States**: `pending` → `in_progress` → `completed` | `blocked`
- **Sequential mode** (interactive, autonomous): Only one task `in_progress` at a time
- **Parallel mode** (`--parallel`): Multiple tasks `in_progress` during batch execution
- Mark tasks complete immediately after finishing

**Safety**: Use dry-run previews before spec modifications. Backups created automatically.

**Context Flow**: Spec metadata (journals, dependencies, completion notes) passes through the workflow.

**Note (Autonomous Capture)**: Proactively add notes when encountering issues - do NOT prompt the user:
- MCP tool errors or unexpected failures → `[Error]`
- Missing/wished-for tools → `[Feature]`
- Confusing behavior or documentation gaps → `[Docs]`
- Ideas beyond current scope → `[Idea]`

Use `authoring` MCP tool with `action="intake-add"` to capture notes programmatically.

User can invoke `foundry-note` skill for manual capture or list pending items.

## Common Workflows

### Workflow Selection

| User Signal | Entry Point |
|-------------|-------------|
| "Build X", "Add feature Y" (multi-file) | Starting New Work |
| "Continue", "What's next?", spec exists | Resuming Active Work |
| "Done with phase", "Ready for PR" | Completing a Phase |
| "First time", "Setup foundry" | Run `foundry-setup` |

### Starting New Work
1. Invoke `foundry-spec` - creates spec in `specs/pending/`
2. Review and refine spec (plan-review and modify are built into foundry-spec)
3. Activate spec (moves to `specs/active/`)

### Resuming Active Work
1. Use `foundry-implement` to find next actionable task
2. Implement the task
3. Complete task via `foundry-implement` workflow (tracks progress automatically)
4. Continue until phase complete

### Completing a Phase
1. Run `foundry-review` to verify implementation matches spec
2. Execute `foundry-test` to validate functionality
3. Create PR with `foundry-pr` when ready

## Codebase Exploration

Launch the Explore tool before skill invocation when you need:
- Codebase context for planning (`foundry-spec`)
- Understanding existing patterns before implementation
- Finding related files for fidelity review

Example: Before `foundry-spec`, launch Explore tool to understand existing architecture.

</foundry-instructions>
