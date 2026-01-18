# Spec Lifecycle

This reference describes spec folder structure and lifecycle transitions.

## Folder Structure

```
specs/
├── pending/      # Backlog - planned but not activated
├── active/       # Currently being implemented
├── completed/    # Finished and verified
└── archived/     # Old or superseded
```

## Lifecycle States

| Folder | Description |
|--------|-------------|
| `pending` | Specs in backlog, not yet started |
| `active` | Specs currently being implemented |
| `completed` | All tasks done, verified, ready for PR |
| `archived` | Superseded or abandoned specs |

## State Transitions

```
pending → active → completed
    ↓                  ↓
    └──→ archived ←────┘
```

## Activate from Pending

Move a spec from pending/ to active/ when ready to start work:

```bash
mcp__plugin_foundry_foundry-mcp__lifecycle action="activate" spec_id={spec-id}
```

This:
- Moves spec file to `specs/active/`
- Updates metadata status to "active"
- Makes spec visible to foundry-implement

## Complete a Spec

When all phases are verified and complete:

```bash
mcp__plugin_foundry_foundry-mcp__lifecycle action="complete" spec_id={spec-id}
```

This:
- Moves spec file to `specs/completed/`
- Updates metadata status to "completed"
- Records completion timestamp
- Regenerates documentation

## Archive a Spec

Move specs that are no longer relevant:

```bash
mcp__plugin_foundry_foundry-mcp__lifecycle action="move" spec_id={spec-id} to_folder="archived"
```

**Archive when:**
- Spec is superseded by a newer version
- Feature was cancelled
- Spec is no longer relevant

## Manual Move

Move spec to any folder:

```bash
mcp__plugin_foundry_foundry-mcp__lifecycle action="move" spec_id={spec-id} to_folder="pending"
```

**Valid folders:** `pending`, `active`, `completed`, `archived`

## Git & PR Handoff

When a spec is completed:
- Local commits are managed during task completion
- Push to remote with `git push -u origin <branch>`
- Use `foundry-pr` skill for pull request creation

**Note:** The lifecycle tools handle spec movement; PR creation is a separate workflow.

## Best Practices

1. **One active spec per feature** - Avoid multiple active specs for same work
2. **Archive don't delete** - Keep history for reference
3. **Complete when done** - Move to completed after all verification passes
4. **Activate when ready** - Only activate specs you're about to work on
