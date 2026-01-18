# Task Lifecycle

This reference describes task status transitions and lifecycle management.

## Task States

| Status | Description |
|--------|-------------|
| `pending` | Not yet started |
| `in_progress` | Currently being worked on |
| `completed` | Successfully finished |
| `blocked` | Cannot proceed due to dependencies or issues |

## State Transitions

```
pending → in_progress → completed
    ↓          ↓
    └──→ blocked ──→ in_progress
```

## Starting a Task

Mark a task as in_progress when you begin work:

```bash
mcp__plugin_foundry_foundry-mcp__task action="start" spec_id={spec-id} task_id={task-id}
```

The MCP tool automatically records the start timestamp.

## Completing a Task

Use `task action="complete"` to atomically mark complete AND create a journal entry:

```bash
mcp__plugin_foundry_foundry-mcp__task action="complete" spec_id={spec-id} task_id={task-id} completion_note="Summary of what was accomplished"
```

**What `task action="complete"` does automatically:**
1. Updates task status to `completed`
2. Records completion timestamp
3. Creates a journal entry documenting the completion
4. Clears the `needs_journaling` flag
5. Syncs metadata and recalculates progress
6. Automatically journals parent nodes (phases, groups) that auto-complete

### Parent Node Journaling

When completing a task causes parent nodes to auto-complete:
- **Automatic detection**: System detects when all child tasks are completed
- **Automatic journaling**: Creates journal entries for each auto-completed parent
- **No manual action needed**: You don't need to manually journal parent completions
- **Hierarchical**: Works for multiple levels

## Handling Blockers

### Mark Task as Blocked

When a task cannot proceed:

```bash
mcp__plugin_foundry_foundry-mcp__task action="block" spec_id={spec-id} task_id={task-id} reason="Description of blocker" blocker_type={type} ticket="TICKET-123"
```

**Blocker types:**
- `dependency` - Waiting on external dependency
- `technical` - Technical issue blocking progress
- `resource` - Resource unavailability
- `decision` - Awaiting architectural/product decision

### Unblock Task

When blocker is resolved:

```bash
mcp__plugin_foundry_foundry-mcp__task action="unblock" spec_id={spec-id} task_id={task-id} resolution="Description of how it was resolved"
```

### List All Blockers

```bash
mcp__plugin_foundry_foundry-mcp__task action="list-blocked" spec_id={spec-id}
```

## Status-Only Update (Not Recommended)

If you need to mark a task completed without journaling (rare):

```bash
mcp__plugin_foundry_foundry-mcp__task action="update-status" spec_id={spec-id} task_id={task-id} status="completed" note="Brief completion note"
```

**Warning:** Use `task action="complete"` instead to ensure proper journaling.

## Best Practices

1. **Update immediately** - Don't batch updates
2. **Be specific** - Vague notes aren't helpful later
3. **Document WHY** - Rationale, not just what changed
4. **Use complete** - Ensures proper journaling

---

## Batch Task States

Parallel mode (`--parallel`) manages multiple tasks as a batch with coordinated lifecycle.

### Batch State Model

```
idle ──[prepare-batch]──> prepared ──[start-batch]──> running
                              │                          │
                              │                          ├──[all complete]──> completed
                              │                          │
                              │                          ├──[partial failure]──> partial
                              │                          │
                              │                          └──[reset-batch]──> idle
                              │
                              └──[abandon]──> idle
```

| State | Description |
|-------|-------------|
| `idle` | No active batch |
| `prepared` | Eligible tasks identified, conflicts excluded |
| `running` | Subagents executing tasks concurrently |
| `completed` | All tasks in batch finished successfully |
| `partial` | Some tasks completed, some failed |

### Starting a Batch

1. **Prepare batch** - Identify eligible tasks:

```bash
mcp__plugin_foundry_foundry-mcp__task action="prepare-batch" \
  spec_id={spec-id} \
  max_tasks=5
```

Response includes `eligible_tasks` (no conflicts) and `excluded_tasks` (conflicts detected).

2. **Start batch** - Begin parallel execution:

```bash
mcp__plugin_foundry_foundry-mcp__task action="start-batch" \
  spec_id={spec-id} \
  batch_id={batch-id}
```

This marks all batch tasks as `in_progress` atomically.

### Completing a Batch

After subagents finish, report aggregated results:

```bash
mcp__plugin_foundry_foundry-mcp__task action="complete-batch" \
  spec_id={spec-id} \
  batch_id={batch-id} \
  results='[
    {"task_id": "task-3-1", "status": "completed", "note": "Implemented auth handler"},
    {"task_id": "task-3-2", "status": "completed", "note": "Added validation utils"},
    {"task_id": "task-3-3", "status": "failed", "error": "Import error in module X"}
  ]'
```

**What `complete-batch` does:**
1. Updates each task's status based on results
2. Creates journal entries for completed tasks
3. Leaves failed tasks as `in_progress` for retry
4. Returns summary with success/failure counts
5. Recalculates phase progress

### Partial Failure Handling

When some tasks in a batch fail:

| Outcome | Task Status | Next Steps |
|---------|-------------|------------|
| Completed | `completed` | Normal - journaled automatically |
| Failed | `in_progress` | Retry in next batch or debug manually |
| Timed out | `in_progress` | Check subagent, retry or block |

**Recovery options:**

1. **Retry in next batch:**
   ```bash
   # Failed tasks remain in_progress, will be included in next prepare-batch
   mcp__plugin_foundry_foundry-mcp__task action="prepare-batch" spec_id={spec-id}
   ```

2. **Switch to interactive mode:**
   ```bash
   # Debug the specific failed task
   foundry-implement  # Without --parallel
   ```

3. **Block the task:**
   ```bash
   mcp__plugin_foundry_foundry-mcp__task action="block" \
     spec_id={spec-id} \
     task_id={failed-task-id} \
     reason="Repeated failure: {error}" \
     blocker_type="technical"
   ```

### Reset Recovery Pattern

If a batch is interrupted (crash, timeout, user abort):

```bash
mcp__plugin_foundry_foundry-mcp__task action="reset-batch" \
  spec_id={spec-id} \
  batch_id={batch-id} \
  reason="Session interrupted by user"
```

**What `reset-batch` does:**
1. Resets all batch tasks to `pending` status
2. Clears partial progress (uncommitted changes may be lost)
3. Returns batch to `idle` state
4. Records reset in journal for audit trail

**When to use reset:**
- Subagent crashed mid-execution
- Network timeout during batch
- User cancelled with Ctrl+C
- Context exhaustion during batch

**After reset:**
1. Review git status for partial changes
2. Decide: commit partial work or revert
3. Re-run `prepare-batch` to start fresh

### Batch vs Single Task Lifecycle

| Aspect | Single Task | Batch |
|--------|-------------|-------|
| Start | `task action="start"` | `task action="start-batch"` |
| Complete | `task action="complete"` | `task action="complete-batch"` |
| Progress | Immediate update | Aggregated at batch end |
| Failure | Block or retry | Isolated per task |
| Journal | Per-task automatic | Per-task in results array |
| Reset | N/A (use block) | `task action="reset-batch"` |
