# Phase 1: Correctness Bugs

## 1A. Bump `repositoryformatversion` to 1

**File:** `lib/git_worktree.sh` — `configure_sparse_checkout()`, after line 14

After setting `extensions.worktreeConfig=true`, bump version if < 1:

```bash
local current_version
current_version=$(git -C "$bare_path" config --get core.repositoryformatversion 2>/dev/null || echo "0")
if [ "$current_version" -lt 1 ] 2>/dev/null; then
    git -C "$bare_path" config core.repositoryformatversion 1
fi
```

## 1B. VirtioFS cache refresh in proxy

**File:** `lib/container_config.sh` — `fix_proxy_worktree_paths()` (already partially done)

After the existing `ls "$BARE_DIR"` cache refresh (line 2075), also explicitly read the config file to force inode refresh:

```bash
cat "$BARE_DIR/config" >/dev/null 2>&1 || true
```

Also defensively ensure `extensions.worktreeConfig` is set inside the proxy (handles case where host-side set was lost to VirtioFS):

```bash
git config --file "$BARE_DIR/config" extensions.worktreeConfig true 2>/dev/null || true
```

And bump `repositoryformatversion` inside the proxy too (idempotent):

```bash
local current_ver
current_ver=$(git config --file "$BARE_DIR/config" --get core.repositoryformatversion 2>/dev/null || echo 0)
if [ "$current_ver" -lt 1 ] 2>/dev/null; then
    git config --file "$BARE_DIR/config" core.repositoryformatversion 1
fi
```

**Ordering note:** The host-side `configure_sparse_checkout()` runs during `sandbox new` before the container starts. The proxy-side heredoc in `fix_proxy_worktree_paths()` runs on container startup. No concurrent write race exists — the proxy writes are purely defensive against VirtioFS losing the host-side writes.

## 1C. `core.bare` conflict — already fixed

`core.bare=false` is already set in `fix_proxy_worktree_paths()` at line 2079. No additional changes needed.

## Verification

Create a sparse checkout sandbox, exec into proxy, verify:

- `git config --get core.repositoryformatversion` returns `1`
- `git config --get extensions.worktreeConfig` returns `true`
- `git sparse-checkout list` returns patterns (no "not sparse" error)
- `git config --get core.sparseCheckout` returns `true`
