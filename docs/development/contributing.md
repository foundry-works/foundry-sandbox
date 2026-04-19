# Contributing Guide

This guide covers how to contribute to Foundry Sandbox.

## Code Organization

```
foundry-sandbox/
├── install.sh              # Installation script
├── completion.bash         # Bash tab completion
├── pyproject.toml          # Python package definition (entry point: cast)
│
├── foundry_sandbox/        # Python package (orchestration layer)
│   ├── cli.py              # Click CLI group with alias resolution
│   ├── constants.py        # Configuration defaults
│   ├── models.py           # Pydantic data models (SbxSandboxMetadata)
│   ├── paths.py            # Path resolution (SandboxPaths)
│   ├── utils.py            # Logging/formatting helpers
│   ├── sbx.py              # sbx CLI wrapper (all subprocess calls)
│   ├── git_safety.py       # Git safety integration bridge
│   ├── git.py              # Git operations with retry
│   ├── git_worktree.py     # Worktree management
│   ├── state.py            # Metadata persistence (JSON, atomic writes)
│   ├── validate.py         # Input validation
│   ├── api_keys.py         # API key validation
│   └── commands/           # Click command implementations
│       ├── new.py          # cast new (dispatches to new_sbx.py)
│       ├── new_sbx.py      # sbx sandbox creation logic
│       ├── attach.py       # cast attach (sbx exec streaming)
│       ├── start.py        # cast start (sbx run)
│       ├── stop.py         # cast stop (sbx stop)
│       ├── destroy.py      # cast destroy (sbx rm + cleanup)
│       ├── destroy_all.py  # cast destroy-all
│       ├── list_cmd.py     # cast list (sbx ls enrichment)
│       ├── config.py       # cast config
│       ├── refresh_creds.py # cast refresh-credentials (sbx secret)
│       ├── help_cmd.py     # cast help
│       └── git_mode.py     # cast git-mode
│
├── foundry-git-safety/     # Standalone git safety package
│   ├── foundry_git_safety/
│   │   ├── cli.py          # CLI entry point (start/stop/status/validate)
│   │   ├── server.py       # Flask git API server (port 8083)
│   │   ├── auth.py         # HMAC auth, nonce store, rate limiter
│   │   ├── policies.py     # Command allowlist, protected branches
│   │   ├── operations.py   # Git command execution
│   │   ├── branch_isolation.py  # Cross-sandbox branch isolation
│   │   ├── github_filter.py     # GitHub API filtering proxy
│   │   └── schemas/        # Pydantic config models
│   └── tests/              # 727 tests (unit, integration, security)
│
├── stubs/                  # Files injected into sandboxes
│   ├── git-wrapper-sbx.sh  # Git wrapper for sbx networking
│   └── ...
│
├── tests/                  # Test suite
│
└── docs/                   # Documentation (you are here)
```
