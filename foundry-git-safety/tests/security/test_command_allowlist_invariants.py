"""Verify deny-by-default properties of the command allowlist.

Security invariants under test:
  1. Only explicitly-allowlisted commands pass validation.
  2. Per-command flag blocklists block destructive flags everywhere they apply.
  3. Config key validation rejects dangerous keys and allows only a minimal
     set of safe prefixes.
"""

import pytest

from foundry_git_safety.command_validation import (
    ALLOWED_COMMANDS,
    COMMAND_BLOCKED_FLAGS,
    CONFIG_NEVER_ALLOW,
    CONFIG_PERMITTED_PREFIXES,
    GLOBAL_BLOCKED_FLAGS,
    _validate_config_key,
    validate_command,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# TestDenyByDefault
# ---------------------------------------------------------------------------


class TestDenyByDefault:
    """Every command in ALLOWED_COMMANDS passes validate_command;
    unknown commands are blocked; extra_allowed extends without polluting."""

    # Commands that need specific args to pass validation (not bare --help)
    _CMD_SPECIAL_ARGS = {
        "clean": ["--dry-run"],
        "config": ["--get", "user.name"],
        "remote": ["-v"],
        "notes": ["list"],
        "sparse-checkout": ["list"],
    }

    def test_every_allowed_command_passes_validation(self) -> None:
        """Each command in ALLOWED_COMMANDS should be accepted with minimal args."""
        for cmd in sorted(ALLOWED_COMMANDS):
            args = self._CMD_SPECIAL_ARGS.get(cmd, ["--help"])
            result = validate_command([cmd] + args)
            assert result is None, (
                f"Allowed command {cmd!r} was rejected: {result.reason}"
            )

    def test_unknown_command_is_blocked(self) -> None:
        """A command not in the allowlist must be rejected."""
        err = validate_command(["submodule", "update"])
        assert err is not None
        assert "not allowed" in err.reason

    def test_arbitrary_command_is_blocked(self) -> None:
        """Random strings must not pass as commands."""
        err = validate_command(["totally-fake-command"])
        assert err is not None

    def test_extra_allowed_extends_without_polluting_base(self) -> None:
        """extra_allowed lets a sandbox add commands, but does not mutate
        the base ALLOWED_COMMANDS frozenset."""
        original_size = len(ALLOWED_COMMANDS)

        # Without extra_allowed, 'submodule' is blocked
        err = validate_command(["submodule", "status"])
        assert err is not None

        # With extra_allowed, 'submodule' passes
        err = validate_command(
            ["submodule", "status"],
            extra_allowed={"submodule"},
        )
        assert err is None

        # Base set is unchanged
        assert len(ALLOWED_COMMANDS) == original_size
        assert "submodule" not in ALLOWED_COMMANDS

    def test_empty_args_is_blocked(self) -> None:
        """Empty arg list must be rejected."""
        err = validate_command([])
        assert err is not None

    def test_flags_only_no_subcommand_is_blocked(self) -> None:
        """Global flags without a subcommand must be rejected."""
        err = validate_command(["--no-pager"])
        assert err is not None


# ---------------------------------------------------------------------------
# TestFlagBlocklistCompleteness
# ---------------------------------------------------------------------------


class TestFlagBlocklistCompleteness:
    """--git-dir is blocked everywhere except rev-parse;
    --force is blocked for every command in COMMAND_BLOCKED_FLAGS."""

    def test_git_dir_blocked_globally(self) -> None:
        """--git-dir as a global flag must be rejected for all commands."""
        for cmd in sorted(ALLOWED_COMMANDS):
            if cmd == "rev-parse":
                continue  # rev-parse has special handling
            err = validate_command(["--git-dir=/tmp/malicious", cmd])
            assert err is not None, (
                f"--git-dir not blocked before {cmd!r}"
            )
            assert "Blocked flag" in err.reason

    def test_git_dir_allowed_for_rev_parse(self) -> None:
        """rev-parse may use --git-dir as a query flag."""
        err = validate_command(["rev-parse", "--git-dir"])
        assert err is None, f"rev-parse --git-dir should be allowed: {err}"

    def test_work_tree_blocked_for_non_rev_parse(self) -> None:
        """--work-tree as a global flag must be rejected for non-rev-parse."""
        err = validate_command(["--work-tree=/tmp/evil", "status"])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_work_tree_allowed_for_rev_parse(self) -> None:
        """rev-parse may use --work-tree."""
        err = validate_command(["rev-parse", "--work-tree"])
        assert err is None

    def test_every_command_blocked_flags_is_enforced(self) -> None:
        """Every command in COMMAND_BLOCKED_FLAGS must have at least one blocked
        flag, and validate_command must reject it."""
        for cmd, blocked_flags in COMMAND_BLOCKED_FLAGS.items():
            assert blocked_flags, f"{cmd} has empty blocked flags set"
            # Validate that the first blocked flag is actually rejected
            flag = next(iter(blocked_flags))
            err = validate_command([cmd, flag])
            assert err is not None, (
                f"{cmd} {flag} should be blocked but was allowed"
            )

    def test_push_force_with_lease_blocked(self) -> None:
        """--force-with-lease must be blocked for push."""
        err = validate_command(["push", "--force-with-lease"])
        assert err is not None

    def test_rebase_interactive_blocked(self) -> None:
        """-i (interactive rebase) must be blocked."""
        err = validate_command(["rebase", "-i", "HEAD~5"])
        assert err is not None

    def test_branch_force_delete_blocked(self) -> None:
        """-D (force delete branch) must be blocked."""
        err = validate_command(["branch", "-D", "some-branch"])
        assert err is not None

    def test_combined_short_flags_blocked(self) -> None:
        """Combined short flags like -fD must be caught."""
        err = validate_command(["branch", "-fD", "some-branch"])
        assert err is not None
        assert "Blocked flag" in err.reason

    def test_exec_global_flag_blocked(self) -> None:
        """--exec is in GLOBAL_BLOCKED_FLAGS and must be rejected."""
        err = validate_command(["--exec=/bin/sh", "status"])
        assert err is not None
        assert "Blocked flag" in err.reason


# ---------------------------------------------------------------------------
# TestConfigKeyCompleteness
# ---------------------------------------------------------------------------


class TestConfigKeyCompleteness:
    """Every key in CONFIG_NEVER_ALLOW is tested; permitted prefixes are minimal."""

    # Map each never-allow pattern to a concrete test key.
    _NEVER_ALLOW_TEST_KEYS: list[tuple[str, str]] = [
        ("alias.", "alias.foo"),
        ("alias.", "alias.co"),
        ("core.sshCommand", "core.sshCommand"),
        ("core.pager", "core.pager"),
        ("core.editor", "core.editor"),
        ("core.hooksPath", "core.hooksPath"),
        ("core.fsmonitor", "core.fsmonitor"),
        ("core.gitProxy", "core.gitProxy"),
        ("core.askPass", "core.askPass"),
        ("credential.", "credential.helper"),
        ("credential.", "credential.useHttpPath"),
        ("http.", "http.proxy"),
        ("http.", "http.sslVerify"),
        ("remote.*.proxy", "remote.origin.proxy"),
        ("remote.*.pushurl", "remote.origin.pushurl"),
        ("protocol.*.allow", "protocol.ext.allow"),
        ("diff.*.textconv", "diff.mydriver.textconv"),
        ("diff.*.command", "diff.mydriver.command"),
        ("filter.", "filter.lfs.clean"),
        ("filter.", "filter.lfs.smudge"),
        ("merge.*.driver", "merge.custom.driver"),
        ("gpg.", "gpg.program"),
        ("gpg.", "gpg.sign"),
        ("sendemail.", "sendemail.smtpserver"),
        ("browser.", "browser.firefox.path"),
        ("instaweb.", "instaweb.httpd"),
        ("difftool.*.cmd", "difftool.meld.cmd"),
        ("mergetool.*.cmd", "mergetool.vimdiff.cmd"),
        ("sequence.editor", "sequence.editor"),
    ]

    def test_every_never_allow_key_is_rejected(self) -> None:
        """Each concrete key derived from CONFIG_NEVER_ALLOW must be blocked."""
        for pattern, key in self._NEVER_ALLOW_TEST_KEYS:
            err = _validate_config_key(key)
            assert err is not None, (
                f"Config key {key!r} (pattern {pattern!r}) should be blocked"
            )
            assert "Blocked" in err.reason

    def test_never_allow_wins_over_permitted_prefix(self) -> None:
        """Even if a key matches a permitted prefix, it must be blocked
        if it also matches a never-allow pattern.

        'diff.' is in both CONFIG_NEVER_ALLOW (as diff.*.textconv, diff.*.command)
        and CONFIG_PERMITTED_PREFIXES (as 'diff.'). A key like diff.tool that
        doesn't match a never-allow wildcard should be permitted, but
        diff.mydriver.command must still be blocked.
        """
        # diff.tool is not a never-allow pattern match -> should be allowed
        err = _validate_config_key("diff.tool")
        assert err is None, f"diff.tool should be allowed: {err}"

        # diff.mydriver.command matches diff.*.command -> blocked
        err = _validate_config_key("diff.mydriver.command")
        assert err is not None

    def test_permitted_prefixes_are_minimal(self) -> None:
        """Only keys matching CONFIG_PERMITTED_PREFIXES should be allowed."""
        # Each permitted prefix should work with a concrete example
        allowed_examples = {
            "user.name": "user.",
            "color.ui": "color.",
            "core.quotepath": "core.quotepath",
            "core.autocrlf": "core.autocrlf",
            "core.eol": "core.eol",
            "core.whitespace": "core.whitespace",
            "log.date": "log.",
            "pretty.format": "pretty.",
        }
        for key, prefix in allowed_examples.items():
            err = _validate_config_key(key)
            assert err is None, (
                f"Key {key!r} (prefix {prefix!r}) should be allowed"
            )

    def test_unknown_config_key_is_rejected(self) -> None:
        """A key that matches no permitted prefix must be rejected."""
        err = _validate_config_key("dangerous.key")
        assert err is not None
        assert "not in permitted" in err.reason

    def test_alias_dot_anything_blocked(self) -> None:
        """Any alias.* key must be blocked regardless of suffix."""
        for key in ("alias.co", "alias.lg", "alias.st", "alias.br"):
            err = _validate_config_key(key)
            assert err is not None, f"{key} should be blocked"

    def test_credential_dot_anything_blocked(self) -> None:
        """Any credential.* key must be blocked."""
        for key in ("credential.helper", "credential.cache"):
            err = _validate_config_key(key)
            assert err is not None, f"{key} should be blocked"

    def test_core_ssh_command_blocked(self) -> None:
        """core.sshCommand must be blocked — it allows command injection."""
        err = _validate_config_key("core.sshCommand")
        assert err is not None

    def test_config_never_allow_via_minus_c_flag(self) -> None:
        """-c core.sshCommand=... must be caught by validate_command."""
        err = validate_command(["-c", "core.sshCommand=/bin/sh", "status"])
        assert err is not None
        assert "Blocked config key" in err.reason

    def test_no_config_never_allow_entry_is_unreachable(self) -> None:
        """Every pattern in CONFIG_NEVER_ALLOW must have at least one test key."""
        tested_patterns = {pattern for pattern, _ in self._NEVER_ALLOW_TEST_KEYS}
        for pattern in CONFIG_NEVER_ALLOW:
            assert pattern in tested_patterns, (
                f"CONFIG_NEVER_ALLOW pattern {pattern!r} has no test coverage"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
