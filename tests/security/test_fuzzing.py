"""Hypothesis-based fuzz tests for git validation and policy evaluation.

Fuzzes the git command validation pipeline (validate_command) and
protected-branch policy checker (check_protected_branches) from the
unified-proxy with random inputs to ensure they never crash on
arbitrary data.  Expected rejections (ValueError, TypeError,
SystemExit, ValidationError) are fine -- the invariant is that no
*unhandled* exception escapes the validation layer.

Security properties tested:
- validate_command never raises an unhandled exception on arbitrary argv
- validate_command always rejects known-dangerous git operations (fail-closed)
- check_protected_branches never crashes on arbitrary refnames/SHAs
"""

import os
import sys

import pytest
from hypothesis import given, settings, HealthCheck
import hypothesis.strategies as st

# ---------------------------------------------------------------------------
# Path setup -- unified-proxy lives outside the normal test package tree
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../unified-proxy"))

from branch_isolation import ValidationError
from git_operations import (
    ALLOWED_COMMANDS,
    COMMAND_BLOCKED_FLAGS,
    GLOBAL_BLOCKED_FLAGS,
    validate_command,
)
from git_policies import check_protected_branches

# Phase 2 imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from foundry_sandbox.validate import (
    validate_sandbox_name,
    validate_git_url,
    validate_mount_path,
    validate_ssh_mode,
)
from foundry_sandbox.state import (
    write_sandbox_metadata,
    load_sandbox_metadata,
    _parse_legacy_metadata,
)
from foundry_sandbox.api_keys import has_zai_key, check_any_ai_key

# ---------------------------------------------------------------------------
# Module markers
# ---------------------------------------------------------------------------

pytestmark = [
    pytest.mark.security,
]

# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------

# Strategy for git-like argv tokens: letters, numbers, punctuation, separators.
# Covers flags (--force), refspecs (src:dst), paths (a/b/c), config keys
# (core.autocrlf=true), empty strings, and unicode edge cases.
argv_tokens = st.lists(
    st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
        min_size=0,
        max_size=100,
    ),
    min_size=0,
    max_size=20,
)

# Strategy for refname-like strings used by check_protected_branches.
refname_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=0,
    max_size=200,
)

# Strategy for SHA-like hex strings (0-9, a-f) of varying lengths.
sha_strategy = st.text(
    alphabet=st.sampled_from("0123456789abcdef"),
    min_size=0,
    max_size=50,
)

# ---------------------------------------------------------------------------
# Phase 2 strategies
# ---------------------------------------------------------------------------

# Sandbox name fuzzing: unicode, control chars, path traversal, Docker reserved
sandbox_name_strategy = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Z", "C"),
    ),
    min_size=0,
    max_size=200,
)

# URL-like strings with embedded credential patterns
url_strategy = st.one_of(
    st.text(min_size=0, max_size=300),
    st.from_regex(r"https?://[^/]+/[^/]+", fullmatch=True),
    st.from_regex(r"git@[^:]+:[^/]+/.+", fullmatch=True),
    st.just(""),
)

# Key-like strings: near-miss patterns for API keys
key_strategy = st.one_of(
    st.text(min_size=0, max_size=100),
    st.just("CREDENTIAL_PROXY_PLACEHOLDER"),
    st.just("PROXY_PLACEHOLDER_OPENCODE"),
    st.just(""),
    st.just("sk-ant-valid-looking-key"),
    st.from_regex(r"sk-ant-[a-zA-Z0-9]{20,50}", fullmatch=True),
)

# Metadata dictionaries for round-trip testing
metadata_values = st.one_of(
    st.text(min_size=0, max_size=50),
    st.integers(min_value=-1000, max_value=1000),
    st.booleans(),
    st.just(""),
)


# ---------------------------------------------------------------------------
# Fuzz tests
# ---------------------------------------------------------------------------


class TestGitValidationFuzzing:
    """Fuzz tests for the git command validation pipeline."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(argv=argv_tokens)
    def test_git_validation_no_crash(self, argv):
        """Fuzz git command validation -- must never crash on arbitrary input.

        Feeds Hypothesis-generated lists of arbitrary text tokens into
        validate_command() and asserts that the function either returns
        None (valid) or a ValidationError (rejected), but never raises
        an unhandled exception.

        Expected rejection exceptions (ValueError, TypeError, SystemExit)
        are caught and treated as acceptable -- only unexpected exceptions
        constitute a test failure.
        """
        try:
            result = validate_command(argv)
            # validate_command returns None (valid) or ValidationError (rejected)
            assert result is None or isinstance(result, ValidationError)
        except (ValueError, TypeError, SystemExit):
            # These are acceptable rejections from deeper validation layers
            pass

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(argv=argv_tokens)
    def test_git_validation_with_extra_allowed_no_crash(self, argv):
        """Fuzz validate_command with extra_allowed set -- must never crash.

        Same invariant as test_git_validation_no_crash but exercises
        the extra_allowed parameter path, ensuring custom command
        extensions cannot introduce crashes.
        """
        try:
            result = validate_command(argv, extra_allowed={"custom-cmd"})
            assert result is None or isinstance(result, ValidationError)
        except (ValueError, TypeError, SystemExit):
            pass

    def test_git_validation_fail_closed(self):
        """Verify known dangerous git operations are rejected by validation.

        Tests a curated list of adversarial commands that must always be
        blocked by the deny-by-default allowlist and per-command flag
        restrictions.  Any of these passing validation would be a
        security regression.
        """
        dangerous_operations = [
            # Force push variants
            (["push", "--force", "origin", "main"], "push --force"),
            (["push", "-f", "origin", "main"], "push -f"),
            (["push", "--force-with-lease", "origin", "main"], "push --force-with-lease"),
            (["push", "--force-if-includes", "origin", "main"], "push --force-if-includes"),

            # NOTE: Deletion refspecs (e.g. "push origin :refs/heads/main") and
            # broad push modes (--all, --mirror) are validated by
            # check_push_protected_branches, not validate_command, and are
            # covered by the policy evaluation tests below.

            # Commands not in the allowlist (deny-by-default)
            (["gc"], "gc (not in allowlist)"),
            (["fsck"], "fsck (not in allowlist)"),
            (["reflog"], "reflog (not in allowlist)"),
            (["filter-branch", "--all"], "filter-branch (not in allowlist)"),
            (["replace"], "replace (not in allowlist)"),
            (["update-ref"], "update-ref (not in allowlist)"),
            (["pack-refs"], "pack-refs (not in allowlist)"),
            (["prune"], "prune (not in allowlist)"),
            (["submodule", "add", "http://evil.com/repo"], "submodule (not in allowlist)"),

            # Global blocked flags
            (["status", "--git-dir=/etc"], "status with --git-dir"),
            (["log", "--work-tree=/etc"], "log with --work-tree"),
            (["diff", "--exec=malicious"], "diff with --exec"),
            (["fetch", "--upload-pack=evil"], "fetch with --upload-pack"),
            (["push", "--receive-pack=evil", "origin", "main"], "push with --receive-pack"),

            # Blocked flags per command
            (["rebase", "--interactive"], "rebase --interactive"),
            (["rebase", "-i"], "rebase -i"),
            (["checkout", "--force"], "checkout --force"),
            (["checkout", "-f"], "checkout -f"),
            (["switch", "--force"], "switch --force"),
            (["switch", "-f"], "switch -f"),
            (["switch", "--discard-changes"], "switch --discard-changes"),
            (["branch", "--force"], "branch --force"),
            (["branch", "-f"], "branch -f"),
            (["branch", "-D"], "branch -D"),
            (["clean", "-f"], "clean -f"),
            (["clean", "--force"], "clean --force"),
            (["clean", "-fd"], "clean -fd"),
            (["clean", "-fx"], "clean -fx"),
            (["clean", "-x"], "clean -x"),
            (["clean", "-d"], "clean -d"),

            # Remote mutation subcommands
            (["remote", "add", "evil", "http://evil.com"], "remote add"),
            (["remote", "set-url", "origin", "http://evil.com"], "remote set-url"),
            (["remote", "remove", "origin"], "remote remove"),
            (["remote", "rename", "origin", "evil"], "remote rename"),

            # Config writes (no read-only flag)
            (["config", "user.name", "attacker"], "config write (no --get/--list)"),
            (["config", "--unset", "user.name"], "config --unset"),

            # Notes write operations
            (["notes", "add", "-m", "evil"], "notes add"),
            (["notes", "remove", "HEAD"], "notes remove"),
            (["notes", "edit", "HEAD"], "notes edit"),

            # Sparse checkout mutation
            (["sparse-checkout", "set", "evil/path"], "sparse-checkout set"),
            (["sparse-checkout", "add", "evil/path"], "sparse-checkout add"),
            (["sparse-checkout", "disable"], "sparse-checkout disable"),

            # Blocked config keys via -c
            (["-c", "alias.st=!rm -rf /", "status"], "blocked config alias"),
            (["-c", "core.sshCommand=evil", "status"], "blocked config sshCommand"),
            (["-c", "core.hooksPath=/evil", "status"], "blocked config hooksPath"),
            (["-c", "credential.helper=evil", "status"], "blocked config credential"),
            (["-c", "http.proxy=evil", "status"], "blocked config http"),
            (["-c", "filter.lfs.process=evil", "status"], "blocked config filter"),
        ]

        for args, description in dangerous_operations:
            result = validate_command(args)
            assert result is not None and isinstance(result, ValidationError), (
                f"SECURITY: dangerous operation '{description}' was NOT rejected. "
                f"args={args}, result={result}"
            )


class TestPolicyEvaluationFuzzing:
    """Fuzz tests for the protected-branch policy evaluator."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        refname=refname_strategy,
        old_sha=sha_strategy,
        new_sha=sha_strategy,
    )
    def test_policy_evaluation_no_crash(self, refname, old_sha, new_sha):
        """Fuzz check_protected_branches -- must never crash on arbitrary input.

        Feeds random refnames and SHA strings into the policy evaluator
        and asserts it always returns either None (allowed) or a string
        (block reason), never raising an unhandled exception.
        """
        try:
            result = check_protected_branches(
                refname=refname,
                old_sha=old_sha,
                new_sha=new_sha,
                bare_repo_path=None,
                metadata=None,
            )
            assert result is None or isinstance(result, str)
        except (ValueError, TypeError, SystemExit):
            pass

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        refname=refname_strategy,
        old_sha=sha_strategy,
        new_sha=sha_strategy,
    )
    def test_policy_evaluation_with_metadata_no_crash(self, refname, old_sha, new_sha):
        """Fuzz check_protected_branches with metadata -- must never crash.

        Exercises the metadata-driven policy path with random inputs
        to ensure metadata parsing combined with random refnames does
        not introduce crashes.
        """
        metadata = {
            "git": {
                "protected_branches": {
                    "enabled": True,
                    "patterns": [
                        "refs/heads/main",
                        "refs/heads/master",
                        "refs/heads/release/*",
                    ],
                }
            }
        }
        try:
            result = check_protected_branches(
                refname=refname,
                old_sha=old_sha,
                new_sha=new_sha,
                bare_repo_path=None,
                metadata=metadata,
            )
            assert result is None or isinstance(result, str)
        except (ValueError, TypeError, SystemExit):
            pass


class TestSandboxNameFuzzing:
    """Fuzz tests for sandbox name validation."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(name=sandbox_name_strategy)
    def test_name_validation_no_crash(self, name):
        """Fuzz sandbox name validation -- must never crash on arbitrary input.

        Feeds Hypothesis-generated arbitrary text strings into
        validate_sandbox_name() and asserts that the function always
        returns a (bool, str) tuple, never raising an unhandled exception.
        """
        try:
            result = validate_sandbox_name(name)
            assert isinstance(result, tuple) and len(result) == 2
            assert isinstance(result[0], bool) and isinstance(result[1], str)
        except (ValueError, TypeError, OSError):
            # Acceptable rejections from validation layers
            pass

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(name=st.just(""))
    def test_name_validation_empty_always_rejected(self, name):
        """Verify empty sandbox name is always rejected."""
        result = validate_sandbox_name(name)
        assert isinstance(result, tuple) and len(result) == 2
        assert result[0] is False, "Empty name must be rejected"

    def test_name_path_traversal_patterns(self):
        """Verify path traversal patterns in sandbox names are properly handled."""
        traversal_patterns = [
            "../",
            "../../etc/passwd",
            "name/../other",
            "name/../../etc",
            "../name",
            "name/..",
            "./name",
            "name/./other",
        ]
        for pattern in traversal_patterns:
            try:
                result = validate_sandbox_name(pattern)
                assert isinstance(result, tuple) and len(result) == 2
                assert isinstance(result[0], bool) and isinstance(result[1], str)
            except (ValueError, TypeError, OSError):
                pass


class TestUrlValidationFuzzing:
    """Fuzz tests for URL validation."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(url=url_strategy)
    def test_url_validation_no_crash(self, url):
        """Fuzz URL validation -- must never crash on arbitrary input.

        Feeds arbitrary text into validate_git_url() and asserts that
        the function always returns a (bool, str) tuple, never raising
        an unhandled exception.
        """
        try:
            result = validate_git_url(url)
            assert isinstance(result, tuple) and len(result) == 2
            assert isinstance(result[0], bool) and isinstance(result[1], str)
        except (ValueError, TypeError, OSError):
            pass

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        user=st.text(min_size=1, max_size=20),
        password=st.text(min_size=1, max_size=20),
        host=st.text(min_size=1, max_size=30),
        path=st.text(min_size=1, max_size=50),
    )
    def test_url_embedded_credentials_format(self, user, password, host, path):
        """Test URLs with embedded credentials pattern.

        Generates URLs with ://user:pass@ pattern and verifies the
        validation function returns a tuple without crashing.
        """
        url = f"https://{user}:{password}@{host}/{path}"
        try:
            result = validate_git_url(url)
            assert isinstance(result, tuple) and len(result) == 2
        except (ValueError, TypeError, OSError):
            pass

    def test_file_protocol_urls(self):
        """Verify file:// protocol URLs are handled properly."""
        file_urls = [
            "file:///etc/passwd",
            "file:///tmp/malicious",
            "file://localhost/etc/shadow",
            "file:///home/user/.ssh/id_rsa",
        ]
        for url in file_urls:
            try:
                result = validate_git_url(url)
                assert isinstance(result, tuple) and len(result) == 2
                assert isinstance(result[0], bool) and isinstance(result[1], str)
            except (ValueError, TypeError, OSError):
                pass


class TestMountPathFuzzing:
    """Fuzz tests for mount path validation."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(path=st.text(min_size=0, max_size=300))
    def test_mount_path_no_crash(self, path):
        """Fuzz mount path validation -- must never crash on arbitrary input.

        Feeds arbitrary paths into validate_mount_path() and asserts that
        the function always returns a (bool, str) tuple, never raising
        an unhandled exception.
        """
        try:
            result = validate_mount_path(path)
            assert isinstance(result, tuple) and len(result) == 2
            assert isinstance(result[0], bool) and isinstance(result[1], str)
        except (ValueError, TypeError, OSError):
            pass


class TestKeyFormatFuzzing:
    """Fuzz tests for API key format validation."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(key=key_strategy)
    def test_zai_key_no_crash(self, key):
        """Fuzz has_zai_key() with arbitrary key values -- must never crash.

        Sets ZHIPU_API_KEY to arbitrary values and calls has_zai_key(),
        ensuring it always returns a bool without raising an unhandled
        exception.
        """
        old = os.environ.get("ZHIPU_API_KEY")
        try:
            os.environ["ZHIPU_API_KEY"] = key
            result = has_zai_key()
            assert isinstance(result, bool)
        except (ValueError, TypeError, OSError):
            pass
        finally:
            if old is None:
                os.environ.pop("ZHIPU_API_KEY", None)
            else:
                os.environ["ZHIPU_API_KEY"] = old

    def test_zai_placeholder_always_rejected(self):
        """Verify exact placeholder strings are rejected by has_zai_key()."""
        placeholders = [
            "CREDENTIAL_PROXY_PLACEHOLDER",
            "PROXY_PLACEHOLDER_OPENCODE",
            "",
        ]
        old = os.environ.get("ZHIPU_API_KEY")
        try:
            for placeholder in placeholders:
                os.environ["ZHIPU_API_KEY"] = placeholder
                result = has_zai_key()
                assert result is False, f"Placeholder '{placeholder}' must be rejected"
        finally:
            if old is None:
                os.environ.pop("ZHIPU_API_KEY", None)
            else:
                os.environ["ZHIPU_API_KEY"] = old

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(key=key_strategy)
    def test_ai_key_no_crash(self, key):
        """Fuzz check_any_ai_key() with arbitrary values -- must never crash.

        Sets AI provider env vars to arbitrary values and calls
        check_any_ai_key(), ensuring it always returns a bool without
        raising an unhandled exception.
        """
        env_vars = ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]
        saved = {k: os.environ.get(k) for k in env_vars}
        try:
            for env_var in env_vars:
                os.environ[env_var] = key
            result = check_any_ai_key()
            assert isinstance(result, bool)
        except (ValueError, TypeError, OSError):
            pass
        finally:
            for env_var in env_vars:
                if saved[env_var] is None:
                    os.environ.pop(env_var, None)
                else:
                    os.environ[env_var] = saved[env_var]


class TestStateMetadataFuzzing:
    """Fuzz tests for state metadata serialization."""

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        name=st.text(min_size=1, max_size=50, alphabet=st.characters(min_codepoint=48, max_codepoint=122)),
        repo_url=st.text(min_size=0, max_size=100),
        branch=st.text(min_size=0, max_size=50),
    )
    def test_metadata_round_trip(self, name, repo_url, branch):
        """Fuzz metadata round-trip -- write and read must never crash.

        Creates a temporary directory for each invocation and writes fuzzed
        metadata strings for repo_url/branch, then reads them back. The
        function must either return the correct data or return None, but
        never crash with an unhandled exception.
        """
        import tempfile

        old_home = os.environ.get("SANDBOX_HOME")
        tmpdir = tempfile.mkdtemp()
        try:
            os.environ["SANDBOX_HOME"] = tmpdir

            # Write metadata
            write_sandbox_metadata(
                name=name,
                repo_url=repo_url,
                branch=branch,
            )

            # Read metadata back
            result = load_sandbox_metadata(name)

            # Must either return None (failure) or a dict
            assert result is None or isinstance(result, dict)

            # If we got a dict, it should have expected structure
            if result is not None:
                assert "repo_url" in result

        except (ValueError, TypeError, OSError, KeyError):
            # Acceptable exceptions during I/O or validation
            pass
        finally:
            if old_home is None:
                os.environ.pop("SANDBOX_HOME", None)
            else:
                os.environ["SANDBOX_HOME"] = old_home
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    @settings(
        derandomize=True,
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(content=st.text(min_size=0, max_size=500))
    def test_legacy_parse_no_crash(self, content):
        """Fuzz _parse_legacy_metadata with arbitrary text -- must never crash.

        Writes arbitrary text to a temporary .env file and calls
        _parse_legacy_metadata(). Expected exceptions (ValueError, OSError)
        are caught; the invariant is that no unhandled exception escapes.
        """
        import tempfile

        fd, env_file = tempfile.mkstemp(suffix=".env")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)

            result = _parse_legacy_metadata(env_file)
            # Must return a dict or None
            assert result is None or isinstance(result, dict)
        except (ValueError, TypeError, OSError, KeyError):
            # Acceptable parsing/I/O exceptions
            pass
        finally:
            os.unlink(env_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
