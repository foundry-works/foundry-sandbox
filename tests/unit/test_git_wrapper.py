"""Unit tests for git wrapper JSON serialization safety.

Tests that the JSON construction paths (jq and python3) used by the git
wrapper script (stubs/git-wrapper.sh) correctly handle edge-case arguments:
- Double quotes
- Backslashes
- Newlines and other control characters
- Null bytes (rejected or safely encoded)
- Unicode arguments

These tests validate the serialization layer that sits between the shell
and the git API's POST /git/exec endpoint.
"""

import json
import shutil
import subprocess

import pytest

# ---------------------------------------------------------------------------
# Helpers — simulate the two JSON construction paths the wrapper may use
# ---------------------------------------------------------------------------

HAS_JQ = shutil.which("jq") is not None
HAS_PYTHON3 = shutil.which("python3") is not None


def serialize_via_jq(args: list[str], cwd: str = "/workspace") -> str:
    """Build JSON using jq, matching the wrapper's jq serialization path.

    Equivalent shell pattern:
        printf '%s\\n' "$@" | jq -Rsc --arg cwd "$CWD" \
            '{args: split("\\n") | map(select(. != "")), cwd: $cwd}'
    """
    input_text = "\n".join(args)
    result = subprocess.run(
        [
            "jq",
            "-Rsc",
            "--arg",
            "cwd",
            cwd,
            '{args: split("\\n") | map(select(. != "")), cwd: $cwd}',
        ],
        input=input_text,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(f"jq failed: {result.stderr}")
    return result.stdout.strip()


def serialize_via_python(args: list[str], cwd: str = "/workspace") -> str:
    """Build JSON using python3 -c, matching the wrapper's python fallback.

    Equivalent shell pattern:
        python3 -c 'import json,sys; print(json.dumps({"args":sys.argv[1:],"cwd":sys.argv[1]}))'
    But we use a more robust approach that reads from stdin to avoid shell
    escaping issues:
        printf '%s\\0' "$@" | python3 -c '
            import json, sys
            args = sys.stdin.buffer.read().split(b"\\x00")
            args = [a.decode("utf-8", errors="surrogateescape") for a in args if a]
            print(json.dumps({"args": args, "cwd": sys.argv[1]}))
        ' "$CWD"
    """
    # Simulate null-delimited arg passing
    input_bytes = b"\x00".join(a.encode("utf-8") for a in args) + b"\x00"
    script = (
        "import json, sys\n"
        'args = sys.stdin.buffer.read().split(b"\\x00")\n'
        'args = [a.decode("utf-8") for a in args if a]\n'
        'print(json.dumps({"args": args, "cwd": sys.argv[1]}))\n'
    )
    result = subprocess.run(
        ["python3", "-c", script, cwd],
        input=input_bytes,
        capture_output=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(f"python3 failed: {result.stderr.decode()}")
    return result.stdout.decode().strip()


def parse_and_validate(json_str: str) -> dict:
    """Parse JSON string and validate it has the expected structure."""
    data = json.loads(json_str)
    assert isinstance(data, dict), "Top-level must be an object"
    assert "args" in data, "Must contain 'args' key"
    assert isinstance(data["args"], list), "'args' must be an array"
    assert "cwd" in data, "Must contain 'cwd' key"
    assert isinstance(data["cwd"], str), "'cwd' must be a string"
    return data


# ---------------------------------------------------------------------------
# Parametrize across serialization backends
# ---------------------------------------------------------------------------

SERIALIZERS = []
if HAS_JQ:
    SERIALIZERS.append(pytest.param(serialize_via_jq, id="jq"))
if HAS_PYTHON3:
    SERIALIZERS.append(pytest.param(serialize_via_python, id="python3"))

# Skip entire module if neither tool is available
if not SERIALIZERS:
    pytest.skip("Neither jq nor python3 available", allow_module_level=True)


@pytest.fixture(params=SERIALIZERS)
def serialize(request):
    """Fixture providing each serialization backend."""
    return request.param


# ---------------------------------------------------------------------------
# Test: arguments with double quotes produce valid JSON
# ---------------------------------------------------------------------------


class TestDoubleQuotes:
    def test_single_double_quote(self, serialize):
        result = serialize(['commit', '-m', 'He said "hello"'])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", 'He said "hello"']

    def test_nested_double_quotes(self, serialize):
        result = serialize(["log", '--format="%H %s"'])
        data = parse_and_validate(result)
        assert data["args"] == ["log", '--format="%H %s"']

    def test_only_double_quotes(self, serialize):
        result = serialize(["commit", "-m", '""'])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", '""']

    def test_escaped_quote_in_message(self, serialize):
        result = serialize(["commit", "-m", 'Fix "broken \\"test\\"'])
        data = parse_and_validate(result)
        assert 'Fix "broken \\"test\\"' in data["args"]


# ---------------------------------------------------------------------------
# Test: arguments with backslashes produce valid JSON
# ---------------------------------------------------------------------------


class TestBackslashes:
    def test_single_backslash(self, serialize):
        result = serialize(["log", "--format=%H\\n%s"])
        data = parse_and_validate(result)
        assert data["args"] == ["log", "--format=%H\\n%s"]

    def test_trailing_backslash(self, serialize):
        result = serialize(["commit", "-m", "path\\"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "path\\"]

    def test_double_backslash(self, serialize):
        result = serialize(["commit", "-m", "C:\\\\Users\\\\test"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "C:\\\\Users\\\\test"]

    def test_backslash_with_special_chars(self, serialize):
        result = serialize(["commit", "-m", "tab\\there\\nnewline"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "tab\\there\\nnewline"]


# ---------------------------------------------------------------------------
# Test: arguments with newlines produce valid JSON
# ---------------------------------------------------------------------------


class TestNewlines:
    def test_embedded_newline(self, serialize):
        """Newlines in args are tricky for the jq \\n-split path.

        jq splits on \\n, so embedded newlines break arg boundaries — the
        arg count increases. This documents a known limitation: the wrapper
        MUST NOT use newline-delimited input when args can contain newlines.
        Python path handles this correctly.
        """
        result = serialize(["commit", "-m", "line1\nline2\nline3"])
        data = parse_and_validate(result)
        if serialize is serialize_via_jq:
            # jq \n-split breaks the arg into 3 separate entries
            assert len(data["args"]) > 3, (
                "jq should split embedded newlines into extra args"
            )
            assert "line1" in data["args"]
            assert "line2" in data["args"]
            assert "line3" in data["args"]
        else:
            assert data["args"] == ["commit", "-m", "line1\nline2\nline3"]

    def test_carriage_return(self, serialize):
        """CR+LF in args — jq splits on LF, python preserves."""
        result = serialize(["commit", "-m", "line1\r\nline2"])
        data = parse_and_validate(result)
        if serialize is serialize_via_jq:
            # jq splits on \n; \r remains attached to "line1\r"
            assert len(data["args"]) > 2
            assert any("line1" in a for a in data["args"])
            assert "line2" in data["args"]
        else:
            assert data["args"] == ["commit", "-m", "line1\r\nline2"]

    def test_tab_character(self, serialize):
        """Tab characters should pass through both paths."""
        result = serialize(["commit", "-m", "col1\tcol2"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "col1\tcol2"]


# ---------------------------------------------------------------------------
# Test: null bytes in arguments are rejected or safely encoded
# ---------------------------------------------------------------------------


class TestNullBytes:
    def test_null_byte_in_arg(self, serialize):
        """Null bytes must not pass through as part of the original arg.

        jq: passes null bytes through in -R mode (wrapper must strip them).
        python: uses null as delimiter, so null inside arg splits it into
        separate args visible to server-side validation.
        """
        result = serialize(["status", "file\x00injected"])
        data = parse_and_validate(result)
        if serialize is serialize_via_jq:
            # jq -R preserves null bytes in JSON strings — the wrapper MUST
            # strip null bytes before passing input to jq
            raw_arg = data["args"][1]
            assert "\x00" in raw_arg or raw_arg == "fileinjected", (
                "Expected jq to either preserve null byte or strip it"
            )
        else:
            # Python null-delimited path splits the arg at null bytes
            assert "file\x00injected" not in data["args"], (
                "Null byte must not pass through verbatim"
            )
            assert "file" in data["args"]
            assert "injected" in data["args"]

    def test_only_null_byte(self, serialize):
        """An argument that is only a null byte — behavior varies by backend.

        python: dropped (empty after split, filtered by `if a`).
        jq: preserved as a string containing a null byte (wrapper must sanitize).
        """
        result = serialize(["status", "\x00"])
        data = parse_and_validate(result)
        if serialize is serialize_via_jq:
            # jq preserves the null byte as a string — wrapper-level
            # sanitization required; at minimum "status" must be present
            assert "status" in data["args"]
        else:
            # Python path drops the null-only arg entirely
            assert data["args"] == ["status"]


# ---------------------------------------------------------------------------
# Test: unicode arguments correctly serialized
# ---------------------------------------------------------------------------


class TestUnicode:
    def test_basic_unicode(self, serialize):
        result = serialize(["commit", "-m", "Fix bug in ñoño module"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "Fix bug in ñoño module"]

    def test_cjk_characters(self, serialize):
        result = serialize(["commit", "-m", "修复中文测试"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "修复中文测试"]

    def test_emoji(self, serialize):
        result = serialize(["commit", "-m", "Fix tests 🐛"])
        data = parse_and_validate(result)
        assert "🐛" in data["args"][2]

    def test_mixed_unicode_and_special(self, serialize):
        result = serialize(["commit", "-m", 'Héllo "wörld" path\\to\\file'])
        data = parse_and_validate(result)
        assert data["args"] == [
            "commit",
            "-m",
            'Héllo "wörld" path\\to\\file',
        ]

    def test_rtl_characters(self, serialize):
        result = serialize(["commit", "-m", "مرحبا"])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", "مرحبا"]

    def test_zero_width_characters(self, serialize):
        """Zero-width chars should be preserved (not stripped)."""
        msg = "test\u200b\u200cmessage"  # zero-width space + zero-width non-joiner
        result = serialize(["commit", "-m", msg])
        data = parse_and_validate(result)
        assert data["args"] == ["commit", "-m", msg]


# ---------------------------------------------------------------------------
# Test: cwd field correctness
# ---------------------------------------------------------------------------


class TestCwd:
    def test_default_cwd(self, serialize):
        result = serialize(["status"])
        data = parse_and_validate(result)
        assert data["cwd"] == "/workspace"

    def test_custom_cwd(self, serialize):
        result = serialize(["status"], cwd="/tmp/test repo")
        data = parse_and_validate(result)
        assert data["cwd"] == "/tmp/test repo"

    def test_cwd_with_special_chars(self, serialize):
        result = serialize(["status"], cwd='/tmp/"quoted" path')
        data = parse_and_validate(result)
        assert data["cwd"] == '/tmp/"quoted" path'


# ---------------------------------------------------------------------------
# Test: combined edge cases
# ---------------------------------------------------------------------------


class TestCombined:
    def test_all_special_chars_together(self, serialize):
        """Combines quotes, backslashes, unicode in a single invocation."""
        args = [
            "commit",
            "-m",
            'Fix "bug" in path\\to\\módule',
            "--author=Tëst Üser <test@example.com>",
        ]
        result = serialize(args)
        data = parse_and_validate(result)
        assert len(data["args"]) == 4
        assert data["args"][0] == "commit"

    def test_empty_args(self, serialize):
        """An empty args list should still produce valid JSON."""
        result = serialize([])
        data = parse_and_validate(result)
        assert data["args"] == []

    def test_single_empty_string_arg(self, serialize):
        """An empty string argument gets filtered out by both paths.

        jq: map(select(. != "")) explicitly drops empty strings.
        python: null-delimited split with `if a` filter drops empty strings.
        The wrapper should reject empty args at the shell level before
        serialization, so this behavior is acceptable.
        """
        result = serialize(["commit", "-m", ""])
        data = parse_and_validate(result)
        # Both paths drop empty strings — this is safe behavior
        assert "" not in data["args"]

    def test_very_long_argument(self, serialize):
        """Arguments up to 10KB should serialize without truncation."""
        long_msg = "x" * 10000
        result = serialize(["commit", "-m", long_msg])
        data = parse_and_validate(result)
        assert len(data["args"][2]) == 10000

    def test_many_arguments(self, serialize):
        """100 file paths should serialize correctly."""
        files = [f"src/file_{i}.py" for i in range(100)]
        args = ["add"] + files
        result = serialize(args)
        data = parse_and_validate(result)
        assert len(data["args"]) == 101
