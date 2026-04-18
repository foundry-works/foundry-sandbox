"""Unit tests for generate_squid_config.py.

Tests Squid domain list generation from allowlist configuration,
including domain format conversion, deduplication, MITM domain inclusion,
and atomic file writes.
"""

import os
import sys
import tempfile
from unittest import mock
from unittest.mock import MagicMock, patch

# generate_squid_config.py imports aiohttp indirectly through gateway modules.
# Ensure mocks are in place.
if "aiohttp" not in sys.modules:
    sys.modules["aiohttp"] = mock.MagicMock()
    sys.modules["aiohttp.web"] = mock.MagicMock()

# conftest.py adds unified-proxy to sys.path.

from generate_squid_config import (
    MITM_DOMAINS,
    _atomic_write_lines,
    _to_squid_domain,
    generate_squid_config,
)


# ---------------------------------------------------------------------------
# _to_squid_domain tests
# ---------------------------------------------------------------------------


class TestToSquidDomain:
    """Tests for _to_squid_domain() format conversion."""

    def test_wildcard_domain(self):
        """*.example.com converts to .example.com (Squid subdomain match)."""
        assert _to_squid_domain("*.example.com") == ".example.com"

    def test_exact_domain(self):
        """Exact domain passes through unchanged."""
        assert _to_squid_domain("example.com") == "example.com"

    def test_nested_wildcard(self):
        """*.sub.example.com converts to .sub.example.com."""
        assert _to_squid_domain("*.sub.example.com") == ".sub.example.com"

    def test_no_wildcard_prefix(self):
        """Domain without wildcard prefix is unchanged."""
        assert _to_squid_domain("api.github.com") == "api.github.com"


# ---------------------------------------------------------------------------
# generate_squid_config tests
# ---------------------------------------------------------------------------


def _make_mock_config(domains):
    """Create a mock AllowlistConfig with given domains."""
    config = MagicMock()
    config.domains = domains
    return config


class TestGenerateSquidConfig:
    """Tests for generate_squid_config()."""

    def test_writes_both_domain_files(self):
        """Generates both allowed_domains.txt and mitm_domains.txt."""
        mock_config = _make_mock_config([
            "api.github.com",
            "api.openai.com",
            "*.example.com",
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            mitm_path = os.path.join(tmpdir, "mitm_domains.txt")

            assert os.path.isfile(allowed_path)
            assert os.path.isfile(mitm_path)

    def test_mitm_domains_in_allowed_list(self):
        """MITM domains are automatically included in the allowed domains list."""
        mock_config = _make_mock_config(["api.github.com"])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            with open(allowed_path) as f:
                allowed = f.read().splitlines()

            # MITM domains should be in the allowed list
            for domain in MITM_DOMAINS:
                squid_domain = _to_squid_domain(domain)
                assert squid_domain in allowed, f"{squid_domain} missing from allowed list"

    def test_duplicate_domains_deduplicated(self):
        """Duplicate domains in the allowlist are deduplicated."""
        mock_config = _make_mock_config([
            "api.github.com",
            "api.github.com",
            "api.openai.com",
            "api.openai.com",
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            with open(allowed_path) as f:
                allowed = f.read().splitlines()

            # Count occurrences of each allowlist domain
            assert allowed.count("api.github.com") == 1
            assert allowed.count("api.openai.com") == 1

    def test_wildcard_conversion_in_output(self):
        """Wildcard domains are converted to Squid dstdomain format in output."""
        mock_config = _make_mock_config(["*.example.com", "exact.com"])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            with open(allowed_path) as f:
                allowed = f.read().splitlines()

            assert ".example.com" in allowed
            assert "exact.com" in allowed
            assert "*.example.com" not in allowed

    def test_output_is_sorted(self):
        """Domain files are sorted for deterministic output."""
        mock_config = _make_mock_config(["z.example.com", "a.example.com"])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            with open(allowed_path) as f:
                allowed = f.read().splitlines()

            assert allowed == sorted(allowed)

    def test_exact_and_wildcard_deduplicated(self):
        """When both example.com and *.example.com exist, only .example.com is emitted.

        Squid fatally errors if both 'example.com' and '.example.com' appear in
        the same dstdomain ACL because .example.com already covers example.com.
        """
        mock_config = _make_mock_config([
            "chatgpt.com",
            "*.chatgpt.com",
            "other.com",
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            with open(allowed_path) as f:
                allowed = f.read().splitlines()

            # .chatgpt.com should be present (wildcard form)
            assert ".chatgpt.com" in allowed
            # chatgpt.com exact should NOT be present (redundant with .chatgpt.com)
            assert "chatgpt.com" not in allowed
            # Unrelated domains should still be present
            assert "other.com" in allowed

    def test_mitm_domain_with_wildcard_deduplicated(self):
        """MITM domains covered by a wildcard don't reintroduce the exact form.

        github.com is both in MITM_DOMAINS and has *.github.com in the
        allowlist.  The exact form must not appear in the final output.
        """
        mock_config = _make_mock_config([
            "github.com",
            "*.github.com",
        ])

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=tmpdir)

            allowed_path = os.path.join(tmpdir, "allowed_domains.txt")
            with open(allowed_path) as f:
                allowed = f.read().splitlines()

            assert ".github.com" in allowed
            assert "github.com" not in allowed

    def test_creates_output_directory(self):
        """Creates output directory if it doesn't exist."""
        mock_config = _make_mock_config(["api.example.com"])

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "nonexistent", "squid")
            with patch("generate_squid_config.load_allowlist_config", return_value=mock_config):
                generate_squid_config(output_dir=output_dir)

            assert os.path.isdir(output_dir)
            assert os.path.isfile(os.path.join(output_dir, "allowed_domains.txt"))


# ---------------------------------------------------------------------------
# Atomic write tests
# ---------------------------------------------------------------------------


class TestAtomicWriteLines:
    """Tests for _atomic_write_lines() atomic file write behavior."""

    def test_writes_lines_to_file(self):
        """Writes lines to the target file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "output.txt")
            _atomic_write_lines(tmpdir, target, ["line1", "line2", "line3"])

            with open(target) as f:
                content = f.read()

            assert content == "line1\nline2\nline3\n"

    def test_atomic_write_no_temp_file_left(self):
        """No temp file remains after successful write."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "output.txt")
            _atomic_write_lines(tmpdir, target, ["hello"])

            # Only the target file should exist
            files = os.listdir(tmpdir)
            assert files == ["output.txt"]

    def test_empty_lines_produces_empty_file(self):
        """Empty line list produces an empty file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "empty.txt")
            _atomic_write_lines(tmpdir, target, [])

            with open(target) as f:
                assert f.read() == ""
