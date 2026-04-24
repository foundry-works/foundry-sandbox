"""Table-driven tests for input validation functions."""

from __future__ import annotations

import pytest

from foundry_sandbox.validate import (
    validate_existing_sandbox_name,
    validate_git_url,
    validate_sandbox_name,
)


# ============================================================================
# validate_sandbox_name
# ============================================================================


@pytest.mark.parametrize(
    "name", ["abc", "repo-1", "repo_1", "repo.1", "A", "Z9", "x" * 64]
)
def test_sandbox_name_valid(name):
    ok, msg = validate_sandbox_name(name)
    assert ok is True
    assert msg == ""


@pytest.mark.parametrize(
    "name, expected_substring",
    [
        ("", "required"),
        ("x" * 65, "too long"),
        (".", "cannot be '.'"),
        ("..", "cannot be '.'"),
        ("a/b", "path separators"),
        ("a\\b", "path separators"),
        ("has space", "whitespace"),
        ("has\ttab", "whitespace"),
        ("has\nnewline", "whitespace"),
        ("-starts-dash", "Invalid sandbox name"),
        (".starts-dot", "Invalid sandbox name"),
        ("_starts-underscore", "Invalid sandbox name"),
    ],
)
def test_sandbox_name_invalid(name, expected_substring):
    ok, msg = validate_sandbox_name(name)
    assert ok is False
    assert expected_substring in msg


# ============================================================================
# validate_existing_sandbox_name
# ============================================================================


@pytest.mark.parametrize(
    "name",
    ["abc", "repo-1", "repo_1", "repo.1", "older_style name with spaces is ok"],
)
def test_existing_sandbox_name_valid(name):
    ok, msg = validate_existing_sandbox_name(name)
    assert ok is True
    assert msg == ""


@pytest.mark.parametrize(
    "name, expected_substring",
    [
        ("", "required"),
        ("x" * 256, "too long"),
        (".", "cannot be '.'"),
        ("..", "cannot be '.'"),
        ("a/b", "path separators"),
        ("a\\b", "path separators"),
        ("ctrl\x00char", "control characters"),
        ("ctrl\x1besc", "control characters"),
        ("del\x7fchar", "control characters"),
    ],
)
def test_existing_sandbox_name_invalid(name, expected_substring):
    ok, msg = validate_existing_sandbox_name(name)
    assert ok is False
    assert expected_substring in msg


# ============================================================================
# validate_git_url — HTTPS
# ============================================================================


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/org/repo",
        "https://github.com/org/repo.git",
        "https://github.com/org/repo.git",
        "https://example.com/org/repo",
        "https://gitlab.com/group/subgroup/repo",
        "http://example.com/org/repo",
    ],
)
def test_git_url_valid_https(url):
    ok, msg = validate_git_url(url)
    assert ok is True
    assert msg == ""


@pytest.mark.parametrize(
    "url, expected_substring",
    [
        ("https://", "missing host"),
        ("https:///org/repo", "missing host"),
        ("https://github.com", "missing path"),
        ("https://github.com/", "missing path"),
        ("https://user@github.com/org/repo", "credentials"),
        ("https://user:pass@github.com/org/repo", "credentials"),
        ("https://token@github.com/org/repo", "credentials"),
    ],
)
def test_git_url_invalid_https(url, expected_substring):
    ok, msg = validate_git_url(url)
    assert ok is False
    assert expected_substring in msg


# ============================================================================
# validate_git_url — SSH
# ============================================================================


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:org/repo.git",
        "git@github.com:org/repo",
        "git@gitlab.com:group/repo.git",
    ],
)
def test_git_url_valid_ssh(url):
    ok, msg = validate_git_url(url)
    assert ok is True
    assert msg == ""


@pytest.mark.parametrize(
    "url, expected_substring",
    [
        ("git@:org/repo", "missing host"),
        ("git@-bad.com:org/repo", "invalid host"),
        ("git@:org/repo", "missing host"),
        ("git@github.com:/org/repo", "missing or absolute path"),
    ],
)
def test_git_url_invalid_ssh(url, expected_substring):
    ok, msg = validate_git_url(url)
    assert ok is False
    assert expected_substring in msg


# ============================================================================
# validate_git_url — GitHub shorthand
# ============================================================================


@pytest.mark.parametrize(
    "url",
    [
        "org/repo",
        "org/repo.git",
        "my-org/my.repo",
        "my_org/my_repo",
        "a/b",
    ],
)
def test_git_url_valid_shorthand(url):
    ok, msg = validate_git_url(url)
    assert ok is True
    assert msg == ""


# ============================================================================
# validate_git_url — local paths
# ============================================================================


@pytest.mark.parametrize(
    "url",
    [
        ".",
        "./repo",
        "./path/to/repo",
        "~/repos/myproject",
    ],
)
def test_git_url_valid_local(url):
    ok, msg = validate_git_url(url)
    assert ok is True
    assert msg == ""


@pytest.mark.parametrize(
    "url, expected_substring",
    [
        ("/etc", "sensitive location"),
        ("/etc/passwd", "sensitive location"),
        ("/proc/self", "sensitive location"),
        ("/sys/kernel", "sensitive location"),
        ("/dev/null", "sensitive location"),
        ("/root", "sensitive location"),
        ("/root/.ssh", "sensitive location"),
        ("/boot/grub", "sensitive location"),
        ("/var/lib/docker", "sensitive location"),
        ("/var/run/docker.sock", "sensitive location"),
    ],
)
def test_git_url_rejects_sensitive_paths(url, expected_substring):
    ok, msg = validate_git_url(url)
    assert ok is False
    assert expected_substring in msg


# ============================================================================
# validate_git_url — rejection categories
# ============================================================================


def test_git_url_rejects_empty():
    ok, msg = validate_git_url("")
    assert ok is False
    assert "required" in msg


@pytest.mark.parametrize(
    "url",
    [
        "../traversal",
        "repo/../secret",
        "/abs/../etc",
    ],
)
def test_git_url_rejects_traversal(url):
    ok, msg = validate_git_url(url)
    assert ok is False
    assert "traversal" in msg


def test_git_url_rejects_unknown_scheme():
    ok, msg = validate_git_url("ftp://example.com/repo")
    assert ok is False
    assert "Invalid" in msg
