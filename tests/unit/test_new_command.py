"""Unit tests for `foundry_sandbox.commands.new` replay/preset helpers."""

from __future__ import annotations

import click.testing

from foundry_sandbox.commands.new import _apply_saved_new_defaults, new


def test_apply_saved_new_defaults_uses_saved_values() -> None:
    saved = {
        "repo": "octocat/hello-world",
        "branch": "sandbox/test",
        "from_branch": "main",
        "mounts": ["a:/a:ro"],
        "copies": ["b:/b"],
        "network_mode": "host-only",
        "sync_ssh": True,
        "enable_opencode": True,
        "enable_zai": False,
        "working_dir": "apps/api",
        "sparse": True,
        "pip_requirements": "requirements.txt",
        "allow_pr": True,
    }

    result = _apply_saved_new_defaults(
        saved,
        explicit_params=set(),
        repo="",
        branch="",
        from_branch="",
        mounts=(),
        copies=(),
        network="",
        with_ssh=False,
        with_opencode=False,
        with_zai=False,
        wd="",
        sparse=False,
        pip_requirements="",
        allow_pr=False,
    )

    assert result[0] == "octocat/hello-world"
    assert result[1] == "sandbox/test"
    assert result[2] == "main"
    assert result[3] == ("a:/a:ro",)
    assert result[4] == ("b:/b",)
    assert result[5] == "host-only"
    assert result[6] is True
    assert result[7] is True
    assert result[8] is False
    assert result[9] == "apps/api"
    assert result[10] is True
    assert result[11] == "requirements.txt"
    assert result[12] is True


def test_apply_saved_new_defaults_preserves_explicit_values() -> None:
    saved = {
        "repo": "octocat/hello-world",
        "branch": "sandbox/test",
        "allow_pr": False,
    }

    result = _apply_saved_new_defaults(
        saved,
        explicit_params={"repo", "branch", "allow_pr"},
        repo="explicit/repo",
        branch="explicit/branch",
        from_branch="",
        mounts=(),
        copies=(),
        network="",
        with_ssh=False,
        with_opencode=False,
        with_zai=False,
        wd="",
        sparse=False,
        pip_requirements="",
        allow_pr=True,
    )

    assert result[0] == "explicit/repo"
    assert result[1] == "explicit/branch"
    assert result[12] is True


def test_new_rejects_last_and_preset_together() -> None:
    runner = click.testing.CliRunner()
    result = runner.invoke(new, ["--last", "--preset", "demo"])
    assert result.exit_code == 1
    assert "cannot be used together" in result.output


def test_new_last_treats_from_flag_as_explicit(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_apply(saved: dict[str, object], **kwargs: object):
        captured["from_branch"] = kwargs["from_branch"]
        captured["explicit_params"] = kwargs["explicit_params"]
        raise SystemExit(0)

    monkeypatch.setattr(
        "foundry_sandbox.commands.new.load_last_cast_new",
        lambda: {"repo": "octocat/hello-world", "from_branch": "saved/base"},
    )
    monkeypatch.setattr("foundry_sandbox.commands.new._apply_saved_new_defaults", _fake_apply)

    runner = click.testing.CliRunner()
    result = runner.invoke(new, ["octocat/hello-world", "--last", "--from", "cli/base"])

    assert result.exit_code == 0
    assert captured["from_branch"] == "cli/base"
    assert "from_branch" in captured["explicit_params"]
