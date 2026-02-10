"""Unit tests for boolean argument parsing in `foundry_sandbox.legacy_bridge`."""

from __future__ import annotations

from foundry_sandbox import legacy_bridge


def test_parse_bool_arg() -> None:
    assert legacy_bridge._parse_bool_arg("1") is True
    assert legacy_bridge._parse_bool_arg("true") is True
    assert legacy_bridge._parse_bool_arg("yes") is True
    assert legacy_bridge._parse_bool_arg("on") is True

    assert legacy_bridge._parse_bool_arg("0") is False
    assert legacy_bridge._parse_bool_arg("false") is False
    assert legacy_bridge._parse_bool_arg("") is False
    assert legacy_bridge._parse_bool_arg(None) is False


def test_bridge_copy_configs_parses_false_isolation(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_copy_configs_to_container(container_id: str, **kwargs: object) -> None:
        captured["container_id"] = container_id
        captured.update(kwargs)

    monkeypatch.setattr(
        legacy_bridge.credential_setup,
        "copy_configs_to_container",
        _fake_copy_configs_to_container,
    )

    rc, stdout, stderr = legacy_bridge._run_bridge(
        "_bridge_copy_configs_to_container",
        ["dev-1", "0", "0", "", "false", "main", "sandbox/test", "https://github.com/o/r.git"],
    )

    assert rc == 0
    assert stdout == ""
    assert stderr == ""
    assert captured["container_id"] == "dev-1"
    assert captured["skip_plugins"] is False
    assert captured["enable_ssh"] is False
    assert captured["isolate_credentials"] is False


def test_bridge_copy_configs_parses_true_isolation(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_copy_configs_to_container(container_id: str, **kwargs: object) -> None:
        captured["container_id"] = container_id
        captured.update(kwargs)

    monkeypatch.setattr(
        legacy_bridge.credential_setup,
        "copy_configs_to_container",
        _fake_copy_configs_to_container,
    )

    rc, _, _ = legacy_bridge._run_bridge(
        "_bridge_copy_configs_to_container",
        ["dev-1", "1", "1", "apps/api", "true", "main", "sandbox/test", "https://github.com/o/r.git"],
    )

    assert rc == 0
    assert captured["skip_plugins"] is True
    assert captured["enable_ssh"] is True
    assert captured["isolate_credentials"] is True
    assert captured["working_dir"] == "apps/api"

