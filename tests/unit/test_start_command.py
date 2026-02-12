"""Unit tests for metadata flag parsing in `foundry_sandbox.commands.start`."""

from __future__ import annotations


from foundry_sandbox.commands.start import _export_feature_flags, _flag_enabled


def test_flag_enabled_accepts_common_true_values() -> None:
    assert _flag_enabled(True) is True
    assert _flag_enabled(1) is True
    assert _flag_enabled("1") is True
    assert _flag_enabled("true") is True
    assert _flag_enabled(" yes ") is True


def test_flag_enabled_rejects_common_false_values() -> None:
    assert _flag_enabled(False) is False
    assert _flag_enabled(0) is False
    assert _flag_enabled("0") is False
    assert _flag_enabled("false") is False
    assert _flag_enabled("") is False
    assert _flag_enabled(None) is False


def test_export_feature_flags_normalizes_env_values(monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_ENABLE_OPENCODE", raising=False)
    monkeypatch.delenv("SANDBOX_ENABLE_ZAI", raising=False)

    env: dict[str, str] = {}
    enable_opencode, enable_zai = _export_feature_flags(
        {"enable_opencode": True, "enable_zai": 0}, env
    )

    assert enable_opencode is True
    assert enable_zai is False
    assert env["SANDBOX_ENABLE_OPENCODE"] == "1"
    assert env["SANDBOX_ENABLE_ZAI"] == "0"
