"""Unit tests for the exception hierarchy in foundry_sandbox.errors."""

import pytest

from foundry_sandbox.errors import (
    DockerError,
    ProxyError,
    SandboxError,
    SetupError,
    ValidationError,
)


class TestExceptionHierarchy:
    """All concrete exceptions must be subclasses of SandboxError."""

    @pytest.mark.parametrize("exc_cls", [ValidationError, SetupError, ProxyError, DockerError])
    def test_subclass_of_sandbox_error(self, exc_cls):
        assert issubclass(exc_cls, SandboxError)

    @pytest.mark.parametrize("exc_cls", [ValidationError, SetupError, ProxyError, DockerError])
    def test_catchable_via_base(self, exc_cls):
        with pytest.raises(SandboxError):
            raise exc_cls("test")

    def test_sandbox_error_is_exception(self):
        assert issubclass(SandboxError, Exception)

    @pytest.mark.parametrize("exc_cls", [ValidationError, SetupError, ProxyError, DockerError])
    def test_message_preserved(self, exc_cls):
        err = exc_cls("something went wrong")
        assert str(err) == "something went wrong"


class TestErrorFunctionalBehavior:
    """Functional error scenario tests."""

    def test_error_chaining(self):
        inner = ValueError("inner failure")
        outer = SandboxError("outer")
        outer.__cause__ = inner
        assert outer.__cause__ is inner
        assert str(outer) == "outer"

    def test_raise_from_chaining(self):
        inner = OSError("disk full")
        with pytest.raises(SandboxError) as exc_info:
            try:
                raise inner
            except OSError as e:
                raise SandboxError("outer") from e
        assert exc_info.value.__cause__ is inner

    @pytest.mark.parametrize("exc_cls", [ValidationError, SetupError, ProxyError, DockerError])
    def test_args_attribute_preserved(self, exc_cls):
        err = exc_cls("msg1", "msg2")
        assert err.args == ("msg1", "msg2")

    def test_multiline_message_str(self):
        msg = "line one\nline two\nline three"
        err = SandboxError(msg)
        assert str(err) == msg
        assert "\n" in str(err)

    @pytest.mark.parametrize("exc_cls", [SandboxError, ValidationError, SetupError, ProxyError, DockerError])
    def test_pickle_roundtrip(self, exc_cls):
        import pickle
        original = exc_cls("pickle test message")
        restored = pickle.loads(pickle.dumps(original))
        assert type(restored) is exc_cls
        assert str(restored) == str(original)
        assert restored.args == original.args


class TestSetupErrorInNewSetup:
    """_SetupError from new_setup should be catchable as SetupError."""

    def test_setup_error_subclass(self):
        from foundry_sandbox.commands.new_setup import _SetupError

        assert issubclass(_SetupError, SetupError)
        assert issubclass(_SetupError, SandboxError)

    def test_catchable_via_setup_error(self):
        from foundry_sandbox.commands.new_setup import _SetupError

        with pytest.raises(SetupError):
            raise _SetupError("rollback needed")
