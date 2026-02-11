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
