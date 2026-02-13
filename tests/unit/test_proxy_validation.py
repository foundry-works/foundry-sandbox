"""Unit tests for proxy_register() input validation and proxy_wait_ready() timing."""

import pytest

from foundry_sandbox.errors import ProxyError
from foundry_sandbox import proxy


class TestProxyRegisterValidation:
    """Validate proxy_register rejects bad inputs before hitting the network."""

    def test_empty_container_id(self):
        with pytest.raises(ProxyError, match="required"):
            proxy.proxy_register("", "10.0.0.1")

    def test_empty_ip_address(self):
        with pytest.raises(ProxyError, match="required"):
            proxy.proxy_register("abc123", "")

    @pytest.mark.parametrize("bad_ip", [
        "not-an-ip",
        "999.999.999.999",
        "10.0.0",
        "10.0.0.1.2",
        "abc",
        "10.0.0.1/24",
    ])
    def test_invalid_ip_rejected(self, bad_ip):
        with pytest.raises(ProxyError, match="invalid IP address"):
            proxy.proxy_register("container-1", bad_ip)

    @pytest.mark.parametrize("good_ip", [
        "10.0.0.1",
        "192.168.1.100",
        "172.16.0.1",
        "::1",
        "fe80::1",
        "2001:db8::1",
    ])
    def test_valid_ip_accepted(self, good_ip, monkeypatch):
        """Valid IPs should pass validation (will fail on curl, but that's OK)."""
        # Stub proxy_curl to avoid actual network calls
        monkeypatch.setattr(
            proxy, "proxy_curl",
            lambda *a, **kw: {"status": "registered"},
        )
        result = proxy.proxy_register("container-1", good_ip)
        assert "registered" in result


class TestProxyWaitReadyMonotonic:
    """proxy_wait_ready uses monotonic clock for accurate elapsed time."""

    def test_uses_clock_for_elapsed(self, monkeypatch):
        """Elapsed time should be based on _clock, not accumulated sleep durations."""
        clock_times = iter([0.0, 0.5, 1.5, 3.0, 10.0])
        sleep_calls = []

        def fake_sleep(duration):
            sleep_calls.append(duration)

        def fake_clock():
            return next(clock_times)

        # proxy_curl always fails — forces timeout
        monkeypatch.setattr(
            proxy, "proxy_curl",
            lambda *a, **kw: (_ for _ in ()).throw(OSError("no proxy")),
        )

        result = proxy.proxy_wait_ready(
            timeout=5,
            _sleep=fake_sleep,
            _clock=fake_clock,
        )

        assert result is False
        # Should have slept at least once
        assert len(sleep_calls) >= 1

    def test_returns_true_on_healthy(self, monkeypatch):
        """Returns True when proxy reports healthy."""
        clock_times = iter([0.0, 0.5])

        monkeypatch.setattr(
            proxy, "proxy_curl",
            lambda *a, **kw: {"http_code": 200, "body": {"status": "healthy"}},
        )

        result = proxy.proxy_wait_ready(
            timeout=5,
            _sleep=lambda d: None,
            _clock=lambda: next(clock_times),
        )

        assert result is True

    def test_timeout_respected(self, monkeypatch):
        """Should not loop past the timeout even if sleep is instant."""
        # Clock jumps past timeout on second call
        clock_times = iter([0.0, 100.0])

        monkeypatch.setattr(
            proxy, "proxy_curl",
            lambda *a, **kw: (_ for _ in ()).throw(OSError("no proxy")),
        )

        result = proxy.proxy_wait_ready(
            timeout=5,
            _sleep=lambda d: None,
            _clock=lambda: next(clock_times),
        )

        assert result is False
