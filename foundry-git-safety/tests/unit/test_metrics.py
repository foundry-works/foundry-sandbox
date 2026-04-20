"""Unit tests for the metrics registry."""

import threading

import pytest

from foundry_git_safety.metrics import _MetricsRegistry, registry


@pytest.fixture
def reg():
    r = _MetricsRegistry()
    r.register_counter("test_counter", "A test counter")
    r.register_histogram("test_histogram", "A test histogram")
    r.register_gauge("test_gauge", "A test gauge")
    return r


class TestCounter:
    def test_increment(self, reg):
        reg.inc_counter("test_counter", {"verb": "push"})
        output = reg.render_prometheus()
        assert 'test_counter{verb="push"} 1' in output

    def test_increment_multiple(self, reg):
        reg.inc_counter("test_counter", {"verb": "push"}, amount=5)
        output = reg.render_prometheus()
        assert 'test_counter{verb="push"} 5' in output

    def test_multiple_labels(self, reg):
        reg.inc_counter("test_counter", {"verb": "push", "sandbox": "sbx-1"})
        reg.inc_counter("test_counter", {"verb": "push", "sandbox": "sbx-2"})
        output = reg.render_prometheus()
        assert 'test_counter{sandbox="sbx-1",verb="push"} 1' in output
        assert 'test_counter{sandbox="sbx-2",verb="push"} 1' in output

    def test_auto_register_on_inc(self):
        r = _MetricsRegistry()
        r.inc_counter("unregistered", {"x": "y"})
        assert "unregistered" in r._counters


class TestHistogram:
    def test_observe(self, reg):
        reg.observe_histogram("test_histogram", 0.5, {"verb": "push"})
        output = reg.render_prometheus()
        assert "# TYPE test_histogram histogram" in output
        assert "test_histogram_count{verb=\"push\"} 1" in output
        assert "test_histogram_sum{verb=\"push\"}" in output

    def test_buckets(self, reg):
        reg.observe_histogram("test_histogram", 0.05, {"verb": "push"})
        reg.observe_histogram("test_histogram", 0.5, {"verb": "push"})
        output = reg.render_prometheus()
        # 0.05 <= 0.1 bucket
        assert "test_histogram_bucket{le=\"0.1\",verb=\"push\"} 1" in output
        # Both <= 0.5
        assert "test_histogram_bucket{le=\"0.5\",verb=\"push\"} 2" in output
        # +Inf
        assert "test_histogram_bucket{le=\"+Inf\",verb=\"push\"} 2" in output


class TestGauge:
    def test_set(self, reg):
        reg.set_gauge("test_gauge", 42.0)
        output = reg.render_prometheus()
        assert "test_gauge 42.0" in output


class TestPrometheusFormat:
    def test_help_and_type(self, reg):
        reg.inc_counter("test_counter", {"verb": "push"})
        output = reg.render_prometheus()
        assert "# HELP test_counter A test counter" in output
        assert "# TYPE test_counter counter" in output

    def test_uptime(self, reg):
        output = reg.render_prometheus()
        assert "process_uptime_seconds" in output


class TestReset:
    def test_reset_clears_all(self, reg):
        reg.inc_counter("test_counter", {"verb": "push"})
        reg.observe_histogram("test_histogram", 0.5, {"verb": "push"})
        reg.set_gauge("test_gauge", 1.0)
        reg.reset()
        output = reg.render_prometheus()
        assert "test_counter" not in output
        assert "test_histogram" not in output


class TestThreadSafety:
    def test_concurrent_counter_increments(self, reg):
        n_threads = 10
        n_increments = 1000

        def worker():
            for _ in range(n_increments):
                reg.inc_counter("test_counter", {"verb": "push"})

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        output = reg.render_prometheus()
        expected = n_threads * n_increments
        assert f'test_counter{{verb="push"}} {expected}' in output


class TestGlobalRegistry:
    def test_registry_has_predefined_metrics(self):
        output = registry.render_prometheus()
        assert "git_safety_operations_total" in output
        assert "git_safety_request_duration_seconds" in output
        assert "git_safety_policy_decisions_total" in output
