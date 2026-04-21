"""Thread-safe Prometheus-style metrics registry.

Provides counters, histograms, and gauges that can be rendered in
Prometheus exposition format. Designed for zero-dependency use inside
the git safety server's threaded WSGI workers.
"""

import threading
import time

# Default histogram bucket boundaries (seconds)
_DEFAULT_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


def _serialize_labels(labels: dict[str, str]) -> str:
    """Sort labels into a deterministic key for dict lookup."""
    return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))


class _MetricsRegistry:
    """Thread-safe registry for Prometheus-style metrics."""

    def __init__(self, buckets: tuple[float, ...] = _DEFAULT_BUCKETS) -> None:
        self._lock = threading.Lock()
        # counter_name -> {label_key: count}
        self._counters: dict[str, dict[str, int]] = {}
        # counter_name -> {label_key: {label_k: label_v, ...}}
        self._counter_labels: dict[str, dict[str, dict[str, str]]] = {}
        # histogram_name -> {label_key: [values]}
        self._histograms: dict[str, dict[str, list[float]]] = {}
        self._histogram_labels: dict[str, dict[str, dict[str, str]]] = {}
        # gauge_name -> value
        self._gauges: dict[str, float] = {}
        self._gauge_labels: dict[str, dict[str, str]] = {}
        self._start_time: float = time.time()
        self._buckets = buckets
        # Metric metadata
        self._help: dict[str, str] = {}
        self._types: dict[str, str] = {}

    def register_counter(self, name: str, help_text: str) -> None:
        with self._lock:
            self._help[name] = help_text
            self._types[name] = "counter"
            self._counters.setdefault(name, {})
            self._counter_labels.setdefault(name, {})

    def register_histogram(self, name: str, help_text: str) -> None:
        with self._lock:
            self._help[name] = help_text
            self._types[name] = "histogram"
            self._histograms.setdefault(name, {})
            self._histogram_labels.setdefault(name, {})

    def register_gauge(self, name: str, help_text: str) -> None:
        with self._lock:
            self._help[name] = help_text
            self._types[name] = "gauge"

    def inc_counter(self, name: str, labels: dict[str, str], amount: int = 1) -> None:
        key = _serialize_labels(labels)
        with self._lock:
            if name not in self._counters:
                self._counters[name] = {}
                self._counter_labels[name] = {}
            self._counters[name][key] = self._counters[name].get(key, 0) + amount
            self._counter_labels[name][key] = labels

    def observe_histogram(self, name: str, value: float, labels: dict[str, str]) -> None:
        key = _serialize_labels(labels)
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = {}
                self._histogram_labels[name] = {}
            bucket = self._histograms[name]
            bucket.setdefault(key, []).append(value)
            self._histogram_labels[name][key] = labels

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = _serialize_labels(labels) if labels else ""
        with self._lock:
            self._gauges[f"{name}|{key}"] = value
            self._gauge_labels[f"{name}|{key}"] = labels or {}

    def render_prometheus(self) -> str:
        """Render all metrics in Prometheus exposition format."""
        with self._lock:
            lines: list[str] = []
            # Counters
            for name, series in sorted(self._counters.items()):
                lines.append(f"# HELP {name} {self._help.get(name, '')}")
                lines.append(f"# TYPE {name} counter")
                for key, count in sorted(series.items()):
                    lbl = self._counter_labels[name].get(key, {})
                    label_str = self._format_labels(lbl)
                    lines.append(f"{name}{label_str} {count}")

            # Histograms
            for name, series in sorted(self._histograms.items()):
                lines.append(f"# HELP {name} {self._help.get(name, '')}")
                lines.append(f"# TYPE {name} histogram")
                for key, values in sorted(series.items()):
                    lbl = self._histogram_labels[name].get(key, {})
                    label_str = self._format_labels(lbl)
                    self._render_histogram_series(lines, name, label_str, lbl, values)

            # Gauges
            for composite, value in sorted(self._gauges.items()):
                name = composite.split("|", 1)[0]
                lbl = self._gauge_labels.get(composite, {})
                if composite == sorted(self._gauges.keys())[0] or name != sorted(self._gauges.keys())[0].split("|", 1)[0]:
                    if f"# HELP {name}" not in "\n".join(lines):
                        lines.append(f"# HELP {name} {self._help.get(name, '')}")
                        lines.append(f"# TYPE {name} gauge")
                label_str = self._format_labels(lbl)
                lines.append(f"{name}{label_str} {value}")

            # Process uptime
            uptime = time.time() - self._start_time
            lines.append("# HELP process_uptime_seconds Total uptime in seconds")
            lines.append("# TYPE process_uptime_seconds gauge")
            lines.append(f"process_uptime_seconds {uptime:.2f}")

            return "\n".join(lines) + "\n"

    def _render_histogram_series(
        self,
        lines: list[str],
        name: str,
        label_str: str,
        labels: dict[str, str],
        values: list[float],
    ) -> None:
        count = len(values)
        total = sum(values)
        for boundary in self._buckets:
            bucket_count = sum(1 for v in values if v <= boundary)
            le_labels = {**labels, "le": str(boundary)}
            lines.append(f"{name}_bucket{self._format_labels(le_labels)} {bucket_count}")
        # +Inf bucket
        le_labels = {**labels, "le": "+Inf"}
        lines.append(f"{name}_bucket{self._format_labels(le_labels)} {count}")
        lines.append(f"{name}_sum{label_str} {total:.6f}")
        lines.append(f"{name}_count{label_str} {count}")

    @staticmethod
    def _format_labels(labels: dict[str, str]) -> str:
        if not labels:
            return ""
        pairs = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return "{" + pairs + "}"

    def reset(self) -> None:
        """Clear all metrics (for testing)."""
        with self._lock:
            self._counters.clear()
            self._counter_labels.clear()
            self._histograms.clear()
            self._histogram_labels.clear()
            self._gauges.clear()
            self._gauge_labels.clear()


# Module-level singleton
registry = _MetricsRegistry()

# Pre-register standard metrics
registry.register_counter(
    "git_safety_operations_total",
    "Total git operations processed",
)
registry.register_histogram(
    "git_safety_request_duration_seconds",
    "Request duration in seconds",
)
registry.register_counter(
    "git_safety_policy_decisions_total",
    "Policy decision counts by rule and outcome",
)
registry.register_counter(
    "wrapper_tamper_events_total",
    "Total wrapper tamper events detected",
)
