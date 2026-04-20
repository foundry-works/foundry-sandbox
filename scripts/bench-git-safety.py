#!/usr/bin/env python3
"""Python benchmark for foundry-git-safety server latency.

Higher-precision version of bench-git-safety.sh using time.perf_counter.
Run with: python scripts/bench-git-safety.py --sandbox <name>

Requires: sbx CLI installed, foundry-git-safety server running.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from typing import Any


def run_sbx_exec(sandbox_name: str, cmd: list[str]) -> tuple[int, float]:
    """Run a command in the sandbox and return (exit_code, elapsed_seconds)."""
    args = ["sbx", "exec", sandbox_name, "--"] + cmd
    start = time.perf_counter()
    try:
        subprocess.run(args, capture_output=True, text=True, timeout=60)
        rc = 0
    except subprocess.TimeoutExpired:
        rc = -1
    except subprocess.CalledProcessError as e:
        rc = e.returncode
    elapsed = time.perf_counter() - start
    return rc, elapsed


def measure_operation(
    sandbox_name: str,
    op_name: str,
    cmd: list[str],
    samples: int = 20,
    warmup: int = 3,
) -> dict[str, Any]:
    """Measure an operation and return statistics."""
    # Warmup
    for _ in range(warmup):
        run_sbx_exec(sandbox_name, cmd)

    # Measure
    timings: list[float] = []
    for _ in range(samples):
        _, elapsed = run_sbx_exec(sandbox_name, cmd)
        timings.append(elapsed)

    # Compute statistics (in milliseconds)
    ms = [t * 1000 for t in timings]
    sorted_ms = sorted(ms)
    n = len(sorted_ms)

    stats = {
        "samples": ms,
        "mean": round(mean(ms), 2),
        "p50": round(median(ms), 2),
        "p95": round(sorted_ms[int(n * 0.95)] if n >= 20 else sorted_ms[-1], 2),
        "p99": round(sorted_ms[int(n * 0.99)] if n >= 100 else sorted_ms[-1], 2),
        "min": round(min(ms), 2),
        "max": round(max(ms), 2),
    }

    print(
        f"  {op_name:<20}  mean={stats['mean']:7.1f}ms  "
        f"p50={stats['p50']:7.1f}ms  p95={stats['p95']:7.1f}ms  "
        f"min={stats['min']:7.1f}ms  max={stats['max']:7.1f}ms"
    )
    return stats


def main():
    parser = argparse.ArgumentParser(description="Benchmark git-safety latency")
    parser.add_argument("--sandbox", required=True, help="Sandbox name")
    parser.add_argument("--samples", type=int, default=20, help="Samples per operation")
    parser.add_argument("--warmup", type=int, default=3, help="Warmup iterations")
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).parent / "bench-results"),
        help="Output directory for JSON results",
    )
    args = parser.parse_args()

    # Prerequisites
    if not shutil_which("sbx"):
        print("ERROR: sbx CLI not found", file=sys.stderr)
        sys.exit(1)

    # System info
    sbx_version = subprocess.run(
        ["sbx", "--version"], capture_output=True, text=True, timeout=10
    ).stdout.strip()

    print("=== Git Safety Latency Benchmark (Python) ===")
    print(f"  Sandbox: {args.sandbox}")
    print(f"  Samples: {args.samples} (warmup: {args.warmup})")
    print(f"  sbx version: {sbx_version}")
    print()

    operations = [
        ("status", ["git", "status"]),
        ("log-10", ["git", "log", "--oneline", "-10"]),
        ("diff", ["git", "diff", "HEAD~1"]),
        ("fetch", ["git", "fetch", "origin"]),
        ("remote-v", ["git", "remote", "-v"]),
    ]

    results = {}
    for op_name, cmd in operations:
        results[op_name] = measure_operation(
            args.sandbox, op_name, cmd, args.samples, args.warmup
        )

    # Write JSON
    os.makedirs(args.output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = Path(args.output_dir) / f"{timestamp}.json"

    output = {
        "timestamp": timestamp,
        "sbx_version": sbx_version,
        "sandbox": args.sandbox,
        "samples": args.samples,
        "warmup": args.warmup,
        "operations": {name: {k: v for k, v in stats.items() if k != "samples"} for name, stats in results.items()},
    }
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nResults written to {output_path}")


def shutil_which(cmd: str) -> str | None:
    """Find executable on PATH."""
    import shutil
    return shutil.which(cmd)


if __name__ == "__main__":
    main()
