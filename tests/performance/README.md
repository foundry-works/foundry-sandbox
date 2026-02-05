# Performance Tests

Performance benchmarks and load testing.

## Structure

- `bench_startup.sh` - Sandbox startup time benchmarks
- `bench_proxy_throughput.sh` - Proxy request throughput
- `bench_concurrent_sandboxes.sh` - Multiple sandbox performance

## Running Tests

```bash
# Run all performance tests
./tests/performance/run.sh

# Run specific benchmark
./tests/performance/bench_startup.sh
```

## Baselines

Performance baselines are stored in `baselines/` and compared against current runs.

## Guidelines

- Run on consistent hardware for meaningful comparisons
- Document system specs when recording baselines
- Test with realistic workloads
- Report p50, p95, p99 latencies
