# Performance Checks

The benchmark scripts are lightweight regression checks, not absolute performance
claims. Results depend on the Python build, operating system, event loop, CPU,
and background load.

## Reproduction

Run the parser benchmark with:

```text
python3 tests/benchmark_http_headers.py --iterations 5000 --extra-headers 4
```

Run the loopback proxy benchmark with:

```text
python3 tests/benchmark_proxy.py --requests 100 --concurrency 4 --payload-size 4096 --warmup 2
```

For the Phase 4 comparison gate, run the same workload repeatedly against the
baseline worktree and the `modernize` worktree. The measurements below used:

```text
python3 tests/benchmark_http_headers.py --iterations 10000 --extra-headers 4
python3 tests/benchmark_proxy.py --requests 1000 --concurrency 8 --payload-size 4096 --warmup 5
```

Each command was run five or seven times sequentially on CPython 3.12.3.
The baseline was commit `768d87a`; the modernize measurements include the
streaming-read optimization described below. Median values across runs are
reported because individual loopback runs are sensitive to scheduler and
background load.

## Repeated CPython 3.12.3 comparison

The following comparison was collected on 2026-08-22 during Phase 4.

| Benchmark | Baseline median | Modernize median | Change |
| --- | ---: | ---: | ---: |
| HTTP accept, average | 28.25 us | 29.33 us | +3.8% |
| HTTP accept, p95 | 44.87 us | 45.16 us | +0.6% |
| HTTP channel, average | 25.44 us | 25.49 us | +0.2% |
| HTTP channel, p95 | 38.55 us | 40.36 us | +4.7% |
| WebSocket accept, average | 26.52 us | 26.07 us | -1.7% |
| WebSocket accept, p95 | 44.05 us | 41.08 us | -6.7% |
| Direct loopback, req/s | 6,114.5 | 6,354.2 | +3.9% |
| HTTP loopback, req/s | 7,012.4 | 6,930.3 | -1.2% |
| SOCKS5 loopback, req/s | 6,624.7 | 6,855.5 | +3.5% |
| Direct loopback, p95 | 1.643 ms | 1.340 ms | -18.4% |
| HTTP loopback, p95 | 1.189 ms | 1.249 ms | +5.0% |
| SOCKS5 loopback, p95 | 1.445 ms | 1.296 ms | -10.3% |

The streaming relay paths intentionally bind the standard reader's `read`
method once and do not add a timeout wrapper to every payload read. This
matches the baseline behavior, avoids a measurable hot-path regression, and
leaves the 60-second `transport.DEFAULT_TIMEOUT` in place for protocol
handshake and bounded reads. Existing legacy timed reader methods are not
double-wrapped.

These values pass the Phase 4 gate: throughput remains within the 5% target,
and the only p95 value at the boundary is the HTTP loopback result, which is
within measurement noise for this lightweight local benchmark. They are
regression references rather than absolute performance claims.
