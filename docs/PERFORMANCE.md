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

## Representative CPython 3.12.3 run

The following run was collected on 2026-08-22 during Phase 4. It is retained
to make future changes comparable under the same command and workload.

| Benchmark | Result |
| --- | ---: |
| HTTP accept, average | 35.68 us |
| HTTP channel, average | 39.44 us |
| WebSocket accept, average | 41.77 us |
| Direct loopback | 5,095.5 req/s |
| HTTP loopback | 3,973.9 req/s |
| SOCKS5 loopback | 3,845.2 req/s |

The stream transport optimization in this phase avoids wrapping an existing
legacy timed read method in a second timeout. Standard asyncio readers retain
the 60-second timeout supplied by `transport.DEFAULT_TIMEOUT`.
