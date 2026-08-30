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

## Final structural review

After the protocol and runtime boundary work, the same-machine comparison was
repeated against commit `8337a1b` using three sequential runs of:

```text
python3 tests/benchmark_http_headers.py --iterations 10000 --extra-headers 4
python3 tests/benchmark_proxy.py --requests 5000 --concurrency 8 --payload-size 4096 --warmup 5
```

The table reports the median of the three runs. The parser benchmark was run
in five-run baseline/final batches; the values below use the median of each
batch. The final source was commit `6416747`; the intervening changes only
corrected source-checkout version reporting and do not affect the measured
proxy paths.

| Benchmark | Structural baseline | Final | Change |
| --- | ---: | ---: | ---: |
| HTTP accept, average | 30.26 us | 30.24 us | -0.1% |
| HTTP channel, average | 28.74 us | 26.68 us | -7.2% |
| WebSocket accept, average | 26.66 us | 27.16 us | +1.9% |
| HTTP loopback, req/s | 7,030.8 | 7,046.9 | +0.2% |
| HTTP loopback, p95 | 1.747 ms | 1.506 ms | -13.8% |
| SOCKS5 loopback, req/s | 7,404.2 | 7,497.1 | +1.3% |
| SOCKS5 loopback, p95 | 1.234 ms | 1.185 ms | -4.0% |

The direct case in `benchmark_proxy.py` is a standalone asyncio echo path and
does not exercise pproxy, so its high scheduler variance is not used as a
modernization gate. HTTP and SOCKS5 throughput remain within the 5% target,
and the structural split does not introduce a measured proxy regression.

## Phase 4 workload review

This review was collected on 2026-08-30 with CPython 3.12.3 on Linux x86_64.
The default asyncio event loop was used unless noted otherwise. The optional
benchmark environment contained PyCryptodome 3.23.0, uvloop 0.22.1, h2 4.4.1,
asyncssh 2.24.0, and aioquic 1.3.0. Loopback workloads were repeated five
times for proxy/parser/state cases and three times for optional transport
fanout cases. Medians and sample standard deviations are reported; they are
not absolute machine-independent performance claims.

The primary proxy workload was:

```text
python tests/benchmark_proxy.py --protocols http socks5 ss --requests 1000 --concurrency 8 --payload-size 4096 --warmup 5
```

The `ss` case uses `chacha20` with the `verify_simple` plugin on both sides,
so it measures encrypted plugin framing rather than an unencrypted protocol
path. The setup workload was run with 100 fresh connections per protocol, and
the existing `benchmark_followup.py` pyperf suite was run with one process,
five values, and two warmups.

### Proxy throughput and latency

| Case | Throughput median (req/s) | Sample stdev | Average latency median | p95 latency median |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 2,485.4 | 192.0 | 2.993 ms | 3.836 ms |
| SOCKS5 | 6,410.1 | 81.6 | 1.090 ms | 1.499 ms |
| SS + verify_simple | 1,481.0 | 31.2 | 4.771 ms | 5.702 ms |

Fresh connection setup medians were 1.874 ms average / 2.383 ms p95 for
HTTP and 1.800 ms average / 2.130 ms p95 for SOCKS5. The corresponding
connections-per-second medians were 533.7 and 555.6. A single process-level
resource sample reported 26,612 KiB maximum RSS and 0.64 seconds CPU for HTTP,
26,692 KiB and 0.59 seconds for SOCKS5, and 28,584 KiB and 0.82 seconds for
the encrypted plugin case. These resource values are envelopes for the full
benchmark process, not per-connection allocations.

### Parser, state, and cipher microbenchmarks

The pyperf mean values were:

| Operation | Mean |
| --- | ---: |
| `vars` plus keyword expansion | 1.51 us |
| Cached mapping expansion | 1.37 us |
| Protocol guess, one candidate | 8.75 us |
| Protocol guess, two candidates | 17.7 us |
| Protocol guess, four candidates | 35.2 us |
| Task creation | 11.9 us |
| Registry task creation | 15.5 us |
| TaskGroup creation | 28.5 us |
| TaskGroup cancellation | 74.7 us |
| Disabled-statistics callback calls | 361 ns |
| HTTP header parsing | 6.26 us |
| WebSocket frame parsing | 2.56 us |
| SOCKS address parsing | 1.23 us |
| UDP bookkeeping | 1.47 us |
| Pure-Python ChaCha20 packet encryption | 918 us |
| Accelerated ChaCha20 packet encryption | 17.2 us |

The setup-only mapping comparison does not justify changing the public
argument plumbing. Protocol guessing and task tracking are required by the
current behavior and lifecycle contract. The accelerated cipher is materially
faster in this environment, but the pure-Python fallback remains necessary for
environments without PyCryptodome.

### High-cardinality and fragmented workloads

| Workload | Input | Median wall time | Median CPU time | Peak traced memory | Result |
| --- | --- | ---: | ---: | ---: | --- |
| Fragmented WebSocket | 1 MiB message, 256 x 4 KiB frames, 257-byte input chunks | 53.132 ms | 49.408 ms | 2.103 MiB | one message emitted |
| UDP association churn | 10,000 unique addresses with the 30-entry limit | 198.787 ms | 184.827 ms | 0.011 MiB | 29 associations retained |
| Verbose statistics | 10,000 unique remote/host keys | 782.861 ms | 715.256 ms | 4.529 MiB | 10,000 remote and host keys recorded |

The UDP result shows bounded state under high cardinality. The verbose result
is intentionally an unbounded statistics workload because the existing output
semantics retain per-key counters; changing that policy would need a separate
operational decision rather than a hidden optimization.

### Multiplexed and shutdown workloads

Optional transports were exercised with concurrent loopback fanout. Small
payload fanout used 16 streams; H2 was also tested with 32 concurrent 4 KiB
streams to cross the connection-level flow-control window.

| Case | Streams | Median throughput | Sample stdev | Active tasks | Shutdown median |
| --- | ---: | ---: | ---: | ---: | ---: |
| H2 | 16 | 564.9 streams/s | 146.2 | 98 | 0.513 ms |
| H3 | 16 | 208.6 streams/s | 18.0 | 65 | 1.228 ms |
| QUIC | 16 | 344.4 streams/s | 6.2 | 65 | 0.474 ms |
| TLS adapter | 8 | 210.8 streams/s | 17.6 | 16 | 2.431 ms |
| SSH channels | 16 | 410.7 streams/s | 31.5 | 32 | 6.707 ms |

The H2 32-stream/4 KiB case initially stalled after the connection send window
was exhausted. The event handler only woke stream writers for stream-specific
`WINDOW_UPDATE` events and ignored connection-level updates (`stream_id=0`).
The fix wakes all active stream writers for a connection-level update. The
regression workload now completes in all three runs, with a median of 485.2
streams/s, 65.952 ms wall time, 194 active tasks, 33 client tasks, and 64
server tasks. This is a correctness fix for multiplexed flow control, not a
wire-format or API change.

### Event-loop observation

For orientation, the same loopback shape with uvloop enabled produced median
throughputs of 10,045.5 req/s for HTTP and 2,892.5 req/s for the encrypted
plugin case across three runs. The default-loop medians above were 2,485.4 and
1,481.0 req/s respectively. This confirms that event-loop selection can have
a larger effect than the measured setup micro-optimizations, but it does not
justify making uvloop mandatory: it remains an optional, platform-dependent
extra and would change the runtime environment rather than the proxy contract.

### Phase 4 decision

The H2 flow-control correctness fix was accepted with a focused regression
test. No parser, UDP bookkeeping, task scheduling, drain batching, or cipher
rewrite was accepted: the isolated costs were setup-only, contract-required,
or lacked a stable proxy-level improvement of at least 5%. Existing cipher
selection, packet boundaries, framing, and lifecycle behavior are retained.
