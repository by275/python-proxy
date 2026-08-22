# Follow-up Performance Review

This document records the Phase 3 and Phase 5 measurements from the follow-up
modernization branch. It is a decision record, not an absolute performance claim.
The loopback workload is sensitive to scheduler and host load, so medians and sample
variation are reported together.

## Environment and commands

- Revision under test: `modernize-followup` after the setup-only cleanup and benchmark
  harness commits.
- Runtime: CPython `3.12.3` on Linux x86_64/WSL2 with the default asyncio event loop.
- Optional runtime modules: `uvloop` and PyCryptodome were not installed.
- Proxy workload:

  ```text
  python tests/benchmark_proxy.py --protocols http socks5 --requests 1000 --concurrency 8 --payload-size 4096 --warmup 5
  ```

- Setup latency workload:

  ```text
  python tests/benchmark_setup.py --connections 100
  ```

- Long-relay workload used to exercise the 256 KiB drain batching threshold:

  ```text
  python tests/benchmark_proxy.py --protocols http socks5 --requests 100 --concurrency 4 --payload-size 1048576 --warmup 2
  ```

- Microbenchmarks:

  ```text
  python tests/benchmark_followup.py -p 1 -n 5 -w 2 --min-time 0.03
  ```

All loopback and setup commands were repeated five times. The pyperf run used five
values and two warmups in one process. The direct echo case is not used as a proxy
performance gate.

## Proxy workload

| Case | Throughput median | Sample stdev | Roundtrip average median | Roundtrip p95 median |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 2,333.1 req/s | 187.1 | 3.217 ms | 4.358 ms |
| SOCKS5 | 5,948.3 req/s | 580.3 | 1.186 ms | 1.698 ms |

These values are the reference for this follow-up branch. They are not compared with
the direct echo path, and the variance is large enough that a small microbenchmark
change cannot be promoted without a separate before/after proxy run.

## Connection setup latency

| Case | Setup median | Sample stdev | Setup p95 median | Connections/s median |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 1.802 ms | 0.138 ms | 2.376 ms | 554.9 |
| SOCKS5 | 1.753 ms | 0.052 ms | 2.258 ms | 570.5 |

The setup measurement opens a new proxy connection, completes the protocol handshake,
and closes the returned stream for every sample. It does not measure an already-open
long-lived relay.

The 1 MiB long-relay run produced these medians across five samples:

| Case | Throughput median | Sample stdev | Roundtrip average median | Roundtrip p95 median |
| --- | ---: | ---: | ---: | ---: |
| HTTP | 128.1 req/s | 28.6 | 27.899 ms | 34.209 ms |
| SOCKS5 | 154.9 req/s | 26.2 | 23.266 ms | 31.631 ms |

This exercises repeated writes and `drain` batching, but it does not identify a safe
alternative batching policy. The existing threshold and close behavior are retained.

## Setup microbenchmarks

The following are pyperf mean values with the reported standard deviation. They isolate
costs; they are not proxy throughput results.

| Operation | Mean | Standard deviation | Interpretation |
| --- | ---: | ---: | --- |
| `vars` plus keyword expansion | 1.20 us | 0.12 us | Small setup cost; not a per-payload operation. |
| Cached mapping expansion | 1.49 us | 0.25 us | No stable advantage over the current operation. |
| Protocol guess, one candidate | 7.57 us | 0.08 us | Required by the current auto-detection contract. |
| Protocol guess, two candidates | 18.6 us | 3.2 us | Scales with configured candidates. |
| Protocol guess, four candidates | 32.5 us | 0.6 us | An explicit listener could avoid this, but would be additive API work. |
| Task creation | 11.3 us | 1.0 us | Baseline asyncio task cost. |
| Registry task creation | 15.7 us | 1.1 us | Tracking adds a small lifecycle cost. |
| TaskGroup creation | 26.6 us | 0.2 us | Preserves structured cancellation semantics. |
| TaskGroup cancellation | 68.0 us | 0.4 us | Error/cancellation path, not the normal payload path. |
| Disabled-statistics callback calls | 319 ns | 2 ns | Too small to justify a new runtime branch. |

The `vars`/mapping comparison is not a production optimization result: server startup
creates the handler partial once, and replacing that setup plumbing would enlarge the
compatibility surface without changing the measured relay path.

## Parser, bookkeeping, and cipher microbenchmarks

| Operation | Mean | Standard deviation |
| --- | ---: | ---: |
| HTTP header parsing | 6.93 us | 0.50 us |
| WebSocket frame parsing | 2.19 us | 0.25 us |
| SOCKS address parsing | 1.51 us | 0.19 us |
| UDP bookkeeping | 1.75 us | 0.36 us |
| Pure-Python ChaCha20 packet encryption | 1.19 ms | 0.20 ms |

The accelerated cipher benchmark was skipped because PyCryptodome was not installed in
the measurement environment. Existing cipher tests continue to cover pure-Python
correctness and packet round trips. The pure-Python implementation remains supported;
this follow-up does not change cipher selection, packet boundaries, nonce/IV handling,
or plugin framing.

The pyperf allocation-tracking mode was also run for the parser, bookkeeping, task, and
cipher cases. It reported process-level memory baselines rather than a stable
operation-specific allocation delta, so no allocation-sensitive rewrite was accepted.

## Optimization decision

No Phase 4 runtime optimization was accepted. The measured candidates either:

- were small setup-only costs;
- were required to preserve protocol auto-detection or structured cancellation;
- had no stable advantage in the isolated comparison; or
- would require a compatibility or API decision outside the approved scope.

No parser or cipher rewrite was accepted either. The measurements identify future
profiling targets, but they do not establish a safe 5% proxy-level improvement. The
existing pure-Python cipher fallback and all current protocol facades therefore remain
unchanged.
