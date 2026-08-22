# Follow-up Legacy Inventory

This inventory records the starting point for the follow-up modernization work. It
separates compatibility surfaces from implementation details that may be simplified
after measurement. It is intentionally limited to the current source tree and does
not add a new protocol or distribution target.

## Baseline

- Base revision: `master` at `9f9f8bd` (`Modernize internals while preserving proxy compatibility (#4)`).
- Working branch: `modernize-followup`.
- Runtime: CPython `3.12.3` on Linux x86_64/WSL2, using the default asyncio event loop.
- Package requirement: Python `3.12+`.
- Distribution model: private Git repository installation through a PEP 517-compatible
  `pip install git+https://...` workflow; no PyPI release is planned.
- Optional modules available in the baseline environment: none of `uvloop`,
  PyCryptodome, `h2`, `aioquic`, or `asyncssh`.
- Development tools are available in the local development environment through the
  existing development setup; reproducible checks are listed below.

## Compatibility surfaces to preserve

The following are user-visible or wire-visible and are out of scope for implicit
cleanup:

- The `pproxy` command, its existing options, defaults, exit behavior, and version/help
  output shape.
- URI parsing, composed schemes, user information, cipher/plugin parameters, local
  binds, query rules, fragments, and jump configuration.
- The public import facades in `pproxy`, `pproxy.proto`, `pproxy.server`,
  `pproxy.transport`, and the protocol/runtime packages introduced by the previous
  modernization.
- HTTP, SOCKS4, SOCKS5, WebSocket, Shadowsocks, ShadowsocksR, Trojan, direct, tunnel,
  redirect, PF, Unix-socket, TCP, and UDP behavior supported by the current tree.
- Authentication, scheduling modes, statistics/verbose meaning, EOF and cancellation
  behavior, cipher fallback behavior, packet boundaries, nonce/IV handling, and plugin
  framing.
- Optional H2, H3/QUIC, and SSH adapters. Their dependencies remain optional and are
  tested separately when installed.

Compatibility facades and optional adapters may be reorganized internally, but their
current import names and callable contracts remain stable unless a separate change is
approved.

## Legacy and simplification candidates

| Area | Current observation | Treatment |
| --- | --- | --- |
| `setup.py` | A one-line setuptools invocation that delegates to `pyproject.toml`. | Approved breaking cleanup for Phase 2, after Phase 0 and Phase 1 validation. |
| Asyncio compatibility | `pproxy.app` still contains a fallback to the removed `asyncio.Task.all_tasks` API. | Safe Phase 1 cleanup. |
| Source versioning | `pproxy.__doc__` uses source Git metadata and a `setuptools-scm` fallback. | Keep; source checkouts and built wheels need consistent versions. |
| Stream compatibility | `pproxy.transport.streams` supports legacy `read_w` and `read_n` reader methods. | Keep until a separately measured compatibility decision is made. |
| Server argument plumbing | Server startup and protocol adapters use `vars(...)` and `**kwargs` in setup paths. | Measure in Phase 3; change only if the proxy workload shows a stable gain. |
| Protocol detection | The registry tries configured protocols in order and preserves auto-detection. | Measure handshake cost; keep the existing path and consider only additive explicit listeners. |
| Relay lifecycle | The bidirectional relay uses `asyncio.TaskGroup` and cancellation propagation. | Measure creation/cancellation and preserve EOF/error semantics. |
| Statistics callbacks | The default callback is a no-op, but callback construction/bookkeeping remains in the connection path. | Measure disabled-statistics cost before considering a fast path. |
| Parser/cipher buffers | Parsers and cipher implementations use existing bytes/bytearray operations and pure-Python fallbacks. | Measure representative workloads; preserve wire behavior and fallback support. |
| Private optional APIs | H2, QUIC, TLS, and SSH adapters access backend-private objects. | Isolate incrementally behind adapters; do not alter optional behavior in this pass. |

## Hot-path map

Connection setup flows through `pproxy.server.stream_handler`, protocol registry
guess/accept calls, optional cipher preparation, remote selection, and relay startup.
The setup path currently includes `vars(self)`/`**kwargs` expansion, protocol guessing,
connection tasks, statistics callback creation, and remote handshake work.

Payload relay flows through `pproxy.relay.relay_with_taskgroup`, protocol channel
methods, transport reads/writes, optional cipher transforms, and `drain` calls. The
relay path must be evaluated separately from setup because its costs scale with byte
volume rather than connection count.

The initial measurement targets are therefore:

1. Argument/context construction and expansion.
2. Protocol guess/accept attempts for HTTP and SOCKS5.
3. Per-connection task creation and `TaskGroup` cancellation.
4. Disabled statistics and verbose callback overhead.
5. HTTP header, WebSocket frame, SOCKS address, UDP bookkeeping, cipher packet, and
   payload relay costs.

## Workloads and reproducible commands

The proxy-facing gate uses loopback HTTP and SOCKS5 requests, while microbenchmarks
are used only to explain individual costs. The direct echo case is not a proxy gate.
Representative workloads are:

- short-lived HTTP connections with a 4 KiB payload;
- short-lived SOCKS5 connections with a 4 KiB payload;
- encrypted Shadowsocks traffic when an accelerated or pure-Python cipher is
  available;
- long-lived bidirectional relay traffic;
- parser and setup microbenchmarks with fixed input fixtures.

Baseline commands:

```text
python -m unittest discover -s tests -p 'test_*.py'
python -O -m unittest discover -s tests -p 'test_*.py'
python -m pytest -q
python -m compileall -q pproxy tests
python tests/benchmark_http_headers.py --iterations 10000 --extra-headers 4
python tests/benchmark_proxy.py --requests 1000 --concurrency 8 --payload-size 4096 --warmup 5
python -m build --wheel
```

The same interpreter, dependency set, workload, and machine must be used for before
and after measurements. At least five repeated samples are required for a decision;
median and variation are recorded. A runtime change proceeds only when the relevant
proxy workload shows a stable improvement of at least 5%, or a clearly documented
memory/CPU reduction with no throughput or latency regression.

## Deliberately deferred changes

The following are not implicit consequences of this inventory:

- making uvloop mandatory;
- removing pure-Python cipher support or requiring accelerated cryptography;
- removing protocol auto-detection or public compatibility facades;
- removing legacy reader methods or private optional-backend adapters;
- changing wire formats, cipher framing, authentication, or lifecycle semantics.

The only currently approved breaking cleanup is removal of the redundant `setup.py`
after the Phase 0 and Phase 1 gates have passed and PEP 517/Git installation has been
validated.
