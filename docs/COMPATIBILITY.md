# Compatibility Baseline

This document defines the Phase 0 baseline for the modernization work. It is not a list of features to remove; it records the external surfaces that must remain stable after internal refactoring.

## Baseline

- Code baseline: `master` `768d87a` (`Fix websocket tunnel frame handling`)
- Working branch: `modernize`
- Supported Python: `3.12+`
- Installation: `pip install git+https://github.com/...` from the personal GitHub repository
- PyPI distribution: none
- `cfp://`: behavior from `feat-cfp` `3fabba2` is a future compatibility target. Phase 0 does not add it to `master`.
- Excluded files: `Dockerfile`, `entrypoint.sh`, and `dev.txt` must not be modified or committed unless explicitly requested.

## External Compatibility Surface

| Area | Surface to preserve | Phase 0 status |
| --- | --- | --- |
| CLI | `pproxy`, `-l`, `-r`, `-ul`, `-ur`, `-b`, `-a`, `-s`, `-d`, `-v`, `--ssl`, `--pac`, `--get`, `--auth`, `--sys`, `--reuse`, `--daemon`, `--test`, `--version` | Recorded from the current parser |
| Defaults | `http+socks4+socks5://:8080/` when no listener is specified; `fa` scheduling | Preserve |
| Python API | `pproxy.Connection`, `pproxy.Server`, `pproxy.Rule`, `pproxy.DIRECT` | Preserve as compatibility facades |
| Server API | `Server(uri)`, `start_server(args)`, and the existing args shape | Preserve while introducing internal adapters incrementally |
| URI grammar | Scheme composition, cipher/userinfo, netloc, local bind, plugin, query rule, fragment auth, and `__` jumps | Preserve |
| Authentication | HTTP/SOCKS/WebSocket/remote proxy auth and the meaning of the per-IP auth cache | Preserve |
| Transports | TCP, UDP, Unix domain sockets, backward tunnels, transparent redirect/PF | Preserve |
| Scheduling | First available (`fa`), round robin (`rr`), random choice (`rc`), least connection (`lc`) | Preserve semantics |
| Wire formats | HTTP, SOCKS4/5, Shadowsocks/SSR/Trojan, WebSocket, and cipher/plugin framing | Lock down with golden and integration tests |
| Optional backends | H2, H3, QUIC, SSH, and future CFP | Isolate behind adapters and optional test jobs |

## Protocol Inventory

| Scheme | Current baseline | Direction | Notes |
| --- | --- | --- | --- |
| `http` / `httponly` | Implemented | Preserve | CONNECT and HTTP request forwarding |
| `socks4` / `socks5` / `socks` | Implemented | Preserve | Includes SOCKS5 TCP/UDP |
| `ss` / `ssr` / `trojan` | Implemented | Preserve | Includes cipher, auth, and plugin framing |
| `ssh` | Optional `asyncssh` | Preserve | Verify separately when the dependency is available |
| `h2` | Optional `h2` | Preserve | HTTP/2 stream and flow-control adapter |
| `h3` / `quic` | Optional `aioquic` | Preserve | HTTP/3 and QUIC stream adapters |
| `redir` / `pf` / `tunnel` | Platform/socket dependent | Preserve | Verify in the relevant Linux/macOS environments |
| `ws` | Implemented | Preserve | Needs framing, masking, and control-frame regression tests |
| `cfp` | Implemented only on `feat-cfp` | Future support target | TLS WebSocket, target header, auth, and graceful close; do not add now |
| `echo` / `direct` / `ssl` / `secure` / `in` | Implemented | Preserve | Includes combined-scheme helper behavior |

## Cipher and Plugin Policy

- Do not remove current cipher names or pure-Python fallbacks in the first modernization release.
- Preserve the current selection behavior where PyCryptodome acceleration is used when available.
- Lock down AEAD packet boundaries, nonce/IV handling, tag validation, and pure-Python versus accelerated parity with golden/vector tests.
- Verify Shadowsocks plugin handshakes and framing separately from the protocol refactor.
- Propose legacy cipher deprecations only after a separate security review.

The current cipher recommendation, warning behavior, deprecation gates, and
rollback procedure are documented in [`SECURITY_POLICY.md`](SECURITY_POLICY.md).

## Baseline Verification Commands

These commands are intended to be reproducible Phase 0 checks:

```text
python3 -m compileall -q pproxy tests
python3 tests/benchmark_proxy.py --requests 20 --concurrency 2 --payload-size 1024 --warmup 1
python3 -m pproxy -h
python3 -m pproxy --version
python3 -m pytest -q
```

Observed in the current environment:

- `compileall`: passed
- Loopback benchmark for direct/http/socks5: passed
- `-h`: worked
- `--version` from an uninstalled source checkout: displayed `unknown`
- `pytest`: unavailable because pytest is not installed (`No module named pytest`)

A representative run with Python `3.12.3`, 20 requests, concurrency 2, and a 1 KiB payload produced direct `3232.3 req/s`, HTTP `3146.5 req/s`, and SOCKS5 `3120.1 req/s`. These values are environment-dependent and are not absolute performance gates.

## Regression Candidates to Lock Down in Phase 0

The following are recorded as test targets before making source changes:

1. `WS.guess()` compares the reader object with `b'GET '` instead of the header it read.
2. WebSocket fragmented frames, masking, extended lengths, ping/pong, and close handling.
3. `ProxyBackward` close/CLOSE_WAIT behavior and normal EOF cleanup.
4. Handshake/auth/checksum/tag validation that currently relies on `assert`, including behavior under `python -O`.
5. Lifecycle behavior while moving direct access to private `asyncio.StreamReader/Writer`, `sslproto`, H2, and QUIC APIs behind adapters.
6. `cfp://` handshake, `X-Proxy-Target`, Authorization, and close control, kept separate from ordinary `ws://`.

## Change Approval Rule

Internal changes should follow a compatibility-preserving path. If a breaking change is found to be necessary, stop before implementing it and request review for changes to any of these surfaces:

- CLI options or output semantics
- URI syntax, default ports, or scheme behavior
- Public Python APIs and return/callback shapes
- Protocol, cipher, or plugin wire behavior
- Authentication, security, or connection-close semantics

The review request must include current behavior, why the change is needed, affected surfaces, alternatives, a migration example, and a rollback plan.
