# Optional adapter contract

The optional H2, H3, QUIC, and SSH transports share a small runtime contract.
The contract is additive and does not replace the historical `Connection`,
`Server`, URI, or protocol APIs.

## Lifecycle contract

Each adapter exposes an `adapter_capabilities` value and implements the
following operations:

- `wait_open_connection(host, port, local_addr, family)` returns the project's
  reader/writer stream pair.
- `close()` requests idempotent shutdown without blocking.
- `wait_closed()` waits for adapter-owned tasks, streams, and shared sessions
  after `close()` has been requested.
- `aclose()` combines `close()` and `wait_closed()`.

An adapter must not publish a partially initialized resource. Missing optional
dependencies raise `ConfigurationError`. Connection and protocol failures keep
their original exception category, and cancellation propagates
`asyncio.CancelledError` after resources created by the canceled operation are
closed.

The contract is represented by `pproxy.runtime.OptionalAdapter`, with
capabilities described by `pproxy.runtime.AdapterCapabilities`.

## Capability matrix

| Adapter | Dependency | Streams | Datagrams | Multiplexed | Shared session |
| --- | --- | --- | --- | --- | --- |
| H2 | `h2` | yes | no | yes | yes |
| H3 | `aioquic` | yes | yes | yes | yes |
| QUIC | `aioquic` | yes | yes | yes | yes |
| SSH | `asyncssh` | yes | no | yes | yes |

## Private API boundary

Version-sensitive third-party and transport-private operations are kept in
`pproxy.transport.private`:

- H2 stream creation through the h2 private stream initializer.
- QUIC protocol, connection, stream, address, send, and closed-state access.
- asyncio stream rollback and buffer fallback in `pproxy.transport.streams`.

Adapter implementations call these helpers rather than reaching into the
corresponding private members at each call site. Tests which need backend
fixture internals may still use explicitly marked fixture-only access to obtain
listener ports or force remote termination.

## Dependency policy

The supported dependency ranges are declared in both `pyproject.toml` optional
extras and `constraints/optional.txt`. The regular optional matrix checks each
backend on Python 3.12 and 3.13. A separate compatibility job installs the
latest versions allowed by those ranges on the latest available Python 3.x and
runs the shared adapter contracts.
