# Runtime API and operations

The public factory names and URI syntax remain compatible with the historical
interface. The lifecycle helpers below are additive and are available on proxy
objects returned by `pproxy.Connection` and `pproxy.Server`.

## Client lifecycle

Use `aclose()` when the connection object owns a transport which should be
released before the surrounding event loop stops:

```python
import asyncio
import pproxy


async def fetch(proxy_uri):
    async with pproxy.Connection(proxy_uri) as connection:
        reader, writer = await connection.tcp_connect('example.com', 80)
        writer.write(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        await writer.drain()
        response = await reader.read(16 * 1024)
        writer.close()
        return response


asyncio.run(fetch('http://127.0.0.1:8080'))
```

The explicit equivalent is:

```python
async def explicit(proxy_uri):
    connection = pproxy.Connection(proxy_uri)
    try:
        reader, writer = await connection.tcp_connect('example.com', 80)
        # Use the stream pair.
        writer.close()
    finally:
        await connection.aclose()


asyncio.run(explicit('http://127.0.0.1:8080'))
```

`close()` remains synchronous for compatibility. Call `await wait_closed()`
after it when the caller needs to wait for owned tasks and sessions.

## Migration note

Existing code can continue to call the synchronous `close()` method. For code
that already runs inside an async function, migrate one owner at a time to
`async with` or to `try`/`finally` with `await aclose()`. The listener returned
by `start_server()` still needs its own `close()` and `wait_closed()` calls;
closing the `Server` option does not implicitly close a listener created from
it.

## Server lifecycle

The listener returned by `start_server()` and the proxy option are separate
owners. Close both explicitly:

```python
import asyncio
import pproxy


async def serve():
    option = pproxy.Server('http://127.0.0.1:8080')
    listener = await option.start_server({'rserver': [], 'verbose': print})
    try:
        await asyncio.Event().wait()
    finally:
        listener.close()
        await listener.wait_closed()
        await option.aclose()


asyncio.run(serve())
```

`start_server(args)` keeps the existing argument mapping and callback shape.
The lifecycle methods only add an explicit shutdown path; they do not change
connection routing or protocol framing.

## Callback compatibility

Protocol callbacks intentionally retain their established positional arguments.
Many overrides also accept an unused `**kw` compatibility context because the
registry passes a common context to different protocol implementations. The
presence of a keyword does not mean that every protocol consumes it, and custom
implementations should tolerate the existing context fields when they follow
the callback contract.

Changing these callbacks to keyword-only context or removing compatibility
arguments would be a breaking API change. That migration is deferred until a
measured need and an explicit compatibility review establish the affected
callers, replacement signature, migration path, and rollback plan.

## Verbose output and structured logging

The CLI `-v` option and the `verbose` callback retain their existing console
format and statistics behavior. `pproxy.observability.configure_logging()` is
an opt-in application logger configuration and does not redirect or convert
legacy verbose output:

```python
import logging
import pproxy.observability


logger = pproxy.observability.configure_logging(
    level=logging.INFO,
    structured=True,
)
logger.info('application event')
```

Structured records are emitted as one JSON object per line. Applications which
want proxy events in that stream should connect their own application logging
or callback integration; enabling the helper alone does not change the
existing `verbose` callback path.
