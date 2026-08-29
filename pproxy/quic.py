"""QUIC and HTTP/3 optional transport adapters."""

# aioquic is optional and its imports must remain inside the selected runtime
# paths so importing the core package does not require HTTP/3 dependencies.
# pylint: disable=import-outside-toplevel

import asyncio
import functools
from typing import Any

from .runtime import AdapterCapabilities, UDP_LIMIT
from .server.connections import ProxySimple
from .server.handlers import datagram_handler, stream_handler
from .transport.private import (
    quic_connection,
    quic_create_stream,
    quic_force_closed,
    quic_is_closed,
    quic_network_address,
    quic_next_stream_id,
    quic_prepare_stream,
    quic_protocol,
    quic_send_stream_data,
)


class ProxyQUIC(ProxySimple):  # pylint: disable=too-many-instance-attributes
    """Proxy backend for QUIC streams using the optional ``aioquic`` package."""

    adapter_capabilities = AdapterCapabilities(
        name='quic',
        dependency='aioquic',
        supports_streams=True,
        supports_datagrams=True,
        multiplexed=True,
        owns_shared_session=True,
    )
    MAX_UDP_FLOWS = UDP_LIMIT

    def __init__(self, quicserver, quicclient, **kw):
        """Initialize QUIC server/client configuration and connection state."""
        super().__init__(**kw)
        self.quicserver = quicserver
        self.quicclient = quicclient
        self.handshake = None
        self.quic_egress_acm = None
        self.quic_protocol = None
        self._quic_connection_task = None
        self._quic_waiters = 0
        self.quic_udpmap = {}
        self.quic_udp_replies = {}

    def patch_writer(self, writer):
        """Adapt a QUIC stream writer to the asyncio stream contract."""
        async def drain():
            """Flush pending QUIC frames to the network."""
            quic_protocol(writer).transmit()

        remote_addr = quic_network_address(quic_protocol(writer))
        writer.get_extra_info = {"peername": remote_addr, "sockname": remote_addr}.get
        writer.drain = drain
        closed = False
        writer.is_closing = lambda: closed

        def close():
            nonlocal closed
            closed = True
            self.writers.discard(writer)
            try:
                writer.write_eof()
            except Exception:  # pylint: disable=broad-exception-caught  # QUIC close is best effort
                pass

        writer.close = close
        self.writers.add(writer)

    def connection_terminated(self, handshake, message):
        """Fail the active handshake and discard state for a dead QUIC path."""
        if self.handshake is handshake:
            if handshake is not None and not handshake.done():
                handshake.set_exception(ConnectionError(message))
            if handshake is not None and not handshake.cancelled():
                handshake.exception()
            self.handshake = None
        self.quic_udpmap.clear()
        self.quic_udp_replies.clear()

    async def _run_quic_connection(self, create_protocol, handshake):  # pylint: disable=too-many-branches
        """Own one aioquic context and publish its lifecycle to waiters."""
        import aioquic.asyncio

        context: Any = aioquic.asyncio.connect(
            self.host_name,
            self.port,
            create_protocol=create_protocol,
            configuration=self.quicclient,
            wait_connected=False,
        )
        self.quic_egress_acm = context
        protocol = None
        entered = False
        try:
            protocol = await context.__aenter__()  # pylint: disable=no-member  # aioquic async context manager
            entered = True
            self.quic_protocol = protocol
            protocol.transmit()
            await protocol.wait_connected()
            if not handshake.done():
                handshake.set_result(protocol)
            await protocol.wait_closed()
        except asyncio.CancelledError:
            if protocol is not None:
                protocol.close()
                quic_force_closed(protocol)
            if not handshake.done():
                handshake.cancel()
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught  # publish adapter failures to waiters
            if not handshake.done():
                handshake.set_exception(exc)
            if not handshake.cancelled():
                handshake.exception()
        finally:
            if self.quic_protocol is protocol:
                self.quic_protocol = None
            if self.quic_egress_acm is context:
                self.quic_egress_acm = None
            if entered:
                await context.__aexit__(None, None, None)  # pylint: disable=no-member  # aioquic async context manager
            if self.handshake is handshake:
                self.handshake = None
            if self._quic_connection_task is asyncio.current_task():
                self._quic_connection_task = None
            self.quic_udpmap.clear()
            self.quic_udp_replies.clear()

    async def _wait_for_quic_connection(self, protocol_factory):
        """Return a live protocol, owning one async QUIC context per proxy."""
        while True:
            handshake = self.handshake
            if handshake is None:
                closing = self._quic_connection_task
                if closing is not None and not closing.done():
                    await asyncio.shield(closing)
                    continue
                handshake = asyncio.get_running_loop().create_future()
                self.handshake = handshake
                self._quic_connection_task = self.task_registry.create_task(
                    self._run_quic_connection(protocol_factory(handshake), handshake),
                    name='quic-connection',
                )
            if handshake.done():
                protocol = handshake.result()
                if not quic_is_closed(protocol):
                    return protocol
                if self.handshake is handshake:
                    self.handshake = None
                continue
            self._quic_waiters += 1
            try:
                return await asyncio.shield(handshake)
            except asyncio.CancelledError:
                if (
                    self.handshake is handshake
                    and not handshake.done()
                    and self._quic_waiters == 1
                    and self._quic_connection_task is not None
                ):
                    self._quic_connection_task.cancel()
                raise
            finally:
                self._quic_waiters -= 1

    def close(self):
        """Close the active QUIC protocol or cancel its connection task."""
        super().close()
        if self.quic_protocol is not None:
            self.quic_protocol.close()
        elif self._quic_connection_task is not None:
            self._quic_connection_task.cancel()

    async def wait_quic_connection(self):
        """Return a live QUIC connection, creating it when necessary."""
        import aioquic.asyncio
        import aioquic.quic.events

        owner = self

        def protocol_factory(handshake):
            """Create a protocol that routes QUIC events to this backend."""
            class Protocol(aioquic.asyncio.QuicConnectionProtocol):
                """Receive QUIC events for one shared connection."""

                def quic_event_received(self, event):
                    """Dispatch control and UDP stream events."""
                    if isinstance(event, aioquic.quic.events.ConnectionTerminated):
                        owner.connection_terminated(handshake, 'QUIC connection terminated')
                    elif isinstance(event, aioquic.quic.events.StreamDataReceived) and event.stream_id in owner.quic_udp_replies:
                        owner.quic_udp_replies[event.stream_id](owner.udp_packet_unpack(event.data))
                        return
                    super().quic_event_received(event)

            return Protocol

        return await self._wait_for_quic_connection(protocol_factory)

    async def udp_open_connection(self, host, port, data, addr, reply):
        conn = await self.wait_quic_connection()
        if addr in self.quic_udpmap:
            stream_id = self.quic_udpmap[addr]
        else:
            if len(self.quic_udpmap) >= self.MAX_UDP_FLOWS:
                oldest_addr, oldest_stream = next(iter(self.quic_udpmap.items()))
                self.quic_udpmap.pop(oldest_addr, None)
                self.quic_udp_replies.pop(oldest_stream, None)
            stream_id = quic_next_stream_id(conn, False)
            self.quic_udpmap[addr] = stream_id
            self.quic_udp_replies[stream_id] = reply
            quic_prepare_stream(conn, stream_id)
        quic_send_stream_data(conn, stream_id, data, False)
        conn.transmit()

    async def wait_open_connection(self, *args):  # pylint: disable=unused-argument
        """Open one bidirectional stream on a live QUIC connection."""
        conn = await self.wait_quic_connection()
        stream_id = quic_next_stream_id(conn, False)
        quic_prepare_stream(conn, stream_id)
        reader, writer = quic_create_stream(conn, stream_id)
        self.patch_writer(writer)
        return reader, writer

    async def udp_start_server(self, args):
        """Start a QUIC listener that exposes incoming streams as datagrams."""
        import aioquic.asyncio
        import aioquic.quic.events

        owner = self

        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            """Dispatch incoming QUIC stream data to datagram handlers."""

            def quic_event_received(self, event):
                """Convert incoming stream events into proxy datagram tasks."""
                if isinstance(event, aioquic.quic.events.StreamDataReceived):
                    stream_id = event.stream_id
                    addr = ('quic ' + owner.bind, stream_id)
                    event.sendto = lambda data, addr: (
                        quic_send_stream_data(self, stream_id, data, False),
                        self.transmit(),
                    )
                    event.get_extra_info = {}.get
                    owner.task_registry.create_task(
                        datagram_handler(event, event.data, addr, **vars(owner), **args)
                    )
                    return
                super().quic_event_received(event)

        return await aioquic.asyncio.serve(
            self.host_name,
            self.port,
            configuration=self.quicserver,
            create_protocol=Protocol,
        ), None

    async def start_server(self, args, stream_handler=stream_handler):
        """Start a QUIC listener for the configured stream handler."""
        import aioquic.asyncio

        def handler(reader, writer):
            self.patch_writer(writer)
            self.task_registry.create_task(stream_handler(reader, writer, **vars(self), **args))

        return await aioquic.asyncio.serve(
            self.host_name,
            self.port,
            configuration=self.quicserver,
            stream_handler=handler,
        )


class ProxyH3(ProxyQUIC):
    """Proxy backend for HTTP/3 streams using the optional ``aioquic`` package."""

    adapter_capabilities = AdapterCapabilities(
        name='h3',
        dependency='aioquic',
        supports_streams=True,
        supports_datagrams=True,
        multiplexed=True,
        owns_shared_session=True,
    )

    def get_stream(self, conn, stream_id):
        """Create an asyncio-like HTTP/3 reader and writer pair."""
        from aioquic.h3.connection import FrameUnexpected

        owner = self
        remote_addr = quic_network_address(conn)
        reader = asyncio.StreamReader()

        class StreamWriter:
            """Expose one HTTP/3 stream through the asyncio writer surface."""

            def __init__(self):
                """Initialize stream state and the request-header future."""
                self.closed = False
                self.headers = asyncio.get_running_loop().create_future()

            def get_extra_info(self, key):
                """Return the synthetic peer or socket address."""
                return {"peername": remote_addr, "sockname": remote_addr}.get(key)

            def write(self, data):
                """Send HTTP/3 DATA frames for this stream."""
                if self.closed or quic_is_closed(conn):
                    return
                conn.http.send_data(stream_id, data, False)
                conn.transmit()

            async def drain(self):
                """Flush pending HTTP/3 frames."""
                if not self.closed and not quic_is_closed(conn):
                    conn.transmit()

            def is_closing(self):
                """Return whether this HTTP/3 stream has been closed."""
                return self.closed

            def close(self):
                """Close the HTTP/3 stream and remove its owner state."""
                if not self.closed:
                    self.closed = True
                    owner.writers.discard(self)
                    if not quic_is_closed(conn):
                        try:
                            conn.http.send_data(stream_id, b'', True)
                            conn.transmit()
                        except FrameUnexpected:
                            pass
                    conn.close_stream(stream_id)
                    conn.streams.pop(stream_id, None)

            def send_headers(self, headers):
                """Send encoded response headers for this stream."""
                if self.closed or quic_is_closed(conn):
                    return
                conn.http.send_headers(stream_id, [(key.encode(), value.encode()) for key, value in headers])
                conn.transmit()

        writer = StreamWriter()
        self.writers.add(writer)
        return reader, writer

    def get_protocol(self, server_side=False, handler=None, handshake=None):
        """Build an aioquic protocol class for HTTP/3 client or server mode."""
        import aioquic.asyncio
        import aioquic.h3.connection
        import aioquic.h3.events
        import aioquic.quic.events

        owner = self

        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            """Translate QUIC and HTTP/3 events into stream callbacks."""

            def __init__(self, *args, **kw):
                """Initialize the HTTP/3 connection and stream registry."""
                super().__init__(*args, **kw)
                self.http = aioquic.h3.connection.H3Connection(quic_connection(self))
                self.streams = {}

            def quic_event_received(self, event):
                """Handle connection termination and forward HTTP/3 events."""
                if isinstance(event, aioquic.quic.events.ConnectionTerminated):
                    if not server_side:
                        owner.connection_terminated(handshake, 'HTTP/3 connection terminated')
                    for reader, writer in tuple(self.streams.values()):
                        reader.feed_eof()
                        writer.close()
                    self.streams.clear()
                    return
                if self.http is not None:
                    for http_event in self.http.handle_event(event):
                        self.http_event_received(http_event)

            def http_event_received(self, event):
                """Create, feed, and close proxy streams from HTTP/3 events."""
                if isinstance(event, aioquic.h3.events.HeadersReceived):
                    if event.stream_id not in self.streams and server_side:
                        if len(self.streams) >= owner.MAX_UDP_FLOWS:
                            return
                        reader, writer = self.open_stream(event.stream_id)
                        writer.headers.set_result(event.headers)

                        async def handle_stream():
                            """Run the configured handler for one HTTP/3 stream."""
                            try:
                                await handler(reader, writer)
                            finally:
                                writer.close()

                        owner.task_registry.create_task(handle_stream(), name='h3-stream')
                elif isinstance(event, aioquic.h3.events.DataReceived) and event.stream_id in self.streams:
                    reader, writer = self.streams[event.stream_id]
                    if event.data:
                        reader.feed_data(event.data)
                    if event.stream_ended:
                        reader.feed_eof()
                        writer.close()
                    self.close_stream(event.stream_id)

            def open_stream(self, stream_id=None):
                """Create and register an HTTP/3 stream pair."""
                if stream_id is None:
                    stream_id = quic_next_stream_id(self, False)
                    quic_prepare_stream(self, stream_id)
                reader, writer = owner.get_stream(self, stream_id)
                self.streams[stream_id] = (reader, writer)
                return reader, writer

            def close_stream(self, stream_id):
                """Forget an HTTP/3 stream after both sides finish."""
                if stream_id in self.streams:
                    reader, writer = self.streams[stream_id]
                    if reader.at_eof() or writer.is_closing():
                        self.streams.pop(stream_id)

        return Protocol

    async def wait_h3_connection(self):
        """Return a live HTTP/3 protocol connection."""
        return await self._wait_for_quic_connection(
            lambda future: self.get_protocol(handshake=future),
        )

    async def wait_open_connection(self, *args):
        """Open one HTTP/3 bidirectional stream."""
        return (await self.wait_h3_connection()).open_stream()

    async def start_server(self, args, stream_handler=stream_handler):
        """Start an HTTP/3 listener for the configured stream handler."""
        import aioquic.asyncio

        return await aioquic.asyncio.serve(
            self.host_name,
            self.port,
            configuration=self.quicserver,
            create_protocol=self.get_protocol(
                True,
                functools.partial(stream_handler, **vars(self), **args),
            ),
        )
