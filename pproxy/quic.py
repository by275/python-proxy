"""QUIC and HTTP/3 optional transport adapters."""

import asyncio
import functools

from . import server as runtime
from .runtime import UDP_LIMIT
from .transport.private import (
    quic_connection,
    quic_force_closed,
    quic_is_closed,
    quic_network_address,
    quic_next_stream_id,
    quic_prepare_stream,
    quic_protocol,
    quic_send_stream_data,
)


class ProxyQUIC(runtime.ProxySimple):
    """Proxy backend for QUIC streams using the optional ``aioquic`` package."""

    MAX_UDP_FLOWS = UDP_LIMIT

    def __init__(self, quicserver, quicclient, **kw):
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
        async def drain():
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
            except Exception:  # noqa: BLE001, S110 - preserve best-effort close
                pass

        writer.close = close
        self.writers.add(writer)

    def _connection_terminated(self, handshake, message):
        """Fail the active handshake and discard state for a dead QUIC path."""
        if self.handshake is handshake:
            if handshake is not None and not handshake.done():
                handshake.set_exception(ConnectionError(message))
            if handshake is not None and not handshake.cancelled():
                handshake.exception()
            self.handshake = None
        self.quic_udpmap.clear()
        self.quic_udp_replies.clear()

    async def _run_quic_connection(self, create_protocol, handshake):
        import aioquic.asyncio

        context = aioquic.asyncio.connect(
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
            protocol = await context.__aenter__()
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
        except Exception as exc:  # noqa: BLE001 - publish adapter failures to waiters
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
                await context.__aexit__(None, None, None)
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
        super().close()
        if self.quic_protocol is not None:
            self.quic_protocol.close()
        elif self._quic_connection_task is not None:
            self._quic_connection_task.cancel()

    async def wait_quic_connection(self):
        import aioquic.asyncio
        import aioquic.quic.events

        def protocol_factory(handshake):
            class Protocol(aioquic.asyncio.QuicConnectionProtocol):
                def quic_event_received(protocol, event):
                    if isinstance(event, aioquic.quic.events.ConnectionTerminated):
                        self._connection_terminated(handshake, 'QUIC connection terminated')
                    elif isinstance(event, aioquic.quic.events.StreamDataReceived) and event.stream_id in self.quic_udp_replies:
                        self.quic_udp_replies[event.stream_id](self.udp_packet_unpack(event.data))
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

    async def wait_open_connection(self, *args):
        conn = await self.wait_quic_connection()
        stream_id = quic_next_stream_id(conn, False)
        quic_prepare_stream(conn, stream_id)
        reader, writer = conn._create_stream(stream_id)
        self.patch_writer(writer)
        return reader, writer

    async def udp_start_server(self, args):
        import aioquic.asyncio
        import aioquic.quic.events

        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            def quic_event_received(protocol, event):
                if isinstance(event, aioquic.quic.events.StreamDataReceived):
                    stream_id = event.stream_id
                    addr = ('quic ' + self.bind, stream_id)
                    event.sendto = lambda data, addr: (
                        quic_send_stream_data(protocol, stream_id, data, False),
                        protocol.transmit(),
                    )
                    event.get_extra_info = {}.get
                    self.task_registry.create_task(
                        runtime.datagram_handler(event, event.data, addr, **vars(self), **args)
                    )
                    return
                super().quic_event_received(event)

        return await aioquic.asyncio.serve(
            self.host_name,
            self.port,
            configuration=self.quicserver,
            create_protocol=Protocol,
        ), None

    def start_server(self, args, stream_handler=runtime.stream_handler):
        import aioquic.asyncio

        def handler(reader, writer):
            self.patch_writer(writer)
            self.task_registry.create_task(stream_handler(reader, writer, **vars(self), **args))

        return aioquic.asyncio.serve(
            self.host_name,
            self.port,
            configuration=self.quicserver,
            stream_handler=handler,
        )


class ProxyH3(ProxyQUIC):
    """Proxy backend for HTTP/3 streams using the optional ``aioquic`` package."""

    def get_stream(self, conn, stream_id):
        from aioquic.h3.connection import FrameUnexpected

        owner = self
        remote_addr = quic_network_address(conn)
        reader = asyncio.StreamReader()

        class StreamWriter:
            def __init__(self):
                self.closed = False
                self.headers = asyncio.get_running_loop().create_future()

            def get_extra_info(self, key):
                return {"peername": remote_addr, "sockname": remote_addr}.get(key)

            def write(self, data):
                if self.closed or quic_is_closed(conn):
                    return
                conn.http.send_data(stream_id, data, False)
                conn.transmit()

            async def drain(self):
                if not self.closed and not quic_is_closed(conn):
                    conn.transmit()

            def is_closing(self):
                return self.closed

            def close(self):
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
                if self.closed or quic_is_closed(conn):
                    return
                conn.http.send_headers(stream_id, [(key.encode(), value.encode()) for key, value in headers])
                conn.transmit()

        writer = StreamWriter()
        self.writers.add(writer)
        return reader, writer

    def get_protocol(self, server_side=False, handler=None, handshake=None):
        import aioquic.asyncio
        import aioquic.h3.connection
        import aioquic.h3.events
        import aioquic.quic.events

        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            def __init__(protocol, *args, **kw):
                super().__init__(*args, **kw)
                protocol.http = aioquic.h3.connection.H3Connection(quic_connection(protocol))
                protocol.streams = {}

            def quic_event_received(protocol, event):
                if isinstance(event, aioquic.quic.events.ConnectionTerminated):
                    if not server_side:
                        self._connection_terminated(handshake, 'HTTP/3 connection terminated')
                    for reader, writer in tuple(protocol.streams.values()):
                        reader.feed_eof()
                        writer.close()
                    protocol.streams.clear()
                    return
                if protocol.http is not None:
                    for http_event in protocol.http.handle_event(event):
                        protocol.http_event_received(http_event)

            def http_event_received(protocol, event):
                if isinstance(event, aioquic.h3.events.HeadersReceived):
                    if event.stream_id not in protocol.streams and server_side:
                        if len(protocol.streams) >= self.MAX_UDP_FLOWS:
                            return
                        reader, writer = protocol.create_stream(event.stream_id)
                        writer.headers.set_result(event.headers)

                        async def handle_stream():
                            try:
                                await handler(reader, writer)
                            finally:
                                writer.close()

                        self.task_registry.create_task(handle_stream(), name='h3-stream')
                elif isinstance(event, aioquic.h3.events.DataReceived) and event.stream_id in protocol.streams:
                    reader, writer = protocol.streams[event.stream_id]
                    if event.data:
                        reader.feed_data(event.data)
                    if event.stream_ended:
                        reader.feed_eof()
                        writer.close()
                    protocol.close_stream(event.stream_id)

            def create_stream(protocol, stream_id=None):
                if stream_id is None:
                    stream_id = quic_next_stream_id(protocol, False)
                    quic_prepare_stream(protocol, stream_id)
                reader, writer = self.get_stream(protocol, stream_id)
                protocol.streams[stream_id] = (reader, writer)
                return reader, writer

            def close_stream(protocol, stream_id):
                if stream_id in protocol.streams:
                    reader, writer = protocol.streams[stream_id]
                    if reader.at_eof() or writer.is_closing():
                        protocol.streams.pop(stream_id)

        return Protocol

    async def wait_h3_connection(self):
        return await self._wait_for_quic_connection(
            lambda future: self.get_protocol(handshake=future),
        )

    async def wait_open_connection(self, *args):
        return (await self.wait_h3_connection()).create_stream()

    def start_server(self, args, stream_handler=runtime.stream_handler):
        import aioquic.asyncio

        return aioquic.asyncio.serve(
            self.host_name,
            self.port,
            configuration=self.quicserver,
            create_protocol=self.get_protocol(
                True,
                functools.partial(stream_handler, **vars(self), **args),
            ),
        )
