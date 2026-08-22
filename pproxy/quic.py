"""QUIC and HTTP/3 optional transport adapters."""

import asyncio
import functools

from . import server as runtime


class ProxyQUIC(runtime.ProxySimple):
    """Proxy backend for QUIC streams using the optional ``aioquic`` package."""

    def __init__(self, quicserver, quicclient, **kw):
        super().__init__(**kw)
        self.quicserver = quicserver
        self.quicclient = quicclient
        self.handshake = None

    def patch_writer(self, writer):
        async def drain():
            writer._transport.protocol.transmit()

        remote_addr = writer._transport.protocol._quic._network_paths[0].addr
        writer.get_extra_info = {"peername": remote_addr, "sockname": remote_addr}.get
        writer.drain = drain
        closed = False
        writer.is_closing = lambda: closed

        def close():
            nonlocal closed
            closed = True
            try:
                writer.write_eof()
            except Exception:  # noqa: BLE001, S110 - preserve best-effort close
                pass

        writer.close = close

    async def wait_quic_connection(self):
        if self.handshake is not None:
            if not self.handshake.done():
                await self.handshake
        else:
            self.handshake = asyncio.get_running_loop().create_future()
            import aioquic.asyncio
            import aioquic.quic.events

            class Protocol(aioquic.asyncio.QuicConnectionProtocol):
                def quic_event_received(protocol, event):
                    if isinstance(event, aioquic.quic.events.HandshakeCompleted):
                        self.handshake.set_result(protocol)
                    elif isinstance(event, aioquic.quic.events.ConnectionTerminated):
                        self.handshake = None
                        self.quic_egress_acm = None
                    elif isinstance(event, aioquic.quic.events.StreamDataReceived) and event.stream_id in self.udpmap:
                        self.udpmap[event.stream_id](self.udp_packet_unpack(event.data))
                        return
                    super().quic_event_received(event)

            self.quic_egress_acm = aioquic.asyncio.connect(
                self.host_name,
                self.port,
                create_protocol=Protocol,
                configuration=self.quicclient,
            )
            await self.quic_egress_acm.__aenter__()
            await self.handshake

    async def udp_open_connection(self, host, port, data, addr, reply):
        await self.wait_quic_connection()
        conn = self.handshake.result()
        if addr in self.udpmap:
            stream_id = self.udpmap[addr]
        else:
            stream_id = conn._quic.get_next_available_stream_id(False)
            self.udpmap[addr] = stream_id
            self.udpmap[stream_id] = reply
            conn._quic._get_or_create_stream_for_send(stream_id)
        conn._quic.send_stream_data(stream_id, data, False)
        conn.transmit()

    async def wait_open_connection(self, *args):
        await self.wait_quic_connection()
        conn = self.handshake.result()
        stream_id = conn._quic.get_next_available_stream_id(False)
        conn._quic._get_or_create_stream_for_send(stream_id)
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
                        protocol._quic.send_stream_data(stream_id, data, False),
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
        remote_addr = conn._quic._network_paths[0].addr
        reader = asyncio.StreamReader()

        class StreamWriter:
            def __init__(self):
                self.closed = False
                self.headers = asyncio.get_running_loop().create_future()

            def get_extra_info(self, key):
                return {"peername": remote_addr, "sockname": remote_addr}.get(key)

            def write(self, data):
                conn.http.send_data(stream_id, data, False)
                conn.transmit()

            async def drain(self):
                conn.transmit()

            def is_closing(self):
                return self.closed

            def close(self):
                if not self.closed:
                    conn.http.send_data(stream_id, b'', True)
                    conn.transmit()
                    conn.close_stream(stream_id)
                self.closed = True

            def send_headers(self, headers):
                conn.http.send_headers(stream_id, [(key.encode(), value.encode()) for key, value in headers])
                conn.transmit()

        return reader, StreamWriter()

    def get_protocol(self, server_side=False, handler=None):
        import aioquic.asyncio
        import aioquic.h3.connection
        import aioquic.h3.events
        import aioquic.quic.events

        class Protocol(aioquic.asyncio.QuicConnectionProtocol):
            def __init__(protocol, *args, **kw):
                super().__init__(*args, **kw)
                protocol.http = aioquic.h3.connection.H3Connection(protocol._quic)
                protocol.streams = {}

            def quic_event_received(protocol, event):
                if not server_side:
                    if isinstance(event, aioquic.quic.events.HandshakeCompleted):
                        self.handshake.set_result(protocol)
                    elif isinstance(event, aioquic.quic.events.ConnectionTerminated):
                        self.handshake = None
                        self.quic_egress_acm = None
                if protocol.http is not None:
                    for http_event in protocol.http.handle_event(event):
                        protocol.http_event_received(http_event)

            def http_event_received(protocol, event):
                if isinstance(event, aioquic.h3.events.HeadersReceived):
                    if event.stream_id not in protocol.streams and server_side:
                        reader, writer = protocol.create_stream(event.stream_id)
                        writer.headers.set_result(event.headers)
                        self.task_registry.create_task(handler(reader, writer))
                elif isinstance(event, aioquic.h3.events.DataReceived) and event.stream_id in protocol.streams:
                    reader, writer = protocol.streams[event.stream_id]
                    if event.data:
                        reader.feed_data(event.data)
                    if event.stream_ended:
                        reader.feed_eof()
                    protocol.close_stream(event.stream_id)

            def create_stream(protocol, stream_id=None):
                if stream_id is None:
                    stream_id = protocol._quic.get_next_available_stream_id(False)
                    protocol._quic._get_or_create_stream_for_send(stream_id)
                reader, writer = self.get_stream(protocol, stream_id)
                protocol.streams[stream_id] = (reader, writer)
                return reader, writer

            def close_stream(protocol, stream_id):
                if stream_id in protocol.streams:
                    reader, writer = protocol.streams[stream_id]
                    if reader.at_eof() and writer.is_closing():
                        protocol.streams.pop(stream_id)

        return Protocol

    async def wait_h3_connection(self):
        if self.handshake is not None:
            if not self.handshake.done():
                await self.handshake
        else:
            import aioquic.asyncio

            self.handshake = asyncio.get_running_loop().create_future()
            self.quic_egress_acm = aioquic.asyncio.connect(
                self.host_name,
                self.port,
                create_protocol=self.get_protocol(),
                configuration=self.quicclient,
            )
            await self.quic_egress_acm.__aenter__()
            await self.handshake

    async def wait_open_connection(self, *args):
        await self.wait_h3_connection()
        return self.handshake.result().create_stream()

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
