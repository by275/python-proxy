"""HTTP/2 optional transport adapter."""

import asyncio
import functools

from . import proto
from .errors import ProtocolError
from . import server as runtime
from .runtime import H2_STREAM_LIMIT
from .transport.private import h2_begin_stream


class ProxyH2(runtime.ProxySimple):
    """Proxy backend for HTTP/2 streams using the optional ``h2`` package."""

    MAX_STREAMS = H2_STREAM_LIMIT
    MAX_STREAM_BUFFER = 1024 * 1024

    def __init__(self, sslserver, sslclient, **kw):
        super().__init__(sslserver=None, sslclient=None, **kw)
        self.handshake = None
        self.h2sslserver = sslserver
        self.h2sslclient = sslclient

    def _handle_event(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-branches
        self,
        event,
        conn,
        streams,
        writer,
        client_side,
        stream_handler,
        events_module,
    ):
        """Apply one HTTP/2 event to the active connection state."""
        if isinstance(event, events_module.RequestReceived) and not client_side:
            if event.stream_id not in streams and len(streams) >= self.MAX_STREAMS:
                conn.reset_stream(event.stream_id, error_code=7)
                return True
            if event.stream_id not in streams:
                stream_reader, stream_writer = self.get_stream(conn, writer, event.stream_id)
                streams[event.stream_id] = (stream_reader, stream_writer)
                self.task_registry.create_task(stream_handler(stream_reader, stream_writer))
            else:
                stream_reader, stream_writer = streams[event.stream_id]
            stream_writer.headers.set_result(event.headers)
        elif isinstance(event, events_module.SettingsAcknowledged) and client_side:
            if self.handshake is not None and not self.handshake.done():
                self.handshake.set_result((conn, streams, writer))
        elif isinstance(event, events_module.DataReceived):
            stream = streams.get(event.stream_id)
            if stream is None:
                return True
            stream_reader, stream_writer = stream
            stream_reader.feed_data(event.data)
            conn.acknowledge_received_data(len(event.data), event.stream_id)
            writer.write(conn.data_to_send())
        elif isinstance(event, (events_module.StreamEnded, events_module.StreamReset)):
            stream = streams.pop(event.stream_id, None)
            if stream is None:
                return True
            stream_reader, stream_writer = stream
            stream_reader.feed_eof()
            if not stream_writer.closed:
                stream_writer.close()
        elif isinstance(event, events_module.ConnectionTerminated):
            return False
        elif isinstance(event, events_module.WindowUpdated) and event.stream_id in streams:
            _stream_reader, stream_writer = streams[event.stream_id]
            stream_writer.window_update()
        return True

    async def handler(  # pylint: disable=import-outside-toplevel,unused-argument
        self,
        reader,
        writer,
        client_side=True,
        stream_handler=None,
        **kw,
    ):
        """Run the HTTP/2 read loop for one client or server connection."""
        import h2.config
        import h2.connection
        import h2.events
        import h2.exceptions

        reader, writer = proto.sslwrap(
            reader,
            writer,
            self.h2sslclient if client_side else self.h2sslserver,
            not client_side,
            None,
            task_registry=self.task_registry,
        )
        config = h2.config.H2Configuration(client_side=client_side)
        conn = h2.connection.H2Connection(config=config)
        streams = {}
        try:
            conn.initiate_connection()
            writer.write(conn.data_to_send())
            read = reader.read
            while not reader.at_eof() and not writer.is_closing():
                try:
                    data = await read(65636)
                    if not data:
                        break
                    events = conn.receive_data(data)
                except (h2.exceptions.H2Error, ConnectionError, OSError, EOFError, ValueError) as exc:
                    if self.handshake is not None and not self.handshake.done():
                        self.handshake.set_exception(exc)
                    break
                writer.write(conn.data_to_send())
                for event in events:
                    if self._handle_event(
                        event,
                        conn,
                        streams,
                        writer,
                        client_side,
                        stream_handler,
                        h2.events,
                    ) is False:
                        break
        finally:
            try:
                writer.write(conn.data_to_send())
            except (ConnectionError, OSError):
                pass
            writer.close()
            wait_closed = getattr(writer, 'wait_closed', None)
            if wait_closed is not None:
                try:
                    await wait_closed()
                except (ConnectionError, OSError):
                    pass
            if self.handshake is not None and not self.handshake.done():
                self.handshake.set_exception(ConnectionError('HTTP/2 connection closed'))

    def get_stream(self, conn, writer, stream_id):
        """Create an HTTP/2 stream pair backed by flow-control events."""
        reader = asyncio.StreamReader()
        write_buffer = bytearray()
        write_wait = asyncio.Event()
        write_full = asyncio.Event()

        class StreamWriter:
            """Expose one HTTP/2 stream through the asyncio writer shape."""

            def __init__(self):
                """Initialize stream state and the response-header future."""
                self.closed = False
                self.headers = asyncio.get_running_loop().create_future()

            def get_extra_info(self, key):
                """Return connection metadata from the parent writer."""
                return writer.get_extra_info(key)

            def write(self, data):
                """Buffer data until the peer grants flow-control credit."""
                if len(write_buffer) + len(data) > ProxyH2.MAX_STREAM_BUFFER:
                    raise ProtocolError('HTTP/2 stream write buffer limit exceeded')
                write_buffer.extend(data)
                write_wait.set()

            def drain(self):
                """Flush pending HTTP/2 frames to the parent writer."""
                writer.write(conn.data_to_send())
                return writer.drain()

            def is_closing(self):
                """Return whether this logical stream has been closed."""
                return self.closed

            def close(self):
                """Stop accepting stream writes and wake pending tasks."""
                self.closed = True
                write_wait.set()

            def window_update(self):
                """Wake the writer after receiving new flow-control credit."""
                write_full.set()

            def send_headers(self, headers):
                """Send response headers on this stream."""
                conn.send_headers(stream_id, headers)
                writer.write(conn.data_to_send())

        stream_writer = StreamWriter()

        async def write_job():
            while not stream_writer.closed:
                while len(write_buffer) > 0:
                    while conn.local_flow_control_window(stream_id) <= 0:
                        write_full.clear()
                        await write_full.wait()
                        if stream_writer.closed:
                            break
                    chunk_size = min(
                        conn.local_flow_control_window(stream_id),
                        len(write_buffer),
                        conn.max_outbound_frame_size,
                    )
                    conn.send_data(stream_id, write_buffer[:chunk_size])
                    writer.write(conn.data_to_send())
                    del write_buffer[:chunk_size]
                if not stream_writer.closed:
                    write_wait.clear()
                    await write_wait.wait()
            conn.send_data(stream_id, b'', end_stream=True)
            writer.write(conn.data_to_send())

        self.task_registry.create_task(write_job())
        return reader, stream_writer

    async def wait_h2_connection(self, local_addr, family):
        """Reuse or establish the shared HTTP/2 connection handshake."""
        if self.handshake is not None:
            if not self.handshake.done():
                await self.handshake
        else:
            self.handshake = asyncio.get_running_loop().create_future()
            reader, writer = await super().wait_open_connection(None, None, local_addr, family)
            self.task_registry.create_task(self.handler(reader, writer))
            await self.handshake
        return self.handshake.result()

    async def wait_open_connection(self, host, port, local_addr, family):
        """Open one logical HTTP/2 stream for a destination request."""
        conn, streams, writer = await self.wait_h2_connection(local_addr, family)
        stream_id = conn.get_next_available_stream_id()
        h2_begin_stream(conn, stream_id, stream_id % 2)
        stream_reader, stream_writer = self.get_stream(conn, writer, stream_id)
        streams[stream_id] = (stream_reader, stream_writer)
        return stream_reader, stream_writer

    async def start_server(self, args, stream_handler=runtime.stream_handler):
        """Start an HTTP/2 listener using the shared proxy handler."""
        handler = functools.partial(stream_handler, **vars(self), **args)
        return await super().start_server(
            args,
            functools.partial(self.handler, client_side=False, stream_handler=handler),
        )
