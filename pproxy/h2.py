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

    async def handler(self, reader, writer, client_side=True, stream_handler=None, **kw):
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
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        read = reader.read
        while not reader.at_eof() and not writer.is_closing():
            try:
                data = await read(65636)
                if not data:
                    break
                events = conn.receive_data(data)
            except asyncio.CancelledError:
                raise
            except (h2.exceptions.H2Error, ConnectionError, OSError, EOFError, ValueError) as exc:
                if self.handshake is not None and not self.handshake.done():
                    self.handshake.set_exception(exc)
                break
            writer.write(conn.data_to_send())
            for event in events:
                if isinstance(event, h2.events.RequestReceived) and not client_side:
                    if event.stream_id not in streams and len(streams) >= self.MAX_STREAMS:
                        conn.reset_stream(event.stream_id, error_code=7)
                        continue
                    if event.stream_id not in streams:
                        stream_reader, stream_writer = self.get_stream(conn, writer, event.stream_id)
                        streams[event.stream_id] = (stream_reader, stream_writer)
                        self.task_registry.create_task(stream_handler(stream_reader, stream_writer))
                    else:
                        stream_reader, stream_writer = streams[event.stream_id]
                    stream_writer.headers.set_result(event.headers)
                elif isinstance(event, h2.events.SettingsAcknowledged) and client_side:
                    if self.handshake is not None and not self.handshake.done():
                        self.handshake.set_result((conn, streams, writer))
                elif isinstance(event, h2.events.DataReceived):
                    stream = streams.get(event.stream_id)
                    if stream is None:
                        continue
                    stream_reader, stream_writer = stream
                    stream_reader.feed_data(event.data)
                    conn.acknowledge_received_data(len(event.data), event.stream_id)
                    writer.write(conn.data_to_send())
                elif isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                    stream = streams.pop(event.stream_id, None)
                    if stream is None:
                        continue
                    stream_reader, stream_writer = stream
                    stream_reader.feed_eof()
                    if not stream_writer.closed:
                        stream_writer.close()
                elif isinstance(event, h2.events.ConnectionTerminated):
                    break
                elif isinstance(event, h2.events.WindowUpdated) and event.stream_id in streams:
                    stream_reader, stream_writer = streams[event.stream_id]
                    stream_writer.window_update()
        writer.write(conn.data_to_send())
        writer.close()
        if self.handshake is not None and not self.handshake.done():
            self.handshake.set_exception(ConnectionError('HTTP/2 connection closed'))

    def get_stream(self, conn, writer, stream_id):
        reader = asyncio.StreamReader()
        write_buffer = bytearray()
        write_wait = asyncio.Event()
        write_full = asyncio.Event()

        class StreamWriter:
            def __init__(self):
                self.closed = False
                self.headers = asyncio.get_running_loop().create_future()

            def get_extra_info(self, key):
                return writer.get_extra_info(key)

            def write(self, data):
                if len(write_buffer) + len(data) > ProxyH2.MAX_STREAM_BUFFER:
                    raise ProtocolError('HTTP/2 stream write buffer limit exceeded')
                write_buffer.extend(data)
                write_wait.set()

            def drain(self):
                writer.write(conn.data_to_send())
                return writer.drain()

            def is_closing(self):
                return self.closed

            def close(self):
                self.closed = True
                write_wait.set()

            def window_update(self):
                write_full.set()

            def send_headers(self, headers):
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
        conn, streams, writer = await self.wait_h2_connection(local_addr, family)
        stream_id = conn.get_next_available_stream_id()
        h2_begin_stream(conn, stream_id, stream_id % 2)
        stream_reader, stream_writer = self.get_stream(conn, writer, stream_id)
        streams[stream_id] = (stream_reader, stream_writer)
        return stream_reader, stream_writer

    def start_server(self, args, stream_handler=runtime.stream_handler):
        handler = functools.partial(stream_handler, **vars(self), **args)
        return super().start_server(
            args,
            functools.partial(self.handler, client_side=False, stream_handler=handler),
        )
