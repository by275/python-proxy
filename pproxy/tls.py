"""TLS stream adapter for asyncio streams."""

import asyncio
from asyncio import create_task

from . import transport


def wrap(reader, writer, sslcontext, server_side=False, server_hostname=None, verbose=None):
    """Wrap an asyncio stream with the project's asynchronous TLS adapter."""
    if sslcontext is None:
        return reader, writer

    ssl_reader = asyncio.StreamReader()

    class Protocol(asyncio.Protocol):
        def data_received(self, data):
            ssl_reader.feed_data(data)

        def eof_received(self):
            ssl_reader.feed_eof()

        def connection_lost(self, exc):
            ssl_reader.feed_eof()

    ssl = asyncio.sslproto.SSLProtocol(
        asyncio.get_running_loop(),
        Protocol(),
        sslcontext,
        None,
        server_side,
        server_hostname,
        False,
    )

    class Transport(asyncio.Transport):
        _paused = False

        def __init__(self, extra=None):
            self._extra = {} if extra is None else extra
            self.closed = False

        def write(self, data):
            if data and not self.closed:
                writer.write(data)

        def close(self):
            self.closed = True
            writer.close()

        def _force_close(self, exc):
            if not self.closed:
                (verbose or print)(f'{exc} from {writer.get_extra_info("peername")[0]}')
            ssl._app_transport._closed = True
            self.close()

        def abort(self):
            self.close()

    ssl.connection_made(Transport())

    async def channel():
        read_size = 65536
        buffer = ssl.get_buffer(read_size) if hasattr(ssl, 'get_buffer') else None
        try:
            while not reader.at_eof() and not ssl._app_transport._closed:
                data = await transport.read(reader, read_size)
                if not data:
                    break
                if buffer is not None:
                    data_len = len(data)
                    buffer[:data_len] = data
                    ssl.buffer_updated(data_len)
                else:
                    ssl.data_received(data)
        except Exception:  # noqa: BLE001, S110 - close the adapter on any stream failure
            pass
        finally:
            ssl.eof_received()

    create_task(channel())

    class Writer:
        def get_extra_info(self, key):
            return writer.get_extra_info(key)

        def write(self, data):
            ssl._app_transport.write(data)

        def drain(self):
            return writer.drain()

        def is_closing(self):
            return ssl._app_transport._closed

        def close(self):
            if not ssl._app_transport._closed:
                ssl._app_transport.close()

    return ssl_reader, Writer()
