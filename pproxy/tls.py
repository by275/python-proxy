"""TLS stream adapter for asyncio streams."""

# SSLProtocol is a deliberately isolated compatibility adapter.  Its app
# transport state is private in CPython and has no public equivalent.
# pylint: disable=protected-access

import asyncio
from asyncio import create_task



def wrap(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-statements
    reader,
    writer,
    sslcontext,
    server_side=False,
    server_hostname=None,
    verbose=None,
    task_registry=None,
):
    """Wrap an asyncio stream with the project's asynchronous TLS adapter."""
    if sslcontext is None:
        return reader, writer

    ssl_reader = asyncio.StreamReader()

    class Protocol(asyncio.Protocol):
        """Feed raw stream bytes into the SSL protocol."""

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
        """Bridge an asyncio stream writer to SSLProtocol's transport API."""

        _paused = False

        def __init__(self, extra=None):
            super().__init__(extra)
            self.closed = False
            self._protocol = None

        def get_extra_info(self, name, default=None):
            """Return adapter metadata or the underlying stream metadata."""
            value = super().get_extra_info(name, None)
            if value is not None:
                return value
            return writer.get_extra_info(name, default)

        def is_closing(self):
            """Report whether the adapter has been closed."""
            return self.closed

        def set_protocol(self, protocol):
            """Remember the protocol assigned by SSLProtocol."""
            self._protocol = protocol

        def get_protocol(self):
            """Return the protocol assigned by SSLProtocol."""
            return self._protocol

        def is_reading(self):
            """Report whether the adapter still accepts input."""
            return not self.closed

        def pause_reading(self):
            """Pause input at the adapter boundary."""
            self._paused = True

        def resume_reading(self):
            """Resume input at the adapter boundary."""
            self._paused = False

        def set_write_buffer_limits(self, high=None, low=None):
            """Forward write-watermark settings when the stream supports them."""
            stream_transport = getattr(writer, 'transport', None)
            if stream_transport is not None:
                stream_transport.set_write_buffer_limits(high, low)

        def get_write_buffer_size(self):
            """Return the underlying stream's pending write size."""
            stream_transport = getattr(writer, 'transport', None)
            return stream_transport.get_write_buffer_size() if stream_transport else 0

        def get_write_buffer_limits(self):
            """Return the underlying stream's write-watermark settings."""
            stream_transport = getattr(writer, 'transport', None)
            if stream_transport is None:
                return (0, 0)
            return stream_transport.get_write_buffer_limits()

        def write(self, data):
            if data and not self.closed:
                writer.write(data)

        def close(self):
            self.closed = True
            writer.close()

        def write_eof(self):
            """Close the underlying stream's write side when supported."""
            writer.write_eof()

        def can_write_eof(self):
            """Return whether the underlying stream supports write EOF."""
            return writer.can_write_eof()

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
        read = reader.read
        try:
            while not reader.at_eof() and not ssl._app_transport._closed:
                data = await read(read_size)
                if not data:
                    break
                if buffer is not None:
                    data_len = len(data)
                    buffer[:data_len] = data
                    ssl.buffer_updated(data_len)
                else:
                    ssl.data_received(data)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # close adapter on stream failure
            if verbose:
                verbose(f'TLS adapter failed: {exc}')
        finally:
            ssl.eof_received()

    if task_registry is not None:
        task_registry.create_task(channel(), name='tls-adapter')
    else:
        create_task(channel(), name='tls-adapter')

    class Writer:
        """Expose the encrypted stream as an asyncio-style writer."""

        def get_extra_info(self, key):
            """Return metadata from the underlying writer."""
            return writer.get_extra_info(key)

        def write(self, data):
            """Write encrypted data through SSLProtocol."""
            ssl._app_transport.write(data)

        def drain(self):
            """Wait for the underlying writer's buffer to drain."""
            return writer.drain()

        def is_closing(self):
            """Return whether SSLProtocol has closed the application transport."""
            return ssl._app_transport._closed

        def close(self):
            """Close the SSL application transport."""
            if not ssl._app_transport._closed:
                ssl._app_transport.close()

    return ssl_reader, Writer()
