"""Shared protocol base classes and bidirectional stream behavior."""

from .. import transport
from ..errors import UnsupportedProtocol

DRAIN_BUFFER_SIZE = 256 * 1024


class BaseProtocol:
    """Common interface implemented by proxy protocol adapters."""

    def __init__(self, param):
        self.param = param

    @property
    def name(self):
        """Return the protocol name used in diagnostics and errors."""
        return self.__class__.__name__.lower()

    def reuse(self):
        """Return whether a protocol instance can be reused for a connection."""
        return False

    def udp_accept(self, data, **kw):
        """Decode a UDP request received by the local proxy server."""
        raise UnsupportedProtocol(f'{self.name} don\'t support UDP server')

    def udp_connect(self, rauth, host_name, port, data, **kw):
        """Encode a UDP request for the remote proxy server."""
        raise UnsupportedProtocol(f'{self.name} don\'t support UDP client')

    def udp_unpack(self, data):
        """Remove protocol framing from a UDP response."""
        return data

    def udp_pack(self, host_name, port, data):
        """Add protocol framing to a UDP payload."""
        return data

    # Keep the complete callback shape for protocol implementations.
    # pylint: disable=unused-argument
    async def connect(  # pylint: disable=unused-argument
        self, reader_remote, writer_remote, rauth, host_name, port, **kw
    ):
        """Open a remote-proxy connection for a target endpoint."""
        raise UnsupportedProtocol(f'{self.name} don\'t support client')

    async def channel(self, reader, writer, stat_bytes, stat_conn):
        """Forward bytes between one reader and writer until they close."""
        normal_eof = reader.at_eof()
        try:
            stat_conn(1)
            pending_drain = 0
            read = reader.read
            while not reader.at_eof() and not writer.is_closing():
                data = await read(65536)
                if not data:
                    normal_eof = True
                    break
                if stat_bytes is None:
                    continue
                stat_bytes(len(data))
                writer.write(data)
                pending_drain += len(data)
                if pending_drain >= DRAIN_BUFFER_SIZE:
                    await writer.drain()
                    pending_drain = 0
        except (ConnectionError, OSError, EOFError):
            pass
        finally:
            stat_conn(-1)
            await transport.close_writer(writer, graceful=normal_eof)


class Direct(BaseProtocol):
    """Protocol adapter for a direct connection without proxy framing."""
