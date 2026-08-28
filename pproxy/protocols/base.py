"""Shared protocol base classes and bidirectional stream behavior."""

from .. import transport
from ..errors import UnsupportedProtocol

DRAIN_BUFFER_SIZE = 256 * 1024


class BaseProtocol:
    def __init__(self, param):
        self.param = param

    @property
    def name(self):
        return self.__class__.__name__.lower()

    def reuse(self):
        return False

    def udp_accept(self, data, **kw):
        raise UnsupportedProtocol(f'{self.name} don\'t support UDP server')

    def udp_connect(self, rauth, host_name, port, data, **kw):
        raise UnsupportedProtocol(f'{self.name} don\'t support UDP client')

    def udp_unpack(self, data):
        return data

    def udp_pack(self, host_name, port, data):
        return data

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        raise UnsupportedProtocol(f'{self.name} don\'t support client')

    async def channel(self, reader, writer, stat_bytes, stat_conn):
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
    pass
