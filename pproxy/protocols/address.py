"""SOCKS address encoding and stream parsing helpers."""

import socket

from .. import transport
from ..errors import ProtocolError


async def socks_address_stream(reader, n):
    """Read a SOCKS address and port from an asynchronous byte stream."""
    if n in (1, 17):
        data = await transport.read_exactly(reader, 4)
        host_name = socket.inet_ntoa(data)
    elif n in (3, 19):
        host_length = await transport.read_exactly(reader, 1)
        host_data = await transport.read_exactly(reader, host_length[0])
        data = host_length + host_data
        host_name = host_data.decode()
    elif n in (4, 20):
        data = await transport.read_exactly(reader, 16)
        host_name = socket.inet_ntop(socket.AF_INET6, data)
    else:
        raise ProtocolError(f'Unknown address header {n}')
    data_port = await transport.read_exactly(reader, 2)
    return host_name, int.from_bytes(data_port, 'big'), data + data_port


def socks_address(reader, n):
    """Read a SOCKS address and port from a synchronous byte buffer."""
    return socket.inet_ntoa(reader.read(4)) if n == 1 else \
           reader.read(reader.read(1)[0]).decode() if n == 3 else \
           socket.inet_ntop(socket.AF_INET6, reader.read(16)), \
           int.from_bytes(reader.read(2), 'big')
