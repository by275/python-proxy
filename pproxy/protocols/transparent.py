"""Transparent and socket-address based protocol implementations."""

import socket
import struct

from .. import config
from ..errors import require
from .base import BaseProtocol


class SSH(BaseProtocol):
    """Protocol marker for SSH-managed direct connections."""

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        """Leave connection setup to the SSH transport layer."""


class Transparent(BaseProtocol):
    """Resolve the destination from a locally accepted socket."""

    def query_remote(self, sock):
        """Return the destination endpoint associated with a local socket."""
        raise NotImplementedError(f'{self.name} must implement query_remote()')

    async def guess(self, reader, sock, **kw):
        """Check whether the socket has a usable transparent destination."""
        remote = self.query_remote(sock)
        return remote is not None and (sock is None or sock.getsockname() != remote)

    async def accept(self, reader, user, sock, **kw):
        """Return the transparent destination for a TCP client."""
        remote = self.query_remote(sock)
        return user, remote[0], remote[1]

    def udp_accept(self, data, sock, **kw):
        """Return the transparent destination for a UDP datagram."""
        remote = self.query_remote(sock)
        return True, remote[0], remote[1], data


SO_ORIGINAL_DST = 80
SOL_IPV6 = 41


class Redir(Transparent):
    """Resolve destinations through Linux REDIRECT socket metadata."""

    def query_remote(self, sock):
        try:
            # if sock.family == socket.AF_INET:
            if '.' in sock.getsockname()[0]:
                buf = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                require(len(buf) == 16)
                return socket.inet_ntoa(buf[4:8]), int.from_bytes(buf[2:4], 'big')
            buf = sock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
            require(len(buf) == 28)
            return socket.inet_ntop(socket.AF_INET6, buf[8:24]), int.from_bytes(buf[2:4], 'big')
        except (OSError, ValueError, AssertionError):
            pass
        return None


class Pf(Transparent):
    """Resolve destinations through the BSD PF divert socket."""

    def __init__(self, param):
        super().__init__(param)
        self.pf = None

    def query_remote(self, sock):
        """Query PF for the original destination of a redirected socket."""
        try:
            import fcntl  # pylint: disable=import-outside-toplevel  # BSD-only standard library

            src = sock.getpeername()
            dst = sock.getsockname()
            src_ip = socket.inet_pton(sock.family, src[0])
            dst_ip = socket.inet_pton(sock.family, dst[0])
            pnl = bytearray(
                struct.pack(
                    '!16s16s32xHxxHxx8xBBxB',
                    src_ip,
                    dst_ip,
                    src[1],
                    dst[1],
                    sock.family,
                    socket.IPPROTO_TCP,
                    2,
                )
            )
            if self.pf is None:
                self.pf = open(  # pylint: disable=consider-using-with  # handle remains open for the adapter
                    '/dev/pf', 'a+b'
                )
            fcntl.ioctl(self.pf.fileno(), 0xc0544417, pnl)
            return socket.inet_ntop(sock.family, pnl[48:48 + len(src_ip)]), int.from_bytes(pnl[76:78], 'big')
        except (OSError, ValueError, AssertionError):
            pass
        return None


class Tunnel(Transparent):
    """Use the configured endpoint instead of socket-derived metadata."""

    def query_remote(self, sock):
        """Return the configured tunnel endpoint."""
        if not self.param:
            return 'tunnel', 0
        dst = sock.getsockname() if sock else (None, None)
        return config.netloc_split(self.param, dst[0], dst[1])

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        """Leave tunnel setup to the surrounding connection handler."""

    def udp_connect(self, rauth, host_name, port, data, **kw):
        """Pass through a UDP payload for the configured tunnel."""
        return data


class Echo(Transparent):
    """Resolve all transparent traffic to the local echo endpoint."""

    def query_remote(self, sock):
        """Return the sentinel endpoint used for echo traffic."""
        return 'echo', 0
