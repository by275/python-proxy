"""Transparent and socket-address based protocol implementations."""

import socket
import struct

from .. import config
from ..errors import require
from .base import BaseProtocol


class SSH(BaseProtocol):
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        pass


class Transparent(BaseProtocol):
    def query_remote(self, sock):
        raise NotImplementedError(f'{self.name} must implement query_remote()')

    async def guess(self, reader, sock, **kw):
        remote = self.query_remote(sock)
        return remote is not None and (sock is None or sock.getsockname() != remote)

    async def accept(self, reader, user, sock, **kw):
        remote = self.query_remote(sock)
        return user, remote[0], remote[1]

    def udp_accept(self, data, sock, **kw):
        remote = self.query_remote(sock)
        return True, remote[0], remote[1], data


SO_ORIGINAL_DST = 80
SOL_IPV6 = 41


class Redir(Transparent):
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


class Pf(Transparent):
    def query_remote(self, sock):
        try:
            import fcntl

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
            if not hasattr(self, 'pf'):
                self.pf = open('/dev/pf', 'a+b')
            fcntl.ioctl(self.pf.fileno(), 0xc0544417, pnl)
            return socket.inet_ntop(sock.family, pnl[48:48 + len(src_ip)]), int.from_bytes(pnl[76:78], 'big')
        except (OSError, ValueError, AssertionError):
            pass


class Tunnel(Transparent):
    def query_remote(self, sock):
        if not self.param:
            return 'tunnel', 0
        dst = sock.getsockname() if sock else (None, None)
        return config.netloc_split(self.param, dst[0], dst[1])

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        pass

    def udp_connect(self, rauth, host_name, port, data, **kw):
        return data


class Echo(Transparent):
    def query_remote(self, sock):
        return 'echo', 0
