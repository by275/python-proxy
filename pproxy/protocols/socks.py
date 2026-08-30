"""SOCKS, Shadowsocks, SSR, and Trojan protocol implementations."""

import asyncio
import hashlib
import hmac
import io
import socket

from .. import transport
from ..errors import AuthenticationError, ConnectionClosed, require
from .address import socks_address, socks_address_stream
from .base import BaseProtocol


def packstr(value, size=1):
    """Prefix bytes with a big-endian length field."""
    return len(value).to_bytes(size, 'big') + value


class Trojan(BaseProtocol):
    """Implement the Trojan stream handshake and target framing."""

    async def guess(self, reader, users, **kw):  # pylint: disable=unused-argument
        """Detect and authenticate a Trojan client preamble."""
        header = await transport.read(reader, 56)
        if users:
            for user in users:
                if hashlib.sha224(user).hexdigest().encode() == header:
                    return user
        elif hashlib.sha224(b'').hexdigest().encode() == header:
            return True
        transport.rollback(reader, header)

    async def accept(self, reader, user, **kw):  # pylint: disable=unused-argument
        """Read a Trojan target request from a local client."""
        require(await transport.read_exactly(reader, 2) == b'\x0d\x0a')
        if (await transport.read_exactly(reader, 1))[0] != 1:
            raise ConnectionClosed()
        host_name, port, _ = await socks_address_stream(
            reader,
            (await transport.read_exactly(reader, 1))[0],
        )
        require(await transport.read_exactly(reader, 2) == b'\x0d\x0a')
        return user, host_name, port

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        """Write a Trojan target request to the upstream proxy."""
        toauth = hashlib.sha224(rauth or b'').hexdigest().encode()
        writer_remote.write(
            toauth + b'\x0d\x0a\x01\x03' + packstr(host_name.encode())
            + port.to_bytes(2, 'big') + b'\x0d\x0a'
        )


class SSR(BaseProtocol):
    """Implement the ShadowsocksR handshake framing."""

    async def guess(self, reader, users, **kw):  # pylint: disable=unused-argument
        """Detect an SSR client header and identify its user."""
        if users:
            header = await transport.read(reader, max(len(item) for item in users))
            transport.rollback(reader, header)
            user = next(filter(lambda item: item == header[:len(item)], users), None)
            if user is None:
                return
            await transport.read_exactly(reader, len(user))
            return user
        header = await transport.read(reader, 1)
        transport.rollback(reader, header)
        return header[0] in (1, 3, 4, 17, 19, 20)

    async def accept(self, reader, user, **kw):  # pylint: disable=unused-argument
        """Read an SSR target request from a local client."""
        host_name, port, _ = await socks_address_stream(
            reader,
            (await transport.read_exactly(reader, 1))[0],
        )
        return user, host_name, port

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        """Write an SSR target request to the upstream proxy."""
        writer_remote.write(rauth + b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))


class SS(SSR):
    """Implement Shadowsocks stream and UDP framing with optional OTA."""

    def patch_ota_reader(self, cipher, reader):
        """Install authenticated chunk decoding on a Shadowsocks reader."""
        chunk_id, data_len, _buffer = 0, None, bytearray()

        def decrypt(data):
            nonlocal chunk_id, data_len
            _buffer.extend(data)
            ret = bytearray()
            while 1:
                if data_len is None:
                    if len(_buffer) < 2:
                        break
                    data_len = int.from_bytes(_buffer[:2], 'big')
                    del _buffer[:2]
                else:
                    if len(_buffer) < 10 + data_len:
                        break
                    payload = _buffer[10:10 + data_len]
                    require(
                        _buffer[:10]
                        == hmac.new(
                            cipher.iv + chunk_id.to_bytes(4, 'big'),
                            payload,
                            hashlib.sha1,
                        ).digest()[:10]
                    )
                    del _buffer[:10 + data_len]
                    data_len = None
                    chunk_id += 1
                    ret.extend(payload)
            return bytes(ret)

        reader.decrypts.append(decrypt)
        buffered = transport.take_buffer(reader)
        if buffered:
            transport.prepend(reader, decrypt(buffered))

    def patch_ota_writer(self, cipher, writer):
        """Install authenticated chunk encoding on a Shadowsocks writer."""
        chunk_id = 0

        def write(data, original=writer.write):
            nonlocal chunk_id
            if not data:
                return None
            checksum = hmac.new(
                cipher.iv + chunk_id.to_bytes(4, 'big'),
                data,
                hashlib.sha1,
            ).digest()
            chunk_id += 1
            return original(len(data).to_bytes(2, 'big') + checksum[:10] + data)

        writer.write = write

    async def accept(self, reader, user, reader_cipher, **kw):  # pylint: disable=arguments-differ,unused-argument
        """Read and validate a Shadowsocks target request."""
        header = await transport.read_exactly(reader, 1)
        ota = header[0] & 0x10 == 0x10
        host_name, port, data = await socks_address_stream(reader, header[0])
        require(ota or not reader_cipher or not reader_cipher.ota, 'SS client must support OTA')
        if ota and reader_cipher:
            checksum = hmac.new(
                reader_cipher.iv + reader_cipher.key,
                header + data,
                hashlib.sha1,
            ).digest()
            require(
                checksum[:10] == await transport.read_exactly(reader, 10),
                'Unknown OTA checksum',
            )
            self.patch_ota_reader(reader_cipher, reader)
        return user, host_name, port

    async def connect(  # pylint: disable=arguments-differ,too-many-arguments,too-many-positional-arguments,unused-argument
        self, reader_remote, writer_remote, rauth, host_name, port, writer_cipher_r, **kw
    ):
        """Write a Shadowsocks target request and optional OTA metadata."""
        writer_remote.write(rauth)
        if writer_cipher_r and writer_cipher_r.ota:
            rdata = b'\x13' + packstr(host_name.encode()) + port.to_bytes(2, 'big')
            checksum = hmac.new(
                writer_cipher_r.iv + writer_cipher_r.key,
                rdata,
                hashlib.sha1,
            ).digest()
            writer_remote.write(rdata + checksum[:10])
            self.patch_ota_writer(writer_cipher_r, writer_remote)
        else:
            writer_remote.write(b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))

    def udp_accept(self, data, users, **kw):  # pylint: disable=arguments-differ,unused-argument
        """Decode a Shadowsocks UDP datagram received by the proxy."""
        reader = io.BytesIO(data)
        user = True
        if users:
            user = next(filter(lambda item: data[:len(item)] == item, users), None)
            if user is None:
                return None
            reader.read(len(user))
        n = reader.read(1)[0]
        if n not in (1, 3, 4):
            return None
        host_name, port = socks_address(reader, n)
        return user, host_name, port, reader.read()

    def udp_unpack(self, data):
        """Remove the address prefix from a Shadowsocks UDP response."""
        reader = io.BytesIO(data)
        n = reader.read(1)[0]
        socks_address(reader, n)
        return reader.read()

    def udp_pack(self, host_name, port, data):
        """Add a SOCKS address prefix to a Shadowsocks UDP payload."""
        try:
            return b'\x01' + socket.inet_aton(host_name) + port.to_bytes(2, 'big') + data
        except (OSError, ValueError, OverflowError):
            pass
        return b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data

    def udp_connect(self, rauth, host_name, port, data, **kw):
        """Encode a Shadowsocks UDP request for an upstream proxy."""
        return rauth + b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data


class Socks4(BaseProtocol):
    """Implement the SOCKS4 client and upstream handshake."""

    async def guess(self, reader, **kw):  # pylint: disable=unused-argument
        """Detect a SOCKS4 request version byte."""
        header = await transport.read(reader, 1)
        if header == b'\x04':
            return True
        transport.rollback(reader, header)

    async def accept(self, reader, user, writer, users, authtable, **kw):  # pylint: disable=unused-argument
        """Authenticate and read a SOCKS4 target request."""
        require(await transport.read_exactly(reader, 1) == b'\x01')
        port = int.from_bytes(await transport.read_exactly(reader, 2), 'big')
        ip = await transport.read_exactly(reader, 4)
        userid = (await transport.read_until(reader, b'\x00'))[:-1]
        user = authtable.authed()
        if users:
            if userid in users:
                user = userid
            elif not user:
                raise AuthenticationError(f'Unauthorized SOCKS {userid}')
            authtable.set_authed(user)
        writer.write(b'\x00\x5a' + port.to_bytes(2, 'big') + ip)
        return user, socket.inet_ntoa(ip), port

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        """Open a SOCKS4 tunnel through the remote proxy."""
        loop = asyncio.get_running_loop()
        ip = socket.inet_aton(
            (await loop.getaddrinfo(host_name, port, family=socket.AF_INET))[0][4][0]
        )
        writer_remote.write(b'\x04\x01' + port.to_bytes(2, 'big') + ip + rauth + b'\x00')
        require(await transport.read_exactly(reader_remote, 2) == b'\x00\x5a')
        await transport.read_exactly(reader_remote, 6)


class Socks5(BaseProtocol):
    """Implement the SOCKS5 client and upstream handshake."""

    async def guess(self, reader, **kw):  # pylint: disable=unused-argument
        """Detect a SOCKS5 request version byte."""
        header = await transport.read(reader, 1)
        if header == b'\x05':
            return True
        transport.rollback(reader, header)

    async def accept(self, reader, user, writer, users, authtable, **kw):  # pylint: disable=unused-argument
        """Authenticate and read a SOCKS5 target request."""
        methods = await transport.read_exactly(reader, (await transport.read_exactly(reader, 1))[0])
        user = authtable.authed()
        if users and (not user or b'\x00' not in methods):
            if b'\x02' not in methods:
                raise AuthenticationError('Unauthorized SOCKS')
            writer.write(b'\x05\x02')
            require(
                (await transport.read_exactly(reader, 1))[0] == 1,
                'Unknown SOCKS auth',
            )
            u = await transport.read_exactly(reader, (await transport.read_exactly(reader, 1))[0])
            p = await transport.read_exactly(reader, (await transport.read_exactly(reader, 1))[0])
            user = u + b':' + p
            if user not in users:
                raise AuthenticationError(f'Unauthorized SOCKS {u}:{p}')
            writer.write(b'\x01\x00')
        elif users and not user:
            raise AuthenticationError('Unauthorized SOCKS')
        else:
            writer.write(b'\x05\x00')
        if users:
            authtable.set_authed(user)
        require(
            await transport.read_exactly(reader, 3) == b'\x05\x01\x00',
            'Unknown SOCKS protocol',
        )
        header = await transport.read_exactly(reader, 1)
        host_name, port, data = await socks_address_stream(reader, header[0])
        writer.write(b'\x05\x00\x00' + header + data)
        return user, host_name, port

    async def connect(
        self, reader_remote, writer_remote, rauth, host_name, port, **kw
    ):  # pylint: disable=unused-argument
        """Open a SOCKS5 tunnel through the remote proxy."""
        if rauth:
            writer_remote.write(b'\x05\x01\x02')
            require(await transport.read_exactly(reader_remote, 2) == b'\x05\x02')
            writer_remote.write(b'\x01' + b''.join(packstr(item) for item in rauth.split(b':', 1)))
            require(
                await transport.read_exactly(reader_remote, 2) == b'\x01\x00',
                'Unknown SOCKS auth',
            )
        else:
            writer_remote.write(b'\x05\x01\x00')
            require(await transport.read_exactly(reader_remote, 2) == b'\x05\x00')
        writer_remote.write(
            b'\x05\x01\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big')
        )
        require(await transport.read_exactly(reader_remote, 3) == b'\x05\x00\x00')
        header = (await transport.read_exactly(reader_remote, 1))[0]
        await transport.read_exactly(
            reader_remote,
            (
                6 if header == 1
                else 18 if header == 4
                else (await transport.read_exactly(reader_remote, 1))[0] + 2
            ),
        )

    def udp_accept(self, data, **kw):
        """Decode a SOCKS5 UDP datagram received by the proxy."""
        reader = io.BytesIO(data)
        if reader.read(3) != b'\x00\x00\x00':
            return None
        n = reader.read(1)[0]
        if n not in (1, 3, 4):
            return None
        host_name, port = socks_address(reader, n)
        return True, host_name, port, reader.read()

    def udp_connect(self, rauth, host_name, port, data, **kw):
        """Encode a SOCKS5 UDP request for an upstream proxy."""
        return b'\x00\x00\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data
