"""WebSocket proxy protocol implementation."""

import base64
import hashlib
import os
import urllib.parse

from .. import transport, websocket
from ..config import netloc_split
from ..errors import AuthenticationError, RequestError
from .base import BaseProtocol
from .http import MAX_HTTP_HEADER_SIZE, parse_http_request_head


class WS(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await transport.read(reader, 4)
        transport.rollback(reader, header)
        return header == b'GET '

    def patch_ws_stream(self, reader, writer, masked=False):
        return websocket.patch_stream(reader, writer, masked)

    async def accept(self, reader, user, writer, users, authtable, sock, **kw):
        lines = await transport.read_until(reader, b'\r\n\r\n', limit=MAX_HTTP_HEADER_SIZE)
        method, path, ver, _, _, pauth, sec_websocket_key = parse_http_request_head(lines[:-4])
        urllib.parse.urlparse(path)
        if users:
            user = authtable.authed()
            if not user:
                user = next(
                    filter(lambda i: ('Basic ' + base64.b64encode(i).decode()) == pauth, users),
                    None,
                )
                if user is None:
                    writer.write(
                        f'{ver} 407 Proxy Authentication Required\r\n'
                        'Connection: close\r\n'
                        'Proxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode()
                    )
                    raise AuthenticationError('Unauthorized WebSocket')
            authtable.set_authed(user)
        if method != 'GET':
            raise RequestError(f'Unsupported method {method}')
        if sec_websocket_key is None:
            raise RequestError('Unsupported headers for WebSocket')
        seckey = base64.b64decode(sec_websocket_key)
        rseckey = base64.b64encode(hashlib.sha1(seckey + b'amtf').digest()[:16]).decode()
        writer.write(
            f'{ver} 101 Switching Protocols\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Accept: {rseckey}\r\n'
            'Sec-WebSocket-Protocol: chat\r\n\r\n'.encode()
        )
        self.patch_ws_stream(reader, writer, False)
        if not self.param:
            return 'tunnel', 0
        dst = sock.getsockname()
        host, port = netloc_split(self.param, dst[0], dst[1])
        return user, host, port

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        seckey = base64.b64encode(os.urandom(16)).decode()
        writer_remote.write(
            f'GET / HTTP/1.1\r\nHost: {myhost}\r\n'
            'Upgrade: websocket\r\nConnection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {seckey}\r\n'
            'Sec-WebSocket-Protocol: chat\r\nSec-WebSocket-Version: 13'.encode()
            + (b'\r\nProxy-Authorization: Basic ' + base64.b64encode(rauth) if rauth else b'')
            + b'\r\n\r\n'
        )
        await transport.read_until(reader_remote, b'\r\n\r\n')
        self.patch_ws_stream(reader_remote, writer_remote, True)
