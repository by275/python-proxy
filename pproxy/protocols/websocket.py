"""WebSocket proxy protocol implementation."""

import asyncio
import base64
import hashlib
import os
import urllib.parse

from .. import transport, websocket
from ..config import netloc_split
from ..errors import AuthenticationError, ProtocolError, RequestError
from .base import BaseProtocol
from .http import MAX_HTTP_HEADER_SIZE, parse_http_request_head


class WS(BaseProtocol):
    """Implement the HTTP upgrade and WebSocket stream adapter."""

    async def guess(self, reader, **kw):  # pylint: disable=unused-argument
        """Detect the HTTP GET used to start a WebSocket handshake."""
        header = await transport.read(reader, 4)
        transport.rollback(reader, header)
        return header == b'GET '

    def patch_ws_stream(self, reader, writer, masked=False, *, on_close=None):
        """Install WebSocket framing on a pair of asynchronous streams."""
        return websocket.patch_stream(reader, writer, masked, on_close=on_close)

    async def accept(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,unused-argument
        self, reader, user, writer, users, authtable, sock, **kw
    ):
        """Authenticate and accept a local WebSocket proxy handshake."""
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

    # The upstream adapter accepts the local host parameter by contract.
    # pylint: disable=arguments-differ,too-many-arguments,too-many-positional-arguments
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        """Open a WebSocket tunnel through a compatible upstream proxy."""
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


CFP_CLOSE_CONTROL = b'cf-proxy:close:v1'
CFP_CLOSE_TIMEOUT = 2
WEBSOCKET_GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class CFP(WS):
    """Authenticated TLS WebSocket client for a compatible worker tunnel."""

    @staticmethod
    def _header_value(name, value):
        if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
            raise ProtocolError(f'invalid {name} header value')
        return value

    @staticmethod
    def _target(host_name, port):
        if ':' in host_name and not host_name.startswith('['):
            host_name = f'[{host_name}]'
        return f'{host_name}:{port}'

    # The CFP handshake keeps the shared upstream callback contract.
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        seckey = base64.b64encode(os.urandom(16)).decode()
        target = self._header_value('X-Proxy-Target', self._target(host_name, port))
        myhost = self._header_value('Host', myhost)
        headers = [
            'GET / HTTP/1.1',
            f'Host: {myhost}',
            'Upgrade: websocket',
            'Connection: Upgrade',
            f'Sec-WebSocket-Key: {seckey}',
            'Sec-WebSocket-Version: 13',
            f'X-Proxy-Target: {target}',
        ]
        if rauth:
            authorization = self._header_value('Authorization', rauth.decode('latin1'))
            headers.append(f'Authorization: {authorization}')
        writer_remote.write(('\r\n'.join(headers) + '\r\n\r\n').encode())
        response = await transport.read_until(
            reader_remote,
            b'\r\n\r\n',
            limit=MAX_HTTP_HEADER_SIZE,
        )
        status, *response_headers = response[:-4].split(b'\r\n')
        status_parts = status.split(b' ', 2)
        if len(status_parts) < 2 or status_parts[1] != b'101':
            raise ProtocolError(f'WebSocket handshake failed: {status.decode("latin1")}')
        response_headers = {
            key.decode('latin1').lower(): value.decode('latin1').strip()
            for line in response_headers
            for key, separator, value in [line.partition(b':')]
            if separator
        }
        expected = base64.b64encode(
            hashlib.sha1(
                seckey.encode() + WEBSOCKET_GUID
            ).digest()
        ).decode()
        if response_headers.get('sec-websocket-accept') != expected:
            raise ProtocolError('Invalid WebSocket handshake')
        if 'sec-websocket-extensions' in response_headers:
            raise ProtocolError('Unsupported WebSocket extensions')

        close_event = asyncio.Event()
        stream = self.patch_ws_stream(
            reader_remote,
            writer_remote,
            True,
            on_close=lambda _payload: close_event.set(),
        )
        raw_close = writer_remote.close
        close_lock = asyncio.Lock()

        async def graceful_close():
            async with close_lock:
                if writer_remote.is_closing():
                    return
                if close_event.is_set():
                    raw_close()
                    return
                try:
                    await writer_remote.drain()
                    stream.write_frame(1, CFP_CLOSE_CONTROL)
                    await writer_remote.drain()
                    await asyncio.wait_for(close_event.wait(), CFP_CLOSE_TIMEOUT)
                    await writer_remote.drain()
                except Exception:  # pylint: disable=broad-exception-caught  # always perform raw close
                    pass
                finally:
                    raw_close()

        writer_remote.graceful_close = graceful_close
