"""HTTP parsing helpers and HTTP-family protocol implementations."""

import base64
import asyncio
import re
import urllib.parse

from .. import admin, transport
from ..config import netloc_split
from ..errors import AuthenticationError, ConnectionClosed, ProtocolError, RequestError
from ..runtime import HTTP_HEADER_LIMIT
from .base import DRAIN_BUFFER_SIZE, BaseProtocol

HTTP_LINE = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
HTTP_METHOD_LINE = re.compile(br'([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
MAX_HTTP_HEADER_SIZE = HTTP_HEADER_LIMIT


def _decode_header_value(value):
    return value.decode('latin1')


def parse_http_request_head(data):
    request_line, *header_lines = data.split(b'\r\n')
    match = HTTP_METHOD_LINE.match(request_line)
    if match is None:
        raise ProtocolError('Unknown HTTP header')
    method_b, path_b, ver_b = match.groups()
    filtered_headers = []
    host = ''
    proxy_authorization = None
    sec_websocket_key = None
    for header in header_lines:
        key, sep, value = header.partition(b': ')
        if sep:
            if key == b'Host':
                host = _decode_header_value(value)
            elif key == b'Proxy-Authorization':
                proxy_authorization = _decode_header_value(value)
            elif key == b'Sec-WebSocket-Key':
                sec_websocket_key = _decode_header_value(value)
        if not header.startswith(b'Proxy-'):
            filtered_headers.append(header)
    return (
        _decode_header_value(method_b),
        _decode_header_value(path_b),
        _decode_header_value(ver_b),
        b'\r\n'.join(filtered_headers),
        host,
        proxy_authorization,
        sec_websocket_key,
    )


def decode_http_header_block(header_block):
    header_lines = header_block.split(b'\r\n') if header_block else ()
    headers = {}
    for line in header_lines:
        key, sep, value = line.partition(b': ')
        if sep:
            headers[_decode_header_value(key)] = _decode_header_value(value)
    return headers, '\r\n'.join(_decode_header_value(line) for line in header_lines)


async def drain_if_needed(writer, force=False):
    if force:
        await writer.drain()


class HTTP(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await transport.read(reader, 4)
        transport.rollback(reader, header)
        return header in (b'GET ', b'HEAD', b'POST', b'PUT ', b'DELE', b'CONN', b'OPTI', b'TRAC', b'PATC')

    async def accept(self, reader, user, writer, **kw):
        lines = await transport.read_until(reader, b'\r\n\r\n', limit=MAX_HTTP_HEADER_SIZE)
        method, path, ver, filtered_headers, host, proxy_authorization, _ = parse_http_request_head(lines[:-4])

        async def reply(code, message, body=None, wait=False):
            writer.write(message)
            if body:
                writer.write(body)
            if wait:
                await drain_if_needed(writer, force=True)

        return await self.http_accept(
            user,
            method,
            path,
            None,
            ver,
            filtered_headers,
            host,
            proxy_authorization,
            reply,
            **kw,
        )

    async def http_accept(
        self,
        user,
        method,
        path,
        authority,
        ver,
        filtered_headers,
        host,
        pauth,
        reply,
        authtable,
        users,
        httpget=None,
        **kw,
    ):
        url = urllib.parse.urlparse(path)
        if method == 'GET' and not url.hostname:
            for path, text in (httpget.items() if httpget else ()):
                if path == url.path:
                    user = next(filter(lambda x: x.decode() == url.query, users), None) if users else True
                    if user:
                        if users:
                            authtable.set_authed(user)
                        if type(text) is str:
                            text = (text % dict(host=host)).encode()
                        await reply(
                            200,
                            f'{ver} 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {len(text)}\r\n\r\n'.encode(),
                            text,
                            True,
                        )
                        raise ConnectionClosed()
            raise RequestError(f'404 {method} {url.path}')
        if users:
            user = authtable.authed()
            if not user:
                user = next(filter(lambda i: ('Basic ' + base64.b64encode(i).decode()) == pauth, users), None)
                if user is None:
                    await reply(
                        407,
                        f'{ver} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode(),
                        wait=True,
                    )
                    raise AuthenticationError('Unauthorized HTTP')
            authtable.set_authed(user)
        if method == 'CONNECT':
            host_name, port = netloc_split(authority or path)
            return user, host_name, port, lambda writer: reply(200, f'{ver} 200 Connection established\r\nConnection: close\r\n\r\n'.encode())
        host_name, port = netloc_split(url.netloc or host, default_port=80)
        newpath = url._replace(netloc='', scheme='').geturl()
        request_head = f'{method} {newpath} {ver}\r\n'.encode() + filtered_headers + b'\r\n\r\n'

        async def connected(writer):
            writer.write(request_head)
            return True

        return user, host_name, port, connected

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        writer_remote.write(
            f'CONNECT {host_name}:{port} HTTP/1.1\r\nHost: {host_name}:{port}'.encode()
            + (b'\r\nProxy-Authorization: Basic ' + base64.b64encode(rauth) if rauth else b'')
            + b'\r\n\r\n'
        )
        await transport.read_until(reader_remote, b'\r\n\r\n')

    async def http_channel(self, reader, writer, stat_bytes, stat_conn):
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
                request_line, sep, _ = data.partition(b'\r\n')
                if sep and HTTP_METHOD_LINE.match(request_line):
                    if b'\r\n\r\n' not in data:
                        data += await transport.read_until(reader, b'\r\n\r\n')
                    lines, data = data.split(b'\r\n\r\n', 1)
                    method, path, ver, filtered_headers, _, _, _ = parse_http_request_head(lines)
                    newpath = urllib.parse.urlparse(path)._replace(netloc='', scheme='').geturl()
                    data = f'{method} {newpath} {ver}\r\n'.encode() + filtered_headers + b'\r\n\r\n' + data
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


class HTTPOnly(HTTP):
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        buffer = bytearray()
        host_name_pattern = re.compile(br'\r\nHost: ([^\r\n]+)\r\n', re.I)

        def write(data, o=writer_remote.write):
            if not data:
                return
            buffer.extend(data)
            pos = buffer.find(b'\r\n\r\n')
            if pos != -1:
                request_head = buffer[:pos]
                request_line = request_head.split(b'\r\n', 1)[0]
                header = HTTP_METHOD_LINE.match(request_line)
                host = host_name_pattern.search(b'\r\n' + request_head + b'\r\n')
                if not header or not host:
                    writer_remote.close()
                    raise RequestError('Unknown HTTP header for protocol HTTPOnly')
                method, path, ver = header.groups()
                host_value = host.group(1)
                data = (
                    method + b' http://' + host_value + path + b' ' + ver + b'\r\nHost: ' + host_value
                    + (b'\r\nProxy-Authorization: Basic ' + base64.b64encode(rauth) if rauth else b'')
                    + b'\r\n\r\n' + buffer[pos + 4:]
                )
                buffer.clear()
                return o(data)

        writer_remote.write = write


class H2(HTTP):
    async def guess(self, reader, **kw):
        return True

    async def accept(self, reader, user, writer, **kw):
        if not writer.headers.done():
            await writer.headers
        headers = writer.headers.result()
        headers = {i.decode().lower(): j.decode() for i, j in headers}
        lines = '\r\n'.join(i for i in headers if not i.startswith('proxy-') and not i.startswith(':'))

        async def reply(code, message, body=None, wait=False):
            writer.send_headers(((':status', str(code)),))
            if body:
                writer.write(body)
            if wait:
                await drain_if_needed(writer, force=True)

        return await self.http_accept(
            user,
            headers[':method'],
            headers.get(':path', '/'),
            headers.get(':authority'),
            '2.0',
            lines,
            '',
            headers.get('proxy-authorization'),
            reply,
            **kw,
        )

    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        headers = [(':method', 'CONNECT'), (':authority', f'{host_name}:{port}')]
        if rauth:
            headers.append(('proxy-authorization', 'Basic ' + base64.b64encode(rauth)))
        writer_remote.send_headers(headers)


class H3(H2):
    pass


class HTTPAdmin(HTTP):
    MAX_HEADER_SIZE = 32 * 1024

    async def accept(self, reader, user, writer, **kw):
        lines = await transport.read_until(reader, b'\r\n\r\n', limit=self.MAX_HEADER_SIZE)
        method, path, ver, filtered_headers, _, proxy_authorization, _ = parse_http_request_head(lines[:-4])
        headers, lines = decode_http_header_block(filtered_headers)

        async def reply(code, message, body=None, wait=False):
            writer.write(message)
            if body:
                writer.write(body)
            if wait:
                await drain_if_needed(writer, force=True)

        users = kw.get('users') or ()
        authorization = next(
            (value for key, value in headers.items() if key.casefold() in {'authorization', 'proxy-authorization'}),
            proxy_authorization,
        )
        authorized = next(
            (candidate for candidate in users if authorization == 'Basic ' + base64.b64encode(candidate).decode()),
            None,
        )
        if authorized is None:
            writer.write(
                f'{ver} 401 Unauthorized\r\nConnection: close\r\n'
                'WWW-Authenticate: Basic realm="pproxy-admin"\r\n\r\n'.encode()
            )
            await drain_if_needed(writer, force=True)
            raise AuthenticationError('Unauthorized HTTP admin')

        try:
            content_length = int(headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise RequestError('Invalid Content-Length') from exc
        if content_length < 0 or content_length > admin.MAX_ADMIN_BODY:
            await reply('413 Payload Too Large', f'{ver} 413 Payload Too Large\r\nConnection: close\r\n\r\n'.encode(), wait=True)
            raise RequestError('HTTP admin request body too large')
        content = b''
        if content_length > 0:
            content = await transport.read_exactly(reader, content_length)

        url = urllib.parse.urlparse(path)
        if url.hostname is not None:
            raise RequestError('HTTP Admin Unsupported hostname')
        if method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            for path, handler in admin.httpget.items():
                if path == url.path:
                    await handler(reply=reply, ver=ver, method=method, headers=headers, lines=lines, content=content)
                    raise ConnectionClosed()
            raise RequestError(f'404 {method} {url.path}')
        raise RequestError(f'405 {method} not allowed')
