"""Diagnostic commands and listener startup reporting."""

import socket
import ssl
import urllib.parse

from .. import proto, transport
from ..__doc__ import __version__
from ..errors import ProtocolError, UpstreamError, require


async def test_url(url, rserver):
    """Fetch a URL through every configured remote and print the response."""
    url = urllib.parse.urlparse(url)
    require(url.scheme in ('http', 'https'), f'Unknown scheme {url.scheme}')
    host_name, port = proto.netloc_split(url.netloc, default_port=80 if url.scheme == 'http' else 443)
    initbuf = (
        f'GET {url.path or "/"} HTTP/1.1\r\n'
        f'Host: {host_name}\r\n'
        f'User-Agent: pproxy-{__version__}\r\n'
        'Accept: */*\r\nConnection: close\r\n\r\n'
    ).encode()
    for roption in rserver:
        print(f'============ {roption.bind} ============')
        try:
            reader, writer = await roption.open_connection(host_name, port, None, None)
        except TimeoutError as exc:
            raise UpstreamError(f'Connection timeout {rserver}') from exc
        try:
            reader, writer = await roption.prepare_connection(reader, writer, host_name, port)
        except (ConnectionError, OSError, EOFError, TimeoutError, ValueError, ProtocolError) as exc:
            writer.close()
            raise UpstreamError('Unknown remote protocol') from exc
        if url.scheme == 'https':
            sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            reader, writer = proto.sslwrap(reader, writer, sslclient, False, host_name)
        writer.write(initbuf)
        headers = await transport.read_until(reader, b'\r\n\r\n')
        print(headers.decode()[:-4])
        print('--------------------------------')
        body = bytearray()
        read = reader.read
        while not reader.at_eof():
            data = await read(65536)
            if not data:
                break
            body.extend(data)
        print(body.decode('utf8', 'ignore'))
    print('============ success ============')


def print_server_started(option, server, print_fn):
    """Print listener addresses while handling protocol-specific socket shapes."""
    for sock in server.sockets:
        # https://github.com/MagicStack/uvloop/blob/master/uvloop/pseudosock.pyx
        local_addr = sock.getsockname()
        host = local_addr[0]
        port = local_addr[1]
        family = sock.family
        ipversion = 'ipv4' if family == socket.AF_INET else 'ipv6' if family == socket.AF_INET6 else 'ipv?'
        print_fn(option, f'{ipversion} {host}:{port}')
