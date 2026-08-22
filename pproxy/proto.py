import asyncio, socket, urllib.parse, re, base64, hmac, struct, hashlib, io, os
from asyncio import create_task
from . import transport
from . import websocket
from .errors import require
from . import tls
from . import config
from .protocols import address as address_protocol
from .protocols import base as base_protocol
from .protocols import http as http_protocol
from .protocols import socks as socks_protocol

HTTP_LINE = http_protocol.HTTP_LINE
HTTP_METHOD_LINE = http_protocol.HTTP_METHOD_LINE
_decode_header_value = http_protocol._decode_header_value
parse_http_request_head = http_protocol.parse_http_request_head
decode_http_header_block = http_protocol.decode_http_header_block
socks_address_stream = address_protocol.socks_address_stream
socks_address = address_protocol.socks_address
netloc_split = config.netloc_split
BaseProtocol = base_protocol.BaseProtocol
Direct = base_protocol.Direct
DRAIN_BUFFER_SIZE = base_protocol.DRAIN_BUFFER_SIZE
drain_if_needed = http_protocol.drain_if_needed
HTTP = http_protocol.HTTP
HTTPOnly = http_protocol.HTTPOnly
H2 = http_protocol.H2
H3 = http_protocol.H3
HTTPAdmin = http_protocol.HTTPAdmin
packstr = socks_protocol.packstr
Trojan = socks_protocol.Trojan
SSR = socks_protocol.SSR
SS = socks_protocol.SS
Socks4 = socks_protocol.Socks4
Socks5 = socks_protocol.Socks5


xor_mask_bytes = websocket.xor_mask_bytes

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
            #if sock.family == socket.AF_INET:
            if "." in sock.getsockname()[0]:
                buf = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                require(len(buf) == 16)
                return socket.inet_ntoa(buf[4:8]), int.from_bytes(buf[2:4], 'big')
            else:
                buf = sock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
                require(len(buf) == 28)
                return socket.inet_ntop(socket.AF_INET6, buf[8:24]), int.from_bytes(buf[2:4], 'big')
        except Exception:
            pass

class Pf(Transparent):
    def query_remote(self, sock):
        try:
            import fcntl
            src = sock.getpeername()
            dst = sock.getsockname()
            src_ip = socket.inet_pton(sock.family, src[0])
            dst_ip = socket.inet_pton(sock.family, dst[0])
            pnl = bytearray(struct.pack('!16s16s32xHxxHxx8xBBxB', src_ip, dst_ip, src[1], dst[1], sock.family, socket.IPPROTO_TCP, 2))
            if not hasattr(self, 'pf'):
                self.pf = open('/dev/pf', 'a+b')
            fcntl.ioctl(self.pf.fileno(), 0xc0544417, pnl)
            return socket.inet_ntop(sock.family, pnl[48:48+len(src_ip)]), int.from_bytes(pnl[76:78], 'big')
        except Exception:
            pass

class Tunnel(Transparent):
    def query_remote(self, sock):
        if not self.param:
            return 'tunnel', 0
        dst = sock.getsockname() if sock else (None, None)
        return netloc_split(self.param, dst[0], dst[1])
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        pass
    def udp_connect(self, rauth, host_name, port, data, **kw):
        return data

class WS(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await transport.read(reader, 4)
        transport.rollback(reader, header)
        return header == b'GET '
    def patch_ws_stream(self, reader, writer, masked=False):
        return websocket.patch_stream(reader, writer, masked)
    async def accept(self, reader, user, writer, users, authtable, sock, **kw):
        lines = await transport.read_until(reader, b'\r\n\r\n')
        method, path, ver, _, _, pauth, sec_websocket_key = parse_http_request_head(lines[:-4])
        url = urllib.parse.urlparse(path)
        if users:
            user = authtable.authed()
            if not user:
                user = next(filter(lambda i: ('Basic '+base64.b64encode(i).decode()) == pauth, users), None)
                if user is None:
                    writer.write(f'{ver} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode())
                    raise Exception('Unauthorized WebSocket')
            authtable.set_authed(user)
        if method != 'GET':
            raise Exception(f'Unsupported method {method}')
        if sec_websocket_key is None:
            raise Exception('Unsupported headers for WebSocket')
        seckey = base64.b64decode(sec_websocket_key)
        rseckey = base64.b64encode(hashlib.sha1(seckey+b'amtf').digest()[:16]).decode()
        writer.write(f'{ver} 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {rseckey}\r\nSec-WebSocket-Protocol: chat\r\n\r\n'.encode())
        self.patch_ws_stream(reader, writer, False)
        if not self.param:
            return 'tunnel', 0
        dst = sock.getsockname()
        host, port = netloc_split(self.param, dst[0], dst[1])
        return user, host, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        seckey = base64.b64encode(os.urandom(16)).decode()
        writer_remote.write(f'GET / HTTP/1.1\r\nHost: {myhost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {seckey}\r\nSec-WebSocket-Protocol: chat\r\nSec-WebSocket-Version: 13'.encode() + (b'\r\nProxy-Authorization: Basic '+base64.b64encode(rauth) if rauth else b'') + b'\r\n\r\n')
        await transport.read_until(reader_remote, b'\r\n\r\n')
        self.patch_ws_stream(reader_remote, writer_remote, True)

class Echo(Transparent):
    def query_remote(self, sock):
        return 'echo', 0

async def accept(protos, reader, **kw):
    for proto in protos:
        try:
            user = await proto.guess(reader, **kw)
        except Exception:
            raise Exception('Connection closed')
        if user:
            ret = await proto.accept(reader, user, **kw)
            while len(ret) < 4:
                ret += (None,)
            return (proto,) + ret
    raise Exception(f'Unsupported protocol')

def udp_accept(protos, data, **kw):
    for proto in protos:
        ret = proto.udp_accept(data, **kw)
        if ret:
            return (proto,) + ret
    raise Exception(f'Unsupported protocol {data[:10]}')

MAPPINGS = dict(direct=Direct, http=HTTP, httponly=HTTPOnly, httpadmin=HTTPAdmin, ssh=SSH, socks5=Socks5, socks4=Socks4, socks=Socks5, ss=SS, ssr=SSR, redir=Redir, pf=Pf, tunnel=Tunnel, echo=Echo, ws=WS, trojan=Trojan, h2=H2, h3=H3, ssl='', secure='', quic='')
MAPPINGS['in'] = ''

def get_protos(rawprotos):
    protos = []
    for s in rawprotos:
        s, _, param = s.partition('{')
        param = param[:-1] if param else None
        p = MAPPINGS.get(s)
        if p is None:
            return f'existing protocols: {list(MAPPINGS.keys())}', None
        if p and p not in protos:
            protos.append(p(param))
    if not protos:
        return 'no protocol specified', None
    return None, protos

sslwrap = tls.wrap
