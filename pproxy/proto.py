import asyncio, socket, urllib.parse, re, base64, hmac, struct, hashlib, io, os
from asyncio import create_task
from . import admin
from . import transport
HTTP_LINE = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
HTTP_METHOD_LINE = re.compile(br'([^ ]+) +(.+?) +(HTTP/[^ ]+)$')
packstr = lambda s, n=1: len(s).to_bytes(n, 'big') + s
DRAIN_BUFFER_SIZE = 256 * 1024


def _decode_header_value(value):
    return value.decode('latin1')


async def drain_if_needed(writer, force=False):
    if force:
        await writer.drain()


def parse_http_request_head(data):
    request_line, *header_lines = data.split(b'\r\n')
    match = HTTP_METHOD_LINE.match(request_line)
    if match is None:
        raise Exception('Unknown HTTP header')
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


def xor_mask_bytes(data, mask_key):
    masked = bytearray(data)
    for index, value in enumerate(masked):
        masked[index] = value ^ mask_key[index % 4]
    return bytes(masked)

def netloc_split(loc, default_host=None, default_port=None):
    ipv6 = re.fullmatch(r'\[([0-9a-fA-F:]*)\](?::(\d+)?)?', loc)
    if ipv6:
        host_name, port = ipv6.groups()
    elif ':' in loc:
        host_name, port = loc.rsplit(':', 1)
    else:
        host_name, port = loc, None
    return host_name or default_host, int(port) if port else default_port

async def socks_address_stream(reader, n):
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
        raise Exception(f'Unknown address header {n}')
    data_port = await transport.read_exactly(reader, 2)
    return host_name, int.from_bytes(data_port, 'big'), data+data_port

def socks_address(reader, n):
    return socket.inet_ntoa(reader.read(4)) if n == 1 else \
           reader.read(reader.read(1)[0]).decode() if n == 3 else \
           socket.inet_ntop(socket.AF_INET6, reader.read(16)), \
           int.from_bytes(reader.read(2), 'big')

class BaseProtocol:
    def __init__(self, param):
        self.param = param
    @property
    def name(self):
        return self.__class__.__name__.lower()
    def reuse(self):
        return False
    def udp_accept(self, data, **kw):
        raise Exception(f'{self.name} don\'t support UDP server')
    def udp_connect(self, rauth, host_name, port, data, **kw):
        raise Exception(f'{self.name} don\'t support UDP client')
    def udp_unpack(self, data):
        return data
    def udp_pack(self, host_name, port, data):
        return data
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        raise Exception(f'{self.name} don\'t support client')
    async def channel(self, reader, writer, stat_bytes, stat_conn):
        try:
            stat_conn(1)
            pending_drain = 0
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(65536)
                if not data:
                    break
                if stat_bytes is None:
                    continue
                stat_bytes(len(data))
                writer.write(data)
                pending_drain += len(data)
                if pending_drain >= DRAIN_BUFFER_SIZE:
                    await writer.drain()
                    pending_drain = 0
        except Exception:
            pass
        finally:
            stat_conn(-1)
            writer.close()

class Direct(BaseProtocol):
    pass

class Trojan(BaseProtocol):
    async def guess(self, reader, users, **kw):
        header = await transport.read(reader, 56)
        if users:
            for user in users:
                if hashlib.sha224(user).hexdigest().encode() == header:
                    return user
        else:
            if hashlib.sha224(b'').hexdigest().encode() == header:
                return True
        transport.rollback(reader, header)
    async def accept(self, reader, user, **kw):
        assert await transport.read_exactly(reader, 2) == b'\x0d\x0a'
        if (await transport.read_exactly(reader, 1))[0] != 1:
            raise Exception('Connection closed')
        host_name, port, _ = await socks_address_stream(reader, (await transport.read_exactly(reader, 1))[0])
        assert await transport.read_exactly(reader, 2) == b'\x0d\x0a'
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        toauth = hashlib.sha224(rauth or b'').hexdigest().encode()
        writer_remote.write(toauth + b'\x0d\x0a\x01\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + b'\x0d\x0a')

class SSR(BaseProtocol):
    async def guess(self, reader, users, **kw):
        if users:
            header = await transport.read(reader, max(len(i) for i in users))
            transport.rollback(reader, header)
            user = next(filter(lambda x: x == header[:len(x)], users), None)
            if user is None:
                return
            await transport.read_exactly(reader, len(user))
            return user
        header = await transport.read(reader, 1)
        transport.rollback(reader, header)
        return header[0] in (1, 3, 4, 17, 19, 20)
    async def accept(self, reader, user, **kw):
        host_name, port, data = await socks_address_stream(reader, (await transport.read_exactly(reader, 1))[0])
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        writer_remote.write(rauth + b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))

class SS(SSR):
    def patch_ota_reader(self, cipher, reader):
        chunk_id, data_len, _buffer = 0, None, bytearray()
        def decrypt(s):
            nonlocal chunk_id, data_len
            _buffer.extend(s)
            ret = bytearray()
            while 1:
                if data_len is None:
                    if len(_buffer) < 2:
                        break
                    data_len = int.from_bytes(_buffer[:2], 'big')
                    del _buffer[:2]
                else:
                    if len(_buffer) < 10+data_len:
                        break
                    data = _buffer[10:10+data_len]
                    assert _buffer[:10] == hmac.new(cipher.iv+chunk_id.to_bytes(4, 'big'), data, hashlib.sha1).digest()[:10]
                    del _buffer[:10+data_len]
                    data_len = None
                    chunk_id += 1
                    ret.extend(data)
            return bytes(ret)
        reader.decrypts.append(decrypt)
        buffered = transport.take_buffer(reader)
        if buffered:
            transport.prepend(reader, decrypt(buffered))
    def patch_ota_writer(self, cipher, writer):
        chunk_id = 0
        def write(data, o=writer.write):
            nonlocal chunk_id
            if not data: return
            checksum = hmac.new(cipher.iv+chunk_id.to_bytes(4, 'big'), data, hashlib.sha1).digest()
            chunk_id += 1
            return o(len(data).to_bytes(2, 'big') + checksum[:10] + data)
        writer.write = write
    async def accept(self, reader, user, reader_cipher, **kw):
        header = await transport.read_exactly(reader, 1)
        ota = (header[0] & 0x10 == 0x10)
        host_name, port, data = await socks_address_stream(reader, header[0])
        assert ota or not reader_cipher or not reader_cipher.ota, 'SS client must support OTA'
        if ota and reader_cipher:
            checksum = hmac.new(reader_cipher.iv+reader_cipher.key, header+data, hashlib.sha1).digest()
            assert checksum[:10] == await transport.read_exactly(reader, 10), 'Unknown OTA checksum'
            self.patch_ota_reader(reader_cipher, reader)
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, writer_cipher_r, **kw):
        writer_remote.write(rauth)
        if writer_cipher_r and writer_cipher_r.ota:
            rdata = b'\x13' + packstr(host_name.encode()) + port.to_bytes(2, 'big')
            checksum = hmac.new(writer_cipher_r.iv+writer_cipher_r.key, rdata, hashlib.sha1).digest()
            writer_remote.write(rdata + checksum[:10])
            self.patch_ota_writer(writer_cipher_r, writer_remote)
        else:
            writer_remote.write(b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
    def udp_accept(self, data, users, **kw):
        reader = io.BytesIO(data)
        user = True
        if users:
            user = next(filter(lambda i: data[:len(i)]==i, users), None)
            if user is None:
                return
            reader.read(len(user))
        n = reader.read(1)[0]
        if n not in (1, 3, 4):
            return
        host_name, port = socks_address(reader, n)
        return user, host_name, port, reader.read()
    def udp_unpack(self, data):
        reader = io.BytesIO(data)
        n = reader.read(1)[0]
        host_name, port = socks_address(reader, n)
        return reader.read()
    def udp_pack(self, host_name, port, data):
        try:
            return b'\x01' + socket.inet_aton(host_name) + port.to_bytes(2, 'big') + data
        except Exception:
            pass
        return b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data
    def udp_connect(self, rauth, host_name, port, data, **kw):
        return rauth + b'\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data

class Socks4(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await transport.read(reader, 1)
        if header == b'\x04':
            return True
        transport.rollback(reader, header)
    async def accept(self, reader, user, writer, users, authtable, **kw):
        assert await transport.read_exactly(reader, 1) == b'\x01'
        port = int.from_bytes(await transport.read_exactly(reader, 2), 'big')
        ip = await transport.read_exactly(reader, 4)
        userid = (await transport.read_until(reader, b'\x00'))[:-1]
        user = authtable.authed()
        if users:
            if userid in users:
                user = userid
            elif not user:
                raise Exception(f'Unauthorized SOCKS {userid}')
            authtable.set_authed(user)
        writer.write(b'\x00\x5a' + port.to_bytes(2, 'big') + ip)
        return user, socket.inet_ntoa(ip), port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        loop = asyncio.get_running_loop()
        ip = socket.inet_aton((await loop.getaddrinfo(host_name, port, family=socket.AF_INET))[0][4][0])
        writer_remote.write(b'\x04\x01' + port.to_bytes(2, 'big') + ip + rauth + b'\x00')
        assert await transport.read_exactly(reader_remote, 2) == b'\x00\x5a'
        await transport.read_exactly(reader_remote, 6)

class Socks5(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await transport.read(reader, 1)
        if header == b'\x05':
            return True
        transport.rollback(reader, header)
    async def accept(self, reader, user, writer, users, authtable, **kw):
        methods = await transport.read_exactly(reader, (await transport.read_exactly(reader, 1))[0])
        user = authtable.authed()
        if users and (not user or b'\x00' not in methods):
            if b'\x02' not in methods:
                raise Exception(f'Unauthorized SOCKS')
            writer.write(b'\x05\x02')
            assert (await transport.read_exactly(reader, 1))[0] == 1, 'Unknown SOCKS auth'
            u = await transport.read_exactly(reader, (await transport.read_exactly(reader, 1))[0])
            p = await transport.read_exactly(reader, (await transport.read_exactly(reader, 1))[0])
            user = u+b':'+p
            if user not in users:
                raise Exception(f'Unauthorized SOCKS {u}:{p}')
            writer.write(b'\x01\x00')
        elif users and not user:
            raise Exception(f'Unauthorized SOCKS')
        else:
            writer.write(b'\x05\x00')
        if users:
            authtable.set_authed(user)
        assert await transport.read_exactly(reader, 3) == b'\x05\x01\x00', 'Unknown SOCKS protocol'
        header = await transport.read_exactly(reader, 1)
        host_name, port, data = await socks_address_stream(reader, header[0])
        writer.write(b'\x05\x00\x00' + header + data)
        return user, host_name, port
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        if rauth:
            writer_remote.write(b'\x05\x01\x02')
            assert await transport.read_exactly(reader_remote, 2) == b'\x05\x02'
            writer_remote.write(b'\x01' + b''.join(packstr(i) for i in rauth.split(b':', 1)))
            assert await transport.read_exactly(reader_remote, 2) == b'\x01\x00', 'Unknown SOCKS auth'
        else:
            writer_remote.write(b'\x05\x01\x00')
            assert await transport.read_exactly(reader_remote, 2) == b'\x05\x00'
        writer_remote.write(b'\x05\x01\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big'))
        assert await transport.read_exactly(reader_remote, 3) == b'\x05\x00\x00'
        header = (await transport.read_exactly(reader_remote, 1))[0]
        await transport.read_exactly(reader_remote, 6 if header == 1 else (18 if header == 4 else (await transport.read_exactly(reader_remote, 1))[0]+2))
    def udp_accept(self, data, **kw):
        reader = io.BytesIO(data)
        if reader.read(3) != b'\x00\x00\x00':
            return
        n = reader.read(1)[0]
        if n not in (1, 3, 4):
            return
        host_name, port = socks_address(reader, n)
        return True, host_name, port, reader.read()
    def udp_connect(self, rauth, host_name, port, data, **kw):
        return b'\x00\x00\x00\x03' + packstr(host_name.encode()) + port.to_bytes(2, 'big') + data

class HTTP(BaseProtocol):
    async def guess(self, reader, **kw):
        header = await transport.read(reader, 4)
        transport.rollback(reader, header)
        return header in (b'GET ', b'HEAD', b'POST', b'PUT ', b'DELE', b'CONN', b'OPTI', b'TRAC', b'PATC')
    async def accept(self, reader, user, writer, **kw):
        lines = await transport.read_until(reader, b'\r\n\r\n')
        method, path, ver, filtered_headers, host, proxy_authorization, _ = parse_http_request_head(lines[:-4])
        async def reply(code, message, body=None, wait=False):
            writer.write(message)
            if body:
                writer.write(body)
            if wait:
                await drain_if_needed(writer, force=True)
        return await self.http_accept(user, method, path, None, ver, filtered_headers, host, proxy_authorization, reply, **kw)
    async def http_accept(self, user, method, path, authority, ver, filtered_headers, host, pauth, reply, authtable, users, httpget=None, **kw):
        url = urllib.parse.urlparse(path)
        if method == 'GET' and not url.hostname:
            for path, text in (httpget.items() if httpget else ()):
                if path == url.path:
                    user = next(filter(lambda x: x.decode()==url.query, users), None) if users else True
                    if user:
                        if users:
                            authtable.set_authed(user)
                        if type(text) is str:
                            text = (text % dict(host=host)).encode()
                        await reply(200, f'{ver} 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nCache-Control: max-age=900\r\nContent-Length: {len(text)}\r\n\r\n'.encode(), text, True)
                        raise Exception('Connection closed')
            raise Exception(f'404 {method} {url.path}')
        if users:
            user = authtable.authed()
            if not user:
                user = next(filter(lambda i: ('Basic '+base64.b64encode(i).decode()) == pauth, users), None)
                if user is None:
                    await reply(407, f'{ver} 407 Proxy Authentication Required\r\nConnection: close\r\nProxy-Authenticate: Basic realm="simple"\r\n\r\n'.encode(), wait=True)
                    raise Exception('Unauthorized HTTP')
            authtable.set_authed(user)
        if method == 'CONNECT':
            host_name, port = netloc_split(authority or path)
            return user, host_name, port, lambda writer: reply(200, f'{ver} 200 Connection established\r\nConnection: close\r\n\r\n'.encode())
        else:
            host_name, port = netloc_split(url.netloc or host, default_port=80)
            newpath = url._replace(netloc='', scheme='').geturl()
            request_head = (
                f'{method} {newpath} {ver}\r\n'.encode() +
                filtered_headers +
                b'\r\n\r\n'
            )
            async def connected(writer):
                writer.write(request_head)
                return True
            return user, host_name, port, connected
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, **kw):
        writer_remote.write(f'CONNECT {host_name}:{port} HTTP/1.1\r\nHost: {host_name}:{port}'.encode() + (b'\r\nProxy-Authorization: Basic '+base64.b64encode(rauth) if rauth else b'') + b'\r\n\r\n')
        await transport.read_until(reader_remote, b'\r\n\r\n')
    async def http_channel(self, reader, writer, stat_bytes, stat_conn):
        try:
            stat_conn(1)
            pending_drain = 0
            while not reader.at_eof() and not writer.is_closing():
                data = await reader.read(65536)
                if not data:
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
        except Exception:
            pass
        finally:
            stat_conn(-1)
            writer.close()

class HTTPOnly(HTTP):
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        buffer = bytearray()
        host_name_pattern = re.compile(br'\r\nHost: ([^\r\n]+)\r\n', re.I)
        def write(data, o=writer_remote.write):
            if not data: return
            buffer.extend(data)
            pos = buffer.find(b'\r\n\r\n')
            if pos != -1:
                request_head = buffer[:pos]
                request_line = request_head.split(b'\r\n', 1)[0]
                header = HTTP_METHOD_LINE.match(request_line)
                host = host_name_pattern.search(b'\r\n' + request_head + b'\r\n')
                if not header or not host:
                    writer_remote.close()
                    raise Exception('Unknown HTTP header for protocol HTTPOnly')
                method, path, ver = header.groups()
                host_value = host.group(1)
                data = method + b' http://' + host_value + path + b' ' + ver + b'\r\nHost: ' + host_value + (b'\r\nProxy-Authorization: Basic ' + base64.b64encode(rauth) if rauth else b'') + b'\r\n\r\n' + buffer[pos+4:]
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
        headers = {i.decode().lower():j.decode() for i,j in headers}
        lines = '\r\n'.join(i for i in headers if not i.startswith('proxy-') and not i.startswith(':'))
        async def reply(code, message, body=None, wait=False):
            writer.send_headers(((':status', str(code)),))
            if body:
                writer.write(body)
            if wait:
                await drain_if_needed(writer, force=True)
        return await self.http_accept(user, headers[':method'], headers[':path'], headers[':authority'], '2.0', lines, '', headers.get('proxy-authorization'), reply, **kw)
    async def connect(self, reader_remote, writer_remote, rauth, host_name, port, myhost, **kw):
        headers = [(':method', 'CONNECT'), (':scheme', 'https'), (':path', '/'),
                   (':authority', f'{host_name}:{port}')]
        if rauth:
            headers.append(('proxy-authorization', 'Basic '+base64.b64encode(rauth)))
        writer_remote.send_headers(headers)

class H3(H2):
    pass


class HTTPAdmin(HTTP):
    async def accept(self, reader, user, writer, **kw):
        lines = await transport.read_until(reader, b'\r\n\r\n')
        method, path, ver, filtered_headers, _, _, _ = parse_http_request_head(lines[:-4])
        headers, lines = decode_http_header_block(filtered_headers)
        async def reply(code, message, body=None, wait=False):
            writer.write(message)
            if body:
                writer.write(body)
            if wait:
                await drain_if_needed(writer, force=True)

        content_length = int(headers.get('Content-Length','0'))
        content = ''
        if content_length > 0:
            content = await transport.read_exactly(reader, content_length)

        url = urllib.parse.urlparse(path)
        if url.hostname is not None:
            raise Exception(f'HTTP Admin Unsupported hostname')
        if method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            for path, handler in admin.httpget.items():
                if path == url.path:
                    await handler(reply=reply, ver=ver, method=method, headers=headers, lines=lines, content=content)
                    raise Exception('Connection closed')
            raise Exception(f'404 {method} {url.path}')
        raise Exception(f'405 {method} not allowed')
        

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
                assert len(buf) == 16
                return socket.inet_ntoa(buf[4:8]), int.from_bytes(buf[2:4], 'big')
            else:
                buf = sock.getsockopt(SOL_IPV6, SO_ORIGINAL_DST, 28)
                assert len(buf) == 28
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
        data_len, mask_key, opcode, _buffer = None, None, None, bytearray()
        raw_write = writer.write
        def write_frame(opcode, payload=b''):
            plen = len(payload)
            second = bytes([(plen | 0x80) if masked else plen]) if plen < 126 else \
                     (b'\xfe' if masked else b'\x7e') + plen.to_bytes(2, 'big') if plen < 65536 else \
                     (b'\xff' if masked else b'\x7f') + plen.to_bytes(8, 'big')
            if masked:
                local_mask_key = os.urandom(4)
                payload = xor_mask_bytes(payload, local_mask_key)
                return raw_write(bytes([0x80 | opcode]) + second + local_mask_key + payload)
            return raw_write(bytes([0x80 | opcode]) + second + payload)
        def feed_data(s, o=reader.feed_data):
            nonlocal data_len, mask_key, opcode
            _buffer.extend(s)
            while 1:
                if data_len is None:
                    if len(_buffer) < 2:
                        break
                    opcode = _buffer[0] & 0x0f
                    required = 2 + (4 if _buffer[1]&128 else 0)
                    p = _buffer[1] & 127
                    required += 2 if p == 126 else 8 if p == 127 else 0
                    if len(_buffer) < required:
                        break
                    data_len = int.from_bytes(_buffer[2:4], 'big') if p == 126 else int.from_bytes(_buffer[2:10], 'big') if p == 127 else p
                    mask_key = _buffer[required-4:required] if _buffer[1]&128 else None
                    del _buffer[:required]
                else:
                    if len(_buffer) < data_len:
                        break
                    data = _buffer[:data_len]
                    if mask_key:
                        data = xor_mask_bytes(data, mask_key)
                    del _buffer[:data_len]
                    data_len = None
                    if opcode == 0x9:  # ping
                        write_frame(0xA, data)
                    elif opcode in (0x8, 0xa):  # close, pong
                        pass
                    else:
                        o(data)
        reader.feed_data = feed_data
        buffered = transport.take_buffer(reader)
        if buffered:
            feed_data(buffered)
        def write(data, o=writer.write):
            if not data: return
            return write_frame(0x2, data)
        writer.write = write
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

def sslwrap(reader, writer, sslcontext, server_side=False, server_hostname=None, verbose=None):
    if sslcontext is None:
        return reader, writer
    ssl_reader = asyncio.StreamReader()
    class Protocol(asyncio.Protocol):
        def data_received(self, data):
            ssl_reader.feed_data(data)
        def eof_received(self):
            ssl_reader.feed_eof()
        def connection_lost(self, exc):
            ssl_reader.feed_eof()
    ssl = asyncio.sslproto.SSLProtocol(asyncio.get_running_loop(), Protocol(), sslcontext, None, server_side, server_hostname, False)
    class Transport(asyncio.Transport):
        _paused = False
        def __init__(self, extra={}):
            self._extra = extra
            self.closed = False
        def write(self, data):
            if data and not self.closed:
                writer.write(data)
        def close(self):
            self.closed = True
            writer.close()
        def _force_close(self, exc):
            if not self.closed:
                (verbose or print)(f'{exc} from {writer.get_extra_info("peername")[0]}')
            ssl._app_transport._closed = True
            self.close()
        def abort(self):
            self.close()
    ssl.connection_made(Transport())
    async def channel():
        read_size=65536
        buffer=None
        if hasattr(ssl,'get_buffer'):
            buffer=ssl.get_buffer(read_size)
        try:
            while not reader.at_eof() and not ssl._app_transport._closed:
                data = await reader.read(read_size)
                if not data:
                    break
                if buffer!=None:
                    data_len=len(data)
                    buffer[:data_len]=data
                    ssl.buffer_updated(data_len)
                else:
                    ssl.data_received(data)
        except Exception:
            pass
        finally:
            ssl.eof_received()
    create_task(channel())
    class Writer():
        def get_extra_info(self, key):
            return writer.get_extra_info(key)
        def write(self, data):
            ssl._app_transport.write(data)
        def drain(self):
            return writer.drain()
        def is_closing(self):
            return ssl._app_transport._closed
        def close(self):
            if not ssl._app_transport._closed:
                ssl._app_transport.close()
    return ssl_reader, Writer()
