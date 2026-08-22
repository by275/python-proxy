import argparse, time, re, asyncio, functools, base64, random, urllib.parse, socket, sys, collections, contextlib
from asyncio import create_task
from . import proto
from . import admin
from . import relay
from .runtime import TaskRegistry
from . import transport
from .config import ProxyConfig
from .errors import require

from .__doc__ import *

SOCKET_TIMEOUT = transport.DEFAULT_TIMEOUT
UDP_LIMIT = 30
DUMMY = lambda s: s

class AuthTable(object):
    def __init__(self, remote_ip, authtime):
        self.remote_ip = remote_ip
        self.authtime = authtime
        self._auth = {}
        self._user = {}
    def authed(self):
        if time.time() - self._auth.get(self.remote_ip, 0) <= self.authtime:
            return self._user[self.remote_ip]
    def set_authed(self, user):
        self._auth[self.remote_ip] = time.time()
        self._user[self.remote_ip] = user

async def prepare_ciphers(cipher, reader, writer, bind=None, server_side=True):
    if cipher:
        cipher.pdecrypt = cipher.pdecrypt2 = cipher.pencrypt = cipher.pencrypt2 = DUMMY
        for plugin in cipher.plugins:
            if server_side:
                await plugin.init_server_data(reader, writer, cipher, bind)
            else:
                await plugin.init_client_data(reader, writer, cipher)
            plugin.add_cipher(cipher)
        return cipher(reader, writer, cipher.pdecrypt, cipher.pdecrypt2, cipher.pencrypt, cipher.pencrypt2)
    else:
        return None, None


relay_with_taskgroup = relay.relay_with_taskgroup


def _create_task(awaitable, registry=None):
    return registry.create_task(awaitable) if registry is not None else create_task(awaitable)

def schedule(rserver, salgorithm, host_name, port):
    filter_cond = lambda o: o.alive and o.match_rule(host_name, port)
    if salgorithm == 'fa':
        return next(filter(filter_cond, rserver), None)
    elif salgorithm == 'rr':
        for i, roption in enumerate(rserver):
            if filter_cond(roption):
                rserver.append(rserver.pop(i))
                return roption
    elif salgorithm == 'rc':
        filters = [i for i in rserver if filter_cond(i)]
        return random.choice(filters) if filters else None
    elif salgorithm == 'lc':
        return min(filter(filter_cond, rserver), default=None, key=lambda i: i.connections)
    else:
        raise Exception('Unknown scheduling algorithm') #Unreachable

async def stream_handler(reader, writer, unix, lbind, protos, rserver, cipher, sslserver, debug=0, authtime=86400*30, block=None, salgorithm='fa', verbose=DUMMY, modstat=lambda u,r,h:lambda i:DUMMY, task_registry=None, **kwargs):
    try:
        reader, writer = proto.sslwrap(reader, writer, sslserver, True, None, verbose)
        if unix:
            remote_ip, server_ip, remote_text = 'local', None, 'unix_local'
        else:
            peername = writer.get_extra_info('peername')
            remote_ip, remote_port, *_ = peername if peername else ('unknow_remote_ip','unknow_remote_port')
            server_ip = writer.get_extra_info('sockname')[0]
            remote_text = f'{remote_ip}:{remote_port}'
        local_addr = None if server_ip in ('127.0.0.1', '::1', None) else (server_ip, 0)
        reader_cipher, _ = await prepare_ciphers(cipher, reader, writer, server_side=False)
        lproto, user, host_name, port, client_connected = await proto.accept(protos, reader=reader, writer=writer, authtable=AuthTable(remote_ip, authtime), reader_cipher=reader_cipher, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name == 'echo':
            _create_task(lproto.channel(reader, writer, DUMMY, DUMMY), task_registry)
        elif host_name == 'empty':
            _create_task(lproto.channel(reader, writer, None, DUMMY), task_registry)
        elif block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        else:
            roption = schedule(rserver, salgorithm, host_name, port) or DIRECT
            verbose(f'{lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            try:
                reader_remote, writer_remote = await roption.open_connection(host_name, port, local_addr, lbind)
            except asyncio.TimeoutError:
                raise Exception(f'Connection timeout {roption.bind}')
            try:
                reader_remote, writer_remote = await roption.prepare_connection(reader_remote, writer_remote, host_name, port)
                use_http = (await client_connected(writer_remote)) if client_connected else None
            except Exception:
                writer_remote.close()
                raise Exception('Unknown remote protocol')
            m = modstat(user, remote_ip, host_name)
            lchannel = lproto.http_channel if use_http else lproto.channel
            await relay_with_taskgroup(
                lproto.channel(reader_remote, writer, m(2+roption.direct), m(4+roption.direct)),
                lchannel(reader, writer_remote, m(roption.direct), roption.connection_change),
            )
    except Exception as ex:
        if not isinstance(ex, asyncio.TimeoutError) and not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')
        try: writer.close()
        except Exception: pass
        if debug:
            raise

async def datagram_handler(writer, data, addr, protos, urserver, block, cipher, salgorithm, verbose=DUMMY, **kwargs):
    try:
        remote_ip, remote_port, *_ = addr
        remote_text = f'{remote_ip}:{remote_port}'
        data = cipher.datagram.decrypt(data) if cipher else data
        lproto, user, host_name, port, data = proto.udp_accept(protos, data, sock=writer.get_extra_info('socket'), **kwargs)
        if host_name == 'echo':
            writer.sendto(data, addr)
        elif host_name == 'empty':
            pass
        elif block and block(host_name):
            raise Exception('BLOCK ' + host_name)
        else:
            roption = schedule(urserver, salgorithm, host_name, port) or DIRECT
            verbose(f'UDP {lproto.name} {remote_text}{roption.logtext(host_name, port)}')
            data = roption.udp_prepare_connection(host_name, port, data)
            def reply(rdata):
                rdata = lproto.udp_pack(host_name, port, rdata)
                writer.sendto(cipher.datagram.encrypt(rdata) if cipher else rdata, addr)
            await roption.udp_open_connection(host_name, port, data, addr, reply)
    except Exception as ex:
        if not str(ex).startswith('Connection closed'):
            verbose(f'{str(ex) or "Unsupported protocol"} from {remote_ip}')

async def check_server_alive(interval, rserver, verbose):
    while True:
        await asyncio.sleep(interval)
        for remote in rserver:
            if type(remote) is ProxyDirect:
                continue
            try:
                _, writer = await remote.open_connection(None, None, None, None, timeout=3)
            except asyncio.CancelledError as ex:
                return
            except Exception as ex:
                if remote.alive:
                    verbose(f'{remote.rproto.name} {remote.bind} -> OFFLINE')
                    remote.alive = False
                continue
            if not remote.alive:
                verbose(f'{remote.rproto.name} {remote.bind} -> ONLINE')
                remote.alive = True
            try:
                if isinstance(remote, ProxyBackward):
                    writer.write(b'\x00')
                writer.close()
            except Exception:
                pass

class ProxyDirect(object):
    def __init__(self, lbind=None):
        self.bind = 'DIRECT'
        self.lbind = lbind
        self.unix = False
        self.alive = True
        self.connections = 0
        self.udpmap = {}
        self.udp_lru = collections.OrderedDict()
        self.task_registry = TaskRegistry()
    @property
    def direct(self):
        return type(self) is ProxyDirect
    def logtext(self, host, port):
        return '' if host == 'tunnel' else f' -> {host}:{port}'
    def match_rule(self, host, port):
        return True
    def connection_change(self, delta):
        self.connections += delta
    def udp_packet_unpack(self, data):
        return data
    def destination(self, host, port):
        return host, port
    def udp_touch(self, addr, prot):
        self.udpmap[addr] = prot
        self.udp_lru[addr] = prot
        self.udp_lru.move_to_end(addr)
    def udp_discard(self, addr):
        self.udp_lru.pop(addr, None)
        prot = self.udpmap.pop(addr, None)
        if prot is not None:
            self.connection_change(-1)
        return prot
    def udp_evict_if_needed(self):
        if len(self.udp_lru) < UDP_LIMIT:
            return
        addr = next(iter(self.udp_lru))
        prot = self.udp_discard(addr)
        if prot.transport:
            prot.transport.close()
    async def udp_open_connection(self, host, port, data, addr, reply):
        class Protocol(asyncio.DatagramProtocol):
            def __init__(prot, data):
                prot.databuf = [data]
                prot.transport = None
                self.udp_touch(addr, prot)
            def connection_made(prot, transport):
                prot.transport = transport
                for data in prot.databuf:
                    transport.sendto(data)
                prot.databuf.clear()
                self.udp_touch(addr, prot)
            def new_data_arrived(prot, data):
                if prot.transport:
                    prot.transport.sendto(data)
                else:
                    prot.databuf.append(data)
                self.udp_touch(addr, prot)
            def datagram_received(prot, data, addr):
                data = self.udp_packet_unpack(data)
                reply(data)
                self.udp_touch(addr, prot)
            def connection_lost(prot, exc):
                self.udp_discard(addr)
        if addr in self.udpmap:
            prot = self.udpmap[addr]
            prot.new_data_arrived(data)
        else:
            self.connection_change(1)
            self.udp_evict_if_needed()
            prot = lambda: Protocol(data)
            remote = self.destination(host, port)
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(prot, remote_addr=remote)

    def close(self):
        self.task_registry.cancel_all()
        for prot in tuple(self.udpmap.values()):
            if getattr(prot, 'transport', None):
                prot.transport.close()

    async def wait_closed(self):
        await self.task_registry.wait_closed()

    async def aclose(self):
        self.close()
        await self.wait_closed()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()
    def udp_prepare_connection(self, host, port, data):
        return data
    def wait_open_connection(self, host, port, local_addr, family):
        return asyncio.open_connection(host=host, port=port, local_addr=local_addr, family=family)
    async def open_connection(self, host, port, local_addr, lbind, timeout=SOCKET_TIMEOUT):
        try:
            local_addr = local_addr if self.lbind == 'in' else (self.lbind, 0) if self.lbind else \
                         local_addr if lbind == 'in' else (lbind, 0) if lbind else None
            family = 0 if local_addr is None else socket.AF_INET6 if ':' in local_addr[0] else socket.AF_INET
            wait = self.wait_open_connection(host, port, local_addr, family)
            reader, writer = await asyncio.wait_for(wait, timeout=timeout)
        except Exception as ex:
            raise
        return reader, writer
    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        return reader_remote, writer_remote
    async def tcp_connect(self, host, port, local_addr=None, lbind=None):
        reader, writer = await self.open_connection(host, port, local_addr, lbind)
        try:
            reader, writer = await self.prepare_connection(reader, writer, host, port)
        except Exception:
            writer.close()
            raise
        return reader, writer
    async def udp_sendto(self, host, port, data, answer_cb, local_addr=None):
        if local_addr is None:
            local_addr = random.randrange(2**32)
        data = self.udp_prepare_connection(host, port, data)
        await self.udp_open_connection(host, port, data, local_addr, answer_cb)
DIRECT = ProxyDirect()

class ProxySimple(ProxyDirect):
    def __init__(self, jump, protos, cipher, users, rule, bind,
                  host_name, port, unix, lbind, sslclient, sslserver):
        super().__init__(lbind)
        self.protos = protos
        self.cipher = cipher
        self.users = users
        self.rule = compile_rule(rule) if rule else None
        self.bind = bind
        self.host_name = host_name
        self.port = port
        self.unix = unix
        self.sslclient = sslclient
        self.sslserver = sslserver
        self.jump = jump
    def logtext(self, host, port):
        return f' -> {self.rproto.name+("+ssl" if self.sslclient else "")} {self.bind}' + self.jump.logtext(host, port)
    def match_rule(self, host, port):
        return (self.rule is None) or self.rule(host) or self.rule(str(port))
    @property
    def rproto(self):
        return self.protos[0]
    @property
    def auth(self):
        return self.users[0] if self.users else b''
    def udp_packet_unpack(self, data):
        data = self.cipher.datagram.decrypt(data) if self.cipher else data
        return self.jump.udp_packet_unpack(self.rproto.udp_unpack(data))
    def destination(self, host, port):
        return self.host_name, self.port
    def udp_prepare_connection(self, host, port, data):
        data = self.jump.udp_prepare_connection(host, port, data)
        whost, wport = self.jump.destination(host, port)
        data = self.rproto.udp_connect(rauth=self.auth, host_name=whost, port=wport, data=data)
        if self.cipher:
            data = self.cipher.datagram.encrypt(data)
        return data
    def udp_start_server(self, args):
        class Protocol(asyncio.DatagramProtocol):
            def connection_made(prot, transport):
                prot.transport = transport
            def datagram_received(prot, data, addr):
                self.task_registry.create_task(
                    datagram_handler(prot.transport, data, addr, **vars(self), **args)
                )
        loop = asyncio.get_running_loop()
        return loop.create_datagram_endpoint(Protocol, local_addr=(self.host_name, self.port))
    def wait_open_connection(self, host, port, local_addr, family):
        if self.unix:
            return asyncio.open_unix_connection(path=self.bind)
        else:
            return asyncio.open_connection(host=self.host_name, port=self.port, local_addr=local_addr, family=family)
    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        reader_remote, writer_remote = proto.sslwrap(reader_remote, writer_remote, self.sslclient, False, self.host_name)
        _, writer_cipher_r = await prepare_ciphers(self.cipher, reader_remote, writer_remote, self.bind)
        whost, wport = self.jump.destination(host, port)
        await self.rproto.connect(reader_remote=reader_remote, writer_remote=writer_remote, rauth=self.auth, host_name=whost, port=wport, writer_cipher_r=writer_cipher_r, myhost=self.host_name, sock=writer_remote.get_extra_info('socket'))
        return await self.jump.prepare_connection(reader_remote, writer_remote, host, port)
    def start_server(self, args, stream_handler=stream_handler):
        handler = functools.partial(stream_handler, **vars(self), **args)
        if self.unix:
            return asyncio.start_unix_server(handler, path=self.bind)
        else:
            return asyncio.start_server(handler, host=self.host_name, port=self.port, reuse_port=args.get('ruport'))

class ProxyBackward(ProxySimple):
    def __init__(self, backward, backward_num, **kw):
        super().__init__(**kw)
        self.backward = backward
        self.server = backward
        while type(self.server.jump) != ProxyDirect:
            self.server = self.server.jump
        self.backward_num = backward_num
        self.closed = False
        self.writers = set()
        self.tasks = self.task_registry
        self.server.task_registry = self.task_registry
        self.conn = asyncio.Queue()
    async def watch_connection(self, reader, writer):
        try:
            data = await transport.read(reader, 1, timeout=None)
            if data:
                transport.rollback(reader, data)
        except Exception:
            pass
        finally:
            if reader.at_eof() and not writer.is_closing():
                writer.close()
    async def wait_open_connection(self, *args):
        while True:
            reader, writer, watcher = await self.conn.get()
            watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watcher
            if not reader.at_eof() and not writer.is_closing():
                return reader, writer
            writer.close()
    def close(self):
        self.closed = True
        if hasattr(self.tasks, 'cancel_all'):
            self.tasks.cancel_all()
        else:
            for task in tuple(self.tasks):
                task.cancel()
        for writer in self.writers:
            try:
                writer.close()
            except Exception:
                pass

    async def wait_closed(self):
        if hasattr(self.tasks, 'wait_closed'):
            await self.tasks.wait_closed()
        else:
            tasks = tuple(self.tasks)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self.tasks.clear()

    async def aclose(self):
        self.close()
        await self.wait_closed()
    async def start_server(self, args, stream_handler=stream_handler):
        handler = functools.partial(stream_handler, **vars(self.server), **args)
        for _ in range(self.backward_num):
            self.tasks.create_task(self.start_server_run(handler))
        return self
    async def start_server_run(self, handler):
        errwait = 0
        while not self.closed:
            wait = self.backward.open_connection(self.host_name, self.port, self.lbind, None)
            try:
                reader, writer = await asyncio.wait_for(wait, timeout=SOCKET_TIMEOUT)
                if self.closed:
                    writer.close()
                    break
                if isinstance(self.server, ProxyQUIC):
                    writer.write(b'\x01')
                writer.write(self.server.auth)
                self.writers.add(writer)
                try:
                    data = await transport.read_exactly(reader, 1)
                except asyncio.TimeoutError:
                    data = None
                if data and data[0] != 0:
                    transport.rollback(reader, data)
                    self.tasks.create_task(handler(reader, writer))
                else:
                    writer.close()
                errwait = 0
                self.writers.discard(writer)
                writer = None
            except Exception as ex:
                try:
                    writer.close()
                except Exception:
                    pass
                if not self.closed:
                    await asyncio.sleep(errwait)
                    errwait = min(errwait*1.3 + 0.1, 30)
    def start_backward_client(self, args):
        async def handler(reader, writer, **kw):
            auth = self.server.auth
            if isinstance(self.server, ProxyQUIC):
                auth = b'\x01'+auth
            if auth:
                try:
                    require(auth == (await transport.read_exactly(reader, len(auth))))
                except Exception:
                    return
            await self.conn.put(
                (reader, writer, self.tasks.create_task(self.watch_connection(reader, writer)))
            )
        return self.backward.start_server(args, handler)


def compile_rule(filename):
    if filename.startswith("{") and filename.endswith("}"):
        return re.compile(filename[1:-1]).match
    with open(filename) as f:
        return re.compile('(:?'+''.join('|'.join(i.strip() for i in f if i.strip() and not i.startswith('#')))+')$').match

def split_uri_jumps(uri_jumps):
    parts = []
    start = 0
    for match in re.finditer(r'__(?=[A-Za-z][A-Za-z0-9+.-]*://)', uri_jumps):
        parts.append(uri_jumps[start:match.start()])
        start = match.end()
    parts.append(uri_jumps[start:])
    return parts

def proxies_by_uri(uri_jumps):
    jump = DIRECT
    for uri in reversed(split_uri_jumps(uri_jumps)):
        jump = proxy_by_uri(uri, jump)
    return jump

sslcontexts = []

def proxy_by_uri(uri, jump):
    scheme, _, uri = uri.partition('://')
    url = urllib.parse.urlparse('s://'+uri)
    rawprotos = [i.lower() for i in scheme.split('+')]
    err_str, protos = proto.get_protos(rawprotos)
    protonames = [i.name for i in protos]
    if err_str:
        raise argparse.ArgumentTypeError(err_str)
    if 'ssl' in rawprotos or 'secure' in rawprotos:
        import ssl
        sslserver = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if 'ssl' in rawprotos:
            sslclient.check_hostname = False
            sslclient.verify_mode = ssl.CERT_NONE
        sslcontexts.append(sslserver)
        sslcontexts.append(sslclient)
    else:
        sslserver = sslclient = None
    if 'quic' in rawprotos or 'h3' in protonames:
        try:
            import ssl, aioquic.quic.configuration
        except Exception:
            raise Exception('Missing library: "pip3 install aioquic"')
        quicserver = aioquic.quic.configuration.QuicConfiguration(is_client=False, max_stream_data=2**60, max_data=2**60, idle_timeout=SOCKET_TIMEOUT)
        quicclient = aioquic.quic.configuration.QuicConfiguration(max_stream_data=2**60, max_data=2**60, idle_timeout=SOCKET_TIMEOUT*5)
        quicclient.verify_mode = ssl.CERT_NONE
        sslcontexts.append(quicserver)
        sslcontexts.append(quicclient)
    if 'h2' in rawprotos:
        try:
            import h2
        except Exception:
            raise Exception('Missing library: "pip3 install h2"')
    urlpath, _, plugins = url.path.partition(',')
    urlpath, _, lbind = urlpath.partition('@')
    plugins = plugins.split(',') if plugins else None
    cipher, _, loc = url.netloc.rpartition('@')
    if cipher:
        from .cipher import get_cipher
        if ':' not in cipher:
            try:
                cipher = base64.b64decode(cipher).decode()
            except Exception:
                pass
            if ':' not in cipher:
                raise argparse.ArgumentTypeError('userinfo must be "cipher:key"')
        err_str, cipher = get_cipher(cipher)
        if err_str:
            raise argparse.ArgumentTypeError(err_str)
        if plugins:
            from .plugin import get_plugin
            for name in plugins:
                if not name: continue
                err_str, plugin = get_plugin(name)
                if err_str:
                    raise argparse.ArgumentTypeError(err_str)
                cipher.plugins.append(plugin)
    if loc:
        host_name, port = proto.netloc_split(loc, default_port=22 if 'ssh' in rawprotos else 8080)
    else:
        host_name = port = None
    if url.fragment.startswith('#'):
        with open(url.fragment[1:]) as f:
            auth = f.read().rstrip().encode()
    else:
        auth = url.fragment.encode()
    users = [i.rstrip() for i in auth.split(b'\n')] if auth else None
    if 'direct' in protonames:
        return ProxyDirect(lbind=lbind)
    else:
        params = ProxyConfig(
            jump=jump,
            protos=protos,
            cipher=cipher,
            users=users,
            rule=url.query,
            bind=loc or urlpath,
            host_name=host_name,
            port=port,
            unix=not loc,
            lbind=lbind,
            sslclient=sslclient,
            sslserver=sslserver,
        ).as_kwargs()
        if 'quic' in rawprotos:
            proxy = ProxyQUIC(quicserver, quicclient, **params)
        elif 'h3' in protonames:
            proxy = ProxyH3(quicserver, quicclient, **params)
        elif 'h2' in protonames:
            proxy = ProxyH2(**params)
        elif 'ssh' in protonames:
            proxy = ProxySSH(**params)
        else:
            proxy = ProxySimple(**params)
        if 'in' in rawprotos:
            proxy = ProxyBackward(proxy, rawprotos.count('in'), **params)
        return proxy

async def test_url(url, rserver):
    url = urllib.parse.urlparse(url)
    require(url.scheme in ('http', 'https'), f'Unknown scheme {url.scheme}')
    host_name, port = proto.netloc_split(url.netloc, default_port = 80 if url.scheme=='http' else 443)
    initbuf = f'GET {url.path or "/"} HTTP/1.1\r\nHost: {host_name}\r\nUser-Agent: pproxy-{__version__}\r\nAccept: */*\r\nConnection: close\r\n\r\n'.encode()
    for roption in rserver:
        print(f'============ {roption.bind} ============')
        try:
            reader, writer = await roption.open_connection(host_name, port, None, None)
        except asyncio.TimeoutError:
            raise Exception(f'Connection timeout {rserver}')
        try:
            reader, writer = await roption.prepare_connection(reader, writer, host_name, port)
        except Exception:
            writer.close()
            raise Exception('Unknown remote protocol')
        if url.scheme == 'https':
            import ssl
            sslclient = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            sslclient.check_hostname = False
            sslclient.verify_mode = ssl.CERT_NONE
            reader, writer = proto.sslwrap(reader, writer, sslclient, False, host_name)
        writer.write(initbuf)
        headers = await transport.read_until(reader, b'\r\n\r\n')
        print(headers.decode()[:-4])
        print(f'--------------------------------')
        body = bytearray()
        read = reader.read
        while not reader.at_eof():
            s = await read(65536)
            if not s:
                break
            body.extend(s)
        print(body.decode('utf8', 'ignore'))
    print(f'============ success ============')

def print_server_started(option, server, print_fn):
    for s in server.sockets:
        # https://github.com/MagicStack/uvloop/blob/master/uvloop/pseudosock.pyx
        laddr = s.getsockname() # tuple size varies with protocol family
        h = laddr[0]
        p = laddr[1]
        family = s.family
        ipversion = "ipv4" if family == socket.AF_INET else ("ipv6" if family == socket.AF_INET6 else "ipv?")
        bind = ipversion+' '+h+':'+str(p)
        print_fn(option, bind)

def main(args=None):
    """Compatibility wrapper for the command-line application."""
    from .app import main as app_main

    return app_main(args)


from .h2 import ProxyH2
from .quic import ProxyH3, ProxyQUIC
from .ssh import ProxySSH


if __name__ == '__main__':
    main()
