"""Connection and listener lifecycle objects used by the server facade."""

import asyncio
import collections
import contextlib
import functools
import random
import socket

from .. import proto, transport
from ..errors import (
    ConnectionClosed,
    ProtocolError,
    require,
)
from ..runtime import (
    TaskRegistry,
    UDP_LIMIT,
    UDP_TASK_LIMIT,
)
from .common import (
    DUMMY,
    SOCKET_TIMEOUT,
    compile_rule,
    prepare_ciphers,
)


class ProxyDirect:
    """Direct TCP and UDP connection strategy."""

    def __init__(self, lbind=None):
        self.bind = 'DIRECT'
        self.lbind = lbind
        self.unix = False
        self.alive = True
        self.connections = 0
        self.writers = set()
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
        owner = self
        client_addr = addr

        class Protocol(asyncio.DatagramProtocol):
            def __init__(self, data):
                self.databuf = [data]
                self.transport = None
                owner.udp_touch(client_addr, self)

            def connection_made(self, new_transport):
                self.transport = new_transport
                for data in self.databuf:
                    new_transport.sendto(data)
                self.databuf.clear()
                owner.udp_touch(client_addr, self)

            def new_data_arrived(self, data):
                if self.transport:
                    self.transport.sendto(data)
                else:
                    self.databuf.append(data)
                owner.udp_touch(client_addr, self)

            def datagram_received(self, data, addr):
                del addr
                data = owner.udp_packet_unpack(data)
                reply(data)
                owner.udp_touch(client_addr, self)

            def connection_lost(self, exc):
                del exc
                owner.udp_discard(client_addr)

        if addr in self.udpmap:
            prot = self.udpmap[addr]
            prot.new_data_arrived(data)
        else:
            self.connection_change(1)
            self.udp_evict_if_needed()
            protocol_factory = lambda: Protocol(data)
            remote = self.destination(host, port)
            loop = asyncio.get_running_loop()
            await loop.create_datagram_endpoint(protocol_factory, remote_addr=remote)

    def close(self):
        self.task_registry.cancel_all()
        for writer in tuple(self.writers):
            writer.close()
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

    async def wait_open_connection(self, host, port, local_addr, family):
        return await asyncio.open_connection(host=host, port=port, local_addr=local_addr, family=family)

    async def open_connection(self, host, port, local_addr, lbind, timeout=SOCKET_TIMEOUT):
        local_addr = (
            local_addr if self.lbind == 'in' else (self.lbind, 0) if self.lbind else
            local_addr if lbind == 'in' else (lbind, 0) if lbind else None
        )
        family = 0 if local_addr is None else socket.AF_INET6 if ':' in local_addr[0] else socket.AF_INET
        wait = self.wait_open_connection(host, port, local_addr, family)
        reader, writer = await asyncio.wait_for(wait, timeout=timeout)
        return reader, writer

    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        return reader_remote, writer_remote

    async def tcp_connect(self, host, port, local_addr=None, lbind=None):
        reader, writer = await self.open_connection(host, port, local_addr, lbind)
        try:
            reader, writer = await self.prepare_connection(reader, writer, host, port)
        except asyncio.CancelledError:
            writer.close()
            raise
        # Cleanup must run for backend-specific preparation failures too.
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
    """Proxy connection strategy with a configured protocol and optional jump."""

    def __init__(self, jump, protos, cipher, users, rule, bind,
                 host_name, port, unix, lbind, sslclient, sslserver,
                 insecure_host_key=False):
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
        self.insecure_host_key = insecure_host_key
        self.jump = jump
        self.udp_inflight = 0

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

    async def udp_start_server(self, args):
        from .handlers import datagram_handler

        owner = self

        class Protocol(asyncio.DatagramProtocol):
            def connection_made(self, new_transport):
                self.transport = new_transport

            def datagram_received(self, data, addr):
                if owner.udp_inflight >= UDP_TASK_LIMIT:
                    return
                owner.udp_inflight += 1

                async def handle_datagram():
                    try:
                        await datagram_handler(self.transport, data, addr, **vars(owner), **args)
                    finally:
                        owner.udp_inflight -= 1

                owner.task_registry.create_task(handle_datagram(), name='udp-datagram')

        loop = asyncio.get_running_loop()
        return await loop.create_datagram_endpoint(Protocol, local_addr=(self.host_name, self.port))

    async def wait_open_connection(self, host, port, local_addr, family):
        if self.unix:
            return await asyncio.open_unix_connection(path=self.bind)
        return await asyncio.open_connection(host=self.host_name, port=self.port, local_addr=local_addr, family=family)

    async def prepare_connection(self, reader_remote, writer_remote, host, port):
        reader_remote, writer_remote = proto.sslwrap(
            reader_remote,
            writer_remote,
            self.sslclient,
            False,
            self.host_name,
            task_registry=self.task_registry,
        )
        _, writer_cipher_r = await prepare_ciphers(self.cipher, reader_remote, writer_remote, self.bind)
        whost, wport = self.jump.destination(host, port)
        await self.rproto.connect(
            reader_remote=reader_remote,
            writer_remote=writer_remote,
            rauth=self.auth,
            host_name=whost,
            port=wport,
            writer_cipher_r=writer_cipher_r,
            myhost=self.host_name,
            sock=writer_remote.get_extra_info('socket'),
        )
        return await self.jump.prepare_connection(reader_remote, writer_remote, host, port)

    async def start_server(self, args, stream_handler=None):
        if stream_handler is None:
            from .handlers import stream_handler

        handler = functools.partial(stream_handler, **vars(self), **args)

        async def tracked_handler(reader, writer):
            self.writers.add(writer)
            try:
                await handler(reader, writer)
            finally:
                self.writers.discard(writer)

        if self.unix:
            return await asyncio.start_unix_server(tracked_handler, path=self.bind)
        return await asyncio.start_server(
            tracked_handler,
            host=self.host_name,
            port=self.port,
            reuse_port=args.get('ruport'),
        )


class ProxyBackward(ProxySimple):
    """Reverse tunnel strategy that maintains outbound connections."""

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
        except (ConnectionError, OSError, EOFError, asyncio.TimeoutError):
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
            except (AttributeError, OSError):
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

    async def start_server(self, args, stream_handler=None):
        if stream_handler is None:
            from .handlers import stream_handler

        handler = functools.partial(stream_handler, **vars(self.server), **args)
        for _ in range(self.backward_num):
            self.tasks.create_task(self.start_server_run(handler))
        return self

    async def start_server_run(self, handler):
        errwait = 0
        while not self.closed:
            wait = self.backward.open_connection(self.host_name, self.port, self.lbind, None)
            writer = None
            try:
                reader, writer = await asyncio.wait_for(wait, timeout=SOCKET_TIMEOUT)
                if self.closed:
                    writer.close()
                    break
                if getattr(self.server, 'quicserver', None) is not None:
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
            except (ConnectionClosed, ProtocolError, ConnectionError, OSError, EOFError, asyncio.TimeoutError, ValueError):
                try:
                    if writer is not None:
                        writer.close()
                except (AttributeError, OSError):
                    pass
                if not self.closed:
                    await asyncio.sleep(errwait)
                    errwait = min(errwait * 1.3 + 0.1, 30)

    def start_backward_client(self, args):
        async def handler(reader, writer, **kw):
            auth = self.server.auth
            if getattr(self.server, 'quicserver', None) is not None:
                auth = b'\x01' + auth
            if auth:
                try:
                    require(auth == (await transport.read_exactly(reader, len(auth))))
                except (ConnectionClosed, ProtocolError, ConnectionError, OSError, EOFError, asyncio.TimeoutError, ValueError):
                    return
            await self.conn.put(
                (reader, writer, self.tasks.create_task(self.watch_connection(reader, writer)))
            )

        return self.backward.start_server(args, handler)


async def check_server_alive(interval, rserver, verbose):
    """Periodically update remote availability without hiding cancellation."""
    while True:
        await asyncio.sleep(interval)
        for remote in rserver:
            if type(remote) is ProxyDirect:
                continue
            try:
                _, writer = await remote.open_connection(None, None, None, None, timeout=3)
            except asyncio.CancelledError:
                return
            except (ConnectionClosed, ProtocolError, ConnectionError, OSError, EOFError, asyncio.TimeoutError, ValueError):
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
            except (AttributeError, OSError):
                pass
