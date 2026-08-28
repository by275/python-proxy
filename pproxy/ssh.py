"""SSH optional transport adapter."""

import asyncio

from . import server as runtime
from .errors import ConfigurationError


class ProxySSH(runtime.ProxySimple):
    """Proxy backend for SSH tunnels using the optional ``asyncssh`` package."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.sshconn = None

    def logtext(self, host, port):
        return f' -> sshtunnel {self.bind}' + self.jump.logtext(host, port)

    def patch_stream(self, ssh_reader, writer, host, port):
        reader = asyncio.StreamReader()

        async def channel():
            read = ssh_reader.read
            while not ssh_reader.at_eof() and not writer.is_closing():
                buf = await read(65536)
                if not buf:
                    break
                reader.feed_data(buf)
            reader.feed_eof()

        self.task_registry.create_task(channel())
        remote_addr = ('ssh:' + str(host), port)
        writer.get_extra_info = {"peername": remote_addr, "sockname": remote_addr}.get
        return reader, writer

    async def wait_ssh_connection(self, local_addr=None, family=0, tunnel=None):
        if self.sshconn is not None and not self.sshconn.cancelled():
            if not self.sshconn.done():
                await self.sshconn
        else:
            self.sshconn = asyncio.get_running_loop().create_future()
            try:
                import asyncssh
            except ImportError as exc:
                self.sshconn.cancel()
                self.sshconn = None
                raise ConfigurationError('Missing library: "pip3 install asyncssh"') from exc
            username, password = self.auth.decode().split(':', 1)
            if password.startswith(':'):
                client_keys = [password[1:]]
                password = None
            else:
                client_keys = None
            connect_kwargs = {
                'host': self.host_name,
                'port': self.port,
                'local_addr': local_addr,
                'family': family,
                'x509_trusted_certs': None,
                'username': username,
                'password': password,
                'client_keys': client_keys,
                'keepalive_interval': 60,
                'tunnel': tunnel,
            }
            if self.insecure_host_key:
                connect_kwargs['known_hosts'] = None
            conn = await asyncssh.connect(**connect_kwargs)
            self.sshconn.set_result(conn)

    async def wait_open_connection(self, host, port, local_addr, family, tunnel=None):
        try:
            await self.wait_ssh_connection(local_addr, family, tunnel)
            conn = self.sshconn.result()
            if isinstance(self.jump, ProxySSH):
                reader, writer = await self.jump.wait_open_connection(host, port, None, None, conn)
            else:
                host, port = self.jump.destination(host, port)
                if self.jump.unix:
                    reader, writer = await conn.open_unix_connection(self.jump.bind)
                else:
                    reader, writer = await conn.open_connection(host, port)
                reader, writer = self.patch_stream(reader, writer, host, port)
            return reader, writer
        # Clear the shared future for backend-specific connection failures.
        except Exception as ex:
            if self.sshconn is not None and not self.sshconn.done():
                self.sshconn.set_exception(ex)
            self.sshconn = None
            raise

    async def start_server(self, args, stream_handler=runtime.stream_handler, tunnel=None):
        if type(self.jump) is runtime.ProxyDirect:
            raise ConfigurationError('ssh server mode unsupported')
        await self.wait_ssh_connection(tunnel=tunnel)
        conn = self.sshconn.result()
        if isinstance(self.jump, ProxySSH):
            return await self.jump.start_server(args, stream_handler, conn)

        def handler(host, port):
            def handler_stream(reader, writer):
                reader, writer = self.patch_stream(reader, writer, host, port)
                return stream_handler(reader, writer, **vars(self.jump), **args)

            return handler_stream

        if self.jump.unix:
            return await conn.start_unix_server(handler, self.jump.bind)
        return await conn.start_server(handler, self.jump.host_name, self.jump.port)
