"""SSH optional transport adapter."""

import asyncio

from .errors import ConfigurationError
from .runtime import AdapterCapabilities
from .server.connections import ProxyDirect, ProxySimple
from .server.handlers import stream_handler as default_stream_handler


class ProxySSH(ProxySimple):
    """Proxy backend for SSH tunnels using the optional ``asyncssh`` package."""

    adapter_capabilities = AdapterCapabilities(
        name='ssh',
        dependency='asyncssh',
        supports_streams=True,
        supports_datagrams=False,
        multiplexed=True,
        owns_shared_session=True,
    )

    def __init__(self, **kw):
        super().__init__(**kw)
        self.sshconn = None

    def logtext(self, host, port):
        """Format the SSH backend and its jump chain for diagnostics."""
        return f' -> sshtunnel {self.bind}' + self.jump.logtext(host, port)

    def patch_stream(self, ssh_reader, writer, host, port):
        """Bridge an asyncssh channel to the project's stream interface."""
        reader = asyncio.StreamReader()

        async def channel():
            """Forward bytes from the SSH channel into the stream reader."""
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

    def close(self):
        """Close local streams and the shared SSH connection."""
        super().close()
        if self.sshconn is None or not self.sshconn.done() or self.sshconn.cancelled():
            return
        try:
            self.sshconn.result().close()
        except Exception:  # pylint: disable=broad-exception-caught
            # A failed connection future has no transport to close.
            pass

    async def wait_closed(self):
        """Wait for local tasks and the shared SSH connection to close."""
        await super().wait_closed()
        if self.sshconn is None or not self.sshconn.done() or self.sshconn.cancelled():
            return
        try:
            await self.sshconn.result().wait_closed()
        except Exception:  # pylint: disable=broad-exception-caught
            # Preserve the cleanup contract when AsyncSSH reports close errors.
            pass

    async def wait_ssh_connection(self, local_addr=None, family=0, tunnel=None):
        """Create or await the shared optional asyncssh connection."""
        if self.sshconn is not None and not self.sshconn.cancelled():
            if not self.sshconn.done():
                await self.sshconn
        else:
            self.sshconn = asyncio.get_running_loop().create_future()
            try:
                import asyncssh  # pylint: disable=import-outside-toplevel  # optional backend
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
            try:
                conn = await asyncssh.connect(**connect_kwargs)
            except asyncio.CancelledError:
                self.sshconn.cancel()
                self.sshconn = None
                raise
            except Exception as exc:
                self.sshconn.set_exception(exc)
                # The caller receives the original exception directly. Retrieve
                # the future exception as well so failed shared handshakes do not
                # produce an unhandled-future warning.
                self.sshconn.exception()
                self.sshconn = None
                raise
            self.sshconn.set_result(conn)

    async def wait_open_connection(self, host, port, local_addr, family, tunnel=None):
        """Open the selected jump destination over the SSH connection."""
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

    async def start_server(self, args, stream_handler=default_stream_handler, tunnel=None):
        """Start an SSH-backed listener for the configured jump destination."""
        # SSH server mode requires a configured jump, not the direct sentinel.
        if type(self.jump) is ProxyDirect:  # pylint: disable=unidiomatic-typecheck
            raise ConfigurationError('ssh server mode unsupported')
        await self.wait_ssh_connection(tunnel=tunnel)
        conn = self.sshconn.result()
        if isinstance(self.jump, ProxySSH):
            return await self.jump.start_server(args, stream_handler, conn)

        def handler(host, port):
            """Build a stream handler for one remote destination."""
            def handler_stream(reader, writer):
                """Bridge an accepted stream before invoking the proxy handler."""
                reader, writer = self.patch_stream(reader, writer, host, port)
                return stream_handler(reader, writer, **vars(self.jump), **args)

            return handler_stream

        if self.jump.unix:
            return await conn.start_unix_server(handler, self.jump.bind)
        return await conn.start_server(handler, self.jump.host_name, self.jump.port)
